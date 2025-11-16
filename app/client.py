"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import sys
import argparse
import secrets
import hashlib
from typing import Optional
from dotenv import load_dotenv 


from app.common.protocol import (
    HelloMessage, ServerHelloMessage, RegisterMessage, LoginMessage,
    DHClientMessage, DHServerMessage, ChatMessage, ReceiptMessage, ResponseMessage
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto.pki import load_certificate, load_private_key, verify_certificate_chain, check_expiry, check_common_name, get_certificate_fingerprint
from app.crypto.sign import sign_message_fields, verify_message_signature, sign_data, verify_signature
from app.crypto.aes import encrypt_aes, decrypt_aes
from app.crypto.dh import generate_dh_params, generate_private_key, public_value, compute_shared_secret, derive_aes_key
from app.storage.transcript import log_message, compute_transcript_hash, get_transcript_stats, save_receipt

load_dotenv()


class SecureChatClient:
    def __init__(self, host='localhost', port=8888, debug=False):
        self.host = host
        self.port = port
        self.debug = debug
        
        # Load client certificate and key
        cert_path = os.getenv('CLIENT_CERT', 'certs/client.crt')
        key_path = os.getenv('CLIENT_KEY', 'certs/client.key')
        ca_cert_path = os.getenv('CA_CERT', 'certs/root_ca.crt')
        
        self.client_cert = load_certificate(cert_path)
        self.client_key = load_private_key(key_path)
        self.ca_cert = load_certificate(ca_cert_path)
        
        # Session state
        self.server_cert: Optional[object] = None
        self.temp_dh_key: Optional[int] = None
        self.temp_dh_params: Optional[tuple] = None
        self.temp_aes_key: Optional[bytes] = None
        self.session_dh_key: Optional[int] = None
        self.session_dh_params: Optional[tuple] = None
        self.session_aes_key: Optional[bytes] = None
        self.seqno = 0
        self.last_server_seqno = -1
        
        if self.debug:
            print(f"[DEBUG] Client initialized")
            print(f"[DEBUG] Client cert CN: {self.client_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value}")
    
    def send_message(self, sock: socket.socket, msg: dict):
        """Send JSON message over socket."""
        data = json.dumps(msg).encode('utf-8')
        sock.sendall(data + b'\n')
    
    def receive_message(self, sock: socket.socket) -> dict:
        """Receive JSON message from socket."""
        buffer = b''
        while b'\n' not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")
            buffer += chunk
        line = buffer.split(b'\n', 1)[0]
        return json.loads(line.decode('utf-8'))
    
    def verify_server_certificate(self, cert_pem: str) -> bool:
        """Verify server certificate against CA."""
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        
        # Check chain signature
        if not verify_certificate_chain(cert, self.ca_cert):
            if self.debug:
                print("[DEBUG] Certificate chain verification failed")
            return False
        
        # Check expiry
        if not check_expiry(cert):
            if self.debug:
                print("[DEBUG] Certificate expired or not yet valid")
            return False
        
        # Check CN (should match expected server CN)
        # For now, accept any valid cert signed by CA
        
        self.server_cert = cert
        return True
    
    def establish_control_plane(self, sock: socket.socket) -> bool:
        """Establish control plane with certificate exchange."""
        # Send client hello
        client_cert_pem = self.client_cert.public_bytes(x509.Encoding.PEM).decode('utf-8')
        client_nonce = secrets.token_bytes(16)
        
        hello = HelloMessage(
            client_cert=client_cert_pem,
            nonce=b64e(client_nonce)
        )
        self.send_message(sock, hello.model_dump())
        
        # Receive server hello
        msg = self.receive_message(sock)
        if msg.get('type') != 'server_hello':
            print("Error: Expected server_hello")
            return False
        
        server_hello = ServerHelloMessage(**msg)
        
        # Verify server certificate
        if not self.verify_server_certificate(server_hello.server_cert):
            print("Error: Invalid server certificate")
            return False
        
        if self.debug:
            print("[DEBUG] Server certificate verified")
        
        # Receive DH parameters for temporary key
        msg = self.receive_message(sock)
        if msg.get('type') != 'dh_params':
            print("Error: Expected dh_params")
            return False
        
        g = msg['g']
        p = msg['p']
        server_public = msg['B']
        
        self.temp_dh_params = (g, p)
        self.temp_dh_key = generate_private_key()
        client_public = public_value(g, self.temp_dh_key, p)
        
        # Compute shared secret
        shared_secret = compute_shared_secret(server_public, self.temp_dh_key, p)
        self.temp_aes_key = derive_aes_key(shared_secret)
        
        if self.debug:
            print(f"[DEBUG] Temp DH params: g={g}, p={p}")
            print(f"[DEBUG] Temp DH private key: {self.temp_dh_key}")
            print(f"[DEBUG] Temp DH public value: {client_public}")
            print(f"[DEBUG] Temp AES key: {self.temp_aes_key.hex()}")
        
        # Send client's public value
        self.send_message(sock, {
            "type": "dh_response",
            "A": client_public
        })
        
        return True
    
    def register(self, sock: socket.socket, email: str, username: str, password: str) -> bool:
        """Register a new user."""
        if not self.temp_aes_key:
            print("Error: Control plane not established")
            return False
        
        # Send plain password (encrypted with temporary AES key)
        # Server will generate salt and hash it
        # Prepare registration data
        reg_data = {
            "email": email,
            "username": username,
            "pwd": password
        }
        
        # Encrypt with temporary AES key
        encrypted = encrypt_aes(self.temp_aes_key, json.dumps(reg_data).encode('utf-8'))
        
        # Send registration request
        register = RegisterMessage(encrypted_data=encrypted)
        self.send_message(sock, register.model_dump())
        
        # Receive response
        msg = self.receive_message(sock)
        if msg.get('status') == 'ok':
            print("Registration successful!")
            return True
        else:
            print(f"Registration failed: {msg.get('message', 'Unknown error')}")
            return False
    
    def login(self, sock: socket.socket, email: str, password: str) -> bool:
        """Login with email and password."""
        if not self.temp_aes_key:
            print("Error: Control plane not established")
            return False
        
        # Send plain password (encrypted with temporary AES key)
        # Server will use stored salt to verify
        # Prepare login data
        login_data = {
            "email": email,
            "pwd": password
        }
        
        # Encrypt with temporary AES key
        encrypted = encrypt_aes(self.temp_aes_key, json.dumps(login_data).encode('utf-8'))
        
        # Send login request
        login = LoginMessage(encrypted_data=encrypted)
        self.send_message(sock, login.model_dump())
        
        # Receive response
        msg = self.receive_message(sock)
        if msg.get('status') != 'ok':
            print("Login failed")
            return False
        
        print("Login successful!")
        
        # Receive session DH parameters
        msg = self.receive_message(sock)
        if msg.get('type') != 'dh_session':
            print("Error: Expected dh_session")
            return False
        
        g = msg['g']
        p = msg['p']
        server_public = msg['B']
        
        self.session_dh_params = (g, p)
        self.session_dh_key = generate_private_key()
        client_public = public_value(g, self.session_dh_key, p)
        
        # Compute session shared secret
        shared_secret = compute_shared_secret(server_public, self.session_dh_key, p)
        self.session_aes_key = derive_aes_key(shared_secret)
        
        if self.debug:
            print(f"[DEBUG] Session DH params: g={g}, p={p}")
            print(f"[DEBUG] Session DH private key: {self.session_dh_key}")
            print(f"[DEBUG] Session DH public value: {client_public}")
            print(f"[DEBUG] Session AES key: {self.session_aes_key.hex()}")
        
        # Send client's session public value
        self.send_message(sock, {
            "type": "dh_session",
            "A": client_public
        })
        
        # Receive session established confirmation
        msg = self.receive_message(sock)
        if msg.get('status') == 'ok':
            return True
        else:
            print("Session establishment failed")
            return False
    
    def send_chat_message(self, sock: socket.socket, text: str) -> bool:
        """Send an encrypted chat message."""
        if not self.session_aes_key:
            print("Error: Session not established")
            return False
        
        # Encrypt message
        ciphertext = encrypt_aes(self.session_aes_key, text.encode('utf-8'))
        
        # Increment sequence number
        self.seqno += 1
        timestamp = now_ms()
        
        # Sign message
        signature = sign_message_fields(self.client_key, self.seqno, timestamp, ciphertext)
        
        # Create chat message
        chat_msg = ChatMessage(
            seqno=self.seqno,
            ts=timestamp,
            ct=ciphertext,
            sig=signature
        )
        
        # Log to transcript
        server_fingerprint = get_certificate_fingerprint(self.server_cert)
        log_message('client', self.seqno, timestamp, ciphertext, signature, server_fingerprint)
        
        # Send message
        self.send_message(sock, chat_msg.model_dump())
        
        # Receive response
        try:
            msg = self.receive_message(sock)
            if msg.get('type') == 'msg':
                chat_response = ChatMessage(**msg)
                
                # Verify signature
                server_public_key = self.server_cert.public_key()
                if not verify_message_signature(server_public_key, chat_response.seqno, chat_response.ts, chat_response.ct, chat_response.sig):
                    print("Error: Server message signature verification failed")
                    return False
                
                # Replay protection
                if chat_response.seqno <= self.last_server_seqno:
                    print("Error: Replay attack detected")
                    return False
                
                # Decrypt response
                decrypted = decrypt_aes(self.session_aes_key, chat_response.ct)
                response_text = decrypted.decode('utf-8')
                
                if self.debug:
                    print(f"[DEBUG] Server response: {response_text}")
                else:
                    print(f"Server: {response_text}")
                
                # Log server's message
                server_fingerprint = get_certificate_fingerprint(self.server_cert)
                log_message('client', chat_response.seqno, chat_response.ts, chat_response.ct, chat_response.sig, server_fingerprint)
                
                self.last_server_seqno = chat_response.seqno
                return True
            else:
                print(f"Unexpected response: {msg}")
                return False
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error receiving response: {e}")
            return False
    
    def end_session(self, sock: socket.socket):
        """End session and exchange receipts."""
        # Generate client receipt
        first_seq, last_seq = get_transcript_stats('client')
        transcript_hash = compute_transcript_hash('client')
        
        receipt_data = f"client|{first_seq}|{last_seq}|{transcript_hash}".encode('utf-8')
        receipt_sig = sign_data(self.client_key, receipt_data)
        
        save_receipt('client', 'server', first_seq, last_seq, transcript_hash, receipt_sig)
        
        client_receipt = ReceiptMessage(
            peer='server',
            first_seq=first_seq,
            last_seq=last_seq,
            transcript_sha256=transcript_hash,
            sig=receipt_sig
        )
        
        self.send_message(sock, client_receipt.model_dump())
        
        # Receive server receipt
        try:
            msg = self.receive_message(sock)
            if msg.get('type') == 'receipt':
                server_receipt = ReceiptMessage(**msg)
                
                # Verify server receipt signature
                server_public_key = self.server_cert.public_key()
                server_receipt_data = f"{server_receipt.peer}|{server_receipt.first_seq}|{server_receipt.last_seq}|{server_receipt.transcript_sha256}".encode('utf-8')
                
                if verify_signature(server_public_key, server_receipt_data, server_receipt.sig):
                    print("✓ Server receipt verified")
                    if self.debug:
                        print(f"[DEBUG] Server receipt: first_seq={server_receipt.first_seq}, last_seq={server_receipt.last_seq}")
                else:
                    print("✗ Server receipt signature verification failed")
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error receiving server receipt: {e}")
        
        # Send bye
        self.send_message(sock, {"type": "bye"})
    
    def interactive_chat(self, sock: socket.socket):
        """Interactive chat loop."""
        print("\n=== Secure Chat Session ===")
        print("Type messages to send. Type 'quit' to end session.")
        print()
        
        try:
            while True:
                user_input = input("You: ").strip()
                if not user_input:
                    continue
                
                if user_input.lower() == 'quit':
                    break
                
                if not self.send_chat_message(sock, user_input):
                    print("Error sending message")
                    break
        except KeyboardInterrupt:
            print("\nInterrupted")
        finally:
            self.end_session(sock)
            print("Session ended")


def main():
    parser = argparse.ArgumentParser(description='Secure Chat Client')
    parser.add_argument('--host', type=str, default='localhost',
                        help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=8888,
                        help='Server port (default: 8888)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')
    parser.add_argument('--register', action='store_true',
                        help='Register a new user')
    parser.add_argument('--email', type=str,
                        help='Email for registration/login')
    parser.add_argument('--username', type=str,
                        help='Username for registration')
    parser.add_argument('--password', type=str,
                        help='Password for registration/login')
    args = parser.parse_args()
    
    client = SecureChatClient(host=args.host, port=args.port, debug=args.debug)
    
    try:
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((args.host, args.port))
        
        # Establish control plane
        if not client.establish_control_plane(sock):
            print("Failed to establish control plane")
            sock.close()
            return
        
        # Register or login
        if args.register:
            if not args.email or not args.username or not args.password:
                print("Error: --email, --username, and --password required for registration")
                sock.close()
                return
            
            if not client.register(sock, args.email, args.username, args.password):
                sock.close()
                return
        else:
            if not args.email or not args.password:
                print("Error: --email and --password required for login")
                sock.close()
                return
            
            if not client.login(sock, args.email, args.password):
                sock.close()
                return
        
        # Start interactive chat
        client.interactive_chat(sock)
        
    except Exception as e:
        if args.debug:
            import traceback
            traceback.print_exc()
        else:
            print(f"Error: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
