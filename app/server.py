"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import sys
import argparse
import secrets
from typing import Optional
from dotenv import load_dotenv

from app.common.protocol import (
    HelloMessage, ServerHelloMessage, RegisterMessage, LoginMessage,
    DHClientMessage, DHServerMessage, ChatMessage, ReceiptMessage, ResponseMessage
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto.pki import load_certificate, load_private_key, verify_certificate_chain, check_expiry, check_common_name, get_certificate_fingerprint
from app.crypto.sign import sign_message_fields, verify_message_signature, sign_data
from app.crypto.aes import encrypt_aes, decrypt_aes
from app.crypto.dh import generate_dh_params, generate_private_key, public_value, compute_shared_secret, derive_aes_key
from app.storage.db import register_user, verify_user, get_user
from app.storage.transcript import log_message, compute_transcript_hash, get_transcript_stats, save_receipt

load_dotenv()


class SecureChatServer:
    def __init__(self, host='localhost', port=8888, debug=False):
        self.host = host
        self.port = port
        self.debug = debug
        
        # Load server certificate and key
        cert_path = os.getenv('SERVER_CERT', 'certs/server.crt')
        key_path = os.getenv('SERVER_KEY', 'certs/server.key')
        ca_cert_path = os.getenv('CA_CERT', 'certs/root_ca.crt')
        
        self.server_cert = load_certificate(cert_path)
        self.server_key = load_private_key(key_path)
        self.ca_cert = load_certificate(ca_cert_path)
        
        # Session state
        self.client_cert: Optional[object] = None
        self.client_cert_pem: Optional[str] = None
        self.temp_dh_key: Optional[int] = None
        self.temp_dh_params: Optional[tuple] = None
        self.temp_aes_key: Optional[bytes] = None
        self.session_dh_key: Optional[int] = None
        self.session_dh_params: Optional[tuple] = None
        self.session_aes_key: Optional[bytes] = None
        self.seqno = 0
        self.last_client_seqno = -1
        self.authenticated_user: Optional[str] = None
        
        if self.debug:
            from cryptography import x509
            print(f"[DEBUG] Server initialized")
            print(f"[DEBUG] Server cert CN: {self.server_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value}")
    
    def send_message(self, conn: socket.socket, msg: dict):
        """Send JSON message over socket."""
        data = json.dumps(msg).encode('utf-8')
        conn.sendall(data + b'\n')
    
    def receive_message(self, conn: socket.socket) -> dict:
        """Receive JSON message from socket."""
        buffer = b''
        while b'\n' not in buffer:
            chunk = conn.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")
            buffer += chunk
        line = buffer.split(b'\n', 1)[0]
        return json.loads(line.decode('utf-8'))
    
    def verify_client_certificate(self, cert_pem: str) -> bool:
        """Verify client certificate against CA."""
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
        
        # Check CN (should match expected client CN)
        # For now, accept any valid cert signed by CA
        # In production, you'd check against a whitelist
        
        self.client_cert = cert
        self.client_cert_pem = cert_pem
        return True
    
    def handle_hello(self, conn: socket.socket, msg: dict):
        """Handle client hello message."""
        hello = HelloMessage(**msg)
        
        # Verify client certificate
        if not self.verify_client_certificate(hello.client_cert):
            self.send_message(conn, {
                "type": "response",
                "status": "error",
                "error_code": "BAD_CERT",
                "message": "Invalid or expired certificate"
            })
            return False
        
        # Generate server nonce
        server_nonce = secrets.token_bytes(16)
        
        # Send server hello
        server_hello = ServerHelloMessage(
            server_cert=self.server_cert.public_bytes(x509.Encoding.PEM).decode('utf-8'),
            nonce=b64e(server_nonce)
        )
        self.send_message(conn, server_hello.model_dump())
        
        # Generate temporary DH parameters for credential encryption
        g, p = generate_dh_params()
        self.temp_dh_params = (g, p)
        self.temp_dh_key = generate_private_key()
        temp_public = public_value(g, self.temp_dh_key, p)
        
        if self.debug:
            print(f"[DEBUG] Generated temp DH params: g={g}, p={p}")
            print(f"[DEBUG] Temp DH private key: {self.temp_dh_key}")
            print(f"[DEBUG] Temp DH public value: {temp_public}")
        
        # Send DH parameters to client
        self.send_message(conn, {
            "type": "dh_params",
            "g": g,
            "p": p,
            "B": temp_public
        })
        
        return True
    
    def handle_dh_response(self, conn: socket.socket, msg: dict):
        """Handle client's DH public value for temporary key."""
        client_public = msg.get('A')
        if not client_public:
            return False
        
        g, p = self.temp_dh_params
        shared_secret = compute_shared_secret(client_public, self.temp_dh_key, p)
        self.temp_aes_key = derive_aes_key(shared_secret)
        
        if self.debug:
            print(f"[DEBUG] Temp AES key: {self.temp_aes_key.hex()}")
        
        return True
    
    def handle_register(self, conn: socket.socket, msg: dict):
        """Handle registration request."""
        if not self.temp_aes_key:
            self.send_message(conn, {
                "type": "response",
                "status": "error",
                "message": "DH key exchange not completed"
            })
            return False
        
        register = RegisterMessage(**msg)
        
        try:
            # Decrypt registration data
            decrypted = decrypt_aes(self.temp_aes_key, register.encrypted_data)
            reg_data = json.loads(decrypted.decode('utf-8'))
            
            email = reg_data['email']
            username = reg_data['username']
            password = reg_data['pwd']  # Plain password
            
            # Generate server-side salt
            salt = secrets.token_bytes(16)
            
            # Compute password hash: SHA256(salt || password)
            import hashlib
            pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
            
            # Register user
            if register_user(email, username, salt, pwd_hash):
                self.send_message(conn, {
                    "type": "response",
                    "status": "ok",
                    "message": "Registration successful"
                })
                return True
            else:
                self.send_message(conn, {
                    "type": "response",
                    "status": "error",
                    "message": "Email already exists"
                })
                return False
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Registration error: {e}")
            self.send_message(conn, {
                "type": "response",
                "status": "error",
                "message": "Registration failed"
            })
            return False
    
    def handle_login(self, conn: socket.socket, msg: dict):
        """Handle login request."""
        if not self.temp_aes_key:
            self.send_message(conn, {
                "type": "response",
                "status": "error",
                "message": "DH key exchange not completed"
            })
            return False
        
        login = LoginMessage(**msg)
        
        try:
            # Decrypt login data
            decrypted = decrypt_aes(self.temp_aes_key, login.encrypted_data)
            login_data = json.loads(decrypted.decode('utf-8'))
            
            email = login_data['email']
            password = login_data['pwd']  # Plain password
            
            # Get user from database
            user = get_user(email)
            if not user:
                self.send_message(conn, {
                    "type": "response",
                    "status": "error",
                    "message": "Invalid credentials"
                })
                return False
            
            # Verify password: hash with stored salt
            import hashlib
            computed_hash = hashlib.sha256(user['salt'] + password.encode('utf-8')).hexdigest()
            expected_hash = user['pwd_hash']
            
            if computed_hash != expected_hash:
                self.send_message(conn, {
                    "type": "response",
                    "status": "error",
                    "message": "Invalid credentials"
                })
                return False
            
            # Login successful - establish session key
            self.authenticated_user = email
            
            # Generate fresh DH parameters for session key
            g, p = generate_dh_params()
            self.session_dh_params = (g, p)
            self.session_dh_key = generate_private_key()
            session_public = public_value(g, self.session_dh_key, p)
            
            if self.debug:
                print(f"[DEBUG] Generated session DH params: g={g}, p={p}")
                print(f"[DEBUG] Session DH private key: {self.session_dh_key}")
                print(f"[DEBUG] Session DH public value: {session_public}")
            
            self.send_message(conn, {
                "type": "response",
                "status": "ok",
                "message": "Login successful"
            })
            
            # Send session DH parameters
            self.send_message(conn, {
                "type": "dh_session",
                "g": g,
                "p": p,
                "B": session_public
            })
            
            return True
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Login error: {e}")
            self.send_message(conn, {
                "type": "response",
                "status": "error",
                "message": "Login failed"
            })
            return False
    
    def handle_dh_session(self, conn: socket.socket, msg: dict):
        """Handle client's session DH public value."""
        client_public = msg.get('A')
        if not client_public:
            return False
        
        g, p = self.session_dh_params
        shared_secret = compute_shared_secret(client_public, self.session_dh_key, p)
        self.session_aes_key = derive_aes_key(shared_secret)
        
        if self.debug:
            print(f"[DEBUG] Session AES key: {self.session_aes_key.hex()}")
        
        self.send_message(conn, {
            "type": "response",
            "status": "ok",
            "message": "Session established"
        })
        
        return True
    
    def handle_chat_message(self, conn: socket.socket, msg: dict):
        """Handle encrypted chat message."""
        if not self.session_aes_key:
            self.send_message(conn, {
                "type": "response",
                "status": "error",
                "message": "Session not established"
            })
            return False
        
        chat = ChatMessage(**msg)
        
        # Replay protection: check sequence number
        if chat.seqno <= self.last_client_seqno:
            if self.debug:
                print(f"[DEBUG] Replay detected: seqno {chat.seqno} <= last {self.last_client_seqno}")
            self.send_message(conn, {
                "type": "response",
                "status": "error",
                "error_code": "REPLAY",
                "message": "Replay attack detected"
            })
            return False
        
        # Verify signature
        client_public_key = self.client_cert.public_key()
        if not verify_message_signature(client_public_key, chat.seqno, chat.ts, chat.ct, chat.sig):
            if self.debug:
                print("[DEBUG] Signature verification failed")
            self.send_message(conn, {
                "type": "response",
                "status": "error",
                "error_code": "SIG_FAIL",
                "message": "Signature verification failed"
            })
            return False
        
        # Decrypt message
        try:
            decrypted = decrypt_aes(self.session_aes_key, chat.ct)
            plaintext = decrypted.decode('utf-8')
            
            if self.debug:
                print(f"[DEBUG] Received message: {plaintext}")
            
            # Log to transcript
            peer_fingerprint = get_certificate_fingerprint(self.client_cert)
            log_message('server', chat.seqno, chat.ts, chat.ct, chat.sig, peer_fingerprint)
            
            # Update sequence number
            self.last_client_seqno = chat.seqno
            
            # Echo back (encrypted and signed)
            self.seqno += 1
            response_text = f"Echo: {plaintext}"
            response_ct = encrypt_aes(self.session_aes_key, response_text.encode('utf-8'))
            response_ts = now_ms()
            response_sig = sign_message_fields(self.server_key, self.seqno, response_ts, response_ct)
            
            response_msg = ChatMessage(
                seqno=self.seqno,
                ts=response_ts,
                ct=response_ct,
                sig=response_sig
            )
            
            # Log server's message
            client_fingerprint = get_certificate_fingerprint(self.client_cert)
            log_message('server', self.seqno, response_ts, response_ct, response_sig, client_fingerprint)
            
            self.send_message(conn, response_msg.model_dump())
            
            return True
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Decryption error: {e}")
            self.send_message(conn, {
                "type": "response",
                "status": "error",
                "message": "Decryption failed"
            })
            return False
    
    def handle_receipt(self, conn: socket.socket, msg: dict):
        """Handle session receipt from client."""
        receipt = ReceiptMessage(**msg)
        
        # Verify receipt signature
        client_public_key = self.client_cert.public_key()
        from app.crypto.sign import verify_signature
        receipt_data = f"{receipt.peer}|{receipt.first_seq}|{receipt.last_seq}|{receipt.transcript_sha256}".encode('utf-8')
        
        if not verify_signature(client_public_key, receipt_data, receipt.sig):
            if self.debug:
                print("[DEBUG] Receipt signature verification failed")
            return False
        
        # Generate and send server receipt
        first_seq, last_seq = get_transcript_stats('server')
        transcript_hash = compute_transcript_hash('server')
        
        server_receipt_data = f"server|{first_seq}|{last_seq}|{transcript_hash}".encode('utf-8')
        server_receipt_sig = sign_data(self.server_key, server_receipt_data)
        
        save_receipt('server', 'client', first_seq, last_seq, transcript_hash, server_receipt_sig)
        
        server_receipt = ReceiptMessage(
            peer='client',
            first_seq=first_seq,
            last_seq=last_seq,
            transcript_sha256=transcript_hash,
            sig=server_receipt_sig
        )
        
        self.send_message(conn, server_receipt.model_dump())
        
        return True
    
    def handle_client(self, conn: socket.socket, addr):
        """Handle a client connection."""
        print(f"Client connected from {addr}")
        
        try:
            # Reset session state
            self.client_cert = None
            self.temp_dh_key = None
            self.temp_aes_key = None
            self.session_dh_key = None
            self.session_aes_key = None
            self.seqno = 0
            self.last_client_seqno = -1
            self.authenticated_user = None
            
            while True:
                msg = self.receive_message(conn)
                msg_type = msg.get('type')
                
                if msg_type == 'hello':
                    if not self.handle_hello(conn, msg):
                        break
                elif msg_type == 'dh_response':
                    if not self.handle_dh_response(conn, msg):
                        break
                elif msg_type == 'register':
                    if not self.handle_register(conn, msg):
                        break
                elif msg_type == 'login':
                    if not self.handle_login(conn, msg):
                        break
                elif msg_type == 'dh_session':
                    if not self.handle_dh_session(conn, msg):
                        break
                elif msg_type == 'msg':
                    if not self.handle_chat_message(conn, msg):
                        break
                elif msg_type == 'receipt':
                    if not self.handle_receipt(conn, msg):
                        break
                elif msg_type == 'bye':
                    break
                else:
                    self.send_message(conn, {
                        "type": "response",
                        "status": "error",
                        "message": f"Unknown message type: {msg_type}"
                    })
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error handling client: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
            print(f"Client {addr} disconnected")
    
    def start(self):
        """Start the server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        
        print(f"Secure Chat Server listening on {self.host}:{self.port}")
        if self.debug:
            print("[DEBUG] Debug mode enabled")
        
        while True:
            conn, addr = sock.accept()
            # Handle each client in the main thread (for simplicity)
            # In production, use threading or async
            self.handle_client(conn, addr)


def main():
    parser = argparse.ArgumentParser(description='Secure Chat Server')
    parser.add_argument('--host', type=str, default='localhost',
                        help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=8888,
                        help='Server port (default: 8888)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')
    args = parser.parse_args()
    
    server = SecureChatServer(host=args.host, port=args.port, debug=args.debug)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")


if __name__ == "__main__":
    main()
