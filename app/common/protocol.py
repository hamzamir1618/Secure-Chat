"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel
from typing import Optional


class HelloMessage(BaseModel):
    """Client hello with certificate and nonce."""
    type: str = "hello"
    client_cert: str  # PEM encoded certificate
    nonce: str  # base64 encoded nonce


class ServerHelloMessage(BaseModel):
    """Server hello with certificate and nonce."""
    type: str = "server_hello"
    server_cert: str  # PEM encoded certificate
    nonce: str  # base64 encoded nonce


class RegisterMessage(BaseModel):
    """Registration request (encrypted with temporary DH key)."""
    type: str = "register"
    encrypted_data: str  # base64 encoded AES encrypted payload


class LoginMessage(BaseModel):
    """Login request (encrypted with temporary DH key)."""
    type: str = "login"
    encrypted_data: str  # base64 encoded AES encrypted payload


class DHClientMessage(BaseModel):
    """Client DH public value for session key establishment."""
    type: str = "dh_client"
    g: int  # generator
    p: int  # prime modulus
    A: int  # client public value (g^a mod p)


class DHServerMessage(BaseModel):
    """Server DH public value for session key establishment."""
    type: str = "dh_server"
    B: int  # server public value (g^b mod p)


class ChatMessage(BaseModel):
    """Encrypted chat message with signature."""
    type: str = "msg"
    seqno: int
    ts: int  # unix timestamp in milliseconds
    ct: str  # base64 encoded ciphertext
    sig: str  # base64 encoded RSA signature


class ReceiptMessage(BaseModel):
    """Session receipt for non-repudiation."""
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex encoded SHA-256 of transcript
    sig: str  # base64 encoded RSA signature


class ResponseMessage(BaseModel):
    """Generic response message."""
    type: str
    status: str  # "ok" or "error"
    message: Optional[str] = None
    error_code: Optional[str] = None  # "BAD_CERT", "SIG_FAIL", "REPLAY", etc.
