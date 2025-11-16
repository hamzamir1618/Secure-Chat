"""AES-128(ECB)+PKCS#7 helpers (use library)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from app.common.utils import b64e, b64d


def encrypt_aes(key: bytes, plaintext: bytes) -> str:
    """Encrypt plaintext using AES-128-ECB with PKCS#7 padding. Returns base64 encoded ciphertext."""
    # Ensure key is 16 bytes (128 bits)
    if len(key) != 16:
        raise ValueError("AES key must be exactly 16 bytes")
    
    # Apply PKCS#7 padding
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Encrypt using AES-128-ECB
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return b64e(ciphertext)


def decrypt_aes(key: bytes, ciphertext_b64: str) -> bytes:
    """Decrypt base64 encoded ciphertext using AES-128-ECB with PKCS#7 unpadding."""
    # Ensure key is 16 bytes (128 bits)
    if len(key) != 16:
        raise ValueError("AES key must be exactly 16 bytes")
    
    # Decode base64
    ciphertext = b64d(ciphertext_b64)
    
    # Decrypt using AES-128-ECB
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext
