"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import secrets
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from app.common.utils import sha256_hex


def generate_dh_params() -> tuple[int, int]:
    """Generate DH parameters (g, p). Returns (generator, prime_modulus)."""
    # Use standard 2048-bit MODP group (RFC 5114)
    # For simplicity, we'll use a well-known safe prime
    # In production, use proper parameter generation
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    return g, p


def generate_private_key() -> int:
    """Generate a random private key (a) for DH."""
    # Generate a random 256-bit private key
    return secrets.randbits(256)


def public_value(g: int, a: int, p: int) -> int:
    """Compute public value: g^a mod p."""
    return pow(g, a, p)


def compute_shared_secret(B: int, a: int, p: int) -> int:
    """Compute shared secret: B^a mod p."""
    return pow(B, a, p)


def derive_aes_key(shared_secret: int) -> bytes:
    """Derive AES-128 key: Trunc16(SHA256(big-endian(Ks)))."""
    # Convert shared secret to big-endian bytes
    # Determine number of bytes needed
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    
    # Compute SHA-256 hash
    from app.common.utils import sha256_hex
    hash_hex = sha256_hex(secret_bytes)
    
    # Convert hex to bytes and truncate to 16 bytes (128 bits)
    hash_bytes = bytes.fromhex(hash_hex)
    aes_key = hash_bytes[:16]
    
    return aes_key
