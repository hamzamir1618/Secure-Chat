"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from app.common.utils import b64e, b64d, sha256_hex


def sign_data(private_key: RSAPrivateKey, data: bytes) -> str:
    """Sign data using RSA PKCS#1 v1.5 with SHA-256. Returns base64 encoded signature."""
    # Hash the data first
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hash_value = digest.finalize()
    
    # Sign the hash
    signature = private_key.sign(
        hash_value,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return b64e(signature)


def verify_signature(public_key: RSAPublicKey, data: bytes, signature_b64: str) -> bool:
    """Verify RSA signature. Returns True if valid, False otherwise."""
    try:
        signature = b64d(signature_b64)
        
        # Hash the data
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        hash_value = digest.finalize()
        
        # Verify the signature
        public_key.verify(
            signature,
            hash_value,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def sign_message_fields(private_key: RSAPrivateKey, seqno: int, ts: int, ct: str) -> str:
    """Sign message fields: seqno||ts||ct (as per protocol)."""
    # Convert to bytes: seqno (big-endian int) || ts (big-endian int) || ct (base64 string as bytes)
    import struct
    data = struct.pack('>Q', seqno) + struct.pack('>Q', ts) + ct.encode('utf-8')
    return sign_data(private_key, data)


def verify_message_signature(public_key: RSAPublicKey, seqno: int, ts: int, ct: str, sig: str) -> bool:
    """Verify message signature."""
    import struct
    data = struct.pack('>Q', seqno) + struct.pack('>Q', ts) + ct.encode('utf-8')
    return verify_signature(public_key, data, sig)
