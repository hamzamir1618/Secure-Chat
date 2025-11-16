"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime
import os


def load_certificate(path: str) -> x509.Certificate:
    """Load X.509 certificate from PEM file."""
    with open(path, 'rb') as f:
        pem_data = f.read()
    return x509.load_pem_x509_certificate(pem_data)


def load_private_key(path: str) -> rsa.RSAPrivateKey:
    """Load RSA private key from PEM file."""
    with open(path, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=None)


def verify_certificate_chain(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """Verify that cert is signed by CA certificate."""
    try:
        # Get the CA's public key
        ca_public_key = ca_cert.public_key()
        
        # Verify the certificate signature
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_algorithm
        )
        return True
    except Exception:
        return False


def check_expiry(cert: x509.Certificate) -> bool:
    """Check if certificate is within validity period."""
    now = datetime.utcnow()
    return cert.not_valid_before <= now <= cert.not_valid_after


def check_common_name(cert: x509.Certificate, expected_cn: str) -> bool:
    """Check if certificate's CN matches expected value."""
    try:
        # Get the subject's common name
        subject = cert.subject
        cn_attributes = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_attributes:
            return False
        actual_cn = cn_attributes[0].value
        return actual_cn == expected_cn
    except Exception:
        return False


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """Get SHA-256 fingerprint of certificate for logging."""
    from app.common.utils import sha256_hex
    return sha256_hex(cert.fingerprint(x509.hashes.SHA256()))
