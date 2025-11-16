"""Create Root CA (RSA + self-signed X.509) using cryptography."""

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import BasicConstraints, Name
from cryptography.x509.oid import NameOID


def generate_ca(name: str = "FAST-NU Root CA"):
    """Generate Root CA certificate and private key."""
    # Ensure certs directory exists
    os.makedirs('certs', exist_ok=True)
    
    # Generate RSA private key (2048 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    
    # Certificate validity: 10 years
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=3650)
    
    # Generate serial number
    serial_number = x509.random_serial_number()
    
    # Build certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        serial_number
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(private_key, hashes.SHA256())
    
    # Save private key
    key_path = 'certs/root_ca.key'
    with open(key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"✓ CA private key saved to {key_path}")
    
    # Save certificate
    cert_path = 'certs/root_ca.crt'
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"✓ CA certificate saved to {cert_path}")
    
    print(f"\n✓ Root CA '{name}' generated successfully!")
    print(f"  Valid from: {valid_from.strftime('%Y-%m-%d')}")
    print(f"  Valid to: {valid_to.strftime('%Y-%m-%d')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate Root CA certificate')
    parser.add_argument('--name', type=str, default='FAST-NU Root CA',
                        help='Common Name for the CA (default: FAST-NU Root CA)')
    args = parser.parse_args()
    
    generate_ca(args.name)
