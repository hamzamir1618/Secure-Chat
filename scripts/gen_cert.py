"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID


def generate_certificate(cn: str, out_path: str, ca_key_path: str, ca_cert_path: str):
    """Generate a certificate signed by the Root CA."""
    # Ensure certs directory exists
    os.makedirs('certs', exist_ok=True)
    
    # Load CA certificate and private key
    from app.crypto.pki import load_certificate, load_private_key
    
    ca_cert = load_certificate(ca_cert_path)
    ca_key = load_private_key(ca_key_path)
    
    # Generate RSA keypair for the certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    # Get CA issuer name
    issuer = ca_cert.subject
    
    # Certificate validity: 1 year
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=365)
    
    # Generate serial number
    serial_number = x509.random_serial_number()
    
    # Build certificate with SAN extension
    cert_builder = x509.CertificateBuilder().subject_name(
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
        x509.SubjectAlternativeName([
            x509.DNSName(cn)
        ]),
        critical=False,
    )
    
    # Sign with CA private key
    cert = cert_builder.sign(ca_key, hashes.SHA256())
    
    # Save private key
    key_path = f'{out_path}.key'
    with open(key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"✓ Private key saved to {key_path}")
    
    # Save certificate
    cert_path = f'{out_path}.crt'
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"✓ Certificate saved to {cert_path}")
    
    print(f"\n✓ Certificate for '{cn}' generated successfully!")
    print(f"  Valid from: {valid_from.strftime('%Y-%m-%d')}")
    print(f"  Valid to: {valid_to.strftime('%Y-%m-%d')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate certificate signed by Root CA')
    parser.add_argument('--cn', type=str, required=True,
                        help='Common Name (CN) for the certificate')
    parser.add_argument('--out', type=str, required=True,
                        help='Output path prefix (e.g., certs/server)')
    parser.add_argument('--ca-key', type=str, default='certs/root_ca.key',
                        help='Path to CA private key (default: certs/root_ca.key)')
    parser.add_argument('--ca-crt', type=str, default='certs/root_ca.crt',
                        help='Path to CA certificate (default: certs/root_ca.crt)')
    args = parser.parse_args()
    
    generate_certificate(args.cn, args.out, args.ca_key, args.ca_crt)
