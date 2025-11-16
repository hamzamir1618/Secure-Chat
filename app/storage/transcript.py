"""Append-only transcript + TranscriptHash helpers."""

import os
import json
from app.common.utils import sha256_hex, now_ms
from cryptography import x509


def ensure_logs_dir():
    """Ensure logs directory exists."""
    os.makedirs('logs', exist_ok=True)


def log_message(role: str, seqno: int, timestamp: int, ciphertext: str, signature: str, peer_cert_fingerprint: str):
    """Append a message to the transcript log.
    
    Args:
        role: 'client' or 'server'
        seqno: Sequence number
        timestamp: Unix timestamp in milliseconds
        ciphertext: Base64 encoded ciphertext
        signature: Base64 encoded signature
        peer_cert_fingerprint: SHA-256 fingerprint of peer's certificate
    """
    ensure_logs_dir()
    log_file = f'logs/transcript_{role}.txt'
    
    # Format: seqno | timestamp | ciphertext | sig | peer-cert-fingerprint
    log_entry = f"{seqno} | {timestamp} | {ciphertext} | {signature} | {peer_cert_fingerprint}\n"
    
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(log_entry)


def compute_transcript_hash(role: str) -> str:
    """Compute SHA-256 hash of the entire transcript.
    
    Args:
        role: 'client' or 'server'
    
    Returns:
        Hex-encoded SHA-256 hash of concatenated transcript lines
    """
    log_file = f'logs/transcript_{role}.txt'
    
    if not os.path.exists(log_file):
        # Empty transcript
        return sha256_hex(b'')
    
    with open(log_file, 'r', encoding='utf-8') as f:
        # Read all lines and concatenate
        lines = f.readlines()
        transcript_content = ''.join(lines).encode('utf-8')
    
    return sha256_hex(transcript_content)


def get_transcript_stats(role: str) -> tuple[int, int]:
    """Get first and last sequence numbers from transcript.
    
    Returns:
        (first_seq, last_seq) or (0, 0) if transcript is empty
    """
    log_file = f'logs/transcript_{role}.txt'
    
    if not os.path.exists(log_file):
        return (0, 0)
    
    first_seq = None
    last_seq = None
    
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(' | ')
            if len(parts) >= 1:
                try:
                    seqno = int(parts[0])
                    if first_seq is None:
                        first_seq = seqno
                    last_seq = seqno
                except ValueError:
                    continue
    
    if first_seq is None:
        return (0, 0)
    
    return (first_seq, last_seq)


def save_receipt(role: str, peer: str, first_seq: int, last_seq: int, transcript_hash: str, signature: str):
    """Save session receipt to JSON file.
    
    Args:
        role: 'client' or 'server' (who is saving the receipt)
        peer: 'client' or 'server' (the peer this receipt is about)
        first_seq: First sequence number
        last_seq: Last sequence number
        transcript_hash: SHA-256 hash of transcript
        signature: Base64 encoded RSA signature
    """
    os.makedirs('receipts', exist_ok=True)
    receipt_file = f'receipts/{role}_receipt.json'
    
    receipt = {
        "type": "receipt",
        "peer": peer,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": transcript_hash,
        "sig": signature
    }
    
    with open(receipt_file, 'w', encoding='utf-8') as f:
        json.dump(receipt, f, indent=2)
