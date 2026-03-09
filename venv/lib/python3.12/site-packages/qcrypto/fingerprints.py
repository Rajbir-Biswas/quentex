import hashlib

def key_fingerprint(public_key: bytes) -> str:
    """Return stable key fingerprint: SHA256(pubkey)[:16] as hex (32 chars)."""
    if not isinstance(public_key, (bytes, bytearray)):
        raise TypeError("public_key must be bytes")
    return hashlib.sha256(bytes(public_key)).digest()[:16].hex()
