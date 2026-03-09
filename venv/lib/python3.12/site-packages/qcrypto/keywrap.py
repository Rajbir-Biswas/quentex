import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"qcrypto-key-v1\n"
PBKDF2_ITERS = 200_000


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive AES-256 key from passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_private_key(raw_key: bytes, passphrase: str) -> bytes:
    """
    AES-GCM encrypt the raw Kyber private key under a passphrase.
    Produces a portable key file format:
        magic + salt + nonce + ciphertext+tag
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase, salt)

    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, raw_key, None)

    return MAGIC + salt + nonce + ct


def decrypt_private_key(data: bytes, passphrase: str) -> bytes:
    """
    Decrypt a key produced by encrypt_private_key().
    Returns the raw private key bytes.
    """
    if not data.startswith(MAGIC):
        raise ValueError("Not a qcrypto passphrase-encrypted key file")

    data = data[len(MAGIC):]
    salt = data[:16]
    nonce = data[16:28]
    ct = data[28:]

    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ct, None)
