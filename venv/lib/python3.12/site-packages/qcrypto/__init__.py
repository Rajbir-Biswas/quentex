"""
qcrypto: Post-quantum cryptography for Python.

Provides:
- Kyber KEM key generation, encapsulation, and decapsulation
- Classic McEliece KEM support
- Dilithium, Falcon, and SPHINCS+ digital signatures
- Generic SignatureScheme wrapper for any liboqs signature algorithm
- Hybrid PQC + AES-GCM authenticated encryption
- High level encrypt() and decrypt() using Kyber768 + HKDF + AES-GCM
- ASCII-armored keys and messages (BEGIN/END blocks for copy-paste workflows)
"""

from .kem import KyberKEM, KyberKeypair, ClassicMcElieceKEM
from .signatures import (
    DilithiumSig,
    DilithiumKeypair,
    SignatureScheme,
    SignatureKeypair,
    FalconSig,
    SphincsSig,
    save_signature_public_key,
    load_signature_public_key,
    save_signature_private_key,
    load_signature_private_key,
    save_signature,
    load_signature,
)
from .fingerprints import key_fingerprint

from .hybrid import (
    encrypt,
    decrypt,
    encrypt_for_recipient,
    decrypt_from_sender,
    encrypt_file,
    decrypt_file,
    encrypt_message_armored,
    decrypt_message_armored,
)

__all__ = [
    "key_fingerprint",
    # KEMs
    "KyberKEM",
    "KyberKeypair",
    "ClassicMcElieceKEM",

    # Signatures
    "DilithiumSig",
    "DilithiumKeypair",
    "SignatureScheme",
    "SignatureKeypair",
    "FalconSig",
    "SphincsSig",

    # Signature file helpers
    "save_signature_public_key",
    "load_signature_public_key",
    "save_signature_private_key",
    "load_signature_private_key",
    "save_signature",
    "load_signature",

    # High level hybrid encryption
    "encrypt",
    "decrypt",

    # Armored message helpers
    "encrypt_message_armored",
    "decrypt_message_armored",

    # File helpers (v0.4)
    "encrypt_file",
    "decrypt_file",

    # Legacy v0.1 API
    "encrypt_for_recipient",
    "decrypt_from_sender",
]
