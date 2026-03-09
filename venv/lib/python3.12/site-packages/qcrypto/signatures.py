from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import oqs
import ctypes as ct

from .armor import armor_encode, armor_decode, looks_armored
from .keywrap import encrypt_private_key, decrypt_private_key


# Existing Dilithium specific API (kept for backwards compatibility)

@dataclass
class DilithiumKeypair:
    public_key: bytes
    secret_key: bytes


class DilithiumSig:
    """
    Thin wrapper around liboqs Dilithium signatures.

    Default algorithm is "Dilithium3".
    """

    def __init__(self, variant: str = "Dilithium3"):
        self.alg = variant

    def generate_keypair(self) -> DilithiumKeypair:
        with oqs.Signature(self.alg) as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
            return DilithiumKeypair(pk, sk)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        with oqs.Signature(self.alg, secret_key=secret_key) as sig:
            return sig.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        with oqs.Signature(self.alg) as sig:
            return sig.verify(message, signature, public_key)


# Generic signature scheme wrappers

@dataclass
class SignatureKeypair:
    public_key: bytes
    secret_key: bytes


class SignatureScheme:
    """
    Generic wrapper for any liboqs signature algorithm string.
    """

    def __init__(self, alg: str):
        self.alg = alg

    def generate_keypair(self) -> SignatureKeypair:
        with oqs.Signature(self.alg) as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
            return SignatureKeypair(pk, sk)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        with oqs.Signature(self.alg, secret_key=secret_key) as sig:
            return sig.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        with oqs.Signature(self.alg) as sig:
            return sig.verify(message, signature, public_key)


class FalconSig(SignatureScheme):
    """
    Convenience wrapper for Falcon signatures.

    Default variant is "Falcon-512".
    """

    def __init__(self, variant: str = "Falcon-512"):
        super().__init__(alg=variant)


class SphincsSig(SignatureScheme):
    """
    Convenience wrapper for SPHINCS+ signatures.

    Default variant is "SPHINCS+-SHA2-128f-simple", which is one
    of the liboqs SPHINCS+ parameter sets. You can override with
    any other SPHINCS+ algorithm string supported by liboqs, such as
    "SPHINCS+-SHA2-256s-simple" or "SPHINCS+-SHAKE-128f-simple".
    """

    def __init__(self, variant: str = "SPHINCS+-SHA2-128f-simple"):
        super().__init__(alg=variant)


# Signature file formats (self-describing keys + signatures)

_SIG_PUB_MAGIC = b"qcrypto-sig-public-v1\n"
_SIG_PRIV_MAGIC = b"qcrypto-sig-private-v1\n"
_SIG_MAGIC = b"qcrypto-signature-v1\n"


def _u16(n: int) -> bytes:
    if not (0 <= n <= 65535):
        raise ValueError("length out of range")
    return bytes([(n >> 8) & 0xFF, n & 0xFF])


def _read_u16(data: bytes, offset: int) -> Tuple[int, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated data")
    return (data[offset] << 8) | data[offset + 1], offset + 2


def save_signature_public_key(
    path: str,
    public_key: bytes,
    alg: str,
    armored: bool = False,
) -> None:
    alg_b = alg.encode("utf-8")
    blob = _SIG_PUB_MAGIC + _u16(len(alg_b)) + alg_b + public_key

    if armored:
        Path(path).write_text(armor_encode("QCRYPTO SIG PUBLIC KEY", blob), encoding="utf-8")
    else:
        Path(path).write_bytes(blob)


def load_signature_public_key(path: str) -> Tuple[str, bytes]:
    data = Path(path).read_bytes()

    if looks_armored(data):
        _, raw = armor_decode(data, expected_label="QCRYPTO SIG PUBLIC KEY")
        data = raw

    if not data.startswith(_SIG_PUB_MAGIC):
        raise ValueError("Not a qcrypto signature public key file")

    off = len(_SIG_PUB_MAGIC)
    alg_len, off = _read_u16(data, off)
    if off + alg_len > len(data):
        raise ValueError("truncated public key header")
    alg = data[off : off + alg_len].decode("utf-8")
    off += alg_len
    pk = data[off:]
    if not pk:
        raise ValueError("empty public key")
    return alg, pk


def save_signature_private_key(
    path: str,
    secret_key: bytes,
    alg: str,
    armored: bool = False,
    passphrase: Optional[str] = None,
) -> None:
    alg_b = alg.encode("utf-8")

    if passphrase:
        payload = encrypt_private_key(secret_key, passphrase)
        enc_flag = b"\x01"
        label = "QCRYPTO SIG ENCRYPTED PRIVATE KEY"
    else:
        payload = secret_key
        enc_flag = b"\x00"
        label = "QCRYPTO SIG PRIVATE KEY"

    blob = _SIG_PRIV_MAGIC + enc_flag + _u16(len(alg_b)) + alg_b + payload

    if armored:
        Path(path).write_text(armor_encode(label, blob), encoding="utf-8")
    else:
        Path(path).write_bytes(blob)


def load_signature_private_key(path: str, passphrase: Optional[str] = None) -> Tuple[str, bytes]:
    data = Path(path).read_bytes()

    if looks_armored(data):
        label, raw = armor_decode(data)
        if label not in ("QCRYPTO SIG PRIVATE KEY", "QCRYPTO SIG ENCRYPTED PRIVATE KEY"):
            raise ValueError(f"Unknown signature private key armor label: {label}")
        data = raw

    if not data.startswith(_SIG_PRIV_MAGIC):
        raise ValueError("Not a qcrypto signature private key file")

    off = len(_SIG_PRIV_MAGIC)

    if off >= len(data):
        raise ValueError("truncated private key header")
    enc_flag = data[off]
    off += 1

    alg_len, off = _read_u16(data, off)
    if off + alg_len > len(data):
        raise ValueError("truncated private key header")
    alg = data[off : off + alg_len].decode("utf-8")
    off += alg_len

    payload = data[off:]
    if not payload:
        raise ValueError("empty private key payload")

    if enc_flag == 1:
        if not passphrase:
            raise ValueError("Private key is encrypted. Provide --pass.")
        sk = decrypt_private_key(payload, passphrase)
        return alg, sk

    if enc_flag == 0:
        return alg, payload

    raise ValueError("invalid encryption flag in private key file")


def save_signature(
    path: str,
    signature: bytes,
    alg: str,
    armored: bool = False,
) -> None:
    alg_b = alg.encode("utf-8")
    blob = _SIG_MAGIC + _u16(len(alg_b)) + alg_b + signature

    if armored:
        Path(path).write_text(armor_encode("QCRYPTO SIGNATURE", blob), encoding="utf-8")
    else:
        Path(path).write_bytes(blob)


def load_signature(path: str) -> Tuple[str, bytes]:
    data = Path(path).read_bytes()

    if looks_armored(data):
        _, raw = armor_decode(data, expected_label="QCRYPTO SIGNATURE")
        data = raw

    if not data.startswith(_SIG_MAGIC):
        raise ValueError("Not a qcrypto signature file")

    off = len(_SIG_MAGIC)
    alg_len, off = _read_u16(data, off)
    if off + alg_len > len(data):
        raise ValueError("truncated signature header")
    alg = data[off : off + alg_len].decode("utf-8")
    off += alg_len
    sig = data[off:]
    if not sig:
        raise ValueError("empty signature")
    return alg, sig
