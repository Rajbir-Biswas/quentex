import os
import zlib
from typing import Tuple
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .kem import KyberKEM, KyberKeypair
from .armor import armor_encode, armor_decode


# Ciphertext format:
# [1 byte]  version
# [1 byte]  algorithm id (1 = Kyber768 here)
# [2 bytes] length of Kyber ciphertext (big endian)
# [N bytes] Kyber ciphertext
# [12 bytes] AES-GCM nonce
# [M bytes] AES-GCM ciphertext + tag

VERSION_V1 = 1
VERSION_V2 = 2  # header includes checksum
CURRENT_VERSION = VERSION_V2
ALGO_ID_KYBER768 = 1  # extend later for other algorithms
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KiB

# Header formats:
# v1:
#   [1] version | [1] algo_id | [2] kem_ct_len
# v2:
#   [1] version | [1] algo_id | [2] kem_ct_len | [4] crc32(version|algo_id|kem_ct_len)
#
# The checksum is for nicer error messages (corrupted header / wrong algorithm / truncated file),
# not for cryptographic integrity (AES-GCM already authenticates the payload).

def _crc32(data: bytes) -> bytes:
    return (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big")


def _build_header(algo_id: int, kem_ct_len: int, version: int = CURRENT_VERSION) -> bytes:
    if not (0 <= algo_id <= 255):
        raise ValueError("algo_id must fit in 1 byte")
    if not (0 <= kem_ct_len <= 0xFFFF):
        raise ValueError("kem_ct_len must fit in 2 bytes")

    base = (
        version.to_bytes(1, "big")
        + algo_id.to_bytes(1, "big")
        + kem_ct_len.to_bytes(2, "big")
    )

    if version == VERSION_V1:
        return base
    if version == VERSION_V2:
        return base + _crc32(base)

    raise ValueError(f"Unsupported header version: {version}")


def _parse_header(buf: bytes) -> tuple[int, int, int, int]:
    """Return (version, algo_id, kem_ct_len, header_len)."""
    if len(buf) < 4:
        raise ValueError("Ciphertext too short to contain header")

    version = buf[0]

    if version == VERSION_V1:
        algo_id = buf[1]
        kem_ct_len = int.from_bytes(buf[2:4], "big")
        return version, algo_id, kem_ct_len, 4

    if version == VERSION_V2:
        if len(buf) < 8:
            raise ValueError("Ciphertext truncated: incomplete v2 header")
        algo_id = buf[1]
        kem_ct_len = int.from_bytes(buf[2:4], "big")
        expected = _crc32(buf[0:4])
        got = buf[4:8]
        if got != expected:
            raise ValueError("Corrupted header (checksum mismatch)")
        return version, algo_id, kem_ct_len, 8

    raise ValueError(f"Unsupported ciphertext version: {version}")


def _derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derive a 256 bit AES key from the Kyber shared secret using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"qcrypto-hybrid-v1",
    )
    return hkdf.derive(shared_secret)


# High level API: single packaged ciphertext

def encrypt(public_key: bytes, plaintext: bytes) -> bytes:
    """
    Hybrid PQC encrypt.
    Returns a single byte string containing:
    version | algo_id | kyber_ct_len | kyber_ct | nonce | aes_ct+tag
    """
    kem = KyberKEM("Kyber768")
    kem_ct, shared_secret = kem.encapsulate(public_key)

    key = _derive_aes_key(shared_secret)
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)
    aes_ct = aesgcm.encrypt(nonce, plaintext, None)

    kem_ct_len = len(kem_ct)

    header = _build_header(ALGO_ID_KYBER768, kem_ct_len, version=CURRENT_VERSION)

    return header + kem_ct + nonce + aes_ct


def decrypt(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts a ciphertext produced by encrypt().
    Expects the same packaged format:
    version | algo_id | kyber_ct_len | kyber_ct | nonce | aes_ct+tag
    """
    version, algo_id, kem_ct_len, header_len = _parse_header(ciphertext)

    if algo_id != ALGO_ID_KYBER768:
        raise ValueError(f"Unsupported algorithm id: {algo_id}")

    offset = header_len
    end_kem_ct = offset + kem_ct_len
    if end_kem_ct + 12 + 16 > len(ciphertext):
        # 12 bytes nonce + at least 16 byte tag (AES-GCM)
        raise ValueError("Ciphertext truncated or malformed")

    kem_ct = ciphertext[offset:end_kem_ct]
    offset = end_kem_ct

    nonce = ciphertext[offset:offset + 12]
    aes_ct = ciphertext[offset + 12:]

    kem = KyberKEM("Kyber768")
    shared_secret = kem.decapsulate(kem_ct, private_key=private_key)

    key = _derive_aes_key(shared_secret)
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, aes_ct, None)


# Backwards compatible low-level API (v0.1.x)

def encrypt_for_recipient(
    recipient_public_key: bytes,
    plaintext: bytes,
) -> Tuple[bytes, bytes]:
    """
    Legacy helper.
    Returns (kem_ciphertext, aes_blob)
    where aes_blob = nonce | ciphertext+tag.
    """
    kem = KyberKEM("Kyber768")
    kem_ciphertext, shared_secret = kem.encapsulate(recipient_public_key)

    key = _derive_aes_key(shared_secret)
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    blob = nonce + ciphertext
    return kem_ciphertext, blob


def decrypt_from_sender(
    recipient_keys: KyberKeypair,
    kem_ciphertext: bytes,
    aes_blob: bytes,
) -> bytes:
    """
    Legacy helper matching encrypt_for_recipient.
    Uses the recipient's private key to decapsulate, then AES-GCM decrypts.
    """
    kem = KyberKEM("Kyber768")
    shared_secret = kem.decapsulate(
        kem_ciphertext,
        private_key=recipient_keys.private_key,
    )

    key = _derive_aes_key(shared_secret)
    aesgcm = AESGCM(key)

    nonce = aes_blob[:12]
    ciphertext = aes_blob[12:]

    return aesgcm.decrypt(nonce, ciphertext, None)

def encrypt_file(
        public_key: bytes,
        input_path: str,
        output_path: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """
    Encrypt a file using the same hybrid format as encrypt():
        version | algo_id | kyber_ct_len | kyber_ct | nonce | aes_ct+tag

    - Encapsulates once with Kyber768 to derive a symmetric AES key.
    - Streams the file through AES-GCM so large files do not have to fit in RAM.
    """

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    
    # Kyber encapsulation and AES key derivation
    kem = KyberKEM("Kyber768")
    kem_ct, shared_secret = kem.encapsulate(public_key)
    key = _derive_aes_key(shared_secret)

    kem_ct_len = len(kem_ct)

    header = _build_header(ALGO_ID_KYBER768, kem_ct_len, version=CURRENT_VERSION)
    # Open files
    in_path = Path(input_path)
    out_path = Path(output_path)

    nonce = os.urandom(12)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    with in_path.open("rb") as fin, out_path.open("wb") as fout:
        # write header and kyber ciphertext
        fout.write(header)
        fout.write(kem_ct)

        # then nonce, and stream AES-GCM ciphertext
        fout.write(nonce)

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            ct = encryptor.update(chunk)
            if ct:
                fout.write(ct)

        encryptor.finalize()
        # append GCM tag at the end so layout is nonce | ct | tag
        fout.write(encryptor.tag)

def decrypt_file(
    private_key: bytes,
    input_path: str,
    output_path: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """
    Decrypt a file produced by encrypt_file().

    Expects format:
        version | algo_id | kyber_ct_len | kyber_ct | nonce | aes_ct+tag
    and streams the AES-GCM decryption to avoid loading the whole file.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    in_path = Path(input_path)
    out_path = Path(output_path)

    with in_path.open("rb") as fin:
        # Read and parse header (v1 or v2)
        first4 = fin.read(4)
        if len(first4) != 4:
            raise ValueError("Ciphertext too short to contain header")

        # For v2, read checksum bytes as well
        if first4[0] == VERSION_V2:
            rest = fin.read(4)
            header = first4 + rest
        else:
            header = first4

        version, algo_id, kem_ct_len, header_len = _parse_header(header)

        if algo_id != ALGO_ID_KYBER768:
            raise ValueError(f"Unsupported algorithm id: {algo_id}")

        kem_ct = fin.read(kem_ct_len)
        if len(kem_ct) != kem_ct_len:
            raise ValueError("File truncated while reading Kyber ciphertext")

        # Recover AES key via Kyber decapsulation + HKDF
        kem = KyberKEM("Kyber768")
        shared_secret = kem.decapsulate(kem_ct, private_key=private_key)
        key = _derive_aes_key(shared_secret)

        # Read nonce
        nonce = fin.read(12)
        if len(nonce) != 12:
            raise ValueError("File truncated while reading AES-GCM nonce")

        # Remaining layout inside the file is: aes_ct | tag (tag is last 16 bytes)
        # We want to stream ciphertext but still know the tag, so we use seeks.
        file_size = in_path.stat().st_size
        header_and_kem_and_nonce_len = header_len + kem_ct_len + 12
        if file_size < header_and_kem_and_nonce_len + 16:
            raise ValueError("Ciphertext too short to contain AES-GCM tag")

        total_ct_plus_tag_len = file_size - header_and_kem_and_nonce_len
        ct_len = total_ct_plus_tag_len - 16

        # Locate and read the tag
        fin.seek(header_and_kem_and_nonce_len + ct_len)
        tag = fin.read(16)
        if len(tag) != 16:
            raise ValueError("File truncated while reading AES-GCM tag")

        # Set up streaming decryptor
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()

        # Go back to start of ciphertext and stream through decryptor
        fin.seek(header_and_kem_and_nonce_len)

        remaining = ct_len

        with out_path.open("wb") as fout:
            while remaining > 0:
                read_size = min(chunk_size, remaining)
                chunk = fin.read(read_size)
                if not chunk:
                    raise ValueError("File truncated while reading AES-GCM ciphertext")
                remaining -= len(chunk)

                pt = decryptor.update(chunk)
                if pt:
                    fout.write(pt)

            # Will raise if tag does not verify
            decryptor.finalize()

def encrypt_message_armored(public_key: bytes, plaintext: bytes) -> str:
    ct = encrypt(public_key, plaintext)
    return armor_encode("QCRYPTO MESSAGE", ct)

def decrypt_message_armored(private_key: bytes, armored: str) -> bytes:
    label, raw = armor_decode(armored, expected_label="QCRYPTO MESSAGE")
    return decrypt(private_key, raw)
