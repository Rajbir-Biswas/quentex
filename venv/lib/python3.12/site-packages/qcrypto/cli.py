import argparse
import sys
from pathlib import Path
from getpass import getpass
from typing import Optional

from . import KyberKEM, encrypt_file, decrypt_file
from .fingerprints import key_fingerprint
from .signatures import (
    SignatureScheme,
    save_signature_public_key,
    load_signature_public_key,
    save_signature_private_key,
    load_signature_private_key,
    save_signature,
    load_signature,
)

# Base config directory
DEFAULT_DIR = Path.home() / ".qcrypto"

# Default key locations (KEM)
DEFAULT_KEM_DIR = DEFAULT_DIR / "kem"
DEFAULT_PRIV = DEFAULT_KEM_DIR / "private.key"
DEFAULT_PUB = DEFAULT_KEM_DIR / "public.key"

# Default key locations (signatures)
DEFAULT_SIG_DIR = DEFAULT_DIR / "sig"
DEFAULT_SIG_PRIV = DEFAULT_SIG_DIR / "private.key"
DEFAULT_SIG_PUB = DEFAULT_SIG_DIR / "public.key"


def _ensure_dir(p: Path) -> None:
    # 0700 so only the user can read/write/execute the directory
    p.mkdir(mode=0o700, parents=True, exist_ok=True)


def _resolve_public_key_path(arg_value: Optional[str] = None) -> Path:
    return Path(arg_value) if arg_value else DEFAULT_PUB


def _resolve_private_key_path(arg_value: Optional[str] = None) -> Path:
    return Path(arg_value) if arg_value else DEFAULT_PRIV


def _resolve_sig_public_key_path(arg_value: Optional[str] = None) -> Path:
    return Path(arg_value) if arg_value else DEFAULT_SIG_PUB


def _resolve_sig_private_key_path(arg_value: Optional[str] = None) -> Path:
    return Path(arg_value) if arg_value else DEFAULT_SIG_PRIV


def cmd_gen_key(args):
    alg = args.alg.lower()
    if alg not in ("kyber768",):
        print(f"Unsupported algorithm: {alg}")
        sys.exit(1)

    kem = KyberKEM("Kyber768")
    kem.generate_keypair()

    pub_path = _resolve_public_key_path(args.public)
    priv_path = _resolve_private_key_path(args.private)

    # If user is using defaults, ensure ~/.qcrypto/kem exists
    if args.public is None or args.private is None:
        _ensure_dir(DEFAULT_KEM_DIR)

    # Safety: avoid accidental overwrite unless --force
    if not args.force:
        if pub_path.exists() or priv_path.exists():
            print("Refusing to overwrite existing key(s).")
            print(f"  Public key:  {pub_path} {'(exists)' if pub_path.exists() else ''}")
            print(f"  Private key: {priv_path} {'(exists)' if priv_path.exists() else ''}")
            print("Use --force to overwrite, or specify different --public/--private paths.")
            sys.exit(1)

    # Ask for passphrase if flag provided without one
    passphrase = args.password
    if args.password is True:
        passphrase = getpass("Passphrase: ")

    encoding = "armor" if args.armored else "raw"

    kem.save_public_key(str(pub_path), encoding=encoding)
    kem.save_private_key(str(priv_path), encoding=encoding, passphrase=passphrase)

    fp = key_fingerprint(KyberKEM.load_public_key(str(pub_path)))

    print("Generated Kyber768 keypair:")
    print(f"  Public key:  {pub_path}")
    print(f"  Fingerprint: {fp}")
    print(f"  Private key: {priv_path}")
    if args.armored:
        print("  (ASCII-armored)")
    if passphrase:
        print("  (private key encrypted with passphrase)")


def cmd_encrypt(args):
    pub_path = _resolve_public_key_path(args.pub)

    if args.pub is None:
        _ensure_dir(DEFAULT_KEM_DIR)

    if not pub_path.exists():
        print(f"Public key not found: {pub_path}")
        print("Run: qcrypto gen-key")
        sys.exit(1)

    pub = KyberKEM.load_public_key(str(pub_path))
    fp = key_fingerprint(pub)
    print(f"Encrypting for key: {fp}")
    input_path = Path(args.input)
    output_path = Path(args.output)

    encrypt_file(
        public_key=pub,
        input_path=str(input_path),
        output_path=str(output_path),
    )

    print(f"Encrypted → {output_path}")


def cmd_decrypt(args):
    priv_path = _resolve_private_key_path(args.key)

    if args.key is None:
        _ensure_dir(DEFAULT_KEM_DIR)

    if not priv_path.exists():
        print(f"Private key not found: {priv_path}")
        print("Run: qcrypto gen-key")
        sys.exit(1)

    passphrase = args.password
    if args.password is True:
        passphrase = getpass("Passphrase: ")

    priv = KyberKEM.load_private_key(str(priv_path), passphrase=passphrase)

    input_path = Path(args.input)
    output_path = Path(args.output)

    decrypt_file(
        private_key=priv,
        input_path=str(input_path),
        output_path=str(output_path),
    )

    print(f"Decrypted → {output_path}")


def cmd_sig_gen_key(args):
    alg = args.alg

    pub_path = _resolve_sig_public_key_path(args.public)
    priv_path = _resolve_sig_private_key_path(args.private)

    # If user is using defaults, ensure ~/.qcrypto/sig exists
    if args.public is None or args.private is None:
        _ensure_dir(DEFAULT_SIG_DIR)

    if not args.force:
        if pub_path.exists() or priv_path.exists():
            print("Refusing to overwrite existing key(s).")
            print(f"  Public key:  {pub_path} {'(exists)' if pub_path.exists() else ''}")
            print(f"  Private key: {priv_path} {'(exists)' if priv_path.exists() else ''}")
            print("Use --force to overwrite, or specify different --public/--private paths.")
            sys.exit(1)

    passphrase = args.password
    if args.password is True:
        passphrase = getpass("Passphrase: ")

    scheme = SignatureScheme(alg)
    kp = scheme.generate_keypair()

    save_signature_public_key(
        path=str(pub_path),
        public_key=kp.public_key,
        alg=alg,
        armored=args.armored,
    )
    save_signature_private_key(
        path=str(priv_path),
        secret_key=kp.secret_key,
        alg=alg,
        armored=args.armored,
        passphrase=passphrase,
    )

    fp = key_fingerprint(load_signature_public_key(str(pub_path))[1])

    print("Generated signature keypair:")
    print(f"  Algorithm:   {alg}")
    print(f"  Public key:  {pub_path}")
    print(f"  Fingerprint: {fp}")
    print(f"  Private key: {priv_path}")
    if args.armored:
        print("  (ASCII-armored)")
    if passphrase:
        print("  (private key encrypted with passphrase)")


def _load_sig_private_key_or_raw(
    path: Path, passphrase: Optional[str], alg_hint: Optional[str]
) -> tuple[str, bytes]:
    try:
        alg, sk = load_signature_private_key(str(path), passphrase=passphrase)
        return alg, sk
    except Exception:
        if not alg_hint:
            raise ValueError("Private key is not a qcrypto key file. Provide --alg for raw keys.")
        return alg_hint, path.read_bytes()


def _load_sig_public_key_or_raw(path: Path, alg_hint: Optional[str]) -> tuple[str, bytes]:
    try:
        alg, pk = load_signature_public_key(str(path))
        return alg, pk
    except Exception:
        if not alg_hint:
            raise ValueError("Public key is not a qcrypto key file. Provide --alg for raw keys.")
        return alg_hint, path.read_bytes()


def _load_signature_or_raw(path: Path, alg_hint: Optional[str]) -> tuple[str, bytes]:
    try:
        alg, sig = load_signature(str(path))
        return alg, sig
    except Exception:
        if not alg_hint:
            raise ValueError("Signature is not a qcrypto signature file. Provide --alg for raw signatures.")
        return alg_hint, path.read_bytes()


def cmd_sign(args):
    key_path = _resolve_sig_private_key_path(args.key)

    # If using default, ensure ~/.qcrypto/sig exists (but don't auto-generate keys)
    if args.key is None:
        _ensure_dir(DEFAULT_SIG_DIR)

    if not key_path.exists():
        print(f"Private key not found: {key_path}")
        print("Run: qcrypto sig-gen-key --alg Dilithium3")
        sys.exit(1)

    passphrase = args.password
    if args.password is True:
        passphrase = getpass("Passphrase: ")

    try:
        alg, sk = _load_sig_private_key_or_raw(key_path, passphrase=passphrase, alg_hint=args.alg)
    except Exception as e:
        print(str(e))
        sys.exit(1)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input not found: {input_path}")
        sys.exit(1)

    msg = input_path.read_bytes()
    scheme = SignatureScheme(alg)
    sig_bytes = scheme.sign(sk, msg)

    out_path = Path(args.output)
    save_signature(str(out_path), sig_bytes, alg=alg, armored=args.armored)

    print("Signed:")
    print(f"  Algorithm:  {alg}")
    print(f"  Input:      {input_path}")
    print(f"  Signature:  {out_path}")
    if args.armored:
        print("  (ASCII-armored)")


def cmd_verify(args):
    pub_path = _resolve_sig_public_key_path(args.pub)

    if args.pub is None:
        _ensure_dir(DEFAULT_SIG_DIR)

    if not pub_path.exists():
        print(f"Public key not found: {pub_path}")
        print("Run: qcrypto sig-gen-key --alg Dilithium3")
        sys.exit(1)

    sig_path = Path(args.sig)
    if not sig_path.exists():
        print(f"Signature not found: {sig_path}")
        sys.exit(1)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input not found: {input_path}")
        sys.exit(1)

    try:
        pk_alg, pk = _load_sig_public_key_or_raw(pub_path, alg_hint=args.alg)
        fp = key_fingerprint(pk)
        sig_alg, sig_bytes = _load_signature_or_raw(sig_path, alg_hint=args.alg)
    except Exception as e:
        print(str(e))
        sys.exit(1)

    # Resolve algorithm
    alg = args.alg or pk_alg or sig_alg
    if pk_alg and sig_alg and pk_alg != sig_alg:
        print(f"Algorithm mismatch: public key uses {pk_alg}, signature uses {sig_alg}")
        sys.exit(1)
    if pk_alg:
        alg = pk_alg
    if sig_alg:
        alg = sig_alg

    msg = input_path.read_bytes()
    scheme = SignatureScheme(alg)
    ok = scheme.verify(pk, msg, sig_bytes)

    print(f"Public key fingerprint: {fp}")

    if ok:
        print("OK: signature valid")
        sys.exit(0)
    else:
        print("FAIL: signature invalid")
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(
        prog="qcrypto",
        description="Quantum-safe encryption command line tool",
    )

    sub = parser.add_subparsers(dest="command")

    # gen-key
    gen = sub.add_parser("gen-key", help="Generate a Kyber keypair")
    gen.add_argument("--alg", default="kyber768")
    gen.add_argument("--public", default=None)
    gen.add_argument("--private", default=None)
    gen.add_argument(
        "--armored",
        action="store_true",
        help="Save keys in ASCII-armored format (BEGIN/END blocks)",
    )
    gen.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing key files if they already exist",
    )
    gen.add_argument(
        "--pass",
        dest="password",
        nargs="?",
        const=True,
        help="Encrypt private key with a passphrase",
    )
    gen.set_defaults(func=cmd_gen_key)

    # sig-gen-key
    sg = sub.add_parser("sig-gen-key", help="Generate a PQ signature keypair (Dilithium/Falcon/SPHINCS+)")
    sg.add_argument(
        "--alg",
        default="Dilithium3",
        help="liboqs signature algorithm name (default: Dilithium3)",
    )
    sg.add_argument("--public", default=None, help="Output path for public key (default: ~/.qcrypto/sig/public.key)")
    sg.add_argument("--private", default=None, help="Output path for private key (default: ~/.qcrypto/sig/private.key)")
    sg.add_argument(
        "--armored",
        action="store_true",
        help="Save keys in ASCII-armored format (BEGIN/END blocks)",
    )
    sg.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing key files if they already exist",
    )
    sg.add_argument(
        "--pass",
        dest="password",
        nargs="?",
        const=True,
        help="Encrypt private key with a passphrase",
    )
    sg.set_defaults(func=cmd_sig_gen_key)

    # sign
    sign = sub.add_parser("sign", help="Sign a file")
    sign.add_argument("--key", default=None, help="Path to signature private key (default: ~/.qcrypto/sig/private.key)")
    sign.add_argument("--in", dest="input", required=True, help="Input file to sign")
    sign.add_argument("--out", dest="output", required=True, help="Output signature file")
    sign.add_argument("--alg", default=None, help="Algorithm name (required only for raw keys/signatures)")
    sign.add_argument(
        "--armored",
        action="store_true",
        help="Write signature in ASCII-armored format",
    )
    sign.add_argument(
        "--pass",
        dest="password",
        nargs="?",
        const=True,
        help="Passphrase for encrypted private key",
    )
    sign.set_defaults(func=cmd_sign)

    # verify
    verify = sub.add_parser("verify", help="Verify a signature")
    verify.add_argument("--pub", default=None, help="Path to signature public key (default: ~/.qcrypto/sig/public.key)")
    verify.add_argument("--in", dest="input", required=True, help="Input file that was signed")
    verify.add_argument("--sig", required=True, help="Signature file")
    verify.add_argument("--alg", default=None, help="Algorithm name (required only for raw keys/signatures)")
    verify.set_defaults(func=cmd_verify)

    # encrypt
    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("--pub", default=None)
    enc.add_argument("--in", dest="input", required=True)
    enc.add_argument("--out", dest="output", required=True)
    enc.set_defaults(func=cmd_encrypt)

    # decrypt
    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("--key", default=None)
    dec.add_argument("--in", dest="input", required=True)
    dec.add_argument("--out", dest="output", required=True)
    dec.add_argument(
        "--pass",
        dest="password",
        nargs="?",
        const=True,
        help="Passphrase for encrypted private key",
    )
    dec.set_defaults(func=cmd_decrypt)

    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
