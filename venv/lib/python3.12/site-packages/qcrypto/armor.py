# qcrypto/armor.py
from __future__ import annotations

import base64
import re
from typing import Tuple, Union

_BEGIN_RE = re.compile(r"^-----BEGIN ([A-Z0-9 ]+)-----\s*$")
_END_RE = re.compile(r"^-----END ([A-Z0-9 ]+)-----\s*$")


def armor_encode(label: str, data: bytes, width: int = 64) -> str:
    """
    Returns an ASCII-armored block:
    -----BEGIN <LABEL>-----
    <base64 payload, wrapped>
    -----END <LABEL>-----
    """
    b64 = base64.b64encode(data).decode("ascii")
    lines = [b64[i : i + width] for i in range(0, len(b64), width)]
    return "\n".join(
        [f"-----BEGIN {label}-----", *lines, f"-----END {label}-----", ""]
    )


def _strip_armor(text: str) -> Tuple[str, str]:
    """
    Returns (label, base64_payload_string) from an armored block.
    Raises ValueError if format is invalid.
    """
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if len(lines) < 3:
        raise ValueError("Invalid armored data (too short)")

    m_begin = _BEGIN_RE.match(lines[0])
    m_end = _END_RE.match(lines[-1])
    if not m_begin or not m_end:
        raise ValueError("Invalid armored data (missing BEGIN/END lines)")

    label_begin = m_begin.group(1)
    label_end = m_end.group(1)
    if label_begin != label_end:
        raise ValueError("Invalid armored data (BEGIN/END labels do not match)")

    payload_lines = lines[1:-1]
    payload = "".join(payload_lines)
    return label_begin, payload


def armor_decode(
    data: Union[bytes, str],
    expected_label: str | None = None,
) -> Tuple[str, bytes]:
    """
    Decodes ASCII armor. Returns (label, decoded_bytes).
    If expected_label is provided, it must match the parsed label.
    """
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="strict")
    else:
        text = data

    label, payload_b64 = _strip_armor(text)

    if expected_label is not None and label != expected_label:
        raise ValueError(f"Unexpected armor label: {label} (expected {expected_label})")

    try:
        raw = base64.b64decode(payload_b64, validate=True)
    except Exception as e:
        raise ValueError("Invalid base64 payload in armored data") from e

    return label, raw


def looks_armored(data: bytes) -> bool:
    return data.lstrip().startswith(b"-----BEGIN ")
