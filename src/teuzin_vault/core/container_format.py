"""TVLT container header serialization and validation."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import struct

from dataclasses import dataclass
from typing import Any, Mapping


MAGIC = b"TVLT"
FORMAT_VERSION = 1

PREFIX_STRUCT = struct.Struct(">4sHI")
PREFIX_SIZE = PREFIX_STRUCT.size

MAX_HEADER_SIZE = 64 * 1024
CHUNK_SIZE = 1024 * 1024
MAX_DATA_RECORDS = 1_048_576

RP_ID = "vault.teuzin.com.br"

ALGORITHMS = {
    "aead": "AES-256-GCM",
    "compression": "Zstandard",
    "kdf": "HKDF-SHA256",
}


class ContainerFormatError(ValueError):
    """Invalid or unsupported TVLT container format."""


@dataclass(frozen=True)
class ParsedHeader:
    header: dict[str, Any]
    raw_header: bytes
    prefix: bytes
    digest: bytes
    consumed: int


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}

    for key, value in pairs:
        if key in result:
            raise ContainerFormatError(
                f"Duplicate JSON key: {key}"
            )
        result[key] = value

    return result


def _reject_constant(value: str) -> None:
    raise ContainerFormatError(
        f"Invalid JSON constant: {value}"
    )


def _require_keys(
    value: dict[str, Any],
    expected: set[str],
    context: str,
) -> None:
    actual = set(value)

    if actual != expected:
        missing = expected - actual
        unexpected = actual - expected

        raise ContainerFormatError(
            f"Invalid fields in {context}: "
            f"missing={sorted(missing)}, "
            f"unexpected={sorted(unexpected)}"
        )


def _valid_hex(value: Any, byte_length: int) -> bool:
    if type(value) is not str:
        return False

    return re.fullmatch(
        rf"[0-9a-f]{{{byte_length * 2}}}",
        value,
    ) is not None


def _valid_credential_id(value: Any) -> bool:
    if type(value) is not str or not value:
        return False

    if len(value) > 2048:
        return False

    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        return False

    try:
        decoded = base64.urlsafe_b64decode(
            value + "=" * (-len(value) % 4)
        )
    except Exception:
        return False

    canonical = base64.urlsafe_b64encode(
        decoded
    ).decode("ascii").rstrip("=")

    return canonical == value and len(decoded) > 0


def _validate_slot(slot: Any) -> str:
    if type(slot) is not dict:
        raise ContainerFormatError(
            "Each key slot must be a JSON object."
        )

    slot_type = slot.get("type")

    if not _valid_hex(slot.get("id"), 16):
        raise ContainerFormatError(
            "Invalid key slot identifier."
        )

    if slot_type == "fido2-hmac-secret":
        expected = {
            "id",
            "type",
            "rp_id",
            "credential_id",
            "hmac_salt",
            "kdf_salt",
        }
        _require_keys(slot, expected, "FIDO2 key slot")

        if slot["rp_id"] != RP_ID:
            raise ContainerFormatError(
                "Unexpected FIDO2 RP ID."
            )

        if not _valid_credential_id(slot["credential_id"]):
            raise ContainerFormatError(
                "Invalid FIDO2 credential identifier."
            )

        if not _valid_hex(slot["hmac_salt"], 32):
            raise ContainerFormatError(
                "Invalid FIDO2 HMAC salt."
            )

        if not _valid_hex(slot["kdf_salt"], 32):
            raise ContainerFormatError(
                "Invalid FIDO2 HKDF salt."
            )

        return slot_type

    if slot_type == "recovery":
        expected = {
            "id",
            "type",
            "kdf_salt",
        }
        _require_keys(slot, expected, "recovery key slot")

        if not _valid_hex(slot["kdf_salt"], 32):
            raise ContainerFormatError(
                "Invalid recovery HKDF salt."
            )

        return slot_type

    raise ContainerFormatError(
        "Unsupported key slot type."
    )


def validate_header(header: Any) -> None:
    """Validate the exact V1 public header schema."""

    if type(header) is not dict:
        raise ContainerFormatError(
            "Header must be a JSON object."
        )

    expected = {
        "container_id",
        "algorithms",
        "chunk_size",
        "nonce_prefix",
        "key_slots",
    }

    _require_keys(header, expected, "container header")

    if not _valid_hex(header["container_id"], 16):
        raise ContainerFormatError(
            "Invalid container identifier."
        )

    if not _valid_hex(header["nonce_prefix"], 4):
        raise ContainerFormatError(
            "Invalid nonce prefix."
        )

    if type(header["chunk_size"]) is not int:
        raise ContainerFormatError(
            "Chunk size must be an integer."
        )

    if header["chunk_size"] != CHUNK_SIZE:
        raise ContainerFormatError(
            "Unsupported chunk size."
        )

    algorithms = header["algorithms"]

    if type(algorithms) is not dict:
        raise ContainerFormatError(
            "Algorithms must be a JSON object."
        )

    _require_keys(
        algorithms,
        {"aead", "compression", "kdf"},
        "algorithms",
    )

    if algorithms != ALGORITHMS:
        raise ContainerFormatError(
            "Unsupported cryptographic algorithms."
        )

    slots = header["key_slots"]

    if type(slots) is not list or len(slots) != 2:
        raise ContainerFormatError(
            "V1 requires exactly two key slots."
        )

    slot_types = []
    slot_ids = []

    for slot in slots:
        slot_types.append(_validate_slot(slot))
        slot_ids.append(slot["id"])

    if sorted(slot_ids) != slot_ids:
        raise ContainerFormatError(
            "Key slots must be sorted by identifier."
        )

    if len(set(slot_ids)) != len(slot_ids):
        raise ContainerFormatError(
            "Duplicate key slot identifier."
        )

    if sorted(slot_types) != sorted(
        ["fido2-hmac-secret", "recovery"]
    ):
        raise ContainerFormatError(
            "V1 requires one FIDO2 slot and one recovery slot."
        )


def _canonical_json(header: dict[str, Any]) -> bytes:
    try:
        text = json.dumps(
            header,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        return text.encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ContainerFormatError(
            "Header cannot be serialized as canonical JSON."
        ) from exc


def create_header(
    fido2_slot: Mapping[str, Any],
    recovery_slot: Mapping[str, Any],
) -> dict[str, Any]:
    """Create fresh public metadata for a new container.

    This function does not create or store any secret material.
    """
    if not isinstance(fido2_slot, Mapping):
        raise TypeError("fido2_slot must be a mapping.")

    if not isinstance(recovery_slot, Mapping):
        raise TypeError("recovery_slot must be a mapping.")

    slots = [
        dict(fido2_slot),
        dict(recovery_slot),
    ]

    slots.sort(key=lambda slot: str(slot.get("id", "")))

    header = {
        "container_id": secrets.token_hex(16),
        "algorithms": dict(ALGORITHMS),
        "chunk_size": CHUNK_SIZE,
        "nonce_prefix": secrets.token_hex(4),
        "key_slots": slots,
    }

    validate_header(header)
    return header


def serialize_header(header: dict[str, Any]) -> bytes:
    """Serialize a validated header into its binary representation."""

    validate_header(header)

    body = _canonical_json(header)

    if not 1 <= len(body) <= MAX_HEADER_SIZE:
        raise ContainerFormatError(
            "Header size exceeds the V1 limit."
        )

    prefix = PREFIX_STRUCT.pack(
        MAGIC,
        FORMAT_VERSION,
        len(body),
    )

    return prefix + body


def parse_header(data: bytes) -> ParsedHeader:
    """Parse one header from the beginning of a container.

    Bytes after the header are permitted because they may contain
    key slots and data records. The consumed field gives the offset
    where those records begin.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes.")

    if len(data) < PREFIX_SIZE:
        raise ContainerFormatError(
            "Truncated container prefix."
        )

    prefix = data[:PREFIX_SIZE]

    magic, version, body_length = PREFIX_STRUCT.unpack(prefix)

    if magic != MAGIC:
        raise ContainerFormatError(
            "Invalid container magic."
        )

    if version != FORMAT_VERSION:
        raise ContainerFormatError(
            "Unsupported container version."
        )

    if not 1 <= body_length <= MAX_HEADER_SIZE:
        raise ContainerFormatError(
            "Invalid header length."
        )

    consumed = PREFIX_SIZE + body_length

    if len(data) < consumed:
        raise ContainerFormatError(
            "Truncated container header."
        )

    raw_header = data[PREFIX_SIZE:consumed]

    try:
        header = json.loads(
            raw_header.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except ContainerFormatError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContainerFormatError(
            "Invalid header JSON."
        ) from exc

    validate_header(header)

    canonical = _canonical_json(header)

    if canonical != raw_header:
        raise ContainerFormatError(
            "Header JSON is not in canonical form."
        )

    digest = hashlib.sha256(
        prefix + raw_header
    ).digest()

    return ParsedHeader(
        header=header,
        raw_header=raw_header,
        prefix=prefix,
        digest=digest,
        consumed=consumed,
    )