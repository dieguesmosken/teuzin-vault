"""Protection and parsing of the TVLT V1 DEK key slots."""

from __future__ import annotations

import json
import secrets
import struct

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from teuzin_vault.core.container_format import ParsedHeader


DEK_SIZE = 32
WRAPPING_KEY_SIZE = 32
SLOT_ID_SIZE = 16
NONCE_SIZE = 12
WRAPPED_DEK_SIZE = 48

SLOT_STRUCT = struct.Struct(">16s12s48s")
SLOT_RECORD_SIZE = SLOT_STRUCT.size

SLOT_AAD_DOMAIN = b"TEUZIN-VAULT\x00KEY-SLOT\x01"
MAX_DESCRIPTOR_SIZE = 4096


class KeySlotFormatError(ValueError):
    """Invalid key slot record or descriptor."""


class KeySlotDecryptionError(ValueError):
    """A key slot could not authenticate or unwrap the DEK."""


@dataclass(frozen=True)
class KeySlotRecord:
    slot_id: bytes
    nonce: bytes
    wrapped_dek: bytes


@dataclass(frozen=True)
class ParsedKeySlotRecords:
    records: tuple[KeySlotRecord, ...]
    consumed: int


def _validate_bytes(name: str, value: bytes, size: int) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes.")

    if len(value) != size:
        raise KeySlotFormatError(
            f"{name} must contain exactly {size} bytes."
        )


def _descriptor_id(descriptor: Mapping[str, Any]) -> bytes:
    if not isinstance(descriptor, Mapping):
        raise TypeError("descriptor must be a mapping.")

    value = descriptor.get("id")

    if not isinstance(value, str) or len(value) != 32:
        raise KeySlotFormatError("Invalid key slot identifier.")

    try:
        slot_id = bytes.fromhex(value)
    except ValueError as exc:
        raise KeySlotFormatError(
            "Invalid hexadecimal key slot identifier."
        ) from exc

    if len(slot_id) != SLOT_ID_SIZE or value != value.lower():
        raise KeySlotFormatError("Invalid key slot identifier.")

    return slot_id


def _descriptor_bytes(descriptor: Mapping[str, Any]) -> bytes:
    _descriptor_id(descriptor)

    try:
        encoded = json.dumps(
            dict(descriptor),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise KeySlotFormatError(
            "Invalid key slot descriptor."
        ) from exc

    if not 1 <= len(encoded) <= MAX_DESCRIPTOR_SIZE:
        raise KeySlotFormatError(
            "Key slot descriptor exceeds its size limit."
        )

    return encoded


def _associated_data(
    descriptor: Mapping[str, Any],
    header_digest: bytes,
) -> bytes:
    _validate_bytes("header_digest", header_digest, 32)

    encoded_descriptor = _descriptor_bytes(descriptor)

    return (
        SLOT_AAD_DOMAIN
        + header_digest
        + len(encoded_descriptor).to_bytes(2, "big")
        + encoded_descriptor
    )


def _validate_record(record: KeySlotRecord) -> None:
    if not isinstance(record, KeySlotRecord):
        raise TypeError("record must be a KeySlotRecord.")

    _validate_bytes("slot_id", record.slot_id, SLOT_ID_SIZE)
    _validate_bytes("nonce", record.nonce, NONCE_SIZE)
    _validate_bytes(
        "wrapped_dek",
        record.wrapped_dek,
        WRAPPED_DEK_SIZE,
    )


def wrap_dek(
    dek: bytes,
    wrapping_key: bytes,
    descriptor: Mapping[str, Any],
    header_digest: bytes,
) -> KeySlotRecord:
    """Protect a 256-bit DEK using an independent wrapping key."""
    _validate_bytes("dek", dek, DEK_SIZE)
    _validate_bytes(
        "wrapping_key",
        wrapping_key,
        WRAPPING_KEY_SIZE,
    )

    slot_id = _descriptor_id(descriptor)
    aad = _associated_data(descriptor, header_digest)

    nonce = secrets.token_bytes(NONCE_SIZE)

    wrapped = AESGCM(wrapping_key).encrypt(
        nonce,
        dek,
        aad,
    )

    if len(wrapped) != WRAPPED_DEK_SIZE:
        raise KeySlotFormatError(
            "Unexpected protected DEK length."
        )

    return KeySlotRecord(
        slot_id=slot_id,
        nonce=nonce,
        wrapped_dek=wrapped,
    )


def unwrap_dek(
    record: KeySlotRecord,
    wrapping_key: bytes,
    descriptor: Mapping[str, Any],
    header_digest: bytes,
) -> bytes:
    """Authenticate a key slot and recover its 256-bit DEK."""
    _validate_record(record)
    _validate_bytes(
        "wrapping_key",
        wrapping_key,
        WRAPPING_KEY_SIZE,
    )

    expected_id = _descriptor_id(descriptor)

    if record.slot_id != expected_id:
        raise KeySlotFormatError(
            "Key slot identifier does not match its descriptor."
        )

    aad = _associated_data(descriptor, header_digest)

    try:
        dek = AESGCM(wrapping_key).decrypt(
            record.nonce,
            record.wrapped_dek,
            aad,
        )
    except InvalidTag:
        raise KeySlotDecryptionError(
            "Key slot authentication failed."
        ) from None

    if len(dek) != DEK_SIZE:
        raise KeySlotDecryptionError(
            "Recovered DEK has an invalid length."
        )

    return dek


def serialize_key_slot_records(
    records: Sequence[KeySlotRecord],
    parsed_header: ParsedHeader,
) -> bytes:
    """Serialize exactly the records described by a parsed header."""
    if not isinstance(parsed_header, ParsedHeader):
        raise TypeError("parsed_header must be a ParsedHeader.")

    if not isinstance(records, Sequence):
        raise TypeError("records must be a sequence.")

    descriptors = parsed_header.header["key_slots"]

    if len(records) != len(descriptors):
        raise KeySlotFormatError(
            "Unexpected number of key slot records."
        )

    output = bytearray()
    seen_nonces: set[bytes] = set()

    for record, descriptor in zip(records, descriptors):
        _validate_record(record)

        expected_id = _descriptor_id(descriptor)

        if record.slot_id != expected_id:
            raise KeySlotFormatError(
                "Key slot records are not in header order."
            )

        if record.nonce in seen_nonces:
            raise KeySlotFormatError(
                "Duplicate key slot nonce."
            )

        seen_nonces.add(record.nonce)

        output.extend(
            SLOT_STRUCT.pack(
                record.slot_id,
                record.nonce,
                record.wrapped_dek,
            )
        )

    return bytes(output)


def parse_key_slot_records(
    data: bytes,
    parsed_header: ParsedHeader,
) -> ParsedKeySlotRecords:
    """Parse fixed-size records and leave subsequent bytes untouched."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes.")

    if not isinstance(parsed_header, ParsedHeader):
        raise TypeError("parsed_header must be a ParsedHeader.")

    descriptors = parsed_header.header["key_slots"]
    required_size = len(descriptors) * SLOT_RECORD_SIZE

    if len(data) < required_size:
        raise KeySlotFormatError(
            "Truncated key slot records."
        )

    records = []
    seen_nonces: set[bytes] = set()
    offset = 0

    for descriptor in descriptors:
        slot_id, nonce, wrapped_dek = SLOT_STRUCT.unpack_from(
            data,
            offset,
        )

        expected_id = _descriptor_id(descriptor)

        if slot_id != expected_id:
            raise KeySlotFormatError(
                "Key slot record does not match header order."
            )

        if nonce in seen_nonces:
            raise KeySlotFormatError(
                "Duplicate key slot nonce."
            )

        seen_nonces.add(nonce)

        records.append(
            KeySlotRecord(
                slot_id=slot_id,
                nonce=nonce,
                wrapped_dek=wrapped_dek,
            )
        )

        offset += SLOT_RECORD_SIZE

    return ParsedKeySlotRecords(
        records=tuple(records),
        consumed=offset,
    )