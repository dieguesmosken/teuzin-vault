"""Authenticated sequential records for TVLT V1."""

from __future__ import annotations

import struct

from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from teuzin_vault.core.container_format import (
    CHUNK_SIZE,
    MAX_DATA_RECORDS,
    ParsedHeader,
)


RECORD_HEADER = struct.Struct(">BQI")
FINAL_PAYLOAD = struct.Struct(">4sQQQ")

DATA_RECORD_TYPE = 0x01
FINAL_RECORD_TYPE = 0xFF

TAG_SIZE = 16
NONCE_PREFIX_SIZE = 4
NONCE_SIZE = 12

MAX_UINT64 = (1 << 64) - 1

RECORD_AAD_DOMAIN = b"TEUZIN-VAULT\x00RECORD\x01"

FINAL_MAGIC = b"END1"

MIN_DATA_CIPHERTEXT = TAG_SIZE + 1
MAX_DATA_CIPHERTEXT = CHUNK_SIZE + TAG_SIZE
FINAL_CIPHERTEXT_SIZE = FINAL_PAYLOAD.size + TAG_SIZE


class RecordFormatError(ValueError):
    """Invalid TVLT record structure."""


class RecordAuthenticationError(ValueError):
    """An authenticated record failed verification."""


class RecordStateError(RuntimeError):
    """An invalid writer or reader state transition."""


@dataclass(frozen=True)
class DataRecord:
    sequence: int
    plaintext: bytes
    consumed: int


@dataclass(frozen=True)
class FinalRecord:
    data_record_count: int
    compressed_bytes: int
    original_bytes: int
    consumed: int


def _validate_key(dek: bytes) -> None:
    if not isinstance(dek, bytes):
        raise TypeError("dek must be bytes.")

    if len(dek) != 32:
        raise RecordFormatError("DEK must contain 32 bytes.")


def _validate_header(parsed_header: ParsedHeader) -> bytes:
    if not isinstance(parsed_header, ParsedHeader):
        raise TypeError("parsed_header must be a ParsedHeader.")

    if not isinstance(parsed_header.header, dict):
        raise RecordFormatError("Invalid parsed header.")

    if not isinstance(parsed_header.digest, bytes):
        raise RecordFormatError("Invalid header digest.")

    if len(parsed_header.digest) != 32:
        raise RecordFormatError("Header digest must contain 32 bytes.")

    prefix_hex = parsed_header.header.get("nonce_prefix")

    if not isinstance(prefix_hex, str):
        raise RecordFormatError("Missing nonce prefix.")

    try:
        prefix = bytes.fromhex(prefix_hex)
    except ValueError as exc:
        raise RecordFormatError("Invalid nonce prefix.") from exc

    if len(prefix) != NONCE_PREFIX_SIZE:
        raise RecordFormatError("Nonce prefix must contain 4 bytes.")

    return prefix


def _validate_counter(sequence: int, *, allow_final: bool) -> None:
    if type(sequence) is not int:
        raise RecordFormatError("Sequence must be an integer.")

    maximum = MAX_DATA_RECORDS if allow_final else MAX_DATA_RECORDS - 1

    if not 0 <= sequence <= maximum:
        raise RecordFormatError("Record sequence is outside V1 limits.")


def _nonce(prefix: bytes, sequence: int) -> bytes:
    return prefix + sequence.to_bytes(8, "big")


def _aad(parsed_header: ParsedHeader, record_header: bytes) -> bytes:
    return (
        RECORD_AAD_DOMAIN
        + parsed_header.digest
        + record_header
    )


def _encrypt_record(
    plaintext: bytes,
    dek: bytes,
    parsed_header: ParsedHeader,
    record_type: int,
    sequence: int,
) -> bytes:
    prefix = _validate_header(parsed_header)
    _validate_key(dek)
    _validate_counter(
        sequence,
        allow_final=(record_type == FINAL_RECORD_TYPE),
    )

    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes.")

    ciphertext_length = len(plaintext) + TAG_SIZE

    record_header = RECORD_HEADER.pack(
        record_type,
        sequence,
        ciphertext_length,
    )

    ciphertext = AESGCM(dek).encrypt(
        _nonce(prefix, sequence),
        plaintext,
        _aad(parsed_header, record_header),
    )

    return record_header + ciphertext


def _decrypt_record(
    record_header: bytes,
    ciphertext: bytes,
    dek: bytes,
    parsed_header: ParsedHeader,
    sequence: int,
) -> bytes:
    prefix = _validate_header(parsed_header)
    _validate_key(dek)

    try:
        return AESGCM(dek).decrypt(
            _nonce(prefix, sequence),
            ciphertext,
            _aad(parsed_header, record_header),
        )
    except InvalidTag:
        raise RecordAuthenticationError(
            "Record authentication failed."
        ) from None


class RecordWriter:
    """Sequential writer. Never resume with an existing DEK."""

    def __init__(self, dek: bytes, parsed_header: ParsedHeader):
        _validate_key(dek)
        _validate_header(parsed_header)

        self._dek = dek
        self._header = parsed_header
        self._next_sequence = 0
        self._compressed_bytes = 0
        self._finalized = False
        self._failed = False

    def _check_active(self) -> None:
        if self._failed:
            raise RecordStateError(
                "Writer failed and cannot be reused."
            )

        if self._finalized:
            raise RecordStateError(
                "Writer has already been finalized."
            )

    @property
    def data_record_count(self) -> int:
        return self._next_sequence

    @property
    def compressed_bytes(self) -> int:
        return self._compressed_bytes

    def write_data(self, plaintext: bytes) -> bytes:
        self._check_active()

        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes.")

        if not 1 <= len(plaintext) <= CHUNK_SIZE:
            raise RecordFormatError(
                "Data records must contain between 1 byte and 1 MiB."
            )

        if self._next_sequence >= MAX_DATA_RECORDS:
            raise RecordFormatError(
                "Maximum data record count exceeded."
            )

        sequence = self._next_sequence

        # Reserve the nonce before encryption. If encryption fails,
        # this writer is permanently disabled.
        self._next_sequence += 1

        try:
            record = _encrypt_record(
                plaintext,
                self._dek,
                self._header,
                DATA_RECORD_TYPE,
                sequence,
            )
            self._compressed_bytes += len(plaintext)
            return record
        except Exception:
            self._failed = True
            raise

    def finish(self, original_bytes: int) -> bytes:
        self._check_active()

        if self._next_sequence == 0:
            raise RecordFormatError(
                "At least one data record is required."
            )

        if (
            type(original_bytes) is not int
            or not 0 <= original_bytes <= MAX_UINT64
        ):
            raise RecordFormatError(
                "Invalid original byte count."
            )

        if self._next_sequence > MAX_DATA_RECORDS:
            raise RecordFormatError(
                "Maximum record count exceeded."
            )

        sequence = self._next_sequence

        # Reserve the final nonce and permanently close this writer.
        self._next_sequence += 1
        self._finalized = True

        payload = FINAL_PAYLOAD.pack(
            FINAL_MAGIC,
            sequence,
            self._compressed_bytes,
            original_bytes,
        )

        try:
            return _encrypt_record(
                payload,
                self._dek,
                self._header,
                FINAL_RECORD_TYPE,
                sequence,
            )
        except Exception:
            self._failed = True
            raise


class RecordReader:
    """Sequential authenticated reader for TVLT V1."""

    def __init__(self, dek: bytes, parsed_header: ParsedHeader):
        _validate_key(dek)
        _validate_header(parsed_header)

        self._dek = dek
        self._header = parsed_header
        self._next_sequence = 0
        self._compressed_bytes = 0
        self._finalized = False

    def _check_active(self) -> None:
        if self._finalized:
            raise RecordStateError(
                "Reader has already reached the final record."
            )

    def read_data(self, data: bytes) -> DataRecord:
        self._check_active()

        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        if self._next_sequence >= MAX_DATA_RECORDS:
            raise RecordFormatError(
                "Maximum data record count exceeded."
            )

        if len(data) < RECORD_HEADER.size:
            raise RecordFormatError(
                "Truncated record header."
            )

        record_header = data[:RECORD_HEADER.size]

        record_type, sequence, ciphertext_length = (
            RECORD_HEADER.unpack(record_header)
        )

        if record_type != DATA_RECORD_TYPE:
            raise RecordFormatError("Expected a data record.")

        if sequence != self._next_sequence:
            raise RecordFormatError(
                "Unexpected record sequence."
            )

        if not MIN_DATA_CIPHERTEXT <= ciphertext_length <= MAX_DATA_CIPHERTEXT:
            raise RecordFormatError(
                "Invalid data record ciphertext length."
            )

        consumed = RECORD_HEADER.size + ciphertext_length

        if len(data) < consumed:
            raise RecordFormatError(
                "Truncated data record."
            )

        ciphertext = data[RECORD_HEADER.size:consumed]

        plaintext = _decrypt_record(
            record_header,
            ciphertext,
            self._dek,
            self._header,
            sequence,
        )

        if not 1 <= len(plaintext) <= CHUNK_SIZE:
            raise RecordFormatError(
                "Invalid decrypted data record size."
            )

        self._next_sequence += 1
        self._compressed_bytes += len(plaintext)

        return DataRecord(
            sequence=sequence,
            plaintext=plaintext,
            consumed=consumed,
        )

    def read_final(self, data: bytes) -> FinalRecord:
        self._check_active()

        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        if self._next_sequence == 0:
            raise RecordFormatError(
                "Final record cannot precede all data records."
            )

        if len(data) < RECORD_HEADER.size:
            raise RecordFormatError(
                "Truncated final record header."
            )

        record_header = data[:RECORD_HEADER.size]

        record_type, sequence, ciphertext_length = (
            RECORD_HEADER.unpack(record_header)
        )

        if record_type != FINAL_RECORD_TYPE:
            raise RecordFormatError("Expected a final record.")

        if sequence != self._next_sequence:
            raise RecordFormatError(
                "Invalid final record sequence."
            )

        if ciphertext_length != FINAL_CIPHERTEXT_SIZE:
            raise RecordFormatError(
                "Invalid final record size."
            )

        consumed = RECORD_HEADER.size + ciphertext_length

        if len(data) < consumed:
            raise RecordFormatError(
                "Truncated final record."
            )

        if len(data) != consumed:
            raise RecordFormatError(
                "Unexpected data after final record."
            )

        ciphertext = data[RECORD_HEADER.size:consumed]

        plaintext = _decrypt_record(
            record_header,
            ciphertext,
            self._dek,
            self._header,
            sequence,
        )

        if len(plaintext) != FINAL_PAYLOAD.size:
            raise RecordFormatError(
                "Invalid final payload size."
            )

        magic, count, compressed_bytes, original_bytes = (
            FINAL_PAYLOAD.unpack(plaintext)
        )

        if magic != FINAL_MAGIC:
            raise RecordFormatError(
                "Invalid final record magic."
            )

        if count != self._next_sequence:
            raise RecordFormatError(
                "Final record count does not match."
            )

        if compressed_bytes != self._compressed_bytes:
            raise RecordFormatError(
                "Final compressed byte count does not match."
            )

        self._finalized = True

        return FinalRecord(
            data_record_count=count,
            compressed_bytes=compressed_bytes,
            original_bytes=original_bytes,
            consumed=consumed,
        )