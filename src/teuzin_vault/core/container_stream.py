"""Integrated streaming writer and reader for TVLT V1."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, BinaryIO

from teuzin_vault.core.container_format import (
    CHUNK_SIZE,
    MAX_HEADER_SIZE,
    PREFIX_SIZE,
    PREFIX_STRUCT,
    ParsedHeader,
    parse_header,
    serialize_header,
)
from teuzin_vault.core.key_protection import (
    recover_dek_with_fido2,
    recover_dek_with_recovery,
)
from teuzin_vault.core.key_slots import (
    SLOT_RECORD_SIZE,
    parse_key_slot_records,
)
from teuzin_vault.core.records import (
    DATA_RECORD_TYPE,
    FINAL_CIPHERTEXT_SIZE,
    MAX_DATA_CIPHERTEXT,
    MIN_DATA_CIPHERTEXT,
    RECORD_HEADER,
    FINAL_RECORD_TYPE,
    RecordReader,
    RecordWriter,
)
from teuzin_vault.core.streaming_compression import (
    iter_compressed_chunks,
    iter_decompressed_chunks,
)


class ContainerStreamError(ValueError):
    """Invalid or incomplete TVLT stream."""


@dataclass(frozen=True)
class ContainerWriteResult:
    original_bytes: int
    compressed_bytes: int
    data_record_count: int
    container_bytes: int


@dataclass(frozen=True)
class ContainerReadResult:
    parsed_header: ParsedHeader
    original_bytes: int
    compressed_bytes: int
    data_record_count: int


def _read_exact(source: BinaryIO, size: int) -> bytes:
    if type(size) is not int or size < 0:
        raise ValueError("size must be a non-negative integer.")

    chunks = []
    remaining = size

    while remaining:
        chunk = source.read(remaining)

        if not isinstance(chunk, bytes):
            raise ContainerStreamError(
                "Input stream must return bytes."
            )

        if not chunk:
            raise ContainerStreamError(
                "Unexpected end of container."
            )

        if len(chunk) > remaining:
            raise ContainerStreamError(
                "Input stream returned more bytes than requested."
            )

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def _write_all(destination: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    offset = 0

    while offset < len(view):
        written = destination.write(view[offset:])

        if type(written) is not int or written <= 0:
            raise ContainerStreamError(
                "Output stream did not accept the complete data."
            )

        if written > len(view) - offset:
            raise ContainerStreamError(
                "Output stream reported an invalid write length."
            )

        offset += written


class _CountingReader:
    """Count source bytes without loading the source into memory."""

    def __init__(self, source: BinaryIO):
        self._source = source
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        data = self._source.read(size)

        if not isinstance(data, bytes):
            raise ContainerStreamError(
                "Source stream must return bytes."
            )

        if size >= 0 and len(data) > size:
            raise ContainerStreamError(
                "Source returned more bytes than requested."
            )

        self.total += len(data)
        return data


def _validated_header_bytes(
    parsed_header: ParsedHeader,
) -> bytes:
    if not isinstance(parsed_header, ParsedHeader):
        raise TypeError("parsed_header must be a ParsedHeader.")

    encoded = serialize_header(parsed_header.header)
    verified = parse_header(encoded)

    if verified.digest != parsed_header.digest:
        raise ContainerStreamError(
            "Header digest does not match its parsed representation."
        )

    return encoded


def _read_stream_header(source: BinaryIO) -> ParsedHeader:
    prefix = _read_exact(source, PREFIX_SIZE)

    try:
        _, _, body_length = PREFIX_STRUCT.unpack(prefix)
    except Exception as exc:
        raise ContainerStreamError(
            "Invalid container prefix."
        ) from exc

    if not 1 <= body_length <= MAX_HEADER_SIZE:
        raise ContainerStreamError(
            "Invalid or oversized container header."
        )

    body = _read_exact(source, body_length)

    return parse_header(prefix + body)


def write_container_stream(
    source: BinaryIO,
    destination: BinaryIO,
    parsed_header: ParsedHeader,
    slot_records: bytes,
    dek: bytes,
) -> ContainerWriteResult:
    """Write a complete TVLT V1 container incrementally.

    The destination must be a temporary file or stream. The caller
    must publish it only after this function returns successfully.

    The source is consumed from its current position.
    """
    if not hasattr(source, "read"):
        raise TypeError("source must provide read().")

    if not hasattr(destination, "write"):
        raise TypeError("destination must provide write().")

    header_bytes = _validated_header_bytes(parsed_header)

    if not isinstance(slot_records, bytes):
        raise TypeError("slot_records must be bytes.")

    parsed_slots = parse_key_slot_records(
        slot_records,
        parsed_header,
    )

    if parsed_slots.consumed != len(slot_records):
        raise ContainerStreamError(
            "Unexpected data after key slot records."
        )

    writer = RecordWriter(dek, parsed_header)
    counting_source = _CountingReader(source)

    container_bytes = 0

    prefix_and_header = header_bytes

    _write_all(destination, prefix_and_header)
    container_bytes += len(prefix_and_header)

    _write_all(destination, slot_records)
    container_bytes += len(slot_records)

    for compressed_chunk in iter_compressed_chunks(
        counting_source,
        output_chunk_size=parsed_header.header["chunk_size"],
    ):
        record = writer.write_data(compressed_chunk)
        _write_all(destination, record)
        container_bytes += len(record)

    final_record = writer.finish(counting_source.total)
    _write_all(destination, final_record)
    container_bytes += len(final_record)

    return ContainerWriteResult(
        original_bytes=counting_source.total,
        compressed_bytes=writer.compressed_bytes,
        data_record_count=writer.data_record_count,
        container_bytes=container_bytes,
    )


def restore_container_stream(
    source: BinaryIO,
    destination: BinaryIO,
    *,
    max_output_size: int,
    fido2_hmac_secret: bytes | None = None,
    recovery_secret: bytes | None = None,
) -> ContainerReadResult:
    """Authenticate and restore one complete TVLT V1 container.

    Exactly one unlocking mechanism must be supplied.

    The destination must be a temporary file or stream. It can
    contain partial plaintext if an error occurs, so the caller
    must discard it unless this function returns successfully.
    """
    if not hasattr(source, "read"):
        raise TypeError("source must provide read().")

    if not hasattr(destination, "write"):
        raise TypeError("destination must provide write().")

    if (fido2_hmac_secret is None) == (recovery_secret is None):
        raise ContainerStreamError(
            "Supply exactly one unlocking mechanism."
        )

    parsed_header = _read_stream_header(source)

    slot_count = len(parsed_header.header["key_slots"])
    slot_data = _read_exact(
        source,
        slot_count * SLOT_RECORD_SIZE,
    )

    parsed_slots = parse_key_slot_records(
        slot_data,
        parsed_header,
    )

    if parsed_slots.consumed != len(slot_data):
        raise ContainerStreamError(
            "Invalid key slot section."
        )

    if recovery_secret is not None:
        dek = recover_dek_with_recovery(
            parsed_header,
            slot_data,
            recovery_secret,
        )
    else:
        dek = recover_dek_with_fido2(
            parsed_header,
            slot_data,
            fido2_hmac_secret,
        )

    reader = RecordReader(dek, parsed_header)
    final_info: dict[str, Any] = {}

    def authenticated_compressed_chunks():
        while True:
            record_header = _read_exact(
                source,
                RECORD_HEADER.size,
            )

            record_type, _, ciphertext_length = (
                RECORD_HEADER.unpack(record_header)
            )

            if record_type == DATA_RECORD_TYPE:
                if not (
                    MIN_DATA_CIPHERTEXT
                    <= ciphertext_length
                    <= MAX_DATA_CIPHERTEXT
                ):
                    raise ContainerStreamError(
                        "Invalid data record length."
                    )

                ciphertext = _read_exact(
                    source,
                    ciphertext_length,
                )

                record = reader.read_data(
                    record_header + ciphertext
                )

                yield record.plaintext

                continue

            if record_type == FINAL_RECORD_TYPE:
                if ciphertext_length != FINAL_CIPHERTEXT_SIZE:
                    raise ContainerStreamError(
                        "Invalid final record length."
                    )

                ciphertext = _read_exact(
                    source,
                    ciphertext_length,
                )

                final_info["record"] = reader.read_final(
                    record_header + ciphertext
                )

                trailing = source.read(1)

                if not isinstance(trailing, bytes):
                    raise ContainerStreamError(
                        "Input stream must return bytes."
                    )

                if trailing:
                    raise ContainerStreamError(
                        "Unexpected bytes after final record."
                    )

                return

            raise ContainerStreamError(
                "Unknown record type."
            )

    restored_bytes = 0

    for output_chunk in iter_decompressed_chunks(
        authenticated_compressed_chunks(),
        max_output_size=max_output_size,
        output_chunk_size=CHUNK_SIZE,
    ):
        _write_all(destination, output_chunk)
        restored_bytes += len(output_chunk)

    final_record = final_info.get("record")

    if final_record is None:
        raise ContainerStreamError(
            "Authenticated final record is missing."
        )

    if restored_bytes != final_record.original_bytes:
        raise ContainerStreamError(
            "Restored byte count does not match the final record."
        )

    return ContainerReadResult(
        parsed_header=parsed_header,
        original_bytes=restored_bytes,
        compressed_bytes=final_record.compressed_bytes,
        data_record_count=final_record.data_record_count,
    )