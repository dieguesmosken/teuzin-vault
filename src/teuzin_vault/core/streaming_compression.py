"""Incremental Zstandard processing for TVLT containers."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import BinaryIO

from compression import zstd

from teuzin_vault.core.container_format import CHUNK_SIZE


DEFAULT_OUTPUT_CHUNK_SIZE = 1024 * 1024
DEFAULT_MAX_WINDOW_LOG = 27


class StreamingCompressionError(ValueError):
    """Invalid compression stream or compression operation."""


class DecompressionLimitError(StreamingCompressionError):
    """Decompressed output exceeded its configured limit."""


class TruncatedCompressedStreamError(StreamingCompressionError):
    """The Zstandard frame did not reach its end marker."""


class TrailingCompressedDataError(StreamingCompressionError):
    """Bytes or additional frames were found after the Zstandard frame."""


def _validate_chunk_size(name: str, value: int) -> None:
    if type(value) is not int or not 1 <= value <= CHUNK_SIZE:
        raise ValueError(
            f"{name} must be between 1 and {CHUNK_SIZE} bytes."
        )


def iter_compressed_chunks(
    source: BinaryIO,
    *,
    read_size: int = CHUNK_SIZE,
    output_chunk_size: int = DEFAULT_OUTPUT_CHUNK_SIZE,
) -> Iterator[bytes]:
    """Compress a binary stream into bounded Zstandard chunks.

    A single Zstandard frame is generated. Its checksum is enabled.
    The source remains open and is not rewound.
    """
    _validate_chunk_size("read_size", read_size)
    _validate_chunk_size("output_chunk_size", output_chunk_size)

    if not hasattr(source, "read"):
        raise TypeError("source must provide read().")

    options = {
        zstd.CompressionParameter.checksum_flag: 1,
    }

    compressor = zstd.ZstdCompressor(options=options)
    pending = bytearray()

    while True:
        raw = source.read(read_size)

        if not isinstance(raw, bytes):
            raise TypeError("source.read() must return bytes.")

        if len(raw) > read_size:
            raise StreamingCompressionError(
                "Source returned more bytes than requested."
            )

        if not raw:
            break

        try:
            pending.extend(compressor.compress(raw))
        except zstd.ZstdError as exc:
            raise StreamingCompressionError(
                "Zstandard compression failed."
            ) from exc

        while len(pending) >= output_chunk_size:
            chunk = bytes(pending[:output_chunk_size])
            del pending[:output_chunk_size]
            yield chunk

    try:
        pending.extend(compressor.flush())
    except zstd.ZstdError as exc:
        raise StreamingCompressionError(
            "Zstandard finalization failed."
        ) from exc

    while len(pending) >= output_chunk_size:
        chunk = bytes(pending[:output_chunk_size])
        del pending[:output_chunk_size]
        yield chunk

    if pending:
        yield bytes(pending)


def iter_decompressed_chunks(
    compressed_chunks: Iterable[bytes],
    *,
    max_output_size: int,
    output_chunk_size: int = DEFAULT_OUTPUT_CHUNK_SIZE,
    max_window_log: int = DEFAULT_MAX_WINDOW_LOG,
) -> Iterator[bytes]:
    """Incrementally decompress exactly one Zstandard frame.

    Enforces a global output-size limit and a maximum decompression
    window. The complete iterator must be consumed to validate EOF.
    """
    if (
        type(max_output_size) is not int
        or max_output_size < 0
    ):
        raise ValueError(
            "max_output_size must be a non-negative integer."
        )

    _validate_chunk_size("output_chunk_size", output_chunk_size)

    if type(max_window_log) is not int:
        raise ValueError("max_window_log must be an integer.")

    lower, upper = (
        zstd.DecompressionParameter.window_log_max.bounds()
    )

    if not lower <= max_window_log <= upper:
        raise ValueError("max_window_log is outside Zstandard limits.")

    options = {
        zstd.DecompressionParameter.window_log_max: max_window_log,
    }

    decompressor = zstd.ZstdDecompressor(options=options)

    total_output = 0
    frame_finished = False

    for compressed in compressed_chunks:
        if not isinstance(compressed, bytes):
            raise TypeError("Compressed chunks must be bytes.")

        if not compressed:
            continue

        if frame_finished:
            raise TrailingCompressedDataError(
                "Data found after the Zstandard frame."
            )

        pending = compressed

        while True:
            remaining = max_output_size - total_output
            output_limit = min(output_chunk_size, remaining + 1)

            try:
                output = decompressor.decompress(
                    pending,
                    max_length=output_limit,
                )
            except (zstd.ZstdError, EOFError) as exc:
                raise StreamingCompressionError(
                    "Zstandard decompression failed."
                ) from exc

            pending = b""

            if len(output) > remaining:
                raise DecompressionLimitError(
                    "Decompressed content exceeds the configured limit."
                )

            if output:
                total_output += len(output)
                yield output

            if decompressor.unused_data:
                raise TrailingCompressedDataError(
                    "Unexpected data or an additional frame was found."
                )

            if decompressor.eof:
                frame_finished = True
                break

            if decompressor.needs_input:
                break

            if not output:
                raise StreamingCompressionError(
                    "Zstandard decompressor made no progress."
                )

    if not frame_finished:
        raise TruncatedCompressedStreamError(
            "Zstandard frame did not reach its end marker."
        )