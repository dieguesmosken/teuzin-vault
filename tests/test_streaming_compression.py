from io import BytesIO
import secrets

import pytest

from teuzin_vault.core.container_format import CHUNK_SIZE
from teuzin_vault.core.streaming_compression import (
    DecompressionLimitError,
    StreamingCompressionError,
    TrailingCompressedDataError,
    TruncatedCompressedStreamError,
    iter_compressed_chunks,
    iter_decompressed_chunks,
)


def compress_bytes(data):
    return b"".join(
        iter_compressed_chunks(BytesIO(data))
    )


def decompress_bytes(data, limit):
    return b"".join(
        iter_decompressed_chunks(
            [data],
            max_output_size=limit,
        )
    )


def test_streaming_round_trip():
    original = (b"Teuzin Vault streaming test. " * 10000)

    compressed = compress_bytes(original)
    restored = decompress_bytes(compressed, len(original))

    assert restored == original


def test_empty_stream_round_trip():
    compressed = compress_bytes(b"")

    assert compressed
    assert decompress_bytes(compressed, 0) == b""


def test_large_stream_is_emitted_in_bounded_chunks():
    original = secrets.token_bytes(CHUNK_SIZE * 2 + 333)

    chunks = list(
        iter_compressed_chunks(
            BytesIO(original),
            read_size=CHUNK_SIZE,
            output_chunk_size=CHUNK_SIZE,
        )
    )

    assert len(chunks) >= 2
    assert all(0 < len(chunk) <= CHUNK_SIZE for chunk in chunks)

    restored = b"".join(
        iter_decompressed_chunks(
            chunks,
            max_output_size=len(original),
        )
    )

    assert restored == original


def test_decompression_output_limit():
    original = b"A" * 100000
    compressed = compress_bytes(original)

    with pytest.raises(DecompressionLimitError):
        decompress_bytes(compressed, 100)


def test_malformed_stream_is_rejected():
    with pytest.raises(StreamingCompressionError):
        decompress_bytes(b"not a zstandard frame", 1024)


def test_truncated_stream_is_rejected():
    compressed = compress_bytes(b"Some data to test truncation")

    with pytest.raises(TruncatedCompressedStreamError):
        decompress_bytes(compressed[:-1], 1024)


def test_trailing_data_in_same_chunk_is_rejected():
    compressed = compress_bytes(b"Original frame")
    corrupted = compressed + b"EXTRA"

    with pytest.raises(TrailingCompressedDataError):
        decompress_bytes(corrupted, 1024)


def test_second_frame_is_rejected():
    first = compress_bytes(b"First frame")
    second = compress_bytes(b"Second frame")

    with pytest.raises(TrailingCompressedDataError):
        b"".join(
            iter_decompressed_chunks(
                [first, second],
                max_output_size=1024,
            )
        )


def test_invalid_read_size_is_rejected():
    with pytest.raises(ValueError):
        list(
            iter_compressed_chunks(
                BytesIO(b"valid input"),
                read_size=0,
            )
        )


def test_non_bytes_source_output_is_rejected():
    class TextSource:
        def read(self, size=-1):
            return "not bytes"

    with pytest.raises(TypeError):
        list(iter_compressed_chunks(TextSource()))


def test_invalid_output_limit_is_rejected():
    with pytest.raises(ValueError):
        list(
            iter_decompressed_chunks(
                [],
                max_output_size=-1,
            )
        )