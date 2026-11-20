import pytest

from teuzin_vault.core.compression import (
    DecompressionLimitError,
    InvalidCompressedDataError,
    compress_data,
    decompress_data,
)


def test_zstandard_round_trip():
    original = (b"Teuzin Vault - compactacao segura. " * 1000)

    compressed = compress_data(original)
    restored = decompress_data(compressed)

    assert restored == original
    assert len(compressed) < len(original)


def test_zstandard_empty_content():
    compressed = compress_data(b"")

    assert decompress_data(compressed) == b""


def test_decompression_output_limit():
    original = b"A" * 10000
    compressed = compress_data(original)

    with pytest.raises(DecompressionLimitError):
        decompress_data(compressed, max_output_size=100)


def test_invalid_zstandard_input():
    with pytest.raises(InvalidCompressedDataError):
        decompress_data(b"isto nao e um quadro zstandard")


def test_truncated_zstandard_frame():
    compressed = compress_data(b"Conteudo para testar truncamento")

    with pytest.raises(InvalidCompressedDataError):
        decompress_data(compressed[:-1])


def test_trailing_data_is_rejected():
    compressed = compress_data(b"Conteudo original")
    corrupted = compressed + b"DADOS EXTRAS"

    with pytest.raises(InvalidCompressedDataError):
        decompress_data(corrupted)