"""Compactação Zstandard com limite de descompressão."""

from __future__ import annotations

from compression import zstd


class InvalidCompressedDataError(ValueError):
    """Indica um fluxo Zstandard inválido ou incompleto."""


class DecompressionLimitError(InvalidCompressedDataError):
    """Indica que o limite de descompressão foi ultrapassado."""


DEFAULT_MAX_OUTPUT_SIZE = 64 * 1024 * 1024


def compress_data(data: bytes, *, level: int | None = None) -> bytes:
    """Compacta bytes usando Zstandard."""
    if not isinstance(data, bytes):
        raise TypeError("data deve ser bytes.")

    try:
        return zstd.compress(data, level=level)
    except zstd.ZstdError as exc:
        raise InvalidCompressedDataError(
            "Não foi possível compactar os dados."
        ) from exc


def decompress_data(
    compressed: bytes,
    *,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
) -> bytes:
    """Descompacta um único quadro Zstandard com limite de saída.

    Esta função trabalha em memória e destina-se a payloads limitados.
    O processamento de arquivos grandes será feito por streaming.
    """
    if not isinstance(compressed, bytes):
        raise TypeError("compressed deve ser bytes.")

    if (
        not isinstance(max_output_size, int)
        or isinstance(max_output_size, bool)
        or max_output_size < 0
    ):
        raise ValueError("max_output_size deve ser um inteiro não negativo.")

    decompressor = zstd.ZstdDecompressor()
    output = bytearray()
    pending = compressed

    try:
        while True:
            remaining = max_output_size - len(output)

            # Solicita no máximo um byte além do limite para detectar excesso.
            chunk = decompressor.decompress(
                pending,
                max_length=remaining + 1,
            )
            pending = b""

            if len(chunk) > remaining:
                raise DecompressionLimitError(
                    "O conteúdo descompactado excede o limite permitido."
                )

            output.extend(chunk)

            if decompressor.eof:
                if decompressor.unused_data:
                    raise InvalidCompressedDataError(
                        "Foram encontrados dados após o quadro Zstandard."
                    )

                return bytes(output)

            if decompressor.needs_input:
                raise InvalidCompressedDataError(
                    "O fluxo Zstandard está incompleto ou truncado."
                )

    except zstd.ZstdError as exc:
        raise InvalidCompressedDataError(
            "O fluxo Zstandard é inválido ou está corrompido."
        ) from exc