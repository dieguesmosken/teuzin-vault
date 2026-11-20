"""Derivação de chaves com HKDF-SHA256."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HASH_SIZE = 32
MIN_SALT_SIZE = 16
MAX_KEY_SIZE = 255 * HASH_SIZE


def derive_key(
    input_key_material: bytes,
    salt: bytes,
    *,
    info: bytes,
    length: int = 32,
) -> bytes:
    """Deriva uma chave com HKDF-SHA256.

    O salt não precisa ser secreto. O parâmetro info separa
    criptograficamente as finalidades das chaves derivadas.
    """
    if not isinstance(input_key_material, bytes):
        raise TypeError("input_key_material deve ser bytes.")

    if not isinstance(salt, bytes):
        raise TypeError("salt deve ser bytes.")

    if not isinstance(info, bytes):
        raise TypeError("info deve ser bytes.")

    if not input_key_material:
        raise ValueError("O material de entrada não pode ser vazio.")

    if len(salt) < MIN_SALT_SIZE:
        raise ValueError("O salt deve possuir pelo menos 16 bytes.")

    if not info:
        raise ValueError("O contexto info não pode ser vazio.")

    if not 1 <= length <= MAX_KEY_SIZE:
        raise ValueError("Comprimento de chave derivada inválido.")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(input_key_material)