"""Primitivas iniciais de criptografia do Teuzin Vault."""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


class DecryptionError(Exception):
    """Indica falha na autenticação ou descriptografia."""


def generate_data_key() -> bytes:
    """Gera uma chave de dados aleatória de 256 bits."""
    return secrets.token_bytes(KEY_SIZE)


def _validate_bytes(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} deve ser bytes.")


def encrypt(
    plaintext: bytes,
    key: bytes,
    *,
    associated_data: bytes = b"",
) -> tuple[bytes, bytes]:
    """Criptografa dados e retorna (nonce, ciphertext_com_tag).

    Esta é uma primitiva para dados em memória. Arquivos grandes
    precisarão de um formato autenticado por blocos.
    """
    _validate_bytes("plaintext", plaintext)
    _validate_bytes("key", key)
    _validate_bytes("associated_data", associated_data)

    if len(key) != KEY_SIZE:
        raise ValueError("A chave AES-256 deve possuir 32 bytes.")

    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext,
        associated_data,
    )

    return nonce, ciphertext


def decrypt(
    nonce: bytes,
    ciphertext: bytes,
    key: bytes,
    *,
    associated_data: bytes = b"",
) -> bytes:
    """Descriptografa e autentica os dados recebidos."""
    _validate_bytes("nonce", nonce)
    _validate_bytes("ciphertext", ciphertext)
    _validate_bytes("key", key)
    _validate_bytes("associated_data", associated_data)

    if len(key) != KEY_SIZE:
        raise ValueError("A chave AES-256 deve possuir 32 bytes.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("O nonce AES-GCM deve possuir 12 bytes.")

    if len(ciphertext) < TAG_SIZE:
        raise ValueError("O ciphertext não contém uma tag válida.")

    try:
        return AESGCM(key).decrypt(
            nonce,
            ciphertext,
            associated_data,
        )
    except InvalidTag:
        raise DecryptionError(
            "Falha na autenticação: chave, dados ou metadados inválidos."
        ) from None