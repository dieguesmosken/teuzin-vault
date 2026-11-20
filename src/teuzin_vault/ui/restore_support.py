"""Leitura segura dos metadados públicos necessários à restauração na UI."""

from __future__ import annotations

import base64
import os
import re

from pathlib import Path

from teuzin_vault.core.container_format import (
    MAX_HEADER_SIZE,
    PREFIX_SIZE,
    ParsedHeader,
    parse_header,
)


def read_container_header(container_path: str | Path) -> ParsedHeader:
    """Lê somente o prefixo e o limite máximo do cabeçalho TVLT."""
    path = Path(container_path)

    with path.open("rb") as source:
        header_bytes = source.read(PREFIX_SIZE + MAX_HEADER_SIZE)

    return parse_header(header_bytes)


def fido2_authentication_material(
    parsed_header: ParsedHeader,
) -> tuple[bytes, bytes]:
    """Retorna (salt HMAC-secret, credential ID) do slot FIDO2."""
    descriptors = [
        item
        for item in parsed_header.header["key_slots"]
        if item.get("type") == "fido2-hmac-secret"
    ]

    if len(descriptors) != 1:
        raise ValueError("O cofre não contém exatamente um slot FIDO2.")

    descriptor = descriptors[0]
    salt = bytes.fromhex(descriptor["hmac_salt"])
    encoded_id = descriptor["credential_id"]
    padded_id = encoded_id + ("=" * (-len(encoded_id) % 4))

    credential_id = base64.b64decode(
        padded_id,
        altchars=b"-_",
        validate=True,
    )

    if len(salt) != 32 or not credential_id:
        raise ValueError("Os dados públicos do slot FIDO2 são inválidos.")

    return salt, credential_id


def decode_recovery_secret(value: str) -> bytes:
    """Converte o segredo de recuperação hexadecimal de 32 bytes."""
    if not isinstance(value, str):
        raise TypeError("O segredo de recuperação deve ser texto.")

    normalized = value.strip()

    if re.fullmatch(r"[0-9a-fA-F]{64}", normalized) is None:
        raise ValueError(
            "Informe o segredo de recuperação com 64 caracteres hexadecimais."
        )

    secret = bytes.fromhex(normalized)

    if len(secret) != 32:
        raise ValueError("O segredo de recuperação deve conter 32 bytes.")

    return secret


def default_credential_metadata_path() -> Path:
    """Caminho padrão local para os metadados públicos da credencial."""
    local_app_data = os.environ.get("LOCALAPPDATA")

    if local_app_data:
        base = Path(local_app_data)
    else:
        base = Path.home() / "AppData" / "Local"

    return (
        base
        / "TeuzinVault"
        / "credentials"
        / "vault-teuzin-test.json"
    )
