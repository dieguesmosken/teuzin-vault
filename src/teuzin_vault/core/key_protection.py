"""Independent HKDF-based protection paths for TVLT V1."""

from __future__ import annotations

import secrets

from collections.abc import Mapping
from typing import Any

from teuzin_vault.core.container_format import ParsedHeader
from teuzin_vault.core.key_derivation import derive_key
from teuzin_vault.core.key_slots import (
    KeySlotDecryptionError,
    KeySlotFormatError,
    parse_key_slot_records,
    serialize_key_slot_records,
    unwrap_dek,
    wrap_dek,
)


SECRET_SIZE = 32
DERIVED_KEY_SIZE = 32

FIDO2_INFO = b"teuzin-vault/v1/key-slot/fido2-hmac-secret"
RECOVERY_INFO = b"teuzin-vault/v1/key-slot/recovery"


class KeyProtectionError(ValueError):
    """Invalid key protection input or container metadata."""


def _validate_secret(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes.")

    if len(value) != SECRET_SIZE:
        raise KeyProtectionError(
            f"{name} must contain exactly 32 bytes."
        )


def generate_recovery_secret() -> bytes:
    """Generate an independent 256-bit recovery secret.

    The returned value must be displayed and saved securely by
    a future user interface. This function never writes it to disk.
    """
    return secrets.token_bytes(SECRET_SIZE)


def _get_kdf_salt(
    descriptor: Mapping[str, Any],
    expected_type: str,
) -> bytes:
    if not isinstance(descriptor, Mapping):
        raise TypeError("descriptor must be a mapping.")

    if descriptor.get("type") != expected_type:
        raise KeyProtectionError(
            f"Expected a {expected_type} key slot."
        )

    value = descriptor.get("kdf_salt")

    if not isinstance(value, str) or len(value) != 64:
        raise KeyProtectionError("Invalid HKDF salt.")

    try:
        salt = bytes.fromhex(value)
    except ValueError as exc:
        raise KeyProtectionError("Invalid HKDF salt.") from exc

    if len(salt) != 32:
        raise KeyProtectionError("HKDF salt must contain 32 bytes.")

    return salt


def derive_fido2_wrapping_key(
    hmac_secret: bytes,
    descriptor: Mapping[str, Any],
) -> bytes:
    """Derive the FIDO2 compartment wrapping key.

    hmac_secret is the 32-byte result from one FIDO2 HMAC-secret salt.
    The HMAC-secret salt itself is supplied to the authenticator
    before this function is called.
    """
    _validate_secret("hmac_secret", hmac_secret)

    if not isinstance(descriptor, Mapping):
        raise TypeError("descriptor must be a mapping.")

    hmac_salt = descriptor.get("hmac_salt")

    if not isinstance(hmac_salt, str) or len(hmac_salt) != 64:
        raise KeyProtectionError("Invalid FIDO2 HMAC salt.")

    try:
        decoded_hmac_salt = bytes.fromhex(hmac_salt)
    except ValueError as exc:
        raise KeyProtectionError(
            "Invalid FIDO2 HMAC salt."
        ) from exc

    if len(decoded_hmac_salt) != 32:
        raise KeyProtectionError(
            "FIDO2 HMAC salt must contain 32 bytes."
        )

    kdf_salt = _get_kdf_salt(
        descriptor,
        "fido2-hmac-secret",
    )

    return derive_key(
        hmac_secret,
        kdf_salt,
        info=FIDO2_INFO,
        length=DERIVED_KEY_SIZE,
    )


def derive_recovery_wrapping_key(
    recovery_secret: bytes,
    descriptor: Mapping[str, Any],
) -> bytes:
    """Derive the independent recovery compartment wrapping key."""
    _validate_secret("recovery_secret", recovery_secret)

    kdf_salt = _get_kdf_salt(
        descriptor,
        "recovery",
    )

    return derive_key(
        recovery_secret,
        kdf_salt,
        info=RECOVERY_INFO,
        length=DERIVED_KEY_SIZE,
    )


def _validate_parsed_header(
    parsed_header: ParsedHeader,
) -> None:
    if not isinstance(parsed_header, ParsedHeader):
        raise TypeError("parsed_header must be a ParsedHeader.")

    if not isinstance(parsed_header.header, dict):
        raise KeyProtectionError("Invalid parsed header.")

    if len(parsed_header.digest) != 32:
        raise KeyProtectionError("Invalid header digest.")


def protect_dek(
    dek: bytes,
    parsed_header: ParsedHeader,
    *,
    fido2_hmac_secret: bytes,
    recovery_secret: bytes,
) -> bytes:
    """Protect one DEK using both independent key compartments.

    Returns only the serialized key slot records.
    Secret inputs and derived keys are never persisted here.
    """
    _validate_secret("dek", dek)
    _validate_secret("fido2_hmac_secret", fido2_hmac_secret)
    _validate_secret("recovery_secret", recovery_secret)
    _validate_parsed_header(parsed_header)

    records = []

    for descriptor in parsed_header.header["key_slots"]:
        slot_type = descriptor["type"]

        if slot_type == "fido2-hmac-secret":
            wrapping_key = derive_fido2_wrapping_key(
                fido2_hmac_secret,
                descriptor,
            )

        if slot_type == "recovery":
            wrapping_key = derive_recovery_wrapping_key(
                recovery_secret,
                descriptor,
            )

        if slot_type not in {"fido2-hmac-secret", "recovery"}:
            raise KeyProtectionError(
                "Unsupported key compartment."
            )

        records.append(
            wrap_dek(
                dek,
                wrapping_key,
                descriptor,
                parsed_header.digest,
            )
        )

    return serialize_key_slot_records(
        records,
        parsed_header,
    )


def _recover_with_slot(
    parsed_header: ParsedHeader,
    record_data: bytes,
    slot_type: str,
    source_secret: bytes,
) -> bytes:
    """Recover a DEK using exactly one independent compartment."""
    _validate_parsed_header(parsed_header)

    parsed_records = parse_key_slot_records(
        record_data,
        parsed_header,
    )

    for descriptor, record in zip(
        parsed_header.header["key_slots"],
        parsed_records.records,
    ):
        if descriptor["type"] == slot_type:
            if slot_type == "fido2-hmac-secret":
                wrapping_key = derive_fido2_wrapping_key(
                    source_secret,
                    descriptor,
                )

            if slot_type == "recovery":
                wrapping_key = derive_recovery_wrapping_key(
                    source_secret,
                    descriptor,
                )

            return unwrap_dek(
                record,
                wrapping_key,
                descriptor,
                parsed_header.digest,
            )

    raise KeySlotFormatError(
        "Requested key compartment was not found."
    )


def recover_dek_with_fido2(
    parsed_header: ParsedHeader,
    record_data: bytes,
    hmac_secret: bytes,
) -> bytes:
    """Recover the DEK using only the FIDO2-derived secret."""
    _validate_secret("hmac_secret", hmac_secret)

    return _recover_with_slot(
        parsed_header,
        record_data,
        "fido2-hmac-secret",
        hmac_secret,
    )


def recover_dek_with_recovery(
    parsed_header: ParsedHeader,
    record_data: bytes,
    recovery_secret: bytes,
) -> bytes:
    """Recover the DEK without requiring the physical authenticator."""
    _validate_secret("recovery_secret", recovery_secret)

    return _recover_with_slot(
        parsed_header,
        record_data,
        "recovery",
        recovery_secret,
    )