import secrets

import pytest

from teuzin_vault.core.container_format import (
    ALGORITHMS,
    CHUNK_SIZE,
    parse_header,
    serialize_header,
)
from teuzin_vault.core.key_slots import SLOT_RECORD_SIZE
from teuzin_vault.core.key_protection import (
    KeyProtectionError,
    derive_fido2_wrapping_key,
    derive_recovery_wrapping_key,
    generate_recovery_secret,
    protect_dek,
    reprotect_fido2_slot,
    recover_dek_with_fido2,
    recover_dek_with_recovery,
)


def make_header():
    fido = {
        "id": "1" * 32,
        "type": "fido2-hmac-secret",
        "rp_id": "vault.teuzin.com.br",
        "credential_id": "AQIDBA",
        "hmac_salt": "a" * 64,
        "kdf_salt": "b" * 64,
    }

    recovery = {
        "id": "2" * 32,
        "type": "recovery",
        "kdf_salt": "c" * 64,
    }

    header = {
        "container_id": "d" * 32,
        "algorithms": dict(ALGORITHMS),
        "chunk_size": CHUNK_SIZE,
        "nonce_prefix": "e" * 8,
        "key_slots": [fido, recovery],
    }

    return parse_header(serialize_header(header))


@pytest.fixture
def protection_setup():
    parsed_header = make_header()
    dek = secrets.token_bytes(32)
    fido_secret = secrets.token_bytes(32)
    recovery_secret = generate_recovery_secret()

    records = protect_dek(
        dek,
        parsed_header,
        fido2_hmac_secret=fido_secret,
        recovery_secret=recovery_secret,
    )

    return (
        parsed_header,
        dek,
        fido_secret,
        recovery_secret,
        records,
    )


def test_recovery_secret_is_256_bits():
    secret = generate_recovery_secret()

    assert isinstance(secret, bytes)
    assert len(secret) == 32


def test_recovery_secrets_are_independent():
    first = generate_recovery_secret()
    second = generate_recovery_secret()

    assert first != second


def test_fido2_hkdf_is_deterministic():
    descriptor = make_header().header["key_slots"][0]
    secret = b"A" * 32

    first = derive_fido2_wrapping_key(secret, descriptor)
    second = derive_fido2_wrapping_key(secret, descriptor)

    assert first == second
    assert len(first) == 32


def test_recovery_hkdf_is_deterministic():
    descriptor = make_header().header["key_slots"][1]
    secret = b"B" * 32

    first = derive_recovery_wrapping_key(secret, descriptor)
    second = derive_recovery_wrapping_key(secret, descriptor)

    assert first == second
    assert len(first) == 32


def test_fido2_and_recovery_contexts_are_separated():
    header = make_header()
    fido_descriptor = dict(header.header["key_slots"][0])
    recovery_descriptor = dict(header.header["key_slots"][1])

    recovery_descriptor["kdf_salt"] = fido_descriptor["kdf_salt"]

    material = b"C" * 32

    fido_key = derive_fido2_wrapping_key(
        material,
        fido_descriptor,
    )
    recovery_key = derive_recovery_wrapping_key(
        material,
        recovery_descriptor,
    )

    assert fido_key != recovery_key


def test_same_dek_can_be_recovered_with_fido2(protection_setup):
    parsed, expected, fido_secret, _, records = protection_setup

    recovered = recover_dek_with_fido2(
        parsed,
        records,
        fido_secret,
    )

    assert recovered == expected


def test_same_dek_can_be_recovered_without_fido2(protection_setup):
    parsed, expected, _, recovery_secret, records = protection_setup

    recovered = recover_dek_with_recovery(
        parsed,
        records,
        recovery_secret,
    )

    assert recovered == expected


def test_wrong_fido2_secret_is_rejected(protection_setup):
    parsed, _, _, _, records = protection_setup

    with pytest.raises(ValueError):
        recover_dek_with_fido2(
            parsed,
            records,
            secrets.token_bytes(32),
        )


def test_wrong_recovery_secret_is_rejected(protection_setup):
    parsed, _, _, _, records = protection_setup

    with pytest.raises(ValueError):
        recover_dek_with_recovery(
            parsed,
            records,
            secrets.token_bytes(32),
        )


def test_invalid_fido2_secret_length_is_rejected():
    descriptor = make_header().header["key_slots"][0]

    with pytest.raises(KeyProtectionError):
        derive_fido2_wrapping_key(b"short", descriptor)


def test_invalid_recovery_secret_length_is_rejected():
    descriptor = make_header().header["key_slots"][1]

    with pytest.raises(KeyProtectionError):
        derive_recovery_wrapping_key(b"short", descriptor)


def test_invalid_dek_length_is_rejected(protection_setup):
    parsed, _, fido_secret, recovery_secret, _ = protection_setup

    with pytest.raises(KeyProtectionError):
        protect_dek(
            b"short",
            parsed,
            fido2_hmac_secret=fido_secret,
            recovery_secret=recovery_secret,
        )


def test_invalid_fido2_salt_is_rejected():
    descriptor = make_header().header["key_slots"][0]
    descriptor["hmac_salt"] = "invalid"

    with pytest.raises(KeyProtectionError):
        derive_fido2_wrapping_key(b"A" * 32, descriptor)


def test_invalid_recovery_salt_is_rejected():
    descriptor = make_header().header["key_slots"][1]
    descriptor["kdf_salt"] = "invalid"

    with pytest.raises(KeyProtectionError):
        derive_recovery_wrapping_key(b"B" * 32, descriptor)


def test_reprotect_fido2_slot_preserves_recovery_record(protection_setup):
    parsed, dek, old_secret, recovery_secret, old_records = protection_setup
    new_secret = b"N" * 32

    new_records = reprotect_fido2_slot(
        parsed,
        old_records,
        dek,
        fido2_hmac_secret=new_secret,
    )

    descriptors = parsed.header["key_slots"]
    recovery_index = next(
        index for index, descriptor in enumerate(descriptors)
        if descriptor["type"] == "recovery"
    )
    start = recovery_index * SLOT_RECORD_SIZE
    end = start + SLOT_RECORD_SIZE

    assert new_records[start:end] == old_records[start:end]
    assert new_records != old_records
    assert recover_dek_with_fido2(parsed, new_records, new_secret) == dek
    assert recover_dek_with_recovery(parsed, new_records, recovery_secret) == dek

    with pytest.raises(ValueError):
        recover_dek_with_fido2(parsed, new_records, old_secret)
