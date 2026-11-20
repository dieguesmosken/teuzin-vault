from dataclasses import replace
import secrets

import pytest

from teuzin_vault.core.container_format import (
    ALGORITHMS,
    CHUNK_SIZE,
    parse_header,
    serialize_header,
)
from teuzin_vault.core.key_slots import (
    SLOT_RECORD_SIZE,
    KeySlotDecryptionError,
    KeySlotFormatError,
    KeySlotRecord,
    parse_key_slot_records,
    serialize_key_slot_records,
    unwrap_dek,
    wrap_dek,
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
def slot_setup():
    parsed_header = make_header()
    dek = secrets.token_bytes(32)

    wrapping_keys = {
        descriptor["id"]: secrets.token_bytes(32)
        for descriptor in parsed_header.header["key_slots"]
    }

    records = [
        wrap_dek(
            dek,
            wrapping_keys[descriptor["id"]],
            descriptor,
            parsed_header.digest,
        )
        for descriptor in parsed_header.header["key_slots"]
    ]

    return parsed_header, dek, wrapping_keys, records


def test_both_slots_unlock_the_same_dek(slot_setup):
    parsed, expected_dek, keys, records = slot_setup

    for descriptor, record in zip(
        parsed.header["key_slots"],
        records,
    ):
        recovered = unwrap_dek(
            record,
            keys[descriptor["id"]],
            descriptor,
            parsed.digest,
        )

        assert recovered == expected_dek


def test_each_slot_record_has_fixed_size(slot_setup):
    parsed, _, _, records = slot_setup

    encoded = serialize_key_slot_records(records, parsed)

    assert SLOT_RECORD_SIZE == 76
    assert len(encoded) == 2 * SLOT_RECORD_SIZE


def test_slot_records_round_trip(slot_setup):
    parsed, _, _, records = slot_setup

    encoded = serialize_key_slot_records(records, parsed)
    restored = parse_key_slot_records(encoded, parsed)

    assert restored.records == tuple(records)
    assert restored.consumed == len(encoded)


def test_parser_preserves_following_records(slot_setup):
    parsed, _, _, records = slot_setup
    following = b"DATA-RECORD"

    encoded = serialize_key_slot_records(records, parsed)
    result = parse_key_slot_records(encoded + following, parsed)

    assert result.consumed == len(encoded)
    assert (encoded + following)[result.consumed:] == following


def test_truncated_slot_records_are_rejected(slot_setup):
    parsed, _, _, records = slot_setup

    encoded = serialize_key_slot_records(records, parsed)

    with pytest.raises(KeySlotFormatError):
        parse_key_slot_records(encoded[:-1], parsed)


def test_record_order_must_match_header(slot_setup):
    parsed, _, _, records = slot_setup

    with pytest.raises(KeySlotFormatError):
        serialize_key_slot_records(list(reversed(records)), parsed)


def test_unknown_slot_id_is_rejected(slot_setup):
    parsed, _, _, records = slot_setup

    encoded = bytearray(
        serialize_key_slot_records(records, parsed)
    )
    encoded[0] ^= 0xFF

    with pytest.raises(KeySlotFormatError):
        parse_key_slot_records(bytes(encoded), parsed)


def test_duplicate_nonces_are_rejected_by_serializer(slot_setup):
    parsed, _, _, records = slot_setup

    duplicate = replace(records[1], nonce=records[0].nonce)

    with pytest.raises(KeySlotFormatError):
        serialize_key_slot_records(
            [records[0], duplicate],
            parsed,
        )


def test_duplicate_nonces_are_rejected_by_parser(slot_setup):
    parsed, _, _, records = slot_setup

    encoded = bytearray(
        serialize_key_slot_records(records, parsed)
    )

    first_nonce = bytes(encoded[16:28])
    encoded[SLOT_RECORD_SIZE + 16:SLOT_RECORD_SIZE + 28] = first_nonce

    with pytest.raises(KeySlotFormatError):
        parse_key_slot_records(bytes(encoded), parsed)


def test_wrong_wrapping_key_is_rejected(slot_setup):
    parsed, _, _, records = slot_setup
    descriptor = parsed.header["key_slots"][0]

    with pytest.raises(KeySlotDecryptionError):
        unwrap_dek(
            records[0],
            secrets.token_bytes(32),
            descriptor,
            parsed.digest,
        )


def test_modified_ciphertext_is_rejected(slot_setup):
    parsed, _, keys, records = slot_setup
    descriptor = parsed.header["key_slots"][0]

    modified = bytearray(records[0].wrapped_dek)
    modified[0] ^= 1

    corrupted_record = replace(
        records[0],
        wrapped_dek=bytes(modified),
    )

    with pytest.raises(KeySlotDecryptionError):
        unwrap_dek(
            corrupted_record,
            keys[descriptor["id"]],
            descriptor,
            parsed.digest,
        )


def test_descriptor_is_authenticated(slot_setup):
    parsed, _, keys, records = slot_setup
    descriptor = dict(parsed.header["key_slots"][0])
    descriptor["hmac_salt"] = "f" * 64

    with pytest.raises(KeySlotDecryptionError):
        unwrap_dek(
            records[0],
            keys[descriptor["id"]],
            descriptor,
            parsed.digest,
        )


def test_header_digest_is_authenticated(slot_setup):
    parsed, _, keys, records = slot_setup
    descriptor = parsed.header["key_slots"][0]

    wrong_digest = bytes([0] * 32)

    with pytest.raises(KeySlotDecryptionError):
        unwrap_dek(
            records[0],
            keys[descriptor["id"]],
            descriptor,
            wrong_digest,
        )


def test_wrong_record_slot_id_is_rejected(slot_setup):
    parsed, _, keys, records = slot_setup
    descriptor = parsed.header["key_slots"][0]

    wrong_record = replace(
        records[0],
        slot_id=b"\x99" * 16,
    )

    with pytest.raises(KeySlotFormatError):
        unwrap_dek(
            wrong_record,
            keys[descriptor["id"]],
            descriptor,
            parsed.digest,
        )


def test_invalid_wrapping_key_length_is_rejected(slot_setup):
    parsed, _, _, records = slot_setup
    descriptor = parsed.header["key_slots"][0]

    with pytest.raises(KeySlotFormatError):
        unwrap_dek(
            records[0],
            b"short",
            descriptor,
            parsed.digest,
        )


def test_invalid_dek_length_is_rejected(slot_setup):
    parsed, _, keys, _ = slot_setup
    descriptor = parsed.header["key_slots"][0]

    with pytest.raises(KeySlotFormatError):
        wrap_dek(
            b"short",
            keys[descriptor["id"]],
            descriptor,
            parsed.digest,
        )