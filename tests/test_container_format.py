import json
import struct

import pytest

from teuzin_vault.core.container_format import (
    ALGORITHMS,
    CHUNK_SIZE,
    FORMAT_VERSION,
    MAGIC,
    MAX_HEADER_SIZE,
    PREFIX_STRUCT,
    ContainerFormatError,
    create_header,
    parse_header,
    serialize_header,
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

    return {
        "container_id": "d" * 32,
        "algorithms": dict(ALGORITHMS),
        "chunk_size": CHUNK_SIZE,
        "nonce_prefix": "e" * 8,
        "key_slots": [fido, recovery],
    }


def pack_body(body, version=FORMAT_VERSION):
    prefix = PREFIX_STRUCT.pack(
        MAGIC,
        version,
        len(body),
    )
    return prefix + body


def test_header_round_trip():
    original = make_header()

    encoded = serialize_header(original)
    parsed = parse_header(encoded)

    assert parsed.header == original
    assert parsed.consumed == len(encoded)
    assert len(parsed.digest) == 32


def test_header_parser_allows_following_records():
    encoded = serialize_header(make_header())
    following_data = b"NEXT-RECORD"

    parsed = parse_header(encoded + following_data)

    assert parsed.consumed == len(encoded)
    assert (encoded + following_data)[parsed.consumed:] == following_data


def test_serialization_is_deterministic():
    header = make_header()

    assert serialize_header(header) == serialize_header(header)


def test_created_header_has_random_identifiers():
    first = create_header(
        make_header()["key_slots"][0],
        make_header()["key_slots"][1],
    )
    second = create_header(
        make_header()["key_slots"][0],
        make_header()["key_slots"][1],
    )

    assert first["container_id"] != second["container_id"]
    assert first["nonce_prefix"] != second["nonce_prefix"]


def test_invalid_magic_is_rejected():
    encoded = bytearray(serialize_header(make_header()))
    encoded[0] ^= 1

    with pytest.raises(ContainerFormatError):
        parse_header(bytes(encoded))


def test_unsupported_version_is_rejected():
    body = json.dumps(make_header()).encode("utf-8")
    encoded = pack_body(body, version=FORMAT_VERSION + 1)

    with pytest.raises(ContainerFormatError):
        parse_header(encoded)


def test_truncated_prefix_is_rejected():
    with pytest.raises(ContainerFormatError):
        parse_header(b"TVLT")


def test_truncated_header_is_rejected():
    encoded = serialize_header(make_header())

    with pytest.raises(ContainerFormatError):
        parse_header(encoded[:-1])


def test_oversized_header_is_rejected():
    prefix = PREFIX_STRUCT.pack(
        MAGIC,
        FORMAT_VERSION,
        MAX_HEADER_SIZE + 1,
    )

    with pytest.raises(ContainerFormatError):
        parse_header(prefix)


def test_duplicate_json_keys_are_rejected():
    body = b'{"container_id":"a","container_id":"b"}'

    with pytest.raises(ContainerFormatError):
        parse_header(pack_body(body))


def test_noncanonical_json_is_rejected():
    body = json.dumps(
        make_header(),
        sort_keys=True,
        indent=2,
    ).encode("utf-8")

    with pytest.raises(ContainerFormatError):
        parse_header(pack_body(body))


def test_unknown_header_field_is_rejected():
    header = make_header()
    header["unexpected"] = "value"

    with pytest.raises(ContainerFormatError):
        serialize_header(header)


def test_invalid_nonce_prefix_is_rejected():
    header = make_header()
    header["nonce_prefix"] = "1234"

    with pytest.raises(ContainerFormatError):
        serialize_header(header)


def test_invalid_fido_rp_id_is_rejected():
    header = make_header()
    header["key_slots"][0]["rp_id"] = "attacker.example"

    with pytest.raises(ContainerFormatError):
        serialize_header(header)


def test_duplicate_key_slot_ids_are_rejected():
    header = make_header()
    header["key_slots"][1]["id"] = header["key_slots"][0]["id"]

    with pytest.raises(ContainerFormatError):
        serialize_header(header)


def test_boolean_chunk_size_is_rejected():
    header = make_header()
    header["chunk_size"] = True

    with pytest.raises(ContainerFormatError):
        serialize_header(header)