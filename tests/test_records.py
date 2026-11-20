import secrets
from dataclasses import replace

import pytest

from teuzin_vault.core.container_format import (
    ALGORITHMS,
    CHUNK_SIZE,
    parse_header,
    serialize_header,
)
from teuzin_vault.core.records import (
    DATA_RECORD_TYPE,
    FINAL_RECORD_TYPE,
    RecordAuthenticationError,
    RecordFormatError,
    RecordReader,
    RecordStateError,
    RecordWriter,
    RECORD_HEADER,
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
def setup_records():
    dek = secrets.token_bytes(32)
    header = make_header()

    writer = RecordWriter(dek, header)
    first = writer.write_data(b"A" * 100)
    second = writer.write_data(b"B" * 200)
    final = writer.finish(500)

    return dek, header, first, second, final


def test_record_round_trip(setup_records):
    dek, header, first, second, final = setup_records
    reader = RecordReader(dek, header)

    decoded_first = reader.read_data(first + second)
    decoded_second = reader.read_data(second + final)
    decoded_final = reader.read_final(final)

    assert decoded_first.plaintext == b"A" * 100
    assert decoded_second.plaintext == b"B" * 200
    assert decoded_final.data_record_count == 2
    assert decoded_final.compressed_bytes == 300
    assert decoded_final.original_bytes == 500


def test_record_header_contains_expected_type(setup_records):
    _, _, first, _, final = setup_records

    assert RECORD_HEADER.unpack(first[:RECORD_HEADER.size])[0] == DATA_RECORD_TYPE
    assert RECORD_HEADER.unpack(final[:RECORD_HEADER.size])[0] == FINAL_RECORD_TYPE


def test_sequences_increase_monotonically(setup_records):
    _, _, first, second, final = setup_records

    assert RECORD_HEADER.unpack(first[:RECORD_HEADER.size])[1] == 0
    assert RECORD_HEADER.unpack(second[:RECORD_HEADER.size])[1] == 1
    assert RECORD_HEADER.unpack(final[:RECORD_HEADER.size])[1] == 2


def test_each_record_has_distinct_ciphertext(setup_records):
    dek, header, _, _, _ = setup_records

    writer = RecordWriter(dek, header)
    first = writer.write_data(b"same content")
    second = writer.write_data(b"same content")

    assert first != second


def test_maximum_chunk_size_is_accepted():
    dek = secrets.token_bytes(32)
    writer = RecordWriter(dek, make_header())

    record = writer.write_data(b"A" * CHUNK_SIZE)

    assert len(record) == RECORD_HEADER.size + CHUNK_SIZE + 16


def test_empty_data_record_is_rejected():
    writer = RecordWriter(secrets.token_bytes(32), make_header())

    with pytest.raises(RecordFormatError):
        writer.write_data(b"")


def test_oversized_data_record_is_rejected():
    writer = RecordWriter(secrets.token_bytes(32), make_header())

    with pytest.raises(RecordFormatError):
        writer.write_data(b"A" * (CHUNK_SIZE + 1))


def test_wrong_key_fails_authentication(setup_records):
    _, header, first, _, _ = setup_records
    reader = RecordReader(secrets.token_bytes(32), header)

    with pytest.raises(RecordAuthenticationError):
        reader.read_data(first)


def test_modified_ciphertext_fails_authentication(setup_records):
    dek, header, first, _, _ = setup_records
    modified = bytearray(first)
    modified[-1] ^= 1

    reader = RecordReader(dek, header)

    with pytest.raises(RecordAuthenticationError):
        reader.read_data(bytes(modified))


def test_modified_header_digest_fails_authentication(setup_records):
    dek, header, first, _, _ = setup_records
    modified_header = replace(header, digest=b"\x00" * 32)

    reader = RecordReader(dek, modified_header)

    with pytest.raises(RecordAuthenticationError):
        reader.read_data(first)


def test_out_of_order_records_are_rejected(setup_records):
    dek, header, _, second, _ = setup_records
    reader = RecordReader(dek, header)

    with pytest.raises(RecordFormatError):
        reader.read_data(second)


def test_truncated_record_header_is_rejected():
    reader = RecordReader(secrets.token_bytes(32), make_header())

    with pytest.raises(RecordFormatError):
        reader.read_data(b"\x01\x00")


def test_truncated_record_payload_is_rejected(setup_records):
    dek, header, first, _, _ = setup_records
    reader = RecordReader(dek, header)

    with pytest.raises(RecordFormatError):
        reader.read_data(first[:-1])


def test_unknown_record_type_is_rejected(setup_records):
    dek, header, first, _, _ = setup_records
    modified = bytes([0x77]) + first[1:]

    reader = RecordReader(dek, header)

    with pytest.raises(RecordFormatError):
        reader.read_data(modified)


def test_final_record_rejects_trailing_data(setup_records):
    dek, header, first, _, final = setup_records
    reader = RecordReader(dek, header)
    reader.read_data(first)

    with pytest.raises(RecordFormatError):
        reader.read_final(final + b"EXTRA")


def test_final_record_is_required(setup_records):
    dek, header, first, _, _ = setup_records
    reader = RecordReader(dek, header)
    reader.read_data(first)

    assert reader._finalized is False


def test_final_record_tampering_is_rejected(setup_records):
    dek, header, first, second, final = setup_records
    modified = bytearray(final)
    modified[-1] ^= 1

    reader = RecordReader(dek, header)
    reader.read_data(first)
    reader.read_data(second)

    with pytest.raises(RecordAuthenticationError):
        reader.read_final(bytes(modified))


def test_writer_cannot_finish_without_data():
    writer = RecordWriter(secrets.token_bytes(32), make_header())

    with pytest.raises(RecordFormatError):
        writer.finish(0)


def test_writer_cannot_be_finalized_twice(setup_records):
    dek, header, _, _, _ = setup_records
    writer = RecordWriter(dek, header)
    writer.write_data(b"data")
    writer.finish(4)

    with pytest.raises(RecordStateError):
        writer.finish(4)


def test_writer_cannot_write_after_finalization(setup_records):
    dek, header, _, _, _ = setup_records
    writer = RecordWriter(dek, header)
    writer.write_data(b"data")
    writer.finish(4)

    with pytest.raises(RecordStateError):
        writer.write_data(b"more")


def test_reader_cannot_read_after_finalization(setup_records):
    dek, header, first, second, final = setup_records
    reader = RecordReader(dek, header)
    reader.read_data(first)
    reader.read_data(second)
    reader.read_final(final)

    with pytest.raises(RecordStateError):
        reader.read_data(first)


def test_invalid_original_size_is_rejected():
    writer = RecordWriter(secrets.token_bytes(32), make_header())
    writer.write_data(b"data")

    with pytest.raises(RecordFormatError):
        writer.finish(True)