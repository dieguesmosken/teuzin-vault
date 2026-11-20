import base64
import secrets

import pytest

from teuzin_vault.core.container_format import (
    ALGORITHMS,
    CHUNK_SIZE,
    parse_header,
    serialize_header,
)
from teuzin_vault.ui.restore_support import (
    decode_recovery_secret,
    fido2_authentication_material,
    read_container_header,
)


def make_header():
    fido = {
        "id": "1" * 32,
        "type": "fido2-hmac-secret",
        "rp_id": "vault.teuzin.com.br",
        "credential_id": base64.urlsafe_b64encode(b"credential-id").decode("ascii").rstrip("="),
        "hmac_salt": secrets.token_hex(32),
        "kdf_salt": secrets.token_hex(32),
    }
    recovery = {
        "id": "2" * 32,
        "type": "recovery",
        "kdf_salt": secrets.token_hex(32),
    }
    return {
        "container_id": secrets.token_hex(16),
        "algorithms": dict(ALGORITHMS),
        "chunk_size": CHUNK_SIZE,
        "nonce_prefix": secrets.token_hex(4),
        "key_slots": [fido, recovery],
    }


def test_read_container_header_reads_only_header(tmp_path):
    header_bytes = serialize_header(make_header())
    path = tmp_path / "sample.tvault"
    path.write_bytes(header_bytes + b"following encrypted records")

    parsed = read_container_header(path)

    assert parsed.header["container_id"]
    assert parsed.consumed == len(header_bytes)


def test_fido2_material_is_extracted_from_header():
    parsed = parse_header(serialize_header(make_header()))

    salt, credential_id = fido2_authentication_material(parsed)

    assert len(salt) == 32
    assert credential_id == b"credential-id"


def test_recovery_secret_requires_32_bytes_hex():
    expected = bytes(range(32))

    assert decode_recovery_secret(expected.hex()) == expected
    assert decode_recovery_secret("  " + expected.hex() + "  ") == expected


@pytest.mark.parametrize("value", ["", "abcd", "z" * 64, "a" * 63, "a" * 66])
def test_invalid_recovery_secret_is_rejected(value):
    with pytest.raises(ValueError):
        decode_recovery_secret(value)


def test_truncated_container_header_is_rejected(tmp_path):
    path = tmp_path / "truncated.tvault"
    path.write_bytes(b"TVLT")

    with pytest.raises(ValueError):
        read_container_header(path)
