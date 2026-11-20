from io import BytesIO
import secrets

import pytest

from teuzin_vault.core.container_format import (
    ALGORITHMS,
    CHUNK_SIZE,
    parse_header,
    serialize_header,
)
from teuzin_vault.core.container_stream import (
    ContainerStreamError,
    migrate_container_stream,
    restore_container_stream,
    write_container_stream,
)
from teuzin_vault.core.key_protection import (
    generate_recovery_secret,
    protect_dek,
)
from teuzin_vault.core.records import RECORD_HEADER


def make_setup(original):
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
        "container_id": secrets.token_hex(16),
        "algorithms": dict(ALGORITHMS),
        "chunk_size": CHUNK_SIZE,
        "nonce_prefix": secrets.token_hex(4),
        "key_slots": [fido, recovery],
    }

    parsed = parse_header(serialize_header(header))

    dek = secrets.token_bytes(32)
    fido_secret = secrets.token_bytes(32)
    recovery_secret = generate_recovery_secret()

    slots = protect_dek(
        dek,
        parsed,
        fido2_hmac_secret=fido_secret,
        recovery_secret=recovery_secret,
    )

    output = BytesIO()

    write_result = write_container_stream(
        BytesIO(original),
        output,
        parsed,
        slots,
        dek,
    )

    return {
        "original": original,
        "container": output.getvalue(),
        "dek": dek,
        "fido_secret": fido_secret,
        "recovery_secret": recovery_secret,
        "write_result": write_result,
        "header_size": len(serialize_header(header)),
        "slot_size": len(slots),
    }


def test_complete_round_trip_with_recovery():
    original = b"Teuzin Vault integrated test. " * 5000
    setup = make_setup(original)

    restored = BytesIO()

    result = restore_container_stream(
        BytesIO(setup["container"]),
        restored,
        max_output_size=len(original),
        recovery_secret=setup["recovery_secret"],
    )

    assert restored.getvalue() == original
    assert result.original_bytes == len(original)
    assert result.data_record_count >= 1


def test_complete_round_trip_with_fido2():
    original = b"Test with FIDO2 unlocking."
    setup = make_setup(original)

    restored = BytesIO()

    result = restore_container_stream(
        BytesIO(setup["container"]),
        restored,
        max_output_size=len(original),
        fido2_hmac_secret=setup["fido_secret"],
    )

    assert restored.getvalue() == original
    assert result.original_bytes == len(original)


def test_empty_file_round_trip():
    original = b""
    setup = make_setup(original)

    restored = BytesIO()

    result = restore_container_stream(
        BytesIO(setup["container"]),
        restored,
        max_output_size=0,
        recovery_secret=setup["recovery_secret"],
    )

    assert restored.getvalue() == b""
    assert result.original_bytes == 0


def test_large_file_round_trip():
    original = secrets.token_bytes(CHUNK_SIZE * 2 + 123)
    setup = make_setup(original)

    restored = BytesIO()

    result = restore_container_stream(
        BytesIO(setup["container"]),
        restored,
        max_output_size=len(original),
        recovery_secret=setup["recovery_secret"],
    )

    assert restored.getvalue() == original
    assert result.original_bytes == len(original)


def test_wrong_recovery_secret_is_rejected():
    setup = make_setup(b"secret data")

    with pytest.raises(ValueError):
        restore_container_stream(
            BytesIO(setup["container"]),
            BytesIO(),
            max_output_size=100,
            recovery_secret=secrets.token_bytes(32),
        )


def test_wrong_fido2_secret_is_rejected():
    setup = make_setup(b"secret data")

    with pytest.raises(ValueError):
        restore_container_stream(
            BytesIO(setup["container"]),
            BytesIO(),
            max_output_size=100,
            fido2_hmac_secret=secrets.token_bytes(32),
        )


def test_both_unlocking_methods_at_once_are_rejected():
    setup = make_setup(b"secret data")

    with pytest.raises(ContainerStreamError):
        restore_container_stream(
            BytesIO(setup["container"]),
            BytesIO(),
            max_output_size=100,
            fido2_hmac_secret=setup["fido_secret"],
            recovery_secret=setup["recovery_secret"],
        )


def test_no_unlocking_method_is_rejected():
    setup = make_setup(b"secret data")

    with pytest.raises(ContainerStreamError):
        restore_container_stream(
            BytesIO(setup["container"]),
            BytesIO(),
            max_output_size=100,
        )


def test_decompression_limit_is_enforced():
    original = b"A" * 100000
    setup = make_setup(original)

    with pytest.raises(ValueError):
        restore_container_stream(
            BytesIO(setup["container"]),
            BytesIO(),
            max_output_size=100,
            recovery_secret=setup["recovery_secret"],
        )


def test_tampered_data_record_is_rejected():
    setup = make_setup(b"important data" * 100)

    damaged = bytearray(setup["container"])
    offset = setup["header_size"] + setup["slot_size"] + RECORD_HEADER.size
    damaged[offset] ^= 1

    with pytest.raises(ValueError):
        restore_container_stream(
            BytesIO(bytes(damaged)),
            BytesIO(),
            max_output_size=len(setup["original"]),
            recovery_secret=setup["recovery_secret"],
        )


def test_truncated_container_is_rejected():
    setup = make_setup(b"important data")

    with pytest.raises(ValueError):
        restore_container_stream(
            BytesIO(setup["container"][:-1]),
            BytesIO(),
            max_output_size=1000,
            recovery_secret=setup["recovery_secret"],
        )


def test_trailing_bytes_are_rejected():
    setup = make_setup(b"important data")

    with pytest.raises(ContainerStreamError):
        restore_container_stream(
            BytesIO(setup["container"] + b"EXTRA"),
            BytesIO(),
            max_output_size=1000,
            recovery_secret=setup["recovery_secret"],
        )


def test_write_result_matches_actual_container_size():
    original = b"size verification" * 1000
    setup = make_setup(original)

    assert setup["write_result"].container_bytes == len(
        setup["container"]
    )

    assert setup["write_result"].original_bytes == len(original)


def test_partial_output_writer_is_supported():
    class PartialWriter(BytesIO):
        def write(self, data):
            part = bytes(data[:max(1, len(data) // 2)])
            return super().write(part)

    original = b"partial output stream test" * 100
    setup = make_setup(original)
    destination = PartialWriter()

    restore_container_stream(
        BytesIO(setup["container"]),
        destination,
        max_output_size=len(original),
        recovery_secret=setup["recovery_secret"],
    )

    assert destination.getvalue() == original


def test_migration_preserves_header_recovery_slot_and_encrypted_records():
    original = b"migration preserves encrypted payload bytes. " * 4000
    setup = make_setup(original)
    new_secret = b"U" * 32
    migrated_output = BytesIO()

    result = migrate_container_stream(
        BytesIO(setup["container"]),
        migrated_output,
        recovery_secret=setup["recovery_secret"],
        fido2_hmac_secret=new_secret,
    )
    migrated = migrated_output.getvalue()
    boundary = setup["header_size"] + setup["slot_size"]
    # The fixture sorts FIDO2 id 11.. before recovery id 22..; each slot is 76 bytes.
    recovery_start = setup["header_size"] + 76

    assert migrated[:setup["header_size"]] == setup["container"][:setup["header_size"]]
    assert migrated[recovery_start:recovery_start + 76] == setup["container"][recovery_start:recovery_start + 76]
    assert migrated[boundary:] == setup["container"][boundary:]
    assert result.container_bytes == len(migrated)
    assert result.original_bytes == len(original)

    for kwargs in (
        {"fido2_hmac_secret": new_secret},
        {"recovery_secret": setup["recovery_secret"]},
    ):
        restored = BytesIO()
        restore_container_stream(
            BytesIO(migrated),
            restored,
            max_output_size=len(original),
            **kwargs,
        )
        assert restored.getvalue() == original

    with pytest.raises(ValueError):
        restore_container_stream(
            BytesIO(migrated),
            BytesIO(),
            max_output_size=len(original),
            fido2_hmac_secret=setup["fido_secret"],
        )


def test_migration_rejects_tampered_final_record():
    setup = make_setup(b"tamper detection during migration" * 100)
    damaged = bytearray(setup["container"])
    damaged[-1] ^= 1

    with pytest.raises(ValueError):
        migrate_container_stream(
            BytesIO(bytes(damaged)),
            BytesIO(),
            recovery_secret=setup["recovery_secret"],
            fido2_hmac_secret=b"U" * 32,
        )
