import secrets

import pytest

from teuzin_vault.core.container_format import (
    ALGORITHMS,
    CHUNK_SIZE,
    parse_header,
    serialize_header,
)
from teuzin_vault.core.file_operations import (
    FileOperationError,
    create_container_file,
    migrate_container_file,
    restore_container_file,
)
from teuzin_vault.core.key_protection import (
    generate_recovery_secret,
    protect_dek,
)


def make_material():
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

    return parsed, dek, slots, fido_secret, recovery_secret


def no_temp_files(directory):
    return list(directory.glob(".teuzin-vault-*.partial"))


def test_file_creation_and_restoration(tmp_path):
    original = b"Teuzin Vault file test. " * 5000
    source = tmp_path / "original.bin"
    container = tmp_path / "backup.tvault"
    restored = tmp_path / "restored.bin"

    source.write_bytes(original)

    parsed, dek, slots, _, recovery = make_material()

    write_result = create_container_file(
        source,
        container,
        parsed,
        slots,
        dek,
    )

    read_result = restore_container_file(
        container,
        restored,
        max_output_size=len(original),
        recovery_secret=recovery,
    )

    assert restored.read_bytes() == original
    assert container.is_file()
    assert write_result.original_bytes == len(original)
    assert read_result.original_bytes == len(original)
    assert no_temp_files(tmp_path) == []


def test_creation_refuses_existing_destination(tmp_path):
    source = tmp_path / "source.bin"
    destination = tmp_path / "existing.tvault"

    source.write_bytes(b"new data")
    destination.write_bytes(b"preserve me")

    parsed, dek, slots, _, _ = make_material()

    with pytest.raises(FileExistsError):
        create_container_file(
            source,
            destination,
            parsed,
            slots,
            dek,
        )

    assert destination.read_bytes() == b"preserve me"
    assert no_temp_files(tmp_path) == []


def test_restoration_refuses_existing_destination(tmp_path):
    source = tmp_path / "source.bin"
    container = tmp_path / "backup.tvault"
    destination = tmp_path / "existing.bin"

    original = b"important data"
    source.write_bytes(original)
    destination.write_bytes(b"preserve me")

    parsed, dek, slots, _, recovery = make_material()

    create_container_file(
        source,
        container,
        parsed,
        slots,
        dek,
    )

    with pytest.raises(FileExistsError):
        restore_container_file(
            container,
            destination,
            max_output_size=len(original),
            recovery_secret=recovery,
        )

    assert destination.read_bytes() == b"preserve me"


def test_explicit_overwrite_replaces_destination(tmp_path):
    source = tmp_path / "source.bin"
    container = tmp_path / "backup.tvault"
    destination = tmp_path / "restored.bin"

    original = b"replacement test"
    source.write_bytes(original)
    destination.write_bytes(b"old data")

    parsed, dek, slots, _, recovery = make_material()

    create_container_file(
        source,
        container,
        parsed,
        slots,
        dek,
    )

    restore_container_file(
        container,
        destination,
        max_output_size=len(original),
        recovery_secret=recovery,
        overwrite=True,
    )

    assert destination.read_bytes() == original


def test_failed_restore_preserves_existing_destination(tmp_path):
    source = tmp_path / "source.bin"
    container = tmp_path / "backup.tvault"
    corrupted = tmp_path / "corrupted.tvault"
    destination = tmp_path / "restored.bin"

    source.write_bytes(b"important data" * 100)
    destination.write_bytes(b"old safe content")

    parsed, dek, slots, _, recovery = make_material()

    create_container_file(
        source,
        container,
        parsed,
        slots,
        dek,
    )

    damaged = bytearray(container.read_bytes())
    damaged[-1] ^= 1
    corrupted.write_bytes(damaged)

    with pytest.raises(ValueError):
        restore_container_file(
            corrupted,
            destination,
            max_output_size=100000,
            recovery_secret=recovery,
            overwrite=True,
        )

    assert destination.read_bytes() == b"old safe content"
    assert no_temp_files(tmp_path) == []


def test_source_and_destination_cannot_be_same_file(tmp_path):
    source = tmp_path / "same.bin"
    source.write_bytes(b"data")

    parsed, dek, slots, _, _ = make_material()

    with pytest.raises(FileOperationError):
        create_container_file(
            source,
            source,
            parsed,
            slots,
            dek,
        )

    assert source.read_bytes() == b"data"


def test_failed_creation_cleans_temporary_file(tmp_path):
    source = tmp_path / "source.bin"
    destination = tmp_path / "backup.tvault"

    source.write_bytes(b"data")

    parsed, _, slots, _, _ = make_material()

    with pytest.raises(ValueError):
        create_container_file(
            source,
            destination,
            parsed,
            slots,
            b"invalid",
        )

    assert not destination.exists()
    assert no_temp_files(tmp_path) == []


def test_restore_requires_exactly_one_unlocking_method(tmp_path):
    source = tmp_path / "source.bin"
    container = tmp_path / "backup.tvault"
    destination = tmp_path / "restored.bin"

    source.write_bytes(b"data")

    parsed, dek, slots, _, recovery = make_material()

    create_container_file(
        source,
        container,
        parsed,
        slots,
        dek,
    )

    with pytest.raises(FileOperationError):
        restore_container_file(
            container,
            destination,
            max_output_size=100,
        )

    with pytest.raises(FileOperationError):
        restore_container_file(
            container,
            destination,
            max_output_size=100,
            fido2_hmac_secret=b"A" * 32,
            recovery_secret=recovery,
        )

    assert not destination.exists()
    assert no_temp_files(tmp_path) == []


def test_file_migration_publishes_new_copy_and_preserves_original(tmp_path):
    original = b"transactional UV migration test. " * 3000
    source = tmp_path / "legacy.tvault"
    destination = tmp_path / "migrated.tvault"
    restored_fido = tmp_path / "restored-fido.bin"
    restored_recovery = tmp_path / "restored-recovery.bin"
    plain = tmp_path / "plain.bin"
    plain.write_bytes(original)

    parsed, dek, slots, old_fido_secret, recovery_secret = make_material()
    create_container_file(plain, source, parsed, slots, dek)
    source_before = source.read_bytes()
    new_fido_secret = b"V" * 32

    result = migrate_container_file(
        source,
        destination,
        recovery_secret=recovery_secret,
        fido2_hmac_secret=new_fido_secret,
    )

    assert source.read_bytes() == source_before
    assert destination.is_file()
    assert result.container_bytes == destination.stat().st_size

    restore_container_file(
        destination,
        restored_fido,
        max_output_size=len(original),
        fido2_hmac_secret=new_fido_secret,
    )
    restore_container_file(
        destination,
        restored_recovery,
        max_output_size=len(original),
        recovery_secret=recovery_secret,
    )
    assert restored_fido.read_bytes() == original
    assert restored_recovery.read_bytes() == original

    with pytest.raises(ValueError):
        restore_container_file(
            destination,
            tmp_path / "old-key-restore.bin",
            max_output_size=len(original),
            fido2_hmac_secret=old_fido_secret,
        )
    assert no_temp_files(tmp_path) == []


def test_failed_file_migration_does_not_publish_destination(tmp_path):
    plain = tmp_path / "plain.bin"
    source = tmp_path / "damaged.tvault"
    destination = tmp_path / "should-not-exist.tvault"
    plain.write_bytes(b"migration tamper test" * 500)

    parsed, dek, slots, _, recovery_secret = make_material()
    create_container_file(plain, source, parsed, slots, dek)
    damaged = bytearray(source.read_bytes())
    damaged[-1] ^= 1
    source.write_bytes(damaged)

    with pytest.raises(ValueError):
        migrate_container_file(
            source,
            destination,
            recovery_secret=recovery_secret,
            fido2_hmac_secret=b"V" * 32,
        )

    assert not destination.exists()
    assert no_temp_files(tmp_path) == []
