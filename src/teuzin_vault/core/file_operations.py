"""Transactional file operations for TVLT V1."""

from __future__ import annotations

import os
import tempfile

from pathlib import Path
from typing import Callable, TypeVar

from teuzin_vault.core.container_format import ParsedHeader
from teuzin_vault.core.container_stream import (
    ContainerMigrationResult,
    ContainerReadResult,
    ContainerWriteResult,
    migrate_container_stream,
    restore_container_stream,
    write_container_stream,
)


T = TypeVar("T")


class FileOperationError(RuntimeError):
    """A file operation could not be completed safely."""


class TemporaryFileCleanupError(FileOperationError):
    """A temporary file could not be removed after failure."""


def _validate_paths(
    source_path: str | Path,
    destination_path: str | Path,
    overwrite: bool,
) -> tuple[Path, Path]:
    if type(overwrite) is not bool:
        raise TypeError("overwrite must be a boolean.")

    source = Path(source_path)
    destination = Path(destination_path)

    if source.is_symlink():
        raise FileOperationError(
            "Symbolic-link sources are not supported."
        )

    if not source.is_file():
        raise FileNotFoundError(
            f"Source file does not exist or is not a regular file: {source}"
        )

    if not destination.parent.is_dir():
        raise FileNotFoundError(
            "Destination directory does not exist."
        )

    if destination.is_symlink():
        raise FileOperationError(
            "Symbolic-link destinations are not supported."
        )

    source_identity = os.path.normcase(
        str(source.resolve(strict=True))
    )
    destination_identity = os.path.normcase(
        str(destination.resolve(strict=False))
    )

    if source_identity == destination_identity:
        raise FileOperationError(
            "Source and destination must be different files."
        )

    if destination.exists() and destination.is_dir():
        raise IsADirectoryError(destination)

    if os.path.lexists(destination) and not overwrite:
        raise FileExistsError(destination)

    return source, destination


def _publish(
    temporary: Path,
    destination: Path,
    overwrite: bool,
) -> None:
    """Atomically publish a complete temporary file."""
    if overwrite:
        os.replace(temporary, destination)
        return

    if os.name == "nt":
        # Windows os.rename does not replace an existing destination.
        os.rename(temporary, destination)
        return

    # On POSIX, hard-link creation fails atomically if the target exists.
    # Both paths are in the same directory/filesystem.
    os.link(temporary, destination)
    os.unlink(temporary)


def _run_with_temporary_file(
    destination: Path,
    overwrite: bool,
    operation: Callable[[object], T],
) -> T:
    """Write to a same-directory temporary file before publication."""
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".teuzin-vault-",
        suffix=".partial",
        dir=str(destination.parent),
    )

    temporary = Path(temporary_name)

    try:
        with os.fdopen(descriptor, "wb") as output:
            result = operation(output)
            output.flush()
            os.fsync(output.fileno())

        _publish(temporary, destination, overwrite)

        return result

    finally:
        if os.path.lexists(temporary):
            try:
                temporary.unlink()
            except OSError as exc:
                raise TemporaryFileCleanupError(
                    f"Could not remove temporary file: {temporary}"
                ) from exc


def _source_snapshot(source) -> tuple[int, int, int]:
    stat = os.fstat(source.fileno())

    return (
        stat.st_size,
        stat.st_mtime_ns,
        stat.st_ctime_ns,
    )


def create_container_file(
    source_path: str | Path,
    destination_path: str | Path,
    parsed_header: ParsedHeader,
    slot_records: bytes,
    dek: bytes,
    *,
    overwrite: bool = False,
) -> ContainerWriteResult:
    """Create a TVLT container without publishing partial output.

    Source files must not be modified during the operation.
    Existing destinations are preserved unless overwrite=True.
    """
    source, destination = _validate_paths(
        source_path,
        destination_path,
        overwrite,
    )

    with source.open("rb") as input_file:
        before = _source_snapshot(input_file)

        def write_operation(output):
            result = write_container_stream(
                input_file,
                output,
                parsed_header,
                slot_records,
                dek,
            )

            after = _source_snapshot(input_file)

            if after != before:
                raise FileOperationError(
                    "Source file changed during container creation."
                )

            return result

        return _run_with_temporary_file(
            destination,
            overwrite,
            write_operation,
        )


def restore_container_file(
    source_path: str | Path,
    destination_path: str | Path,
    *,
    max_output_size: int,
    fido2_hmac_secret: bytes | None = None,
    recovery_secret: bytes | None = None,
    overwrite: bool = False,
) -> ContainerReadResult:
    """Restore a TVLT container without publishing partial plaintext.

    Exactly one unlocking mechanism must be supplied.

    A failed restoration discards its temporary output. This does
    not guarantee secure erasure on SSDs or journaling filesystems.
    """
    if (fido2_hmac_secret is None) == (recovery_secret is None):
        raise FileOperationError(
            "Supply exactly one unlocking mechanism."
        )

    source, destination = _validate_paths(
        source_path,
        destination_path,
        overwrite,
    )

    with source.open("rb") as input_file:
        before = _source_snapshot(input_file)

        def restore_operation(output):
            result = restore_container_stream(
                input_file,
                output,
                max_output_size=max_output_size,
                fido2_hmac_secret=fido2_hmac_secret,
                recovery_secret=recovery_secret,
            )

            after = _source_snapshot(input_file)

            if after != before:
                raise FileOperationError(
                    "Container file changed during restoration."
                )

            return result

        return _run_with_temporary_file(
            destination,
            overwrite,
            restore_operation,
        )


def migrate_container_file(
    source_path: str | Path,
    destination_path: str | Path,
    *,
    recovery_secret: bytes,
    fido2_hmac_secret: bytes,
    overwrite: bool = False,
) -> ContainerMigrationResult:
    """Create a migrated copy without modifying the source container.

    The destination is published atomically only after all records have
    authenticated and both replacement key slots have been verified.
    """
    source, destination = _validate_paths(
        source_path,
        destination_path,
        overwrite,
    )

    with source.open("rb") as input_file:
        before = _source_snapshot(input_file)

        def migrate_operation(output):
            result = migrate_container_stream(
                input_file,
                output,
                recovery_secret=recovery_secret,
                fido2_hmac_secret=fido2_hmac_secret,
            )

            after = _source_snapshot(input_file)
            if after != before:
                raise FileOperationError(
                    "Container file changed during migration."
                )
            return result

        return _run_with_temporary_file(
            destination,
            overwrite,
            migrate_operation,
        )
