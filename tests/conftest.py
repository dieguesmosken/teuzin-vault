"""Isolated temporary directories for Teuzin Vault tests."""

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator

import pytest


# TEUZIN_VAULT_CUSTOM_TMP_PATH
@pytest.fixture
def tmp_path() -> Iterator[Path]:
    """Provide a temporary directory without pytest symlink management."""
    with TemporaryDirectory(prefix="teuzin-vault-test-") as directory:
        yield Path(directory)
