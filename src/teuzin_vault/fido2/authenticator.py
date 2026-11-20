"""Windows FIDO2 HMAC-secret adapter for Teuzin Vault."""

from __future__ import annotations

import base64
import hmac
import json
import os

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fido2.webauthn import AttestedCredentialData


RP_ID = "vault.teuzin.com.br"
ORIGIN = "https://vault.teuzin.com.br"

METADATA_FORMAT = 1
MAX_METADATA_SIZE = 16 * 1024
MAX_CREDENTIAL_SIZE = 4096
MAX_CREDENTIAL_ID_SIZE = 1023
HMAC_SECRET_SIZE = 32
DEFAULT_TIMEOUT_MS = 60_000


class CredentialMetadataError(ValueError):
    """Stored credential metadata is invalid."""


class Fido2AuthenticationError(RuntimeError):
    """FIDO2 authentication or HMAC-secret retrieval failed."""


@dataclass(frozen=True)
class StoredCredential:
    name: str
    rp_id: str
    credential: AttestedCredentialData


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result = {}

    for key, value in pairs:
        if key in result:
            raise CredentialMetadataError(
                "Duplicate metadata field."
            )

        result[key] = value

    return result


def _decode_credential_data(value: Any) -> bytes:
    if not isinstance(value, str):
        raise CredentialMetadataError(
            "Credential data must be a Base64 string."
        )

    if not value or len(value) > 8192:
        raise CredentialMetadataError(
            "Credential data length is invalid."
        )

    try:
        raw = base64.b64decode(
            value,
            altchars=b"-_",
            validate=True,
        )
    except Exception as exc:
        raise CredentialMetadataError(
            "Credential data is not valid Base64."
        ) from exc

    standard = base64.b64encode(raw).decode("ascii")
    urlsafe = base64.urlsafe_b64encode(raw).decode("ascii")

    if value not in {standard, urlsafe}:
        raise CredentialMetadataError(
            "Credential data is not canonically encoded."
        )

    if not 1 <= len(raw) <= MAX_CREDENTIAL_SIZE:
        raise CredentialMetadataError(
            "Credential data exceeds its size limit."
        )

    return raw


def load_credential_metadata(
    metadata_path: str | Path,
) -> StoredCredential:
    """Load and validate previously registered public credential data.

    No credential is created, modified or deleted.
    """
    path = Path(metadata_path)

    if path.is_symlink():
        raise CredentialMetadataError(
            "Credential metadata cannot be a symbolic link."
        )

    if not path.is_file():
        raise FileNotFoundError(
            "Stored FIDO2 credential metadata was not found."
        )

    try:
        with path.open("rb") as source:
            raw_json = source.read(MAX_METADATA_SIZE + 1)
    except OSError as exc:
        raise CredentialMetadataError(
            "Could not read credential metadata."
        ) from exc

    if len(raw_json) > MAX_METADATA_SIZE:
        raise CredentialMetadataError(
            "Credential metadata exceeds its size limit."
        )

    try:
        metadata = json.loads(
            raw_json.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (
                (_ for _ in ()).throw(
                    CredentialMetadataError(
                        "Invalid JSON constant."
                    )
                )
            ),
        )
    except CredentialMetadataError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CredentialMetadataError(
            "Credential metadata JSON is invalid."
        ) from exc

    if type(metadata) is not dict:
        raise CredentialMetadataError(
            "Credential metadata must be a JSON object."
        )

    expected_fields = {
        "format",
        "rp_id",
        "name",
        "credential_data",
    }

    if set(metadata) != expected_fields:
        raise CredentialMetadataError(
            "Unexpected credential metadata fields."
        )

    if (
        type(metadata["format"]) is not int
        or metadata["format"] != METADATA_FORMAT
    ):
        raise CredentialMetadataError(
            "Unsupported credential metadata version."
        )

    if metadata["rp_id"] != RP_ID:
        raise CredentialMetadataError(
            "Credential RP ID does not match Teuzin Vault."
        )

    name = metadata["name"]

    if (
        not isinstance(name, str)
        or not name.strip()
        or len(name) > 64
    ):
        raise CredentialMetadataError(
            "Invalid credential name."
        )

    credential_bytes = _decode_credential_data(
        metadata["credential_data"]
    )

    try:
        credential = AttestedCredentialData(
            credential_bytes
        )
    except Exception as exc:
        raise CredentialMetadataError(
            "Stored credential structure is invalid."
        ) from exc

    credential_id = credential.credential_id

    if not (
        isinstance(credential_id, bytes)
        and 1 <= len(credential_id) <= MAX_CREDENTIAL_ID_SIZE
    ):
        raise CredentialMetadataError(
            "Invalid credential identifier."
        )

    if credential.public_key is None:
        raise CredentialMetadataError(
            "Credential public key is missing."
        )

    return StoredCredential(
        name=name,
        rp_id=RP_ID,
        credential=credential,
    )


def _create_windows_client(rp_id: str):
    """Create a Windows WebAuthn client with HMAC-secret enabled."""
    if os.name != "nt":
        raise Fido2AuthenticationError(
            "The initial authenticator adapter supports Windows only."
        )

    try:
        from fido2.client import DefaultClientDataCollector
        from fido2.client.windows import WindowsClient
    except ImportError as exc:
        raise Fido2AuthenticationError(
            "Windows WebAuthn support is unavailable."
        ) from exc

    if not WindowsClient.is_available():
        raise Fido2AuthenticationError(
            "Windows WebAuthn API is unavailable."
        )

    collector = DefaultClientDataCollector(
        f"https://{rp_id}"
    )

    return WindowsClient(
        collector,
        allow_hmac_secret=True,
    )


def _create_server(rp_id: str):
    from fido2.server import Fido2Server

    return Fido2Server(
        {
            "id": rp_id,
            "name": "Teuzin Vault",
        },
        attestation="none",
    )


def get_hmac_secret(
    metadata_path: str | Path,
    salt: bytes,
    *,
    expected_credential_id: bytes,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> bytes:
    """Authenticate an existing FIDO2 credential and obtain HMAC-secret.

    The secret is returned only in memory. This function never
    prints or writes the HMAC-secret to disk.

    The supplied salt must be the exact 32-byte HMAC salt stored
    in the selected TVLT key-slot descriptor.
    """
    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes.")

    if len(salt) != HMAC_SECRET_SIZE:
        raise ValueError(
            "FIDO2 HMAC salt must contain exactly 32 bytes."
        )

    if (
        type(timeout_ms) is not int
        or not 1_000 <= timeout_ms <= 120_000
    ):
        raise ValueError("Invalid FIDO2 timeout.")

    if not isinstance(expected_credential_id, bytes):
        raise TypeError("expected_credential_id must be bytes.")

    if not 1 <= len(expected_credential_id) <= MAX_CREDENTIAL_ID_SIZE:
        raise CredentialMetadataError(
            "Expected credential identifier has an invalid length."
        )

    stored = load_credential_metadata(metadata_path)

    if not hmac.compare_digest(
        stored.credential.credential_id,
        expected_credential_id,
    ):
        raise CredentialMetadataError(
            "Stored credential does not match the container key slot."
        )

    try:
        client = _create_windows_client(stored.rp_id)
        server = _create_server(stored.rp_id)

        credentials = [stored.credential]

        request_options, state = server.authenticate_begin(
            credentials,
            user_verification="discouraged",
        )

        public_key_options = {
            **request_options["publicKey"],
            "timeout": timeout_ms,
            "extensions": {
                "hmacGetSecret": {
                    "salt1": salt,
                }
            },
        }

        # This is the point where Windows may request interaction
        # with the physical authenticator.
        selection = client.get_assertion(
            public_key_options
        )

        response = selection.get_response(0)

        # Verify challenge, origin, RP ID, user presence and signature
        # before trusting any extension output.
        server.authenticate_complete(
            state,
            credentials,
            response,
        )

        extension_output = getattr(
            response.client_extension_results,
            "hmac_get_secret",
            None,
        )

        if extension_output is None:
            raise Fido2AuthenticationError(
                "The authenticator did not return HMAC-secret."
            )

        result = getattr(
            extension_output,
            "output1",
            None,
        )

        if not isinstance(result, bytes):
            raise Fido2AuthenticationError(
                "HMAC-secret output has an invalid type."
            )

        if len(result) != HMAC_SECRET_SIZE:
            raise Fido2AuthenticationError(
                "HMAC-secret output has an invalid length."
            )

        return result

    except Fido2AuthenticationError:
        raise
    except Exception as exc:
        raise Fido2AuthenticationError(
            "FIDO2 authentication failed or was cancelled. "
            "Check the authenticator and try again."
        ) from exc