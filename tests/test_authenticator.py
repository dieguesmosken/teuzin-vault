import base64
import json
from types import SimpleNamespace

import pytest

import teuzin_vault.fido2.authenticator as auth


FAKE_CREDENTIAL_BYTES = b"fake-public-credential-data"


class FakeCredential:
    def __init__(self, raw):
        if raw != FAKE_CREDENTIAL_BYTES:
            raise ValueError("Invalid fixture")

        self.credential_id = b"fake-credential-id"
        self.public_key = object()


def metadata_dict():
    return {
        "format": 1,
        "rp_id": auth.RP_ID,
        "name": "TrustKey Test",
        "credential_data": base64.b64encode(
            FAKE_CREDENTIAL_BYTES
        ).decode("ascii"),
    }


def write_metadata(tmp_path, data=None):
    path = tmp_path / "credential.json"

    if data is None:
        data = metadata_dict()

    path.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    return path


@pytest.fixture
def fake_credential_parser(monkeypatch):
    monkeypatch.setattr(
        auth,
        "AttestedCredentialData",
        FakeCredential,
    )


def test_load_valid_metadata(tmp_path, fake_credential_parser):
    path = write_metadata(tmp_path)

    stored = auth.load_credential_metadata(path)

    assert stored.name == "TrustKey Test"
    assert stored.rp_id == auth.RP_ID
    assert stored.credential.credential_id == b"fake-credential-id"


def test_wrong_rp_id_is_rejected(tmp_path, fake_credential_parser):
    data = metadata_dict()
    data["rp_id"] = "attacker.example"

    with pytest.raises(auth.CredentialMetadataError):
        auth.load_credential_metadata(write_metadata(tmp_path, data))


def test_wrong_metadata_version_is_rejected(tmp_path, fake_credential_parser):
    data = metadata_dict()
    data["format"] = 99

    with pytest.raises(auth.CredentialMetadataError):
        auth.load_credential_metadata(write_metadata(tmp_path, data))


def test_boolean_metadata_version_is_rejected(tmp_path, fake_credential_parser):
    data = metadata_dict()
    data["format"] = True

    with pytest.raises(auth.CredentialMetadataError):
        auth.load_credential_metadata(write_metadata(tmp_path, data))


def test_invalid_base64_is_rejected(tmp_path, fake_credential_parser):
    data = metadata_dict()
    data["credential_data"] = "not-valid-base64!"

    with pytest.raises(auth.CredentialMetadataError):
        auth.load_credential_metadata(write_metadata(tmp_path, data))


def test_invalid_credential_structure_is_rejected(tmp_path, fake_credential_parser):
    data = metadata_dict()
    data["credential_data"] = base64.b64encode(b"invalid").decode("ascii")

    with pytest.raises(auth.CredentialMetadataError):
        auth.load_credential_metadata(write_metadata(tmp_path, data))


def test_unknown_metadata_field_is_rejected(tmp_path, fake_credential_parser):
    data = metadata_dict()
    data["private_secret"] = "must not be accepted"

    with pytest.raises(auth.CredentialMetadataError):
        auth.load_credential_metadata(write_metadata(tmp_path, data))


def test_duplicate_json_keys_are_rejected(tmp_path, fake_credential_parser):
    path = tmp_path / "credential.json"
    path.write_text(
        '{"format":1,"format":1}',
        encoding="utf-8",
    )

    with pytest.raises(auth.CredentialMetadataError):
        auth.load_credential_metadata(path)


def test_oversized_metadata_is_rejected(tmp_path, fake_credential_parser):
    path = tmp_path / "credential.json"
    path.write_bytes(b" " * (auth.MAX_METADATA_SIZE + 1))

    with pytest.raises(auth.CredentialMetadataError):
        auth.load_credential_metadata(path)


def test_missing_metadata_is_rejected(tmp_path):
    path = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError):
        auth.load_credential_metadata(path)


def test_invalid_salt_length_is_rejected(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("Credential loading must not happen.")

    monkeypatch.setattr(auth, "load_credential_metadata", fail_if_called)

    with pytest.raises(ValueError):
        auth.get_hmac_secret(
            "unused.json", b"short",
            expected_credential_id=b"fake-credential-id"
        )


def test_invalid_timeout_is_rejected(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("Credential loading must not happen.")

    monkeypatch.setattr(auth, "load_credential_metadata", fail_if_called)

    with pytest.raises(ValueError):
        auth.get_hmac_secret(
            "unused.json",
            b"A" * 32,
            expected_credential_id=b"fake-credential-id",
            timeout_ms=0,
        )


def test_hmac_secret_authentication_flow_is_verified(
    tmp_path,
    monkeypatch,
    fake_credential_parser,
):
    path = write_metadata(tmp_path)
    expected_secret = b"S" * 32
    salt = b"A" * 32
    calls = {}

    response = SimpleNamespace(
        client_extension_results=SimpleNamespace(
            hmac_get_secret=SimpleNamespace(
                output1=expected_secret
            )
        )
    )

    class FakeSelection:
        def get_response(self, index):
            assert index == 0
            return response

    class FakeClient:
        def get_assertion(self, options):
            calls["options"] = options
            return FakeSelection()

    class FakeServer:
        def authenticate_begin(self, credentials, user_verification):
            calls["credentials"] = credentials
            calls["uv"] = user_verification

            return (
                {"publicKey": {"challenge": b"test"}},
                {"state": True},
            )

        def authenticate_complete(self, state, credentials, result):
            assert state == {"state": True}
            assert result is response
            calls["verified"] = True

    monkeypatch.setattr(
        auth,
        "_create_windows_client",
        lambda rp_id: FakeClient(),
    )

    monkeypatch.setattr(
        auth,
        "_create_server",
        lambda rp_id: FakeServer(),
    )

    result = auth.get_hmac_secret(
        path, salt,
        expected_credential_id=b"fake-credential-id",
    )

    assert result == expected_secret
    assert calls["verified"] is True
    assert calls["uv"] == "discouraged"
    assert calls["options"]["extensions"]["hmacGetSecret"]["salt1"] == salt


def test_authentication_rejects_missing_hmac_output(
    tmp_path,
    monkeypatch,
    fake_credential_parser,
):
    path = write_metadata(tmp_path)

    response = SimpleNamespace(
        client_extension_results=SimpleNamespace()
    )

    class FakeSelection:
        def get_response(self, index):
            return response

    class FakeClient:
        def get_assertion(self, options):
            return FakeSelection()

    class FakeServer:
        def authenticate_begin(self, credentials, user_verification):
            return {"publicKey": {}}, {}

        def authenticate_complete(self, state, credentials, result):
            return credentials[0]

    monkeypatch.setattr(
        auth,
        "_create_windows_client",
        lambda rp_id: FakeClient(),
    )

    monkeypatch.setattr(
        auth,
        "_create_server",
        lambda rp_id: FakeServer(),
    )

    with pytest.raises(auth.Fido2AuthenticationError):
        auth.get_hmac_secret(
            path, b"A" * 32,
            expected_credential_id=b"fake-credential-id",
        )


def test_authentication_signature_failure_rejects_secret(
    tmp_path,
    monkeypatch,
    fake_credential_parser,
):
    path = write_metadata(tmp_path)

    response = SimpleNamespace(
        client_extension_results=SimpleNamespace(
            hmac_get_secret=SimpleNamespace(
                output1=b"S" * 32
            )
        )
    )

    class FakeSelection:
        def get_response(self, index):
            return response

    class FakeClient:
        def get_assertion(self, options):
            return FakeSelection()

    class FakeServer:
        def authenticate_begin(self, credentials, user_verification):
            return {"publicKey": {}}, {}

        def authenticate_complete(self, state, credentials, result):
            raise ValueError("Invalid signature")

    monkeypatch.setattr(
        auth,
        "_create_windows_client",
        lambda rp_id: FakeClient(),
    )

    monkeypatch.setattr(
        auth,
        "_create_server",
        lambda rp_id: FakeServer(),
    )

    with pytest.raises(auth.Fido2AuthenticationError):
        auth.get_hmac_secret(
            path, b"A" * 32,
            expected_credential_id=b"fake-credential-id",
        )

def test_wrong_expected_credential_id_is_rejected_before_authentication(
    tmp_path,
    monkeypatch,
    fake_credential_parser,
):
    path = write_metadata(tmp_path)

    def should_not_connect(*args, **kwargs):
        raise AssertionError("Hardware must not be contacted.")

    monkeypatch.setattr(
        auth,
        "_create_windows_client",
        should_not_connect,
    )

    with pytest.raises(auth.CredentialMetadataError):
        auth.get_hmac_secret(
            path,
            b"A" * 32,
            expected_credential_id=b"different-credential-id",
        )


def test_empty_expected_credential_id_is_rejected(
    tmp_path,
    fake_credential_parser,
):
    path = write_metadata(tmp_path)

    with pytest.raises(auth.CredentialMetadataError):
        auth.get_hmac_secret(
            path,
            b"A" * 32,
            expected_credential_id=b"",
        )
