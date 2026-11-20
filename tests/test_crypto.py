import pytest

from teuzin_vault.core.encryption import (
    DecryptionError,
    decrypt,
    encrypt,
    generate_data_key,
)
from teuzin_vault.core.key_derivation import derive_key


def test_aes256_gcm_round_trip():
    key = generate_data_key()
    original = b"Teuzin Vault - teste de criptografia"
    aad = b"teuzin-vault-test-v1"

    nonce, ciphertext = encrypt(
        original,
        key,
        associated_data=aad,
    )

    restored = decrypt(
        nonce,
        ciphertext,
        key,
        associated_data=aad,
    )

    assert restored == original


def test_aes256_gcm_uses_different_nonces():
    key = generate_data_key()

    nonce1, _ = encrypt(b"Primeiro", key)
    nonce2, _ = encrypt(b"Segundo", key)

    assert len(nonce1) == 12
    assert len(nonce2) == 12
    assert nonce1 != nonce2


def test_aes256_gcm_detects_tampering():
    key = generate_data_key()
    nonce, ciphertext = encrypt(b"Dados protegidos", key)

    modified = bytearray(ciphertext)
    modified[0] ^= 1

    with pytest.raises(DecryptionError):
        decrypt(nonce, bytes(modified), key)


def test_aes256_gcm_rejects_wrong_key():
    nonce, ciphertext = encrypt(
        b"Conteudo secreto",
        generate_data_key(),
    )

    with pytest.raises(DecryptionError):
        decrypt(nonce, ciphertext, generate_data_key())


def test_hkdf_is_deterministic_for_same_inputs():
    material = b"A" * 32
    salt = b"B" * 32
    context = b"teuzin-vault/test/v1"

    key1 = derive_key(material, salt, info=context)
    key2 = derive_key(material, salt, info=context)

    assert len(key1) == 32
    assert key1 == key2


def test_hkdf_changes_with_context():
    material = b"A" * 32
    salt = b"B" * 32

    key1 = derive_key(material, salt, info=b"purpose-one")
    key2 = derive_key(material, salt, info=b"purpose-two")

    assert key1 != key2


def test_data_keys_are_random():
    key1 = generate_data_key()
    key2 = generate_data_key()

    assert len(key1) == 32
    assert len(key2) == 32
    assert key1 != key2