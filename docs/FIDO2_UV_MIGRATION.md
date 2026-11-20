# FIDO2 user-verification migration (TVLT V1)

Teuzin Vault requests FIDO2 user verification for HMAC-secret assertions.
The WebAuthn `userVerification: required` request delegates verification to
the authenticator and platform; depending on the device, this can mean a PIN
or built-in biometric verification. The application does not silently retry
with user verification discouraged.

## Existing TVLT V1 containers

A credential can produce different HMAC-secret output when user verification
is required. Therefore, an existing FIDO2 slot created under a weaker policy
must not be assumed to remain decryptable with the new assertion output. The
explicit migration path uses the independent recovery secret to recover the
existing DEK, then obtains a fresh HMAC-secret with user verification required.

The migration API creates a separate destination file by default. It keeps
the header and slot descriptors unchanged, replaces only the FIDO2 wrapping
record with a fresh AES-GCM nonce, preserves the recovery record byte-for-byte,
and authenticates/copies all encrypted data and final records byte-for-byte.
The original file is not modified. The destination is published only after
the records authenticate and both key slots successfully unwrap the same DEK.

## Compatibility and limits

Migration requires a valid recovery secret and an existing credential that
supports the HMAC-secret extension and can satisfy the required user
verification request. Unit tests use simulated HMAC-secret values; they do not
prove that a particular physical authenticator or credential supports this
combination. A real-device test is still required before relying on migration.

The stream migration authenticates the encrypted record sequence but does
not decompress or rewrite its Zstandard payload. Normal restoration remains
responsible for decompression limits and plaintext validation. This project is
still experimental and has not undergone an independent security audit.

## Real-device validation (2026-11-20)

- Hardware: Yubico T110 using Windows WebAuthn.
- HMAC-secret retrieval succeeded with user verification required.
- A disposable TVLT V1 container was migrated into a separate copy.
- The original container was preserved byte-for-byte.
- The new FIDO2 slot successfully unlocked the migrated container.
- The independent recovery slot also successfully unlocked it.
- Temporary files were removed; no secrets were displayed or persisted.

Scope: the source container used a synthetic legacy FIDO2 secret and
was unlocked through its recovery secret. This validates the hardware
UV operation and migration mechanics, not migration of a personal
pre-existing vault or an independent security audit.
