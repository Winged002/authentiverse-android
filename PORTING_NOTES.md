# Windows/macOS interoperability notes

## Preserved canonical formats

The Android implementation preserves the desktop clients' UTF-8, newline-delimited signature payloads and Unix-second timestamps for:

- `digitalspace-contact-v1`;
- `digitalspace-file-v1`;
- `digitalspace-nda-v1`;
- `digitalspace-nda-decision-v1`;
- `digitalspace-nda-exchange-v1`;
- `digitalspace-share-v1`;
- `digitalspace-indoor-route-v1`.

ECDSA signatures are transported as IEEE P1363 (`r || s`, 32 bytes each). Java's DER ECDSA output is converted at the protocol boundary. Certificates remain DER-in-base64 where the desktop contract requires it.

## ECDH and authenticated encryption

Recipient exchange uses P-256 ECDH followed by:

```text
SHA-256(UTF8(context) || raw_shared_secret || UTF8(identifier))
```

This matches the desktop `ECDiffieHellman.DeriveKeyFromHash` prepend/append contract. AES-GCM uses 12-byte nonces, 16-byte tags, and the same per-envelope associated-data strings.

## Vault format

`DSVLT001` is written as:

1. eight ASCII magic bytes;
2. little-endian chunk size (`1048576`);
3. repeated little-endian plaintext length, 12-byte nonce, 16-byte tag, and equal-length ciphertext;
4. a zero little-endian length terminator.

Chunk associated data is `content_id:index`. Sharing decrypts and re-encrypts each chunk under a random recipient content key; the original vault key never leaves its holder.

## Intentional platform differences

- Android uses `VpnService` plus upstream WireGuard `GoBackend`; Windows uses WireGuardNT and macOS uses Network Extension/WireGuardKit.
- Android uses Android Keystore-backed envelope encryption instead of Windows DPAPI or macOS Keychain protection.
- File selection/export uses Android's Storage Access Framework.
- Android privacy deep links are declared as `digitalspace://present` intents.

## Server dependency

The Android app uses the same enrollment, PKI, Area, tunnel, and Indoor inbox endpoints as v1.1 desktop. Predicate presentation is fail-closed until `POST /v1/privacy/predicate-credentials` is available and its issuer chain can be verified against the pinned CA.
