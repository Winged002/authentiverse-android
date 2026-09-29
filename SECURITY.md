# Security boundaries

## Local secrets

Application state, session material, P-256 private keys, WireGuard private key, information manifest, file content keys, and private attributes are encrypted with AES-256-GCM under a non-exportable Android Keystore key. Files live below the app's no-backup storage, cloud backup and device transfer are excluded, and Android backup is disabled.

Private attributes are never added to X.509 subjects, contact cards, WireGuard configuration, or package metadata. Editing them invalidates cached derived credentials.

## Network and certificate trust

- Public control plane: `https://internal.syntal.pro/`
- Indoor API: `https://api.digitalspace.home.arpa/`
- Pinned Digital Space CA SHA-256: `AFED586A711469936E15C0F13E371089D6DF6331C7FF3BDA348E05C998704E25`
- Cleartext HTTP is disabled.
- Indoor calls require the enrolled device certificate and key.
- Redirects are disabled so credentials cannot be forwarded to another origin.
- The embedded browser presents the short-lived profile certificate only to
  `home.digitalspace.home.arpa` and the device certificate only to
  `api.digitalspace.home.arpa`. Other resource hosts and certificate requests
  are blocked.
- WebView's private-CA error is accepted only after exact hostname, validity,
  server-auth usage, signature, and pinned server-CA checks succeed. Other TLS
  errors are cancelled.

Area-only WireGuard configurations accept only Digital Space routes below
`10.200.0.0/16`. The explicit isolated-Indoor policy accepts `0.0.0.0/0`,
captures IPv6 locally, and relies on the Area gateway to block public Internet
access.

## File and package integrity

`DSVLT001` files use independent AES-256-GCM nonces and associated data for each 1 MiB chunk. Signed descriptors bind identifiers, names, types, sizes, hashes, owners, and timestamps. Contact and NDA packages use ECDSA P-256 signatures; recipient packages use ephemeral P-256 ECDH and AES-GCM.

NDA-controlled previews are decrypted only into the app's private cache after the
acceptance signature and expiry policy are revalidated. Supported images and
text stay inside an in-app viewer with Android's secure-window flag, no text
selection, and no Save a copy action. The temporary plaintext is deleted when
the viewer closes; unsupported formats remain encrypted. Holder-owned files can
still be opened through a temporary read-only `FileProvider` grant because they
are not controlled by a received NDA.

An issued `.dsnda` package binds the signed agreement to each covered file. On
import, the app verifies the envelope recipient, authority chain, issuer and
participant signatures, exact attachment set, encrypted content hash, file
descriptor signature, and that every attachment signer matches the NDA issuer.

## Privacy requests

The URI parser accepts only the fixed predicate registry, 16–64 byte nonces, a maximum five-minute lifetime, HTTPS callbacks below `.home.arpa`, exact callback/verifier origin equality, and configured verifier origins. Every valid request is shown to the holder. The current client intentionally withholds presentations until the server implements the reviewed v7 issuer endpoint.

## Production responsibilities

Before release, commission independent review of cryptographic interoperability, Android lifecycle behavior, backend authorization, certificate revocation, privacy issuance, dependency provenance, and package parsers. Rotate or revoke compromised devices server-side. Never commit signing keys, invitation codes, production fixtures, access tokens, or private certificates.
