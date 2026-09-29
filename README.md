# Authentiverse for Android 1.7.0

Native Android Authentiverse client, evolved from the Digital Space Android protocol implementation and kept wire-compatible with the current Windows Authentiverse client where the platforms share formats and services. The Android application ID remains `pro.digitalspace.android` so an installed Digital Space Android client can migrate forward instead of being treated as an unrelated application.

## Consumer interface

Revision r3 replaces the older technical client shell with a familiar five-destination layout:

- **Home** — account identity, Identity Level ring, Send / Share / Open actions, Protection status, recent activity and Private Network access.
- **Messages** — contact-based private conversations, protected calls, view-once and expiring messages.
- **Vault** — protected Files, Passwords and Agreements.
- **Browser** — authenticated HTTPSA browsing with a conventional address-bar experience and exact-origin Password Vault filling.
- **You** — Personal Information, Identity Level / IDQA, trusted people, Protection, certificates, updates and account switching.

The launcher uses a separate locked account-selection experience. No account client data is constructed before the selected account is unlocked.

See `R3_UI_REDESIGN.md` for the UI mapping and terminology changes.

## Included capabilities

- multiple isolated local Authentiverse accounts with PIN-gated Vault sessions;
- migration/registration support for an existing Digital Space Android account;
- verified invitation, email and phone enrollment;
- Android Keystore P-256 identity, device, profile and contact-exchange keys where supported;
- account-local ML-KEM-1024 and ML-DSA-87 identity material protected by the PIN-gated Vault;
- PKCS#10 certificate requests and pinned Authentiverse/Digital Space authority validation;
- Area discovery, membership, profile certificate issuance and WireGuard Private Network sessions;
- authenticated in-app browser with host-scoped profile/device client certificates;
- HTTPSA / Indoor / MOI / Authentiverse protocol routing while retaining legacy Digital Space compatibility;
- hybrid private messaging and call invitations with view-once / expiring-message policies;
- encrypted inbox delivery for chat, protected agreements and agreement responses;
- holder-owned encrypted files using the cross-platform `DSVLT001` chunk format;
- signed `.dscontact`, encrypted `.dsnda`, and re-encrypted `.dsshare` interchange;
- protected agreement creation, multi-recipient signing and expiry-aware managed access;
- memory-only Secure Viewer for supported text, images and PDFs, with screen capture blocked and managed expiry enforcement;
- Password Vault with per-record encryption, health checks, TOTP, exact-origin browser filling, encrypted `.avbackup` support and permissioned credential sharing/revocation;
- private attribute wallet and privacy-request routing;
- IDQA trust-bundle / attestation storage and Identity Level presentation;
- signed update manifest / APK verification infrastructure.

## Security model notes

Android platform primitives are used rather than pretending Windows-specific primitives exist on Android. Classical keys can use Android Keystore non-exportability/hardware backing when supported. Post-quantum identity seeds are Vault-protected because Android Keystore does not currently expose ML-KEM/ML-DSA key generation. See `SECURITY.md` and `PORTING_NOTES.md` for the exact boundaries.

Private Network isolation and the authenticated browser retain the existing server contract and host restrictions. The browser displays authenticated addresses as `httpsa://` to the user while its WebView uses the underlying authenticated HTTPS transport required by Android.

## WireGuard foundation

The app links the official `com.wireguard.android:tunnel:1.0.20260102` artifact. An unreferenced source snapshot from the official WireGuard Android repository remains in the archive for provenance. The application uses `GoBackend` directly and accepts the control plane's approved Area routes, including the explicit isolated route used by the existing Authentiverse/Digital Space server contract.

## Open and build

Open this directory as a project in a current stable Android Studio. Install Android SDK Platform 36 and Android SDK Build Tools when prompted. The project requires JDK 17 and uses its checked-in Gradle 9.3.1 wrapper.

```bash
./gradlew :app:testDebugUnitTest
./gradlew :app:lintDebug
./gradlew :app:assembleDebug
```

The debug APK is written under `app/build/outputs/apk/debug/`. A production release requires your own Android signing key and normal distribution review; no signing secret is included.

This environment could not download the Gradle distribution because `services.gradle.org` was not resolvable. XML resources and Kotlin syntax for the r3 UI changes were checked locally, but Android Studio / Gradle remains the authoritative type, lint and APK validation step.

See `ANDROID_BUILD_AND_TEST.md` for setup and device checks, `SECURITY.md` for security boundaries, `PORTING_NOTES.md` for protocol compatibility, and `R3_UI_REDESIGN.md` for this revision's interface changes.

## Package identity and support

- Product: Authentiverse
- Application ID: `pro.digitalspace.android` (retained intentionally for upgrade compatibility)
- Minimum Android: 7.0 / API 24
- Target and compile SDK: API 36
- Version: `1.7.0` (`versionCode` 170)

## Licensing

New Authentiverse application code is MIT licensed. The WireGuard tunnel sources and their components retain their upstream licenses and notices. See `COPYING`, `LICENSE-MIT`, source headers and `NOTICE`.


## Revision r4

Fixes the r3 Kotlin `Unsupported escape sequence` compiler failure in `MainActivity.initials()`; see `R4_COMPILE_FIXES.md`.
