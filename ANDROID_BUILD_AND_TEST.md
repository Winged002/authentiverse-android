# Android build and test guide

## Prerequisites

Use a current stable Android Studio with:

- JDK 17;
- Android SDK Platform 36;
- the latest compatible Android SDK Build Tools;
- network access for the first Gradle and Maven dependency resolution.

Android Studio can install the SDK from **Tools → SDK Manager**. Accept the Android SDK licenses in that tool. The application uses the official precompiled WireGuard Android tunnel artifact, so Windows does not need NDK, CMake, `cc`, `uname`, GNU Make, or Go. Do not add `local.properties` to source control; Android Studio writes the local `sdk.dir` value.

## Development build

1. Open the source directory in Android Studio.
2. Allow Gradle sync and Maven dependency resolution to finish.
3. Select the `app` run configuration and a physical device on Android 7.0 or later.
4. Run, approve Android's VPN consent dialog, and enroll using a test invitation.

Command-line equivalent:

```bash
./gradlew --version
./gradlew :app:testDebugUnitTest
./gradlew :app:lintDebug
./gradlew :app:assembleDebug
```

## Required device verification

- Enrollment creates identity and WireGuard keys once and survives an app restart.
- The pinned server CA fingerprint is checked before certificates are accepted.
- Entering an Area requests VPN permission and assigns only a `10.200.x.x/32` address.
- Area-only mode accepts routes below `10.200.0.0/16`; isolated mode accepts the explicit `0.0.0.0/0` policy and captures IPv6 locally.
- **Open Indoor Home** loads only the trusted home/API hosts and completes mTLS without installing the private keys in Android's shared credential store.
- `home.digitalspace.home.arpa` receives the short-lived profile certificate; `api.digitalspace.home.arpa` receives the enrolled device certificate.
- External navigation, mixed content, file/content access, and an unpinned Indoor server certificate are rejected.
- Going Outdoors tears down the backend and clears the active profile certificate.
- A protected file round-trips with the same SHA-256 digest.
- A byte changed in a `.dsvault`, `.dsnda`, or `.dsshare` package causes import/decryption to fail.
- Windows/macOS-generated `.dscontact`, `.dsnda`, and `.dsshare` fixtures import successfully; Android exports import on both desktop clients.
- Create an NDA for multiple people and files, export or deliver each recipient's encrypted package, and verify every covered file appears locked under **Shared with me** before acceptance.
- Accepting or declining produces a participant-specific countersignature; the issuer imports each response without changing another participant's status.
- A forged participant response, mismatched issuer/file signer, missing or extra attachment, duplicate file ID, or response sent to a non-issuer is rejected.
- NDA rejection and expiry with `RevokeManagedAccess` prevent managed decryption.
- Supported NDA-controlled images and text open only in the protected in-app viewer, with screenshots blocked and no export action; unsupported formats remain encrypted.
- A stale, oversized, unknown-predicate, non-HTTPS, non-`.home.arpa`, or unallowlisted privacy request is rejected.
- Airplane/reconnect and process-death tests leave the app Outdoors unless the WireGuard backend is actually active.

## Release build

Configure a private signing key outside this repository, then build an Android App Bundle:

```bash
./gradlew clean :app:testDebugUnitTest :app:lintRelease :app:bundleRelease
```

Before distribution, test the signed build on at least one API 24 device and one current Android release. Verify the control-plane production configuration, privacy verifier allowlist, legal copy, Play data-safety answers, and third-party notices.

## Reproducibility note

This archive pins the Gradle wrapper, Android Gradle Plugin, and application dependencies. Android SDK packages and Maven artifacts are intentionally not redistributed; Android Studio resolves them from their official repositories.
