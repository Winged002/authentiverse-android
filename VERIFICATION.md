# Verification record

Generated: 2026-08-15

## Completed in the generation environment

- Gradle 9.3.1 wrapper checksum retained from upstream.
- Android Gradle Plugin 9.1.0 and its plugin graph resolved from the configured repositories.
- Root and `app` Gradle scripts reached Android plugin configuration.
- The v1.2.0 manifest, version metadata, browser host policy, certificate-role
  selection, and pinned-authority checks were reviewed after patching.
- NDA issuer signatures, participant countersignatures, recipient binding,
  attachment membership, signer certificates, package entry limits, and managed
  access checks were reviewed after implementation.
- The modernized code-built Material UI and all application/tunnel Android XML
  files passed structural syntax checks.
- `gradlew` passed shell syntax validation.
- The WireGuard root commit and both native submodule revisions were verified and copied without nested Git metadata.
- Static security scans found no bundled private keys, session tokens, signing stores, APKs, AABs, or `local.properties`.

## Environment limitation

The generation container cannot reach the Gradle distribution service and has
no cached Gradle 9.3.1 installation, so it cannot perform the final Android
resource merge, lint run, JVM unit tests, APK assembly, or device test. Complete
the commands in `ANDROID_BUILD_AND_TEST.md` in Android Studio or an Android CI
runner before distribution.

This record does not represent an independent security audit or a signed release certification.
