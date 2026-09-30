# Authentiverse for Android

**Native Android client for the Authentiverse identity, private networking, secure communication, encrypted storage and authenticated application ecosystem.**

Current release: **1.7.0**  
Android application ID: `pro.digitalspace.android`  
Minimum Android: **7.0 / API 24**  
Target / Compile SDK: **API 36**  
Version code: **170**

---

## What is Authentiverse?

Authentiverse is a security and identity platform designed around the idea that a person should control their identity, credentials, private information, communications and access to digital spaces from their own trusted devices.

The Android client brings that model to phones and tablets.

It combines:

- cryptographic identity;
- device identity and certificates;
- authenticated private networking;
- private messaging and protected calls;
- encrypted files;
- password management;
- protected agreements;
- authenticated browsing;
- identity-quality information;
- private attributes;
- account isolation;
- secure application-to-application workflows.

Rather than treating identity, passwords, files, messaging, VPN access and authenticated applications as unrelated services, Authentiverse places them behind one user-controlled identity and protection layer.

The Android implementation evolved from the original **Digital Space Android protocol client** and remains wire-compatible with the current Authentiverse infrastructure and other Authentiverse clients wherever the platforms share protocols, formats and services.

---

## Why does this client exist?

Conventional mobile applications usually separate identity across many independent systems:

- passwords are stored in one application;
- authentication certificates in another;
- private files somewhere else;
- VPN access is configured separately;
- communication applications maintain their own identity databases;
- websites repeatedly request the same personal information;
- applications often rely on centralized accounts as the ultimate source of trust.

Authentiverse takes a different approach.

The Android client gives the device a cryptographically protected identity that can participate directly in the Authentiverse ecosystem.

The goal is to make the user's device an active part of the trust model rather than merely a terminal connected to a remote account.

This allows Authentiverse services to determine not only that credentials were supplied, but also which protected identity, device, profile and authorization context are participating in an operation.

---

## Where does it fit?

The Android client is one endpoint of the broader Authentiverse architecture.

A typical relationship looks like:

```text
                         Authentiverse
                              │
                    Identity / Control Plane
                              │
            ┌─────────────────┼─────────────────┐
            │                 │                 │
        Android             macOS            Windows
            │                 │                 │
            └──────── Authenticated Identity ───┘
                              │
               ┌──────────────┼───────────────┐
               │              │               │
            Areas           Indoor            MOI
               │              │               │
         Private Network   Applications   Private Data
               │
          WireGuard
```

The client communicates with Authentiverse control-plane and application services for enrollment, certificates, Areas, authenticated browsing, messaging, agreements, private information and other protected capabilities.

Where interoperability is required, Android uses the same Authentiverse formats and server contracts as the Windows and macOS clients.

---

## Digital Space compatibility

The Android application intentionally retains:

```text
pro.digitalspace.android
```

as its Android application ID.

This is deliberate.

Authentiverse Android is an evolution of the existing Digital Space Android client rather than an unrelated application. Retaining the package identity allows supported installations to migrate forward instead of forcing users into a completely separate application identity.

Legacy Digital Space protocol paths and formats are retained where required for migration or interoperability.

---

# User experience

Version 1.7.0 replaces the earlier technical client-oriented interface with a consumer-facing five-destination application.

## Home

The main identity and protection dashboard.

Home presents:

- active Authentiverse identity;
- Identity Level;
- Send;
- Share;
- Open;
- protection status;
- recent activity;
- Private Network access;
- relevant identity and connection state.

The goal is to expose common actions without requiring users to understand the protocol or certificate architecture underneath them.

---

## Messages

Private communication associated with Authentiverse identities and contacts.

Messages supports:

- contact-based conversations;
- protected messages;
- hybrid cryptographic messaging;
- protected call invitations;
- view-once messages;
- expiring messages;
- encrypted inbox delivery.

Communication is tied to Authentiverse identity rather than an unrelated messaging account.

---

## Vault

Vault is the protected storage area for information owned by the user.

It contains three primary categories:

```text
Vault
├── Files
├── Passwords
└── Agreements
```

Vault access is tied to the unlocked account and its PIN-gated protection state.

### Files

Authentiverse Files provides holder-owned encrypted storage using the cross-platform `DSVLT001` chunk format.

Supported workflows include:

- protected local files;
- encrypted sharing;
- controlled re-encryption;
- secure viewing;
- expiry-aware managed access.

### Passwords

The Password Vault stores encrypted credentials and related authentication information.

Capabilities include:

- encrypted credential records;
- password health checks;
- weak-password detection;
- reused-password detection;
- stale-password checks;
- TOTP;
- exact-origin browser autofill;
- encrypted audit information;
- protected credential sharing;
- credential revocation;
- passphrase-encrypted `.avbackup` backup/export.

Plaintext password-database export is not part of the normal workflow.

### Agreements

Protected agreements support:

- agreement creation;
- multiple recipients;
- signatures;
- encrypted delivery;
- responses;
- expiry;
- managed access.

Supported interchange includes `.dsnda`.

---

## Browser

Authentiverse includes an authenticated browser rather than treating browser identity as separate from the rest of the platform.

The browser supports:

- authenticated HTTPS transport;
- Authentiverse client certificates;
- profile and device certificate selection;
- HTTPSA addressing;
- exact-origin Password Vault matching;
- controlled credential filling;
- Authentiverse protocol routing.

Authenticated addresses are presented to the user as:

```text
httpsa://
```

while Android WebView uses the corresponding authenticated HTTPS transport required by the Android platform.

Password filling is origin-bound rather than based on loose URL matching.

---

## You

The **You** area contains the user's identity, device and account configuration.

It includes:

- Personal Information;
- Identity Level;
- IDQA information;
- trusted people;
- Protection settings;
- certificates;
- update information;
- account switching.

This is where lower-level identity and security information is exposed without cluttering the primary Home workflow.

---

# Multiple accounts

Authentiverse Android supports multiple isolated local identities.

Each account has independent:

- application state;
- cryptographic material;
- Vault data;
- certificates;
- contacts;
- private information;
- network state.

The launcher uses a separate locked account-selection experience.

No account-specific client data is constructed until the selected account has been unlocked.

This prevents one local Authentiverse account from being casually exposed while another account is active.

---

# Identity and enrollment

The Android client supports enrollment into the Authentiverse identity infrastructure.

Supported flows include:

- invitation verification;
- email verification;
- phone verification;
- existing Digital Space account migration;
- new account registration;
- device enrollment;
- profile enrollment;
- certificate issuance.

Android Keystore is used for suitable classical key material.

Where supported, the client creates P-256 keys for:

- identity operations;
- device operations;
- profiles;
- contact exchange.

The application also creates PKCS#10 certificate requests and validates certificates against pinned Authentiverse / Digital Space authorities.

---

# Post-quantum identity

Authentiverse includes post-quantum identity material alongside classical cryptography.

Android 1.7.0 supports account-local:

- **ML-KEM-1024**
- **ML-DSA-87**

Android Keystore does not currently provide native ML-KEM or ML-DSA key generation comparable to its classical key facilities.

For that reason, Authentiverse does not pretend those keys are hardware-backed when the Android platform cannot provide that guarantee.

Post-quantum identity seeds are instead protected inside the PIN-gated Authentiverse Vault.

See:

```text
SECURITY.md
PORTING_NOTES.md
```

for the exact trust and storage boundaries.

---

# Private Network

Authentiverse Areas can provide authenticated private network access.

The Android client supports:

- Area discovery;
- Area membership;
- profile certificate issuance;
- approved route retrieval;
- WireGuard tunnel establishment;
- Authentiverse private network isolation.

The client uses the server-approved routes supplied for the selected Area instead of exposing arbitrary unrestricted tunnel configuration through the consumer interface.

---

# WireGuard foundation

Authentiverse Android uses the official WireGuard Android tunnel implementation:

```text
com.wireguard.android:tunnel:1.0.20260102
```

The application integrates `GoBackend` directly.

A source snapshot from the official WireGuard Android repository may also be retained in the source archive for provenance and licensing/reference purposes, but the application build uses the declared Android tunnel dependency.

WireGuard components remain subject to their upstream licenses.

---

# Authenticated applications and protocols

The client understands Authentiverse-specific application routes including:

```text
httpsa://
indoor://
```

along with Authentiverse / MOI routing and retained Digital Space compatibility paths.

These protocols allow applications and services to request protected operations without reducing the user identity to a conventional username/password session.

Depending on the operation, Authentiverse can associate requests with:

- account identity;
- device identity;
- profile;
- certificates;
- authenticated origin;
- Area membership;
- Vault authorization;
- explicit user approval.

---

# Messaging and protected calls

The communication subsystem supports private identity-based communication.

Capabilities include:

- hybrid protected messages;
- encrypted inbox delivery;
- private contacts;
- call invitations;
- view-once messages;
- expiring messages.

The architecture is designed so that messaging participates in the same identity system as the rest of Authentiverse instead of maintaining a completely independent account model.

---

# Protected file formats

Authentiverse Android interoperates with several Authentiverse / Digital Space formats.

Examples include:

| Format | Purpose |
|---|---|
| `DSVLT001` | Encrypted Vault file chunk format |
| `.dscontact` | Signed contact information |
| `.dsnda` | Protected agreement |
| `.dsshare` | Re-encrypted protected share |
| `.avbackup` | Passphrase-encrypted Authentiverse backup |

Compatibility details are documented in `PORTING_NOTES.md`.

---

# Secure Viewer

Supported protected content can be opened using the in-app Secure Viewer.

Supported content includes appropriate:

- text;
- images;
- PDF documents.

The viewer is designed around memory-only handling where practical and applies managed access controls including:

- screen-capture blocking;
- protected viewing state;
- expiry enforcement;
- managed access validation.

It is not intended to behave like an unrestricted file export mechanism.

---

# Password Vault

The Android Password Vault is integrated with Authentiverse Browser and the wider protected-data system.

Each credential is independently protected and can contain information such as:

- title;
- username;
- password;
- URL/origin information;
- notes;
- TOTP information;
- sharing metadata.

The browser uses exact-origin matching so credentials intended for one origin are not automatically offered to unrelated hosts.

Credential sharing can be permissioned and subsequently revoked.

Backups use the encrypted Authentiverse `.avbackup` format.

---

# Personal Information and privacy requests

Authentiverse includes a private attribute wallet for information that a user may need to provide to trusted services.

Instead of every application independently collecting and permanently storing the same user information, Authentiverse can mediate requests for protected attributes through the identity and authorization layer.

The Android client includes infrastructure for:

- private attributes;
- personal information;
- privacy requests;
- controlled information release;
- MOI workflows.

---

# IDQA and Identity Level

The Android client can store and present Authentiverse identity-quality information.

This includes:

- IDQA trust bundles;
- attestations;
- Identity Level presentation;
- relevant verification state.

The UI summarizes this information for the user while the underlying trust information remains available for validation and diagnostics.

---

# Updates

Authentiverse Android contains infrastructure for authenticated application updates.

This includes support for:

- signed update manifests;
- APK verification;
- release metadata validation.

Production distribution still follows the normal Android signing and distribution model.

No private signing key is included in this repository.

---

# Security model

Authentiverse uses the security mechanisms actually available on Android rather than claiming equivalence with platform-specific security primitives from Windows or macOS.

Important boundaries include:

### Android Keystore

Suitable classical private keys can use Android Keystore and, when supported by the device, hardware-backed key protection.

### Post-quantum keys

ML-KEM and ML-DSA identity material is protected by the Authentiverse Vault because Android Keystore does not currently expose equivalent native post-quantum key-generation facilities.

### Account isolation

Each local Authentiverse account has an isolated state and protection context.

### Vault locking

Sensitive Vault operations require the appropriate unlocked account/Vault state.

### Authenticated origins

Browser credential operations are associated with the authenticated origin rather than arbitrary page text or URL fragments.

### Certificates

Authentiverse validates expected certificate chains and pinned authorities for protected services.

### Private Network

Network routes come from the authorized Authentiverse Area configuration.

For the detailed security model, read:

```text
SECURITY.md
```

---

# Version 1.7.0

Version **1.7.0** is the first Android release in the current Authentiverse 1.7 family.

It brings the Android application into the modern Authentiverse client model with:

- redesigned consumer UI;
- Home / Messages / Vault / Browser / You navigation;
- protected multi-account operation;
- Password Vault;
- authenticated browser;
- exact-origin credential filling;
- protected files;
- protected agreements;
- hybrid messaging;
- protected call invitations;
- post-quantum identity material;
- IDQA presentation;
- private attributes;
- Private Network access;
- cross-platform Authentiverse interoperability.

The current source also incorporates the **r4 compiler correction** for the Kotlin `Unsupported escape sequence` failure previously present in `MainActivity.initials()`.

See:

```text
R3_UI_REDESIGN.md
R4_COMPILE_FIXES.md
```

for revision-specific details.

---

# Repository structure

The exact tree may evolve, but the repository contains the Android application and supporting Authentiverse documentation.

Typical areas include:

```text
.
├── app/
│   └── Android application
├── gradle/
│   └── Gradle wrapper/support files
├── ANDROID_BUILD_AND_TEST.md
├── PORTING_NOTES.md
├── R3_UI_REDESIGN.md
├── R4_COMPILE_FIXES.md
├── SECURITY.md
├── COPYING
├── LICENSE-MIT
├── NOTICE
└── README.md
```

---

# Requirements

To build Authentiverse Android you need:

- a current stable Android Studio;
- JDK 17;
- Android SDK Platform 36;
- required Android SDK Build Tools;
- network access for Gradle dependency resolution.

The repository uses its checked-in:

```text
Gradle 9.3.1
```

wrapper.

---

# Build

Clone the repository and enter the project directory:

```bash
git clone <repository-url>
cd authentiverse-android
```

Run the standard validation/build tasks:

```bash
./gradlew :app:testDebugUnitTest
./gradlew :app:lintDebug
./gradlew :app:assembleDebug
```

A successful debug build produces an APK under:

```text
app/build/outputs/apk/debug/
```

Android Studio / Gradle should be treated as the authoritative Kotlin type checking, Android resource validation, lint and APK build environment.

For detailed setup and device testing instructions, see:

```text
ANDROID_BUILD_AND_TEST.md
```

---

# Production builds

A production release requires an Android signing key controlled by the distributor.

Signing secrets are intentionally not included in this repository.

Before production deployment, validate at minimum:

```bash
./gradlew :app:testDebugUnitTest
./gradlew :app:lintDebug
./gradlew :app:assembleDebug
```

and perform the appropriate release build, device testing, signing and distribution review for the intended deployment environment.

---

# Documentation

Additional technical documentation is included in the repository:

### `SECURITY.md`

Security architecture, key-storage boundaries, trust assumptions and platform-specific limitations.

### `PORTING_NOTES.md`

Cross-platform protocol compatibility and differences between Android, Windows, macOS and legacy Digital Space behavior.

### `ANDROID_BUILD_AND_TEST.md`

Android Studio configuration, Gradle validation and device-testing procedures.

### `R3_UI_REDESIGN.md`

Mapping from the previous technical interface to the current consumer-oriented Authentiverse UI.

### `R4_COMPILE_FIXES.md`

Compiler corrections incorporated after the r3 interface revision.

---

# Platform identity

| Property | Value |
|---|---|
| Product | Authentiverse |
| Platform | Android |
| Release | `1.7.0` |
| Version code | `170` |
| Application ID | `pro.digitalspace.android` |
| Minimum Android | Android 7.0 / API 24 |
| Target SDK | API 36 |
| Compile SDK | API 36 |
| Java | JDK 17 |
| Gradle | 9.3.1 |
| WireGuard tunnel | `1.0.20260102` |

The application ID remains `pro.digitalspace.android` intentionally to preserve the supported upgrade path from the earlier Digital Space Android client.

---

# Licensing

New Authentiverse application code is licensed under the **MIT License** unless otherwise noted.

WireGuard and other third-party components retain their respective upstream licenses, copyright notices and licensing requirements.

See:

```text
LICENSE-MIT
COPYING
NOTICE
```

and individual source headers for details.

---

## Authentiverse

Authentiverse for Android turns an Android device into a protected participant in the Authentiverse ecosystem: an identity holder, credential store, secure communication endpoint, private-network client, authenticated browser and controlled gateway to the user's own information.

The objective is not simply to add another account to Android.

It is to give the user a cryptographically protected identity that can be used consistently across devices, applications, private networks and digital spaces.
