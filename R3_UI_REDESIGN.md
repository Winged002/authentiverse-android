# Authentiverse Android v1.7.0 r3 — Consumer UI redesign

This revision keeps the r2 security, account, Vault, messaging, IDQA, HTTPSA and Private Network implementation while replacing the application shell with a more familiar consumer interface.

## Navigation

Top-level navigation is now:

- Home
- Messages
- Vault
- Browser
- You

People, MOI/private attributes, IDQA, certificates and client/security details remain available, but are consolidated under **You** and **Protection** instead of occupying technical top-level destinations.

## Home

- Familiar greeting and account identity card.
- Circular Identity Level indicator backed by the existing IDQA score (0–72 / Levels 1–6).
- Send, Share and Open quick actions.
- Plain-language Protection card.
- Recent messages and protected files.
- Private Network connection cards use Connect/Disconnect language rather than requiring users to learn INDOORS/OUTDOORS first.

## Messages

- Conversation-first list similar to mainstream messaging applications.
- Contact-based message history with outgoing/incoming bubbles.
- View-once messages and private call invitations remain enforced by the existing chat layer.
- Post-quantum and signature details are kept out of the primary UI and surfaced as advanced security information instead.

## Vault

- One Vault entry point with Files, Passwords and Agreements categories.
- Password-health information uses consumer language.
- Protected files continue to use the memory-only secure viewer.
- Secure Viewer now explains restrictions in plain language while retaining FLAG_SECURE, memory clearing, and expiry enforcement.

## Browser

- Browser now uses a familiar toolbar/address-bar layout.
- HTTPSA is displayed directly in the address bar while the underlying WebView continues using the existing authenticated HTTPS transport.
- Tapping the authenticated indicator explains the security state.
- Password Vault access is exposed as “Passwords”.
- Existing host restrictions, client certificates, pinned authority verification, mixed-content blocking and external-navigation blocking are unchanged.

## You / Protection

- Account profile, verified handle and device state.
- Identity Level and IDQA import controls.
- Personal information/privacy wallet.
- Trusted people/contact-card management.
- Global Protection view showing identity, device key, post-quantum identity, Private Network and IDQA state.
- Certificate details, update check and account switching remain available.

## Launcher and visual identity

- Account selection now resembles familiar Google/Microsoft-style account pickers while preserving the existing locked-before-client security boundary.
- PIN unlock is presented as a focused account-unlock flow.
- New Authentiverse shield/A launcher icon and navigation icon set.
- Visual system uses restrained white surfaces, #5755D9 as the primary accent, #08735E for verified/protected state, and #F7F8FB application background.

## Validation performed in this environment

- All Android XML resources parse successfully.
- Kotlin parser pass over the modified UI files reports no syntax-level errors.
- Full Gradle compilation could not be executed because this environment cannot resolve `services.gradle.org` to download Gradle 9.3.1. Run `:app:assembleDebug` in Android Studio or a network-enabled Gradle environment for the authoritative Android type/resource/lint build.
