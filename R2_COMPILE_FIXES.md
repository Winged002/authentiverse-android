# Authentiverse Android v1.7.0 source r2 — compile fixes

This revision addresses the Kotlin compiler failures reported by `:app:compileDebugKotlin` on 2026-08-21.

- `IdentityKeyStore.kt`: removed invalid `PrivateKey.provider` access. Hardware-backed detection now rejects exportable software keys and obtains `KeyInfo` through the `AndroidKeyStore` `KeyFactory`.
- `LauncherActivity.kt`: fixed the one-argument platform `setPadding` call by supplying all four padding values.
- `MainActivity.kt`: implemented the required `ProxyFileDescriptorCallback.onRelease()` callback for the memory-only PDF viewer.
- `MainActivity.kt`: changed the Secure Viewer dialog reference to `androidx.appcompat.app.AlertDialog`, matching the object created by `MaterialAlertDialogBuilder`.

The project could not be recompiled in the packaging environment because the Gradle wrapper distribution (`gradle-9.3.1-bin.zip`) cannot be fetched from `services.gradle.org` there. Run `:app:assembleDebug` in Android Studio/your normal build environment to verify the next compiler pass.
