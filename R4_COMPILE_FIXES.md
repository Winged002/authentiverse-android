# AuthentiVerse Android v1.7.0 source r4

## Compile fix

This revision fixes the Kotlin compiler error reported against r3:

- `MainActivity.kt:868:95 Unsupported escape sequence`

The whitespace-splitting regular expression in `initials()` used an invalid Kotlin string escape (`"\s+"` in source form). It now uses the correctly escaped Kotlin regex string `Regex("\\s+")`.

A source-wide scan of Kotlin ordinary string literals found no additional unsupported one-character escape sequences of the same class.

## Validation note

The Gradle wrapper could not execute in the packaging environment because `services.gradle.org` is not DNS-resolvable there, so the real Android/Gradle compiler remains the authoritative validation step on a development machine with the Gradle distribution available.
