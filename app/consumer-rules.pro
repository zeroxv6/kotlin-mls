# ── JNA (required for UniFFI native bridge) ─────────────────────────────────
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-dontwarn com.sun.jna.**

# ── UniFFI generated bindings ────────────────────────────────────────────────
-keep class uniffi.android_openmls.** { *; }
-keepclassmembers class uniffi.android_openmls.** { *; }

# ── Public API ───────────────────────────────────────────────────────────────
-keep class space.zeroxv6.kotlin_mls.MlsService { *; }
-keep class space.zeroxv6.kotlin_mls.MlsServiceException { *; }
-keep class space.zeroxv6.kotlin_mls.MlsStorageEncryptor { *; }
