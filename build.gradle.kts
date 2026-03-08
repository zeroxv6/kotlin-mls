
plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    id("org.mozilla.rust-android-gradle.rust-android") version "0.9.6" apply false
}