plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    id("org.mozilla.rust-android-gradle.rust-android")
    id("com.vanniktech.maven.publish") version "0.30.0"
}

tasks.matching { it.name.startsWith("cargoBuild") }.configureEach {
    doFirst {
        val linkerWrapperFile = file("${rootProject.layout.buildDirectory.get().asFile}/linker-wrapper/linker-wrapper.py")
        if (linkerWrapperFile.exists()) {
            val content = linkerWrapperFile.readText()
            if (content.contains("import pipes")) {
                linkerWrapperFile.writeText(
                    content
                        .replace("import pipes", "import shlex")
                        .replace("pipes.quote", "shlex.quote")
                )
                println("Patched linker-wrapper.py for Python 3.13 compatibility")
            }
        }
    }
}

android {
    namespace = "space.zeroxv6.kotlin_mls"
    compileSdk = 36

    defaultConfig {
        minSdk = 26

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("build/generated/source/uniffi/main/java")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }

    ndkVersion = "29.0.14206865"
}
cargo {
    module = "../rust_layer"
    libname = "android_openmls"
    targets = listOf("arm64", "x86_64")
    pythonCommand = "python3"
}

tasks.register<Exec>("generateUniffiBindings") {
    description = "Generate Kotlin bindings from Rust using UniFFI"
    group = "build"
    
    val outputDir = file("build/generated/source/uniffi/main/java")
    val libFile = file("../rust_layer/target/aarch64-linux-android/debug/libandroid_openmls.so")
    
    outputs.dir(outputDir)
    inputs.file(libFile)
    
    doFirst {
        outputDir.mkdirs()
    }
    
    workingDir = file("../rust_layer")
    
    commandLine(
        "cargo", "run",
        "--bin", "uniffi-bindgen",
        "--",
        "generate",
        "--library", libFile.absolutePath,
        "--language", "kotlin",
        "--out-dir", outputDir.absolutePath
    )
}

tasks.named("preBuild") {
    dependsOn("generateUniffiBindings")
}

tasks.matching { it.name.startsWith("cargoBuild") }.configureEach {
    finalizedBy("generateUniffiBindings")
}

tasks.matching { it.name.contains("SourcesJar") }.configureEach {
    dependsOn("generateUniffiBindings")
}


dependencies {
    implementation(libs.androidx.core.ktx)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("net.java.dev.jna:jna:5.13.0@aar")

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

mavenPublishing {
    publishToMavenCentral(com.vanniktech.maven.publish.SonatypeHost.CENTRAL_PORTAL)
    signAllPublications()
    
    coordinates("space.zeroxv6", "kotlin-mls", "1.0.1")
    
    pom {
        name.set("Kotlin MLS")
        description.set("Messaging Layer Security (MLS) library for Android using OpenMLS")
        url.set("https://github.com/zeroxv6/kotlin-mls")
        
        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/licenses/MIT")
            }
        }
        
        developers {
            developer {
                id.set("zeroxv6")
                name.set("Raman Mann (aka zeroxv6)")
                email.set("raman.mann.205@gmail.com")
            }
        }
        
        scm {
            connection.set("scm:git:git://github.com/zeroxv6/kotlin-mls.git")
            developerConnection.set("scm:git:ssh://github.com/zeroxv6/kotlin-mls.git")
            url.set("https://github.com/zeroxv6/kotlin-mls")
        }
    }
}
