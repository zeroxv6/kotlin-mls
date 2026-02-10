# Kotlin MLS

A Messaging Layer Security (MLS) library for Android, built with Rust and Kotlin using [OpenMLS](https://github.com/openmls/openmls).

[![Maven Central](https://img.shields.io/maven-central/v/space.zeroxv6/kotlin-mls)](https://central.sonatype.com/artifact/space.zeroxv6/kotlin-mls)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- End-to-end encrypted group messaging
- Built on the MLS protocol (RFC 9420)
- Native performance with Rust backend
- Simple Kotlin API for Android

## Installation

Add to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("space.zeroxv6:kotlin-mls:1.0.1")
}
```

## Usage

```kotlin
import space.zeroxv6.kotlin_mls.MlsService

// Initialize
val mlsService = MlsService(context)

// Create a group
val groupId = mlsService.createGroup()

// Generate key package
val keyPackage = mlsService.generateKeyPackage()

// Add member
mlsService.addMember(groupId, keyPackage)

// Send encrypted message
val ciphertext = mlsService.sendMessage(groupId, "Hello, MLS!")

// Receive and decrypt
val plaintext = mlsService.receiveMessage(groupId, ciphertext)
```

## Requirements

- Android API 26+
- NDK 29.0.14206865

## Building

```bash
# Build the library
./gradlew :app:assembleRelease

# Run tests
./gradlew :app:test
./gradlew :app:connectedAndroidTest
```

## Architecture

- **Rust Layer**: Core MLS implementation using OpenMLS
- **UniFFI**: Automatic Kotlin bindings generation
- **Android Library**: Kotlin wrapper with Android-friendly API

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Raman Mann (aka zeroxv6)
- GitHub: [@zeroxv6](https://github.com/zeroxv6)
- Email: raman.mann.205@gmail.com
