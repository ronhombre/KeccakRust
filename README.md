# KeccakRust (0.0.6)

A Rust port of [KeccakKotlin](https://github.com/ronhombre/KeccakKotlin) utilizing
[neo-rust-gradle-plugin](https://github.com/ronhombre/neo-rust-gradle-plugin). This is a proof of concept project for
building Rust Gradle projects using my plugin.

> [!NOTE]
> All code in this project is directly ported from [KeccakKotlin](https://github.com/ronhombre/KeccakKotlin). Many
> design modifications have been made to accommodate the new environment that is Rust, so it is not a 1:1 port.

> [!WARNING]
> This crate only supports LITTLE ENDIAN systems at the moment i.e., X86 and ARM (most)

Run the test executable with `./gradlew runTest` or `./gradlew test`.

## Features
* Stack Allocation ONLY (No need for a heap allocator)
* no_std crate support (For embedded systems)
* Standalone crate. Doesn't depend on anything

### Standard FIPS 202
* SHA-3 (224, 256, 384, 512)
* RawSHAKE (128, 256)
* SHAKE (128, 256)

### SHA-3 Derived Functions (SP 800-185)
* cSHAKE (128, 256)
* KMAC (128, 256)
* KMACXOF (128, 256)

```rust
use keccakrust::*;

fn main() {
    let mut sha3_224 = SHA3_224::new_input_stream();
    sha3_224.write_bytes(&[0u8; 0]); //Write nothing
    let mut sha3_224_output = sha3_224.close();
    let mut hash_224 = [0u8; 28];
    match sha3_224_output.next_bytes(&mut hash_224) {
        Some(error) => println!("{}", error),
        _ => println!("{}", hex::encode(hash_224))
    }

    let mut sha3_256 = SHA3_256::new_input_stream();
    sha3_256.write_bytes(&[0u8; 0]); //Write nothing
    let mut sha3_256_output = sha3_256.close();
    let mut hash_256 = [0u8; 32];
    match sha3_256_output.next_bytes(&mut hash_256) {
        Some(error) => println!("{}", error),
        _ => println!("{}", hex::encode(hash_256))
    }

    let mut sha3_384 = SHA3_384::new_input_stream();
    sha3_384.write_bytes(&[0u8; 0]); //Write nothing
    let mut sha3_384_output = sha3_384.close();
    let mut hash_384 = [0u8; 48];
    match sha3_384_output.next_bytes(&mut hash_384) {
        Some(error) => println!("{}", error),
        _ => println!("{}", hex::encode(hash_384))
    }

    let mut sha3_512 = SHA3_512::new_input_stream();
    sha3_512.write_bytes(&[0u8; 0]); //Write nothing
    let mut sha3_512_output = sha3_512.close();
    let mut hash_512 = [0u8; 64];
    match sha3_512_output.next_bytes(&mut hash_512) {
        Some(error) => println!("{}", error),
        _ => println!("{}", hex::encode(hash_512))
    }

    let mut rawshake_128 = RAWSHAKE_128::new_input_stream();
    rawshake_128.write_bytes(&[0u8; 0]); //Write nothing
    let mut rawshake_128_output = rawshake_128.close();
    let mut hash_rawshake_128 = [0u8; 32];
    match rawshake_128_output.next_bytes(&mut hash_rawshake_128) {
        Some(error) => println!("{}", error),
        _ => println!("{}", hex::encode(hash_rawshake_128))
    }

    let mut rawshake_256 = RAWSHAKE_256::new_input_stream();
    rawshake_256.write_bytes(&[0u8; 0]); //Write nothing
    let mut rawshake_256_output = rawshake_256.close();
    let mut hash_rawshake_256 = [0u8; 64];
    match rawshake_256_output.next_bytes(&mut hash_rawshake_256) {
        Some(error) => println!("{}", error),
        _ => println!("{}", hex::encode(hash_rawshake_256))
    }

    let mut shake_128 = SHAKE_128::new_input_stream();
    shake_128.write_bytes(&[0u8; 0]); //Write nothing
    let mut shake_128_output = shake_128.close();
    let mut hash_shake_128 = [0u8; 32];
    match shake_128_output.next_bytes(&mut hash_shake_128) {
        Some(error) => println!("{}", error),
        _ => println!("{}", hex::encode(hash_shake_128))
    }

    let mut shake_256 = SHAKE_256::new_input_stream();
    shake_256.write_bytes(&[0u8; 0]); //Write nothing
    let mut shake_256_output = shake_256.close();
    let mut hash_shake_256 = [0u8; 64];
    match shake_256_output.next_bytes(&mut hash_shake_256) {
        Some(error) => println!("{}", error),
        _ => println!("{}", hex::encode(hash_shake_256))
    }

    let mut cshake_128 = CSHAKE_128::new_input_stream("TAK".as_bytes(), "KAT".as_bytes());
    cshake_128.write_bytes(&[0u8; 0]); //Write nothing
    let mut cshake_128_output = cshake_128.close();
    let mut hash_cshake_128 = [0u8; 32];
    match cshake_128_output.next_bytes(&mut hash_cshake_128) {
        Some(error) => println!("{}", error),
        _ => println!("{}", hex::encode(hash_cshake_128))
    }

    let mut cshake_256 = CSHAKE_256::new_input_stream("TAK".as_bytes(), "KAT".as_bytes());
    cshake_256.write_bytes(&[0u8; 0]); //Write nothing
    let mut cshake_256_output = cshake_256.close();
    let mut hash_cshake_256 = [0u8; 64];
    match cshake_256_output.next_bytes(&mut hash_cshake_256) {
        Some(error) => println!("{}", error),
        _ => println!("{}", hex::encode(hash_cshake_256))
    }

    let key = hex::decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F".to_string());
    let customization = "My Tagged Application".as_bytes();
    let mut kmac_128 = KMAC_128::new_input_stream(key.unwrap().as_slice(), customization, 256 / 8);
    kmac_128.write_bytes(hex::decode("00010203".to_string()).unwrap().as_slice()); //Write nothing
    let mut kmac_128_output = kmac_128.close();
    let mut hash_kmac_128 = [0u8; 256 / 8];
    println!("{}", match kmac_128_output.next_bytes(&mut hash_kmac_128) {
        Some(error) => error.to_string(),
        _ => hex::encode(hash_kmac_128)
    });

    let key = hex::decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F".to_string());
    let customization = "My Tagged Application".as_bytes();
    let mut kmac_256 = KMAC_256::new_input_stream(key.unwrap().as_slice(), customization, 512 / 8);
    kmac_256.write_bytes(hex::decode("00010203".to_string()).unwrap().as_slice()); //Write nothing
    let mut kmac_256_output = kmac_256.close();
    let mut hash_kmac_256 = [0u8; 512 / 8];
    println!("{}", match kmac_256_output.next_bytes(&mut hash_kmac_256) {
        Some(error) => error.to_string(),
        _ => hex::encode(hash_kmac_256)
    });
}
```

This is a copy of the generated `Cargo.toml` by my plugin given the current `build.gradle.kts`.
```toml
# THIS FILE IS AUTO-GENERATED by neo-rust-gradle-plugin
# MODIFY YOUR build.gradle.kts/build.gradle FILE INSTEAD!
# CHANGES HERE WILL BE LOST!!!
[package]
name = "keccakrust"
version = "0.0.6"
authors = ["Ron Lauren Hombre <ronlauren@hombre.asia>"]
edition = "2024"

[profile.dev]
panic = "abort"

[profile.release]
panic = "abort"

[features]
default = ["standalone"]
standalone = []
executable = ["dep:hex"]

[dependencies]
hex = { version = "0.4.3", optional = true }

[dev-dependencies]
hex = { version = "0.4.3" }

[lib]
path = "../src/main/rust/lib.rs"
crate-type = ["dylib", "rlib"]

[[bin]]
name = "test"
path = "../src/main/rust/main.rs"

```

### Sidenote

In the future, this will be integrated into **KeccakKotlin** as a native backend, and the Kotlin code will remain untouched
as a backup for platforms I can't build a binary for. (_This seems illogical given KMP is supposed to provide a common
language for multiple platforms. However, the main goal here is to prove Rust can be built with Gradle using my plugin
and to learn Rust myself._)

### License

```
Copyright 2025 Ron Lauren Hombre

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0
       
       and included as LICENSE.txt in this Project.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
