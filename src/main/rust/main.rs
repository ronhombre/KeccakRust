#[cfg(feature = "executable")]
use keccakrust::*;

#[cfg(feature = "executable")]
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

#[cfg(not(feature = "executable"))]
fn main() {
    
}