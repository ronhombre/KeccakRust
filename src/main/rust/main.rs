use keccakrust::{KeccakParameter, *};

fn main() {
    let mut sha3_224 = SHA3_224::new_input_stream();
    sha3_224.write_bytes(&[0u8; 0]); //Write nothing
    let mut sha3_224_output = sha3_224.close();
    let hash_224 = sha3_224_output.next_bytes((KeccakParameter::SHA3_224.min_length / 8) as usize);
    println!("{}", hex::encode(hash_224));

    let mut sha3_256 = SHA3_256::new_input_stream();
    sha3_256.write_bytes(&[0u8; 0]); //Write nothing
    let mut sha3_256_output = sha3_256.close();
    let hash_256 = sha3_256_output.next_bytes((KeccakParameter::SHA3_256.min_length / 8) as usize);
    println!("{}", hex::encode(hash_256));

    let mut sha3_384 = SHA3_384::new_input_stream();
    sha3_384.write_bytes(&[0u8; 0]); //Write nothing
    let mut sha3_384_output = sha3_384.close();
    let hash_384 = sha3_384_output.next_bytes((KeccakParameter::SHA3_384.min_length / 8) as usize);
    println!("{}", hex::encode(hash_384));

    let mut sha3_512 = SHA3_512::new_input_stream();
    sha3_512.write_bytes(&[0u8; 0]); //Write nothing
    let mut sha3_512_output = sha3_512.close();
    let hash_512 = sha3_512_output.next_bytes((KeccakParameter::SHA3_512.min_length / 8) as usize);
    println!("{}", hex::encode(hash_512));

    let mut rawshake_128 = RAWSHAKE_128::new_input_stream();
    rawshake_128.write_bytes(&[0u8; 0]); //Write nothing
    let mut rawshake_128_output = rawshake_128.close();
    let hash_rawshake_128 = rawshake_128_output.next_bytes((256 / 8) as usize);
    println!("{}", hex::encode(hash_rawshake_128));

    let mut rawshake_256 = RAWSHAKE_256::new_input_stream();
    rawshake_256.write_bytes(&[0u8; 0]); //Write nothing
    let mut rawshake_256_output = rawshake_256.close();
    let hash_rawshake_256 = rawshake_256_output.next_bytes((512 / 8) as usize);
    println!("{}", hex::encode(hash_rawshake_256));

    let mut shake_128 = SHAKE_128::new_input_stream();
    shake_128.write_bytes(&[0u8; 0]); //Write nothing
    let mut shake_128_output = shake_128.close();
    let hash_shake_128 = shake_128_output.next_bytes((256 / 8) as usize);
    println!("{}", hex::encode(hash_shake_128));

    let mut shake_256 = SHAKE_256::new_input_stream();
    shake_256.write_bytes(&[0u8; 0]); //Write nothing
    let mut shake_256_output = shake_256.close();
    let hash_shake_256 = shake_256_output.next_bytes((512 / 8) as usize);
    println!("{}", hex::encode(hash_shake_256));
}