/*
 * Copyright 2025 Ron Lauren Hombre
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *        and included as LICENSE.txt in this Project.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#![cfg_attr(all(not(debug_assertions), not(feature = "executable")), no_std)]

#[cfg(all(not(debug_assertions), not(feature = "executable")))]
use core::panic::PanicInfo;

use crate::streams::{HashInputStream};

mod keccakmath;
mod constants;
mod streams;

#[derive(PartialEq)]
pub struct KeccakParameter {
    pub min_length: u32,
    pub max_length: u32,
    pub bitrate: u32,
    pub padding_bytes: &'static [u8],
    pub padding_bitcount: u8
}

impl KeccakParameter {
    pub const SHA3_224: KeccakParameter = KeccakParameter {
        min_length: 224,
        max_length: 256,
        bitrate: 1152,
        padding_bytes: &[0b10],
        padding_bitcount: 2
    };
    pub const SHA3_256: KeccakParameter = KeccakParameter {
        min_length: 256,
        max_length: 256,
        bitrate: 1088,
        padding_bytes: &[0b10],
        padding_bitcount: 2
    };
    pub const SHA3_384: KeccakParameter = KeccakParameter {
        min_length: 384,
        max_length: 384,
        bitrate: 832,
        padding_bytes: &[0b10],
        padding_bitcount: 2
    };
    pub const SHA3_512: KeccakParameter = KeccakParameter {
        min_length: 512,
        max_length: 512,
        bitrate: 576,
        padding_bytes: &[0b10],
        padding_bitcount: 2
    };
    pub const RAWSHAKE_128: KeccakParameter = KeccakParameter {
        min_length: 128,
        max_length: 0,
        bitrate: 1344,
        padding_bytes: &[0b11],
        padding_bitcount: 2
    };
    pub const RAWSHAKE_256: KeccakParameter = KeccakParameter {
        min_length: 256,
        max_length: 0,
        bitrate: 1088,
        padding_bytes: &[0b11],
        padding_bitcount: 2
    };
    pub const SHAKE_128: KeccakParameter = KeccakParameter {
        min_length: 128,
        max_length: 0,
        bitrate: 1344,
        padding_bytes: &[0b1111],
        padding_bitcount: 4
    };
    pub const SHAKE_256: KeccakParameter = KeccakParameter {
        min_length: 256,
        max_length: 0,
        bitrate: 1088,
        padding_bytes: &[0b1111],
        padding_bitcount: 4
    };

    pub fn byterate(&self) -> u8 {
        return (self.bitrate >> 3).try_into().unwrap();
    }
}
#[allow(non_camel_case_types)]
pub struct SHA3_224 {}
#[allow(non_camel_case_types)]
pub struct SHA3_256 {}
#[allow(non_camel_case_types)]
pub struct SHA3_384 {}
#[allow(non_camel_case_types)]
pub struct SHA3_512 {}
#[allow(non_camel_case_types)]
pub struct RAWSHAKE_128 {}
#[allow(non_camel_case_types)]
pub struct RAWSHAKE_256 {}
#[allow(non_camel_case_types)]
pub struct SHAKE_128 {}
#[allow(non_camel_case_types)]
pub struct SHAKE_256 {}

//TODO: Implement non-inputstream variants
impl SHA3_224 {
    pub fn new_input_stream() -> HashInputStream {
        return HashInputStream::new(
            KeccakParameter::SHA3_224,
            (KeccakParameter::SHA3_224.min_length / 8) as usize
        );
    }
}

impl SHA3_256 {
    pub fn new_input_stream() -> HashInputStream {
        return HashInputStream::new(
            KeccakParameter::SHA3_256,
            (KeccakParameter::SHA3_256.min_length / 8) as usize
        );
    }
}

impl SHA3_384 {
    pub fn new_input_stream() -> HashInputStream {
        return HashInputStream::new(
            KeccakParameter::SHA3_384,
            (KeccakParameter::SHA3_384.min_length / 8) as usize
        );
    }
}

impl SHA3_512 {
    pub fn new_input_stream() -> HashInputStream {
        return HashInputStream::new(
            KeccakParameter::SHA3_512,
            (KeccakParameter::SHA3_512.min_length / 8) as usize
        );
    }
}

impl RAWSHAKE_128 {
    pub fn new_input_stream() -> HashInputStream {
        return HashInputStream::new(
            KeccakParameter::RAWSHAKE_128,
            0usize
        );
    }
}

impl RAWSHAKE_256 {
    pub fn new_input_stream() -> HashInputStream {
        return HashInputStream::new(
            KeccakParameter::RAWSHAKE_256,
            0usize
        );
    }
}


impl SHAKE_128 {
    pub fn new_input_stream() -> HashInputStream {
        return HashInputStream::new(
            KeccakParameter::SHAKE_128,
            0usize
        );
    }
}

impl SHAKE_256 {
    pub fn new_input_stream() -> HashInputStream {
        return HashInputStream::new(
            KeccakParameter::SHAKE_256,
            0usize
        );
    }
}

#[cfg(all(not(debug_assertions), not(feature = "executable")))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[cfg(debug_assertions)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_224() {
        let mut sha3_224 = SHA3_224::new_input_stream();
        sha3_224.write_bytes(&[0u8; 0]); //Write nothing
        let mut sha3_224_output = sha3_224.close();
        let mut hash_224 = [0u8; 28];
        assert_eq!(match sha3_224_output.next_bytes(&mut hash_224) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_224)
        }, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    }

    #[test]
    fn sha3_256() {
        let mut sha3_256 = SHA3_256::new_input_stream();
        sha3_256.write_bytes(&[0u8; 0]); //Write nothing
        let mut sha3_256_output = sha3_256.close();
        let mut hash_256 = [0u8; 32];
        assert_eq!(match sha3_256_output.next_bytes(&mut hash_256) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_256)
        }, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }

    #[test]
    fn sha3_384() {
        let mut sha3_384 = SHA3_384::new_input_stream();
        sha3_384.write_bytes(&[0u8; 0]); //Write nothing
        let mut sha3_384_output = sha3_384.close();
        let mut hash_384 = [0u8; 48];
        assert_eq!(match sha3_384_output.next_bytes(&mut hash_384) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_384)
        }, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    }

    #[test]
    fn sha3_512() {
        let mut sha3_512 = SHA3_512::new_input_stream();
        sha3_512.write_bytes(&[0u8; 0]); //Write nothing
        let mut sha3_512_output = sha3_512.close();
        let mut hash_512 = [0u8; 64];
        assert_eq!(match sha3_512_output.next_bytes(&mut hash_512) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_512)
        }, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    }

    #[test]
    fn rawshake_128() {
        let mut rawshake_128 = RAWSHAKE_128::new_input_stream();
        rawshake_128.write_bytes(&[0u8; 0]); //Write nothing
        let mut rawshake_128_output = rawshake_128.close();
        let mut hash_rawshake_128 = [0u8; 32];
        assert_eq!(match rawshake_128_output.next_bytes(&mut hash_rawshake_128) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_rawshake_128)
        }, "fa019a3b17630df6014853b5470773f13c3ab704478211d7a65867515dea1cc7");
    }

    #[test]
    fn rawshake_256() {
        let mut rawshake_256 = RAWSHAKE_256::new_input_stream();
        rawshake_256.write_bytes(&[0u8; 0]); //Write nothing
        let mut rawshake_256_output = rawshake_256.close();
        let mut hash_rawshake_256 = [0u8; 64];
        assert_eq!(match rawshake_256_output.next_bytes(&mut hash_rawshake_256) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_rawshake_256)
        }, "3a1108d4a90a31b85a10bdce77f4bfbdcc5b1d70dd405686f8bbde834aa1a410db8c9e1c166c3e239cd76a55f6a692aa2d1749f2ec79cd0ba3b17bb659959b6e");
    }

    #[test]
    fn shake_128() {
        let mut shake_128 = SHAKE_128::new_input_stream();
        shake_128.write_bytes(&[0u8; 0]); //Write nothing
        let mut shake_128_output = shake_128.close();
        let mut hash_shake_128 = [0u8; 32];
        assert_eq!(match shake_128_output.next_bytes(&mut hash_shake_128) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_shake_128)
        }, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    }

    #[test]
    fn shake_256() {
        let mut shake_256 = SHAKE_256::new_input_stream();
        shake_256.write_bytes(&[0u8; 0]); //Write nothing
        let mut shake_256_output = shake_256.close();
        let mut hash_shake_256 = [0u8; 64];
        assert_eq!(match shake_256_output.next_bytes(&mut hash_shake_256) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_shake_256)
        }, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
    }
}