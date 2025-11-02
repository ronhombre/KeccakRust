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