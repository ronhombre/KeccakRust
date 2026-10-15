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
#![allow(non_camel_case_types)]
#![cfg_attr(all(not(debug_assertions), not(feature = "executable")), no_std)]

use crate::constants::KMAC_ENCODED;
#[cfg(all(not(debug_assertions), not(feature = "executable")))]
use core::panic::PanicInfo;

//Expose streams to allow usage in `Option<T>` for example
pub use crate::streams::HashInputStream;
pub use crate::streams::HashOutputStream;

mod constants;
#[cfg(feature = "ffi")]
pub mod keccakmath;
#[cfg(not(feature = "ffi"))]
mod keccakmath;
mod streams;

#[derive(PartialEq)]
pub struct KeccakParameter {
    pub name: &'static str,
    pub min_length: u32,
    pub max_length: u32,
    pub bitrate: u32,
    pub padding_bytes: &'static [u8],
    pub padding_bitcount: u8,
}

impl KeccakParameter {
    /// Keccak\[448\](M||01, 224)
    pub const SHA3_224: KeccakParameter = KeccakParameter {
        name: "SHA3-224",
        min_length: 224,
        max_length: 256,
        bitrate: 1152,
        padding_bytes: &[0b10],
        padding_bitcount: 2,
    };
    /// Keccak\[512\](M||01, 256)
    pub const SHA3_256: KeccakParameter = KeccakParameter {
        name: "SHA3-256",
        min_length: 256,
        max_length: 256,
        bitrate: 1088,
        padding_bytes: &[0b10],
        padding_bitcount: 2,
    };
    /// Keccak\[768\](M||01, 384)
    pub const SHA3_384: KeccakParameter = KeccakParameter {
        name: "SHA3-384",
        min_length: 384,
        max_length: 384,
        bitrate: 832,
        padding_bytes: &[0b10],
        padding_bitcount: 2,
    };
    /// Keccak\[1024\](M||01, 512)
    pub const SHA3_512: KeccakParameter = KeccakParameter {
        name: "SHA3-512",
        min_length: 512,
        max_length: 512,
        bitrate: 576,
        padding_bytes: &[0b10],
        padding_bitcount: 2,
    };
    /// Keccak\[256\](M||11, d)
    pub const RAWSHAKE_128: KeccakParameter = KeccakParameter {
        name: "RawSHAKE-128",
        min_length: 128,
        max_length: 0,
        bitrate: 1344,
        padding_bytes: &[0b11],
        padding_bitcount: 2,
    };
    /// Keccak\[512\](M||11, d)
    pub const RAWSHAKE_256: KeccakParameter = KeccakParameter {
        name: "RawSHAKE-256",
        min_length: 256,
        max_length: 0,
        bitrate: 1088,
        padding_bytes: &[0b11],
        padding_bitcount: 2,
    };
    /// Keccak\[256\](M||1111, d) = RawSHAKE128(M||11, d)
    pub const SHAKE_128: KeccakParameter = KeccakParameter {
        name: "SHAKE-128",
        min_length: 128,
        max_length: 0,
        bitrate: 1344,
        padding_bytes: &[0b1111],
        padding_bitcount: 4,
    };
    /// Keccak\[512\](M||1111, d) = RawSHAKE256(M||11, d)
    pub const SHAKE_256: KeccakParameter = KeccakParameter {
        name: "SHAKE-256",
        min_length: 256,
        max_length: 0,
        bitrate: 1088,
        padding_bytes: &[0b1111],
        padding_bitcount: 4,
    };
    /// SHAKE128 equivalent if N and S is empty "".
    ///
    /// Keccak\[256\](bytepad(encode_string(N)||encode_string(S), 168)||X||00, d) = cSHAKE128(encode_string(N)||encode_string(S), 168)||X||00, d)
    pub const CSHAKE_128: KeccakParameter = KeccakParameter {
        name: "cSHAKE-128",
        min_length: 128,
        max_length: 0,
        bitrate: 1344,
        padding_bytes: &[0b00],
        padding_bitcount: 2,
    };
    /// SHAKE256 equivalent if N and S is empty "".
    ///
    /// Keccak\[512\](bytepad(encode_string(N)||encode_string(S), 136)||X||00, d) = cSHAKE128(encode_string(N)||encode_string(S), 136)||X||00, d)
    pub const CSHAKE_256: KeccakParameter = KeccakParameter {
        name: "cSHAKE-256",
        min_length: 256,
        max_length: 0,
        bitrate: 1088,
        padding_bytes: &[0b00],
        padding_bitcount: 2,
    };
    /// newX = bytepad(encode_string(K), 136) || X || right_encode(L);
    /// T = bytepad(encode_string("KMAC") || encode_string(S), 136);
    /// Keccak\[256\](T || newX || 00, L)
    pub const KMAC_128: KeccakParameter = KeccakParameter {
        name: "KMAC-128",
        min_length: 128,
        max_length: 0,
        bitrate: 1344,
        padding_bytes: &[0b00],
        padding_bitcount: 2,
    };
    /// newX = bytepad(encode_string(K), 168) || X || right_encode(L);
    /// T = bytepad(encode_string("KMAC") || encode_string(S), 168);
    /// Keccak\[512\](T || newX || 00, L)
    pub const KMAC_256: KeccakParameter = KeccakParameter {
        name: "KMAC-256",
        min_length: 256,
        max_length: 0,
        bitrate: 1088,
        padding_bytes: &[0b00],
        padding_bitcount: 2,
    };
    /// newX = bytepad(encode_string(K), 136) || X || right_encode(0);
    /// T = bytepad(encode_string("KMAC") || encode_string(S), 136);
    /// Keccak\[256\](T || newX || 00, L)
    pub const KMACXOF_128: KeccakParameter = KeccakParameter {
        name: "KMACXOF-128",
        min_length: 128,
        max_length: 0,
        bitrate: 1344,
        padding_bytes: &[0b00],
        padding_bitcount: 2,
    };
    /// newX = bytepad(encode_string(K), 168) || X || right_encode(0);
    /// T = bytepad(encode_string("KMAC") || encode_string(S), 168);
    /// Keccak\[512\](T || newX || 00, L)
    pub const KMACXOF_256: KeccakParameter = KeccakParameter {
        name: "KMACXOF-256",
        min_length: 256,
        max_length: 0,
        bitrate: 1088,
        padding_bytes: &[0b00],
        padding_bitcount: 2,
    };

    /// Get byterate from bitrate
    pub fn byterate(&self) -> u8 {
        (self.bitrate >> 3).try_into().unwrap()
    }
}

impl Clone for KeccakParameter {
    fn clone(&self) -> Self {
        KeccakParameter {
            name: self.name,
            min_length: self.min_length,
            max_length: self.max_length,
            bitrate: self.bitrate,
            padding_bytes: self.padding_bytes,
            padding_bitcount: self.padding_bitcount,
        }
    }
}
pub struct SHA3_224 {}
pub struct SHA3_256 {}
pub struct SHA3_384 {}
pub struct SHA3_512 {}
pub struct RAWSHAKE_128 {}
pub struct RAWSHAKE_256 {}
pub struct SHAKE_128 {}
pub struct SHAKE_256 {}
pub struct CSHAKE_128 {}
pub struct CSHAKE_256 {}
pub struct KMAC_128 {}
pub struct KMAC_256 {}
pub struct KMACXOF_128 {}
pub struct KMACXOF_256 {}

//Type aliases to make it a tiny bit more readable when using.

type SHA3_224InputStream = HashInputStream;
type SHA3_256InputStream = HashInputStream;
type SHA3_384InputStream = HashInputStream;
type SHA3_512InputStream = HashInputStream;
type RAWSHAKE_128InputStream = HashInputStream;
type RAWSHAKE_256InputStream = HashInputStream;
type SHAKE_128InputStream = HashInputStream;
type SHAKE_256InputStream = HashInputStream;
type CSHAKE_128InputStream = HashInputStream;
type CSHAKE_256InputStream = HashInputStream;
type KMAC_128InputStream = HashInputStream;
type KMAC_256InputStream = HashInputStream;
type KMACXOF_128InputStream = HashInputStream;
type KMACXOF_256InputStream = HashInputStream;

//There's no point using traits here.

//TODO: Implement non-inputstream variants
impl SHA3_224 {
    pub fn new_input_stream() -> SHA3_224InputStream {
        HashInputStream::new(
            &KeccakParameter::SHA3_224,
            (KeccakParameter::SHA3_224.min_length / 8) as usize,
            false,
        )
    }

    pub fn digest(input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream();

        stream.write_bytes(input);

        stream.close()
    }
}

impl SHA3_256 {
    pub fn new_input_stream() -> SHA3_256InputStream {
        HashInputStream::new(
            &KeccakParameter::SHA3_256,
            (KeccakParameter::SHA3_256.min_length / 8) as usize,
            false,
        )
    }

    pub fn digest(input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream();

        stream.write_bytes(input);

        stream.close()
    }
}

impl SHA3_384 {
    pub fn new_input_stream() -> SHA3_384InputStream {
        HashInputStream::new(
            &KeccakParameter::SHA3_384,
            (KeccakParameter::SHA3_384.min_length / 8) as usize,
            false,
        )
    }

    pub fn digest(input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream();

        stream.write_bytes(input);

        stream.close()
    }
}

impl SHA3_512 {
    pub fn new_input_stream() -> SHA3_512InputStream {
        HashInputStream::new(
            &KeccakParameter::SHA3_512,
            (KeccakParameter::SHA3_512.min_length / 8) as usize,
            false,
        )
    }

    pub fn digest(input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream();

        stream.write_bytes(input);

        stream.close()
    }
}

impl RAWSHAKE_128 {
    pub fn new_input_stream() -> RAWSHAKE_128InputStream {
        HashInputStream::new(&KeccakParameter::RAWSHAKE_128, 0usize, false)
    }

    pub fn digest(input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream();

        stream.write_bytes(input);

        stream.close()
    }
}

impl RAWSHAKE_256 {
    pub fn new_input_stream() -> RAWSHAKE_256InputStream {
        HashInputStream::new(&KeccakParameter::RAWSHAKE_256, 0usize, false)
    }

    pub fn digest(input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream();

        stream.write_bytes(input);

        stream.close()
    }
}

impl SHAKE_128 {
    pub fn new_input_stream() -> SHAKE_128InputStream {
        HashInputStream::new(&KeccakParameter::SHAKE_128, 0usize, false)
    }

    pub fn digest(input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream();

        stream.write_bytes(input);

        stream.close()
    }
}

impl SHAKE_256 {
    pub fn new_input_stream() -> SHAKE_256InputStream {
        HashInputStream::new(&KeccakParameter::SHAKE_256, 0usize, false)
    }

    pub fn digest(input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream();

        stream.write_bytes(input);

        stream.close()
    }
}

fn write_cshake_pre_padding(
    stream: &mut HashInputStream,
    function_name: &[u8],
    customization: &[u8],
) {
    let mut encoding_buffer = [0u8; 9];
    let mut encoded_length: usize;

    //left_encode(r)
    encoded_length =
        keccakmath::left_encode(&mut encoding_buffer, stream.parameter.byterate() as u64);
    stream.write_bytes(&encoding_buffer[0..encoded_length]);

    //encode_string(N)
    encoding_buffer.fill(0); //Clear buffer
    encoded_length = keccakmath::left_encode(&mut encoding_buffer, function_name.len() as u64 * 8);
    stream.write_bytes(&encoding_buffer[0..encoded_length]);

    stream.write_bytes(function_name);

    //encode_string(S)
    encoding_buffer.fill(0); //Clear buffer
    encoded_length = keccakmath::left_encode(&mut encoding_buffer, customization.len() as u64 * 8);
    stream.write_bytes(&encoding_buffer[0..encoded_length]);

    stream.write_bytes(customization);

    //Pad to a multiple of r
    stream.force_permute(); //Equivalent to padding with zeroes
}

impl CSHAKE_128 {
    pub fn new_input_stream(function_name: &[u8], customization: &[u8]) -> CSHAKE_128InputStream {
        let parameter = if function_name.len() + customization.len() != 0 {
            KeccakParameter::CSHAKE_128
        } else {
            KeccakParameter::SHAKE_128
        };
        let mut stream = HashInputStream::new(&parameter, 0, false);

        if function_name.len() + customization.len() != 0 {
            write_cshake_pre_padding(&mut stream, function_name, customization);
        }

        stream
    }

    pub fn digest(function_name: &[u8], customization: &[u8], input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream(function_name, customization);

        stream.write_bytes(input);

        stream.close()
    }
}

impl CSHAKE_256 {
    pub fn new_input_stream(function_name: &[u8], customization: &[u8]) -> CSHAKE_256InputStream {
        let parameter = if function_name.len() + customization.len() != 0 {
            KeccakParameter::CSHAKE_256
        } else {
            KeccakParameter::SHAKE_256
        };
        let mut stream = HashInputStream::new(&parameter, 0, false);

        if function_name.len() + customization.len() != 0 {
            write_cshake_pre_padding(&mut stream, function_name, customization);
        }

        stream
    }

    pub fn digest(function_name: &[u8], customization: &[u8], input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream(function_name, customization);

        stream.write_bytes(input);

        stream.close()
    }
}

fn write_kmac_pre_padding(stream: &mut HashInputStream, key: &[u8], customization: &[u8]) {
    let mut encoding_buffer = [0u8; 9];
    let mut encoded_length: usize;

    //Add T bytes and padding
    //left_encode(r)
    encoded_length =
        keccakmath::left_encode(&mut encoding_buffer, stream.parameter.byterate() as u64);
    stream.write_bytes(&encoding_buffer[0..encoded_length]);

    //encode_string("KMAC")
    encoding_buffer.fill(0); //Clear buffer
    encoded_length = keccakmath::left_encode(&mut encoding_buffer, KMAC_ENCODED.len() as u64 * 8);
    stream.write_bytes(&encoding_buffer[0..encoded_length]);

    stream.write_bytes(&KMAC_ENCODED);

    //encode_string(S)
    encoding_buffer.fill(0); //Clear buffer
    encoded_length = keccakmath::left_encode(&mut encoding_buffer, customization.len() as u64 * 8);
    stream.write_bytes(&encoding_buffer[0..encoded_length]);

    stream.write_bytes(customization);

    //Pad to a multiple of r
    stream.force_permute(); //Equivalent to padding with zeroes

    //Add newX bytes and padding
    //left_encode(r)
    encoding_buffer.fill(0); //Clear buffer
    encoded_length =
        keccakmath::left_encode(&mut encoding_buffer, stream.parameter.byterate() as u64);
    stream.write_bytes(&encoding_buffer[0..encoded_length]);

    //encode_string(K)
    encoding_buffer.fill(0); //Clear buffer
    encoded_length = keccakmath::left_encode(&mut encoding_buffer, key.len() as u64 * 8);
    stream.write_bytes(&encoding_buffer[0..encoded_length]);

    stream.write_bytes(key);

    //Pad to a multiple of r
    stream.force_permute(); //Equivalent to padding with zeroes
}

impl KMAC_128 {
    pub fn new_input_stream(
        key: &[u8],
        customization: &[u8],
        output_length: usize,
    ) -> KMAC_128InputStream {
        let mut stream = HashInputStream::new(&KeccakParameter::KMAC_128, output_length, true);

        write_kmac_pre_padding(&mut stream, key, customization);

        stream
    }

    pub fn digest(
        key: &[u8],
        customization: &[u8],
        output_length: usize,
        input: &[u8],
    ) -> HashOutputStream {
        let mut stream = Self::new_input_stream(key, customization, output_length);

        stream.write_bytes(input);

        stream.close()
    }
}

impl KMAC_256 {
    pub fn new_input_stream(
        key: &[u8],
        customization: &[u8],
        output_length: usize,
    ) -> KMAC_256InputStream {
        let mut stream = HashInputStream::new(&KeccakParameter::KMAC_256, output_length, true);

        write_kmac_pre_padding(&mut stream, key, customization);

        stream
    }

    pub fn digest(
        key: &[u8],
        customization: &[u8],
        output_length: usize,
        input: &[u8],
    ) -> HashOutputStream {
        let mut stream = Self::new_input_stream(key, customization, output_length);

        stream.write_bytes(input);

        stream.close()
    }
}

impl KMACXOF_128 {
    pub fn new_input_stream(key: &[u8], customization: &[u8]) -> KMACXOF_128InputStream {
        let mut stream = HashInputStream::new(&KeccakParameter::KMACXOF_128, 0usize, true);

        write_kmac_pre_padding(&mut stream, key, customization);

        stream
    }

    pub fn digest(key: &[u8], customization: &[u8], input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream(key, customization);

        stream.write_bytes(input);

        stream.close()
    }
}

impl KMACXOF_256 {
    pub fn new_input_stream(key: &[u8], customization: &[u8]) -> KMACXOF_256InputStream {
        let mut stream = HashInputStream::new(&KeccakParameter::KMACXOF_256, 0usize, true);

        write_kmac_pre_padding(&mut stream, key, customization);

        stream
    }

    pub fn digest(key: &[u8], customization: &[u8], input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream(key, customization);

        stream.write_bytes(input);

        stream.close()
    }
}

#[cfg(all(not(debug_assertions), not(feature = "executable"), not(feature = "ffi")))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}