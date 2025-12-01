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

#[cfg(all(not(debug_assertions), not(feature = "executable")))]
use core::panic::PanicInfo;
use crate::constants::KMAC_ENCODED;

//Expose streams to allow usage in `Option<T>` for example
pub use crate::streams::HashInputStream;
pub use crate::streams::HashOutputStream;

mod keccakmath;
mod constants;
mod streams;

#[derive(PartialEq)]
pub struct KeccakParameter {
    pub name: &'static str,
    pub min_length: u32,
    pub max_length: u32,
    pub bitrate: u32,
    pub padding_bytes: &'static [u8],
    pub padding_bitcount: u8
}

impl KeccakParameter {
    /// Keccak\[448\](M||01, 224)
    pub const SHA3_224: KeccakParameter = KeccakParameter {
        name: "SHA3-224",
        min_length: 224,
        max_length: 256,
        bitrate: 1152,
        padding_bytes: &[0b10],
        padding_bitcount: 2
    };
    /// Keccak\[512\](M||01, 256)
    pub const SHA3_256: KeccakParameter = KeccakParameter {
        name: "SHA3-256",
        min_length: 256,
        max_length: 256,
        bitrate: 1088,
        padding_bytes: &[0b10],
        padding_bitcount: 2
    };
    /// Keccak\[768\](M||01, 384)
    pub const SHA3_384: KeccakParameter = KeccakParameter {
        name: "SHA3-384",
        min_length: 384,
        max_length: 384,
        bitrate: 832,
        padding_bytes: &[0b10],
        padding_bitcount: 2
    };
    /// Keccak\[1024\](M||01, 512)
    pub const SHA3_512: KeccakParameter = KeccakParameter {
        name: "SHA3-512",
        min_length: 512,
        max_length: 512,
        bitrate: 576,
        padding_bytes: &[0b10],
        padding_bitcount: 2
    };
    /// Keccak\[256\](M||11, d)
    pub const RAWSHAKE_128: KeccakParameter = KeccakParameter {
        name: "RawSHAKE-128",
        min_length: 128,
        max_length: 0,
        bitrate: 1344,
        padding_bytes: &[0b11],
        padding_bitcount: 2
    };
    /// Keccak\[512\](M||11, d)
    pub const RAWSHAKE_256: KeccakParameter = KeccakParameter {
        name: "RawSHAKE-256",
        min_length: 256,
        max_length: 0,
        bitrate: 1088,
        padding_bytes: &[0b11],
        padding_bitcount: 2
    };
    /// Keccak\[256\](M||1111, d) = RawSHAKE128(M||11, d)
    pub const SHAKE_128: KeccakParameter = KeccakParameter {
        name: "SHAKE-128",
        min_length: 128,
        max_length: 0,
        bitrate: 1344,
        padding_bytes: &[0b1111],
        padding_bitcount: 4
    };
    /// Keccak\[512\](M||1111, d) = RawSHAKE256(M||11, d)
    pub const SHAKE_256: KeccakParameter = KeccakParameter {
        name: "SHAKE-256",
        min_length: 256,
        max_length: 0,
        bitrate: 1088,
        padding_bytes: &[0b1111],
        padding_bitcount: 4
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
        padding_bitcount: 2
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
        padding_bitcount: 2
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
        padding_bitcount: 2
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
        padding_bitcount: 2
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
        padding_bitcount: 2
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
        padding_bitcount: 2
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
            padding_bitcount: self.padding_bitcount
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
            false
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
            false
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
            false
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
            false
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
        HashInputStream::new(
            &KeccakParameter::RAWSHAKE_128,
            0usize,
            false
        )
    }

    pub fn digest(input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream();

        stream.write_bytes(input);

        stream.close()
    }
}

impl RAWSHAKE_256 {
    pub fn new_input_stream() -> RAWSHAKE_256InputStream {
        HashInputStream::new(
            &KeccakParameter::RAWSHAKE_256,
            0usize,
            false
        )
    }

    pub fn digest(input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream();

        stream.write_bytes(input);

        stream.close()
    }
}

impl SHAKE_128 {
    pub fn new_input_stream() -> SHAKE_128InputStream {
        HashInputStream::new(
            &KeccakParameter::SHAKE_128,
            0usize,
            false
        )
    }

    pub fn digest(input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream();

        stream.write_bytes(input);

        stream.close()
    }
}

impl SHAKE_256 {
    pub fn new_input_stream() -> SHAKE_256InputStream {
        HashInputStream::new(
            &KeccakParameter::SHAKE_256,
            0usize,
            false
        )
    }

    pub fn digest(input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream();

        stream.write_bytes(input);

        stream.close()
    }
}

fn write_cshake_pre_padding(stream: &mut HashInputStream, function_name: &[u8], customization: &[u8]) {
    let mut encoding_buffer = [0u8; 9];
    let mut encoded_length: usize;

    //left_encode(r)
    encoded_length = keccakmath::left_encode(&mut encoding_buffer, stream.parameter.byterate() as u64);
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
        let mut stream =  HashInputStream::new(
            &parameter,
            0,
            false
        );

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
        let mut stream =  HashInputStream::new(
            &parameter,
            0,
            false
        );

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
    encoded_length = keccakmath::left_encode(&mut encoding_buffer, stream.parameter.byterate() as u64);
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
    encoded_length = keccakmath::left_encode(&mut encoding_buffer, stream.parameter.byterate() as u64);
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
    pub fn new_input_stream(key: &[u8], customization: &[u8], output_length: usize) -> KMAC_128InputStream {
        let mut stream =  HashInputStream::new(
            &KeccakParameter::KMAC_128,
            output_length,
            true
        );

        write_kmac_pre_padding(&mut stream, key, customization);

        stream
    }

    pub fn digest(key: &[u8], customization: &[u8], output_length: usize, input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream(key, customization, output_length);

        stream.write_bytes(input);

        stream.close()
    }
}

impl KMAC_256 {
    pub fn new_input_stream(key: &[u8], customization: &[u8], output_length: usize) -> KMAC_256InputStream {
        let mut stream =  HashInputStream::new(
            &KeccakParameter::KMAC_256,
            output_length,
            true
        );

        write_kmac_pre_padding(&mut stream, key, customization);

        stream
    }

    pub fn digest(key: &[u8], customization: &[u8], output_length: usize, input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream(key, customization, output_length);

        stream.write_bytes(input);

        stream.close()
    }
}

impl KMACXOF_128 {
    pub fn new_input_stream(key: &[u8], customization: &[u8]) -> KMACXOF_128InputStream {
        let mut stream =  HashInputStream::new(
            &KeccakParameter::KMACXOF_128,
            0usize,
            true
        );

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
        let mut stream =  HashInputStream::new(
            &KeccakParameter::KMACXOF_256,
            0usize,
            true
        );

        write_kmac_pre_padding(&mut stream, key, customization);

        stream
    }

    pub fn digest(key: &[u8], customization: &[u8], input: &[u8]) -> HashOutputStream {
        let mut stream = Self::new_input_stream(key, customization);

        stream.write_bytes(input);

        stream.close()
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

    const EXPECTED_SHA3_224: &str = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
    const EXPECTED_SHA3_256: &str = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    const EXPECTED_SHA3_384: &str = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
    const EXPECTED_SHA3_512: &str = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    const EXPECTED_RAWSHAKE_128: &str = "fa019a3b17630df6014853b5470773f13c3ab704478211d7a65867515dea1cc7";
    const EXPECTED_RAWSHAKE_128_LONG: &str = "8e591af01377bc9f205190814ad7d05b5ef10bfd452dfca5f90e18926cd9606f099731cd6fa67e8482217efab5e63a7feefaa4ab6dec169934088c9ee82438ef0dc611216bcb10686a490b3c64420aae840819a738152c3cc3379973718f6b5bb9124a7bff68448b8fbb1954174508a839642109872a820a87b90666f91c255072696772ca644a15ba46d65c76ca2d079d9496d6480896049a039223ea523af6ba76df5b8d6797ee0eccd62be387d3560fdc188296c96ab52efd7fc6c044c39098c2568044c945bee4a300becf8ebc59a2b33f88da5362f06bd47aba7e45f133c4a273c2b123f20535d044e925a1954b2858cf3243178548bc176228fc836f60ebbf55773846970a0b9aac290e50b9791ec0802abace3595a17d2620a0ae84de0ba7ea3e6d7fdf4d5e0d70ab1a688c9a7a67d0e95718c361e4675d44cc69db06555a30277da3f78503a7cf964ae88fa6dd0b9f5411cddd090543e51ac23815210abb7d21ad392847cb5b9a742d3238c2587fa3ba4761d649a5007bfe03aab65a8e6c082dab9c1a6715ea2816546b20f0714b42f172e60e1f7cd1da63948e8829550de6f7233fbcb0b2a00af4f848ace1a4e20ad74510ae0712f56ec0b64bb90415b5c21a4cf1f1bbbfe1cc1ef43519493f4307a346245c33f08da2688de3feb4f20d1fa57db703f2865d69e70d45f3dc465dba33fb62b249e766d5dbaa3153f824590def8d05319061f3a49adb0188f0cac3d8f41296fce0bf1456cc789604a301d890e35e01120e3fe0a895864f05df8e385ad5d3b66a0ffc9ec7e0bb5b64c4a8e26e946ef1d41ddeb69c503e85a298ba9346bcfa2ff353488a92821558a457470098e251929ec648dcf9d8d75c07647d28431457e49dfc49de22beba72bcdc8ada6a7ed9baa09221681d32662adfff3bfac5931e6f6a25bd93c3f53115262bfe76ca3fa6439a3693e6c7bf55aac8aeb4a2cbe7d2d6f713d4bf2ea1a8761d695a897b52b369a6e8bd4be9bac97c19455ee1d013021438d63e680d9f6204dd2ad4a683c6e06824494034fd01a9d00838bee12ebe27fb609dec9f58c323223f6386adc7368c6c8bf865a7f025ce7bfaed38b93f5c945d2644e8e6c9f03b651905a228093bcee633b10132be9c4cca813693486880e9e5b3dd3cae9e84b90cee443afd2f734a29413cd31ab65e1bd4563701526e44a47008b27412c339e83d324b2a67c6fba4c2cd3448454dd74d84572069097567c162d4855fe56130b5588ff44179b429081c0cfaafde1eae13babfdae660ab3d80dc1b77b8526c13935413a85e7cfc3676bc091f6caaa55a8fabca5f4205eb880ef06647fc1540fd878e3228f0c0018a930232a14d995c08d38b281d16a8336b39995e1b099f93ac31e28e244a1a2973fe494ddb2e332522790fd728e8ad1bb18052dfc56a1f5dd43fd9b74f";
    const EXPECTED_RAWSHAKE_256: &str = "3a1108d4a90a31b85a10bdce77f4bfbdcc5b1d70dd405686f8bbde834aa1a410db8c9e1c166c3e239cd76a55f6a692aa2d1749f2ec79cd0ba3b17bb659959b6e";
    const EXPECTED_RAWSHAKE_256_LONG: &str = "717b3130468c871173530b5d48f27cd2afb8034d9ff755bbaff88c95fba72f8513735d9e9207df038de8a6218facac57349aa411352d719ea157ff07efb16e37d0ca4234ce7811e5487a93c6f05b10a7e246567b8115d4e8898273f4e038a3d752dbf108856b22879492d44d34a51ffa6b051a667bdf04cc0136e64590dd29a34153e30bc4f36a4bae5135e78734c1189d792129bd0828d488b386b7b32405d3c8e265c3a5aa9272177ebfd247b2cf3202bb213fc31a5ac9afef8064a911ded3636c556770fd9e593756853fe19a947fd3b940789ce8968059d8753b4752fc39af5c92aba715e00db9522a029df7d66805a9839de18ed72a45c44cf202b226266c94673f37605f201895a82bebe42fed180627673a379e759a42a6148bf7c4b96495fe215b9fcf2913e609e5aac0a050f16b9bd56f39563e53bfebae22c47edfb0b9ef1852b07631d0ae28fd22a908c0416db8bbc98e15a7b0be2b99d6689898535218d4247135d1ad280ace371d764e5217cb9adc6d8318a398c704ab73e24ff9065808bc4baf1852bf80aaa771d24b78cccc98bdddda013cf64f2efd2874e0ba97ab4e88d22804043d6d7d0f93f3efbad48609146b5779625b427d66927a997279fdf32e22b7753a2dfbd2061dbfba30d9ec7be06bdab2c666eacb9f7720265c0749e807bff83457cd7d0688f4cff225086fd171c661fc21cdb317b6ab3651ea8dbbd74291ddde49e0f8ab4cdcf0cdefe58772836d33058f44a9850aa5a8358122f53516fa4d0a77e6ef10dafec885acb22f078952119d613fb750fe53968f78e4d440b243cfd62d97bc459d88302a55b37f981ff50531d32b4d87c317eca8f2e025fdbb2c2955158b9de6d26ed464ed8c6d973ffd3af91e287456ab007d0973ddcbd7d07ea98443aeb2e74bc16ec33dbb83be8c409a689e685e5f516f166692a0b29433701d3da3049641d1f72fb17682bcfe46d020c04c1851dac3a5af1cadfdbee4ba213495064c37ea2108efd678946406d11a1fddb9549ab9bbd1dd8b0106ec72f73db598840878a641b8a534e849d7f018fedd1bb67e83d0d7271ecc8ea10ee72a07ea0a82c466510f4a748fcc646c8e433ce6da9c0857eada732e61b3983dec4772c109bfc83d1c59c52aa0a7bd5a571a5d60c979f86db596e058271028d299ece998dfd52467431729f1b1708514412ecc6af6d4be4e8e475cf2e9fbc89a83be83688ecbef7c64aa758e81bbcef3dfeca94f0fe3241435482037595f2751baf41489cd2ce806b5a97d7ebd1c6cdd8d884c1d9f3a1927c0c439e3912e5364eaa6cd6a891a870b697c4e812f9fc43f2d934c35b7dfe74d3dac09ed24da2a39dcca7a9dee831fa9c17aa3bddac208cec686cda5355f06ad143e48381bf99e109cc517bff507b948863395eabaec7ecda2a7d0399414395a4f58771efe";
    const EXPECTED_SHAKE_128: &str = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
    const EXPECTED_SHAKE_128_LONG: &str = "ded1700844a9e88da77fa25120bdf862309aa1b9a134c8ddde2605e820174ab038f7bfd132648f5fce7f3bf3b9874dcd8b824e588df3be94f2c0ae680c8ad423b28fd1c590850cdb6762eff7d9f4de14da4738e0cd2a0eac90bf397bb380ec910d9055ae876fb77e7cc03328ac1f239e3009d255b8a2798224821aa66e088a8fa317ed65a3a6f12cdaaa16edf78fb38379a079270b7c75f9ab9ef757da3347e1e312cd69ae1657a3a870dc2a7b6f8815862e98965c2f6eaa51e2abca21b87b4e12be39571ebe278a6e577dd6d232fa92510ea50070629e7eb41fe08af64843a2e4aa502eb70bcfa98ad24769bbd820e83c3e8d4b113b8219cd0d1c87b807b0cc90f7086f4d4832799ea7b99ab1242326fcb2304827669fd7ddadd6d5083f6b9468c8f0aeeaea69a43894a8122ea6d46e9547c164f998fad9215f6517b467dfada261577b09a83d6751c616a5122f6aab0cf3249221893270498764d2a1043bf226d9cd61d2b1f30f7386a89c1e1bf1b1e24f412c83607b0e80f4c62527658715ea94b9bf3a355e3cba23f2b2a801aac4111e1714bcb03edbd6ea3f50e01142688b6d22ebc069c1d5cc9f718316e1e280d38417f07fbb82ff87734d57e426cdd0a392bb18b190905c0d598892ca0a3a623b22f2068202993da74f38a71cb4d125cbf71d691167029e592a0302a6e44dfdb764ac1bb2615db272195f622cbb83f83dacdcb8557814bfb39dfe283716e6b2f06299a82a83c15912ffc5ca72ee61b4207c289421835652252af8ea4be3abefebbb686e450baa69db2761fb3da64ae7bfe3ac03d326a3f5dd7bc6e9932040699097d111b77a0813c3f2eda9888872b35d3c130953511b61f3d9e8061f447a9dd320b3a1522f77d0da8560b0d5651a6517c9aefc022423b5738828c241ff9c01706ebe7772a1b51c074285ef0d6028da472179c82292207ce2761c3b298c512f2b75f421414e8febf05b1f6441de800dbfb0094b665fa80663f522f23f291e386f0d03a1255c13345ff1ecd3618ff0dddac73685055c43f9908ef9c87af1dbc2488ad6f5d4c8a194f19667e318d30e7ddc5a2fe241a465cb3c02d3c539615f352f1c58ced21d4e3aaf1fa79c169cccb86b6ca04718b6ef5059bc11420ff9093dc893aa3bb35d1980595f156601b41ef5f9dcd86e0478722fd1b506229f121f2c97c240f8ecc5a6782e433969e38974fd71d31874c6ad3751f43640a7697484fad3ba0aeec0e82a82d6087ebf923d40bd93d03e4a680eda0426b68b86af9046899fe9a8b1f639a5fc2b6547c63a06aed42c02cae64de594dc648b69d56bb7ae2bd590a759383ee291bcf454bfca7bda73eaee0658256c973bea914f76825bc6b842cad4d0b7c29cafa6310eadf85ebc83a2d759564de74613d35941b045403d17501fd500939523d87d880fdf0066fa61";
    const EXPECTED_SHAKE_256: &str = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
    const EXPECTED_SHAKE_256_LONG: &str = "98de64677ff98f899d33f8ac72f6155235a9a2815be05fd44334a36c93d22b40f201dc7186b9036e6611d0ef3172a35cf30f79b637fb19e79aebf5d7c301775fbdfee5282f6d06955ac86747e414432d5034c412adff611e3e86a2fb606caec0375322a2d42abb4953390ec5939289e254fcdfce03e5b9750710efaa84f3cbe24ef972e351be0f3fe737ec5a39cbf1987b0674d68e1f57c497074762eb064a77bdd7b93b91ef8260a17879fcb3cb39ab932127dad84585e970fc564312e4c3af52b36d76babeb9599cb1479bb883408f6da4540c3cccca8006616d5120b12afc6974ca50ae0b60d4f5534bdc87e501bf35faab8979d6b00ff73ac94da6d2b4e3bab321cb4291dd6c84a781c027f10d25ad91aacdde9348fef33e7182e41904c4b33d784fe385ad5102b7fcce2300a4e8576f54aa15737ed8982aeeb50de4bda2570f50729844e618fe625b2852e12a6ec55557a4e09b76634629be41a9fd534198b215ec667ce128562d45dc21654f74d0846458c07b11809bb5b7debf2a4d95f44881b79cd77f5d1841eae96062b04371ce048794023387b2c8db2a11e41881f4b8762ae3492d675d40481b9a2ce00b065023cb3b69327543fbfe79fb62a7c83430e9f859a8becb158d7987fdbe75b1f134161e8a5918994591ac449ac7ec1b4ab0041a14b89d3237a319b4051caa16f23db0b763b640822895bc2f0885df03af30e9742384f2bc938f27498cdf47e3c2043c56cfd1a326ff6f41bbc5044981037831bcd14c001b27b39e58841fcbd26e16ec2b69fe5f9c85bf02f3b5ba96bc5487171f91efa2589fdbf80d7062e1d6adef855c901055c0548d7f6255ee106d0e1d3947a58f7c4e8856a0095c5e3a806eb33853c208a79923350141be4de01277a0caedc26e72452c9c11b9743d6799b014d35836e7d117008a6d3fe27b429e1430dd3e5cfb0f89c10d50c8fe2a6c2d43077994488e0b592e1c43c85414373841dfdc9a751d0c78416ab41340b044a6ae4f22a146da5e51551dc100875b0fa5fc0041737adf9c86d3aca56bc1f2fd2d42521c6239285f99f72d6c402d26577d2cfcecff4ab703c632ee9a6b740e0fb0f7df90ec8a20de8ca10e9d72fae7469993bd9afa68fca07efe08a054a5ba5260a6cba317d9605b15c193574d7a9eb11ffbec53b276b690e5b6dc7d3c6f2b8e2f8e7b5b5e8e5382649352a71652240fd9d1d465e55e556a4f4a59a0b8782f6fad1e1226fadaec0a45eca9ef107d954ac22076c8245b77ac5c31bd1ff6fc3f3a25e89c9d8c1f6bb524f5e554e5970cae92e4a5d376bc08feba396b6334540b7c5b3c9a3791993f4d24551f49bd9a46e2391b9201f65b9d58cfa95c579c6035aa4b3956cf1d44a03486f2763b8437d4a86940192866d91979ed01fc221ff24179bf040272ae83f06c16d3c2defaff5383ef";

    //SP 800-185
    //These values are based on the test cases in KeccakKotlin
    const CSHAKE_FUNCTION_NAME: &str = "TAK";
    const CSHAKE_CUSTOMIZATION: &str = "KAT";

    const EXPECTED_CSHAKE_128: &str = "3284fd3b44c6d5e3a3acec6c81cebf62";
    const EXPECTED_CSHAKE_256: &str = "c1495f818da538983d382ba9675cad7c44f5df0940d24a6c11d0edcabf235308";

    //These values are based on NIST CSRC
    const KMAC_KEY: &str = "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F";
    const KMAC_CUSTOMIZATION: &str = "My Tagged Application";
    const KMAC_DATA: &str = "00010203";

    const EXPECTED_KMAC_128: &str = "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5";
    const EXPECTED_KMAC_256: &str = "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd";
    const EXPECTED_KMACXOF_128: &str = "31a44527b4ed9f5c6101d11de6d26f06";
    const EXPECTED_KMACXOF_256: &str = "1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa9";

    #[test]
    fn sha3_224() {
        let mut sha3_224 = SHA3_224::new_input_stream();
        sha3_224.write_bytes(&[0u8; 0]); //Write nothing
        let mut sha3_224_output = sha3_224.close();
        let mut hash_224 = [0u8; 28];
        assert_eq!(match sha3_224_output.next_bytes(&mut hash_224) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_224)
        }, EXPECTED_SHA3_224);
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
        }, EXPECTED_SHA3_256);
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
        }, EXPECTED_SHA3_384);
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
        }, EXPECTED_SHA3_512);
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
        }, EXPECTED_RAWSHAKE_128);
    }

    #[test]
    fn rawshake_128_long() {
        let mut rawshake_128 = RAWSHAKE_128::new_input_stream();
        rawshake_128.write_bytes(EXPECTED_RAWSHAKE_128.as_bytes());
        let mut rawshake_128_output = rawshake_128.close();
        let mut hash_rawshake_128 = [0u8; 1024];
        assert_eq!(match rawshake_128_output.next_bytes(&mut hash_rawshake_128) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_rawshake_128)
        }, EXPECTED_RAWSHAKE_128_LONG);
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
        }, EXPECTED_RAWSHAKE_256);
    }

    #[test]
    fn rawshake_256_long() {
        let mut rawshake_256 = RAWSHAKE_256::new_input_stream();
        rawshake_256.write_bytes(EXPECTED_RAWSHAKE_256.as_bytes());
        let mut rawshake_256_output = rawshake_256.close();
        let mut hash_rawshake_256 = [0u8; 1024];
        assert_eq!(match rawshake_256_output.next_bytes(&mut hash_rawshake_256) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_rawshake_256)
        }, EXPECTED_RAWSHAKE_256_LONG);
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
        }, EXPECTED_SHAKE_128);
    }

    #[test]
    fn shake_128_long() {
        let mut shake_128 = SHAKE_128::new_input_stream();
        shake_128.write_bytes(EXPECTED_SHAKE_128.as_bytes());
        let mut shake_128_output = shake_128.close();
        let mut hash_shake_128 = [0u8; 1024];
        assert_eq!(match shake_128_output.next_bytes(&mut hash_shake_128) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_shake_128)
        }, EXPECTED_SHAKE_128_LONG);
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
        }, EXPECTED_SHAKE_256);
    }

    #[test]
    fn shake_256_long() {
        let mut shake_256 = SHAKE_256::new_input_stream();
        shake_256.write_bytes(EXPECTED_SHAKE_256.as_bytes());
        let mut shake_256_output = shake_256.close();
        let mut hash_shake_256 = [0u8; 1024];
        assert_eq!(match shake_256_output.next_bytes(&mut hash_shake_256) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_shake_256)
        }, EXPECTED_SHAKE_256_LONG);
    }

    #[test]
    fn cshake_128() {
        let mut cshake_128 = CSHAKE_128::new_input_stream(CSHAKE_FUNCTION_NAME.as_bytes(), CSHAKE_CUSTOMIZATION.as_bytes());
        cshake_128.write_bytes(&[0u8; 0]); //Write nothing
        let mut cshake_128_output = cshake_128.close();
        let mut hash_cshake_128 = [0u8; 16];
        assert_eq!(match cshake_128_output.next_bytes(&mut hash_cshake_128) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_cshake_128)
        }, EXPECTED_CSHAKE_128);
    }

    #[test]
    fn cshake_256() {
        let mut cshake_256 = CSHAKE_256::new_input_stream(CSHAKE_FUNCTION_NAME.as_bytes(), CSHAKE_CUSTOMIZATION.as_bytes());
        cshake_256.write_bytes(&[0u8; 0]); //Write nothing
        let mut cshake_256_output = cshake_256.close();
        let mut hash_cshake_256 = [0u8; 32];
        assert_eq!(match cshake_256_output.next_bytes(&mut hash_cshake_256) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_cshake_256)
        }, EXPECTED_CSHAKE_256);
    }

    #[test]
    fn cshake_128_eq_shake_128() {
        let mut cshake_128 = CSHAKE_128::new_input_stream(&[0u8; 0], &[0u8; 0]); //Empty
        cshake_128.write_bytes(&[0u8; 0]); //Write nothing
        let mut cshake_128_output = cshake_128.close();
        let mut hash_cshake_128 = [0u8; 32];
        assert_eq!(match cshake_128_output.next_bytes(&mut hash_cshake_128) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_cshake_128)
        }, EXPECTED_SHAKE_128);
    }

    #[test]
    fn cshake_256_eq_shake_256() {
        let mut cshake_256 = CSHAKE_256::new_input_stream(&[0u8; 0], &[0u8; 0]); //Empty
        cshake_256.write_bytes(&[0u8; 0]); //Write nothing
        let mut cshake_256_output = cshake_256.close();
        let mut hash_cshake_256 = [0u8; 64];
        assert_eq!(match cshake_256_output.next_bytes(&mut hash_cshake_256) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_cshake_256)
        }, EXPECTED_SHAKE_256);
    }

    #[test]
    fn kmac_128() {
        let key = hex::decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
        let customization = "My Tagged Application".as_bytes();
        let mut kmac_128 = KMAC_128::new_input_stream(key.unwrap().as_slice(), customization, 256 / 8);
        kmac_128.write_bytes(hex::decode("00010203").unwrap().as_slice());
        let mut kmac_128_output = kmac_128.close();
        let mut hash_kmac_128 = [0u8; 256 / 8];
        assert_eq!(match kmac_128_output.next_bytes(&mut hash_kmac_128) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_kmac_128)
        }, EXPECTED_KMAC_128);
    }

    #[test]
    fn kmac_256() {
        let key = hex::decode(KMAC_KEY);
        let customization = KMAC_CUSTOMIZATION.as_bytes();
        let mut kmac_256 = KMAC_256::new_input_stream(key.unwrap().as_slice(), customization, 512 / 8);
        kmac_256.write_bytes(hex::decode(KMAC_DATA).unwrap().as_slice());
        let mut kmac_256_output = kmac_256.close();
        let mut hash_kmac_256 = [0u8; 512 / 8];
        assert_eq!(match kmac_256_output.next_bytes(&mut hash_kmac_256) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_kmac_256)
        }, EXPECTED_KMAC_256);
    }

    #[test]
    fn kmacxof_128() {
        let key = hex::decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
        let customization = "My Tagged Application".as_bytes();
        let mut kmacxof_128 = KMACXOF_128::new_input_stream(key.unwrap().as_slice(), customization);
        kmacxof_128.write_bytes(hex::decode("00010203").unwrap().as_slice());
        let mut kmacxof_128_output = kmacxof_128.close();
        let mut hash_kmacxof_128 = [0u8; 128 / 8];
        assert_eq!(match kmacxof_128_output.next_bytes(&mut hash_kmacxof_128) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_kmacxof_128)
        }, EXPECTED_KMACXOF_128);
    }

    #[test]
    fn kmacxof_256() {
        let key = hex::decode(KMAC_KEY);
        let customization = KMAC_CUSTOMIZATION.as_bytes();
        let mut kmacxof_256 = KMACXOF_256::new_input_stream(key.unwrap().as_slice(), customization);
        kmacxof_256.write_bytes(hex::decode(KMAC_DATA).unwrap().as_slice());
        let mut kmacxof_256_output = kmacxof_256.close();
        let mut hash_kmacxof_256 = [0u8; 256 / 8];
        assert_eq!(match kmacxof_256_output.next_bytes(&mut hash_kmacxof_256) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_kmacxof_256)
        }, EXPECTED_KMACXOF_256);
    }
}