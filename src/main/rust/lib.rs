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

    const EXPECTED_SHA3_224: &str = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
    const EXPECTED_SHA3_256: &str = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    const EXPECTED_SHA3_384: &str = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
    const EXPECTED_SHA3_512: &str = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    const EXPECTED_RAWSHAKE_128: &str = "fa019a3b17630df6014853b5470773f13c3ab704478211d7a65867515dea1cc7";
    const EXPECTED_RAWSHAKE_128_LONG: &str = "fa019a3b17630df6014853b5470773f13c3ab704478211d7a65867515dea1cc7926b2147e396076b22cb72633af50647c7f23d0d8f001d6d8daf0f6f2e92fc0eb0b52819062a6537a7753ace55690efc5f9ad847d414cb9f387ff66d849a47c209d6470189a802ff0ea7cff30515a7e102267b413885a3925f6506b4613717aca48195cfb075af6c5d93f813056d9215ff2a44e328ee25d039270798d2609d9c1ca03f0e0f1a550352a20a54c95c3ade4bd3762360673b32a8a0a984fa2a4126ad03240b46e181f2ab0ad7d1b07b025548f5c09b900533cface06c850873c835be5c17aeffae03446457744258ddcf4a994a5e21cd7a0660f5952c7c4c0d594ee4361508d9ed73256f35efa968ffcc47ebb67f03135210dcda5d33eba36a0a9c3ac9a791d7c10f6849a7a1c21e7122a99990d28891b3378caac0227eee6642a2af6597d874d47aa3a73cf1580da135c40be7fb5a3fd804100e049fe72f3201faf16e3fe29207dd5e02d529f1ab1a69119f5272f0f73bd527fa4ecb539b4eda200a4cc07137022ad152076d06c960734b609da760e07f5600e18e2c2167f75849e49e5e29e0a3de680be01a79157647ab5e1e57fc10a927dbdb2825d7caaec77567870b1c7722b1fa073977d342a03ee4fce57be3df5e70892869fb347c01cbcea39c044019d8ba08713716f2c9f00a1107a106ede6522cb1e57cc7b7fe1de3d31986f20daa3b6b00769f552099403780e639bdc31a769b35d76bdb9842d7c8dcb6ff246a7f7cfd2c4419a67aef05aa73e360e4daa01f0a535859e819e0bd385b8bfa9410b5bc939fe8fdb9fa128ee9e28091258ef4f4b0ac3d853cd1ae286fcb026fe0a026dcaeaea9522b47cfbe3a8a9d7a264396c57cb9a0099b3f24baba7ede47b24679d088eb4a76c3a353401c1e39f05c85f19791d8721d1ab914d800131c93b2fe5d8b055cf0e09295d6ab3faaead073e8b3240a2a5179e2b6e47af291f3d6bc2dcd6d237b4a3526dcd34273074deaf1529b1678c9d6f416037729be01a983534d6d6302599c4e351f1062d93d9e84b3e6f1b9d381e3caacc055b247813b448cbda89daa7e648edfd259d445ffe3029230c398b8a32280bd51514a3cd2762d20b8da0711451be38406444327219392fc0faafa33e7e63fc5aac737c10eeff12c96bd370fe36a20cb0da7791a3c7a2d89482ac10585dd7587caa2f5e1f630ddd75c8ef7e0f07445532a3e1e525a3790161131aaa4c6c87f3eba0c3024941da8a37c87b571bb56e7568068bb07ccd6c89e957152848a0d65fcf60c61eede178c0dbd39a5e2b894fec60eb5b64bbc4e95ba4709f2ba97f8637e50785e66ba7ee3cecd91b410a5ba1558318ffc9c07034f5195c49615e663dd1331cfc3731653c70cc84ec2b58252dcb2f77350dd334b2643318acf069521beb7581f338d8a";
    const EXPECTED_RAWSHAKE_256: &str = "3a1108d4a90a31b85a10bdce77f4bfbdcc5b1d70dd405686f8bbde834aa1a410db8c9e1c166c3e239cd76a55f6a692aa2d1749f2ec79cd0ba3b17bb659959b6e";
    const EXPECTED_RAWSHAKE_256_LONG: &str = "3a1108d4a90a31b85a10bdce77f4bfbdcc5b1d70dd405686f8bbde834aa1a410db8c9e1c166c3e239cd76a55f6a692aa2d1749f2ec79cd0ba3b17bb659959b6e4ebed14550bcbf28d8207bfdab5854d0e0ca74dbecc21eef3ce54f12c13421da57d6ba2da3b2d761667bfb181077db091430dea1327a54a49d01b54028335c2c2b5d19965cb89d1a2efa54090ff8816e9c407bbd91009263cd7ae47d2adbc7b4934816da02957eeef2c873a044d18ba30308f4dc5cd1363b06aa064352af83ef7f42145dedfc1b3c9f7514817b2fdef5a98a099668b8712b0fdc67b36637ce4801a75d9280c515c3a883ba066f2946589aeb876097197254b43ff849c52dea652ca131049ce756535215be09bc7f8a124cbc1b4a7e5a64f9513056e8cb035a114ffaaa2fe4ee46df34cc12a846bfc39c5844f0fbe62ae26a6b212354660ca357261cfe49624f0e944db22abb337123ec30e7a8bb77df4b5a4d67dbb3a45a1d40d296d575c18aa7c97f992c5dc154a517f72b5ccd9542e713664961940f603e4d0aadba5df666043967009a9ac9e981d09bea1d04c56619ad63918af41b576a5fe9b5459e24396327a2d114e043b04053332c001bcaa0068841576c1186abcb431fae5960fb33be1d00cd05f806c7e2bb13392dae2d8e27f1d262d9d6bce444ba5f026e256940bf11cc18be6559ba1a8a2a1b460cab8e929e09fae5ad1f665c687dec6129abae83747e079ac36222e28d20acdf67774b2956dbd2bf06367308291ca4a1a840c47a628b3d278702dc6efef572192383815f07a73852d249497a115105d71831ef45312aa076d5d3d43cdcf95b850f10f80977c4b0faf1854b9a9a00c35bed7908fb813e604558aa9e53c9a01342fb304cdf9d7434e3e2e61a28ce64e1259b29aaeba51c1d6a193aacfd6adba0d416044656ea61f6206d1a1b7a9346d0dca57af3c4dbb21229f6ad374aeb3ac00d7f562f578874e094d3b5680114a1b626c5c4ae57cd2a10e18b1a1a7a598e0467a2e3ce13b6b6b92e299e5c0b48a1ce30aaf98ea0ed90dd5211c7f47eb04f30fc05da501754364548a5d91d0d89a00ac9e2c1505446963b37df9aef997280dccfa7a1812e08d2a8d54a779774768113c0796cc28afedda5c3d5a35dfb418e9f47a79f42f1e681245c84e4ae6f7756740a2f9c568ab5a8dfa017e7551ace767df0d6de31e9113b8ba5e1ed5c171d7710a9c5fef4a74f0a08218f0525821caf6c96b1c54ee188c8bda00566e2b09d02c39fc7c77de0f7020d0da3271d2074f24cf828b4f6b7ec572b95f39a6071da305dae0f0427e3435d0f95e7f2160b7983b4e5130872414f480f3b39f5f0083bfb1ad6a6d9769d2b7d1ec77ef74bcdd21d499a6675d74e203a4c2b6af87a600ceada5643a606bf9aacb899b76a6a7c74e9ab2ce9b8f3eb7af214ac54f885aeb6";
    const EXPECTED_SHAKE_128: &str = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
    const EXPECTED_SHAKE_128_LONG: &str = "ded1700844a9e88da77fa25120bdf862309aa1b9a134c8ddde2605e820174ab038f7bfd132648f5fce7f3bf3b9874dcd8b824e588df3be94f2c0ae680c8ad423b28fd1c590850cdb6762eff7d9f4de14da4738e0cd2a0eac90bf397bb380ec910d9055ae876fb77e7cc03328ac1f239e3009d255b8a2798224821aa66e088a8fa317ed65a3a6f12cdaaa16edf78fb38379a079270b7c75f9ab9ef757da3347e1e312cd69ae1657a3a870dc2a7b6f8815862e98965c2f6eaa51e2abca21b87b4e12be39571ebe278a6e577dd6d232fa92510ea50070629e7eb41fe08af64843a2e4aa502eb70bcfa98ad24769bbd820e83c3e8d4b113b8219cd0d1c87b807b0cc90f7086f4d4832799ea7b99ab1242326fcb2304827669fd7ddadd6d5083f6b9468c8f0aeeaea69a43894a8122ea6d46e9547c164f998fad9215f6517b467dfada261577b09a83d6751c616a5122f6aab0cf3249221893270498764d2a1043bf226d9cd61d2b1f30f7386a89c1e1bf1b1e24f412c83607b0e80f4c62527658715ea94b9bf3a355e3cba23f2b2a801aac4111e1714bcb03edbd6ea3f50e01142688b6d22ebc069c1d5cc9f718316e1e280d38417f07fbb82ff87734d57e426cdd0a392bb18b190905c0d598892ca0a3a623b22f2068202993da74f38a71cb4d125cbf71d691167029e592a0302a6e44dfdb764ac1bb2615db272195f622cbb83f83dacdcb8557814bfb39dfe283716e6b2f06299a82a83c15912ffc5ca72ee61b4207c289421835652252af8ea4be3abefebbb686e450baa69db2761fb3da64ae7bfe3ac03d326a3f5dd7bc6e9932040699097d111b77a0813c3f2eda9888872b35d3c130953511b61f3d9e8061f447a9dd320b3a1522f77d0da8560b0d5651a6517c9aefc022423b5738828c241ff9c01706ebe7772a1b51c074285ef0d6028da472179c82292207ce2761c3b298c512f2b75f421414e8febf05b1f6441de800dbfb0094b665fa80663f522f23f291e386f0d03a1255c13345ff1ecd3618ff0dddac73685055c43f9908ef9c87af1dbc2488ad6f5d4c8a194f19667e318d30e7ddc5a2fe241a465cb3c02d3c539615f352f1c58ced21d4e3aaf1fa79c169cccb86b6ca04718b6ef5059bc11420ff9093dc893aa3bb35d1980595f156601b41ef5f9dcd86e0478722fd1b506229f121f2c97c240f8ecc5a6782e433969e38974fd71d31874c6ad3751f43640a7697484fad3ba0aeec0e82a82d6087ebf923d40bd93d03e4a680eda0426b68b86af9046899fe9a8b1f639a5fc2b6547c63a06aed42c02cae64de594dc648b69d56bb7ae2bd590a759383ee291bcf454bfca7bda73eaee0658256c973bea914f76825bc6b842cad4d0b7c29cafa6310eadf85ebc83a2d759564de74613d35941b045403d17501fd500939523d87d880fdf0066fa61";
    const EXPECTED_SHAKE_256: &str = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
    const EXPECTED_SHAKE_256_LONG: &str = "98de64677ff98f899d33f8ac72f6155235a9a2815be05fd44334a36c93d22b40f201dc7186b9036e6611d0ef3172a35cf30f79b637fb19e79aebf5d7c301775fbdfee5282f6d06955ac86747e414432d5034c412adff611e3e86a2fb606caec0375322a2d42abb4953390ec5939289e254fcdfce03e5b9750710efaa84f3cbe24ef972e351be0f3fe737ec5a39cbf1987b0674d68e1f57c497074762eb064a77bdd7b93b91ef8260a17879fcb3cb39ab932127dad84585e970fc564312e4c3af52b36d76babeb9599cb1479bb883408f6da4540c3cccca8006616d5120b12afc6974ca50ae0b60d4f5534bdc87e501bf35faab8979d6b00ff73ac94da6d2b4e3bab321cb4291dd6c84a781c027f10d25ad91aacdde9348fef33e7182e41904c4b33d784fe385ad5102b7fcce2300a4e8576f54aa15737ed8982aeeb50de4bda2570f50729844e618fe625b2852e12a6ec55557a4e09b76634629be41a9fd534198b215ec667ce128562d45dc21654f74d0846458c07b11809bb5b7debf2a4d95f44881b79cd77f5d1841eae96062b04371ce048794023387b2c8db2a11e41881f4b8762ae3492d675d40481b9a2ce00b065023cb3b69327543fbfe79fb62a7c83430e9f859a8becb158d7987fdbe75b1f134161e8a5918994591ac449ac7ec1b4ab0041a14b89d3237a319b4051caa16f23db0b763b640822895bc2f0885df03af30e9742384f2bc938f27498cdf47e3c2043c56cfd1a326ff6f41bbc5044981037831bcd14c001b27b39e58841fcbd26e16ec2b69fe5f9c85bf02f3b5ba96bc5487171f91efa2589fdbf80d7062e1d6adef855c901055c0548d7f6255ee106d0e1d3947a58f7c4e8856a0095c5e3a806eb33853c208a79923350141be4de01277a0caedc26e72452c9c11b9743d6799b014d35836e7d117008a6d3fe27b429e1430dd3e5cfb0f89c10d50c8fe2a6c2d43077994488e0b592e1c43c85414373841dfdc9a751d0c78416ab41340b044a6ae4f22a146da5e51551dc100875b0fa5fc0041737adf9c86d3aca56bc1f2fd2d42521c6239285f99f72d6c402d26577d2cfcecff4ab703c632ee9a6b740e0fb0f7df90ec8a20de8ca10e9d72fae7469993bd9afa68fca07efe08a054a5ba5260a6cba317d9605b15c193574d7a9eb11ffbec53b276b690e5b6dc7d3c6f2b8e2f8e7b5b5e8e5382649352a71652240fd9d1d465e55e556a4f4a59a0b8782f6fad1e1226fadaec0a45eca9ef107d954ac22076c8245b77ac5c31bd1ff6fc3f3a25e89c9d8c1f6bb524f5e554e5970cae92e4a5d376bc08feba396b6334540b7c5b3c9a3791993f4d24551f49bd9a46e2391b9201f65b9d58cfa95c579c6035aa4b3956cf1d44a03486f2763b8437d4a86940192866d91979ed01fc221ff24179bf040272ae83f06c16d3c2defaff5383ef";

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
        rawshake_128.write_bytes(&[0u8; 0]); //Write nothing
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
        rawshake_256.write_bytes(&[0u8; 0]); //Write nothing
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
        shake_128.write_bytes(EXPECTED_SHAKE_128.as_bytes()); //Write nothing
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
        shake_256.write_bytes(EXPECTED_SHAKE_256.as_bytes()); //Write nothing
        let mut shake_256_output = shake_256.close();
        let mut hash_shake_256 = [0u8; 1024];
        assert_eq!(match shake_256_output.next_bytes(&mut hash_shake_256) {
            Some(error) => error.to_string(),
            _ => hex::encode(hash_shake_256)
        }, EXPECTED_SHAKE_256_LONG);
    }
}