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
use core::cmp::min;
use crate::constants::OUTPUT_STREAM_LIMIT_ERROR;
use crate::{keccakmath, KeccakParameter};

/// Represents a generic streaming input mechanism for hashing using the Keccak algorithm.
///
/// This struct encapsulates an internal state and configuration needed to process input
/// data and manage the intermediate state for the Keccak hashing process. Bytes are copied in
/// batches to fill the internal state and advance the state repeatedly until all the bytes are
/// consumed.
///
/// # Usage
/// This struct is designed for use in streaming scenarios, where input data is processed in chunks
/// over time, supporting incremental hashing workflows.
///
/// ```rust
/// use keccakrust::SHAKE_128;
/// let mut input_stream = SHAKE_128::new_input_stream();
/// let helloworld = "helloworld".as_bytes();
///
/// //Writing can be repeated infinitely
/// input_stream.write_bytes(&helloworld);
///
/// //or for a single byte
///
/// input_stream.write_byte(0x23);
///
/// let output_stream = input_stream.close(); //Close to get an output stream instance
/// ```
///
/// Uses about 430 bytes to process any amount of input.
pub struct HashInputStream {
    pub(crate) parameter: KeccakParameter,
    max_output_length: usize,
    input_buffer: [u8; 200],
    input_pos: usize,
    incomplete_state: [u64; 25],
    add_right_encode_at_close: bool //KMAC specific property
}

impl HashInputStream {
    pub(crate) fn new(parameter: &KeccakParameter, max_output_length: usize, add_right_encode_at_close: bool) -> Self {
        HashInputStream {
            parameter: parameter.clone(),
            max_output_length,
            input_buffer: [0u8; 200],
            input_pos: 0,
            incomplete_state: [0u64; 25],
            add_right_encode_at_close
        }
    }

    /// Clones the loaded internal parameter.
    pub fn clone_parameter(&self) -> KeccakParameter {
        self.parameter.clone()
    }

    fn try_permute(&mut self) {
        if self.input_pos < self.parameter.byterate() as usize {
            return;
        }

        let mut input_state = keccakmath::bytes_to_state_array(self.input_buffer);

        for y in 0..5usize {
            for x in 0..5usize {
                let i = 5usize * x + y;
                let transposed_i = 5usize * y + x;

                self.incomplete_state[i] ^= input_state[transposed_i];
            }
        }
        
        input_state.fill(0);

        keccakmath::permute(&mut self.incomplete_state);

        self.input_buffer[0..self.parameter.byterate() as usize].fill(0);
        self.input_pos = 0;
    }

    fn on_absorb(&mut self, bytes: &[u8], offset: u64, length: usize) {
        let mut input_index = offset as usize;
        let end_index = offset as usize + length;

        while input_index < end_index {
            let bytes_to_digest = min(end_index - input_index, self.parameter.byterate() as usize - self.input_pos);

            self
                .input_buffer[self.input_pos..(self.input_pos + bytes_to_digest)]
                .copy_from_slice(&bytes[input_index..(input_index + bytes_to_digest)]);

            self.input_pos = self.input_pos + bytes_to_digest;
            input_index = input_index + bytes_to_digest;

            self.try_permute();
        }
    }

    fn on_absorb_one(&mut self, byte: &u8) {
        self.input_buffer[self.input_pos] = *byte;
        self.input_pos += 1;

        self.try_permute();
    }

    /// Write a single u8 into the internal state. This advances the state if it reaches the
    /// byterate threshold of the loaded parameter.
    pub fn write_byte(&mut self, byte: u8) {
        self.on_absorb_one(&byte);
    }

    /// Copy a u8 array into the internal state (batch by batch) and advances the state repeatedly
    /// until the whole u8 array is consumed.
    ///
    /// This doesn't zero fill the input array.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.on_absorb(&bytes, 0, bytes.len());
    }

    /// Force a permutation. This is equivalent to padding with zeroes. Useful for KMAC.
    pub(crate) fn force_permute(&mut self) {
        self.input_pos = self.parameter.byterate() as usize;
        self.try_permute();
    }

    /// Completes the Keccak permutation and consumes the whole `HashInputStream` to produce a
    /// `HashOutputStream` which can then be used to output the hash bytes.
    pub fn close(mut self) -> HashOutputStream {
        if self.add_right_encode_at_close {
            let mut buffer = [0u8; 9];
            let size = keccakmath::right_encode(&mut buffer, self.max_output_length as u64 * 8);
            self.write_bytes(&buffer[0..size]);
        }
        
        keccakmath::pad10n1(
            &mut self.input_buffer[0..self.parameter.byterate() as usize],
            self.input_pos,
            self.parameter.padding_bytes[0],
            self.parameter.padding_bitcount
        );

        self.force_permute();

        HashOutputStream {
            parameter: self.parameter.clone(),
            max_output_length: self.max_output_length,
            internal_state: self.incomplete_state,
            internal_buffer: keccakmath::state_to_output_copy(self.incomplete_state),
            total_output_length: 0usize,
            used: 0usize
        }
    }
}

/// Represents a generic streaming output mechanism for generating hashes of the Keccak algorithm.
///
/// This struct encapsulates an internal state and configuration needed to process output
/// data and manage the internal state for the Keccak hashing process. Bytes are copied in batches
/// to reduce memcopy operations to the bare minimum until the state needs to be advanced again.
///
/// # Usage
/// This struct is designed for use in streaming scenarios, where output data is processed in chunks
/// over time, supporting incremental hashing workflows.
///
/// ```rust
/// use keccakrust::SHAKE_128;
///
/// let mut output_stream = SHAKE_128::new_input_stream().close();
/// let mut results = [0u8; 32];
///
/// output_stream.next_bytes(&mut results);
///
/// //or to get a single byte
///
/// let result = output_stream.next_byte().unwrap();
/// ```
///
/// Uses about 430 bytes to generate an infinite number of bytes.
pub struct HashOutputStream {
    pub(crate) parameter: KeccakParameter,
    max_output_length: usize,
    internal_state: [u64; 25],
    internal_buffer: [u8; 200],
    total_output_length: usize,
    used: usize
}

impl HashOutputStream {
    pub fn clone_parameter(&self) -> KeccakParameter {
        self.parameter.clone()
    }

    /// Some Keccak parameters can't be squeezed infinitely. This checks if the loaded parameter
    /// can be squeezed infinitely.
    pub fn is_squeezable(&self) -> bool {
        match self.parameter {
            KeccakParameter::SHA3_224 |
            KeccakParameter::SHA3_256 |
            KeccakParameter::SHA3_384 |
            KeccakParameter::SHA3_512 |
            KeccakParameter::KMAC_128 |
            KeccakParameter::KMAC_256 => false,
            _ => true
        }
    }

    /// Returns true if there are more bytes permitted to be outputted.
    pub fn has_next(&self) -> bool {
        self.is_squeezable() && self.max_output_length == 0 || self.total_output_length < self.max_output_length
    }

    fn try_squeeze(&mut self)  {
        if self.used < self.parameter.byterate() as usize {
            return;
        }

        keccakmath::permute(&mut self.internal_state);
        
        let mut output_buffer = keccakmath::state_to_output_copy(self.internal_state);
        
        self.internal_buffer = output_buffer; //This does a memory copy in Rust

        output_buffer.fill(0); //Zero-fill the buffer since we don't need it

        self.used = 0;

        return;
    }

    fn get_as_many_bytes(&mut self, destination: &mut [u8], offset: usize) -> Option<usize> {
        if !self.has_next() {
            return None;
        }
        self.try_squeeze();

        let as_much = min(self.parameter.byterate() as usize - self.used, destination.len() - offset);

        destination[offset..(offset + as_much)].copy_from_slice(&self.internal_buffer[self.used..(self.used + as_much)]);
        self.used = self.used + as_much;
        self.total_output_length = self.total_output_length + as_much;

        Some(offset + as_much)
    }

    /// Returns a u8 if it can and gracefully fails by returning `None`.
    pub fn next_byte(&mut self) -> Option<u8> {
        if !self.has_next() {
            return None;
        }
        self.try_squeeze();

        self.used = self.used + 1;
        self.total_output_length = self.total_output_length + 1;

        Some(self.internal_buffer[self.used - 1])
    }

    /// Fills the destination array with u8's or fails gracefully by returning `Some(&str)` with the
    /// error message.
    pub fn next_bytes(&mut self, destination_array: &mut [u8]) -> Option<&str> {
        if !self.is_squeezable() && self.total_output_length + destination_array.len() > self.max_output_length {
            return Some(OUTPUT_STREAM_LIMIT_ERROR);
        }
        let mut offset = 0usize;
        while offset < destination_array.len() {
            match self.get_as_many_bytes(destination_array, offset) {
                Some(new_offset) => offset = new_offset,
                _ => return Some(OUTPUT_STREAM_LIMIT_ERROR)
            }
        }

        None
    }
}

//Automatically zero fill once out of scope
impl Drop for HashInputStream {
    fn drop(&mut self) {
        self.incomplete_state.fill(0);
        self.input_buffer.fill(0);
    }
}

//Automatically zero fill once out of scope
impl Drop for HashOutputStream {
    fn drop(&mut self) {
        self.internal_state.fill(0);
        self.internal_buffer.fill(0);
    }
}