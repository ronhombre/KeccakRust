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
use crate::KeccakParameter;

pub struct HashInputStream {
    pub parameter: KeccakParameter,
    max_output_length: usize,
    input_buffer: [u8; 200],
    input_pos: usize,
    incomplete_state: [u64; 25]
}

impl HashInputStream {
    pub fn new(parameter: KeccakParameter, max_output_length: usize) -> Self {
        return HashInputStream {
            parameter: parameter,
            max_output_length: max_output_length,
            input_buffer: [0u8; 200],
            input_pos: 0,
            incomplete_state: [0u64; 25]
        };
    }
    fn try_permute(&mut self) {
        if self.input_pos < self.parameter.byterate() as usize {
            return;
        }

        let mut input_state = crate::keccakmath::bytes_to_state_array(self.input_buffer);

        crate::keccakmath::transpose_state(&mut input_state);
        for i in 0..25usize {
            self.incomplete_state[i] ^= input_state[i];
        }

        crate::keccakmath::permute(&mut self.incomplete_state);

        self.input_buffer[0..self.parameter.byterate() as usize].fill(0);
        self.input_pos = 0;
    }

    fn on_absorb(&mut self, bytes: &[u8], offset: u64, length: usize) {
        let mut input_index = offset as usize;
        let end_index = offset as usize + length;

        while input_index < end_index {
            let bytes_to_digest = min((end_index - input_index) as usize, self.parameter.byterate() as usize - self.input_pos);

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

    pub fn write_byte(&mut self, byte: u8) {
        self.on_absorb_one(&byte);
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.on_absorb(&bytes, 0, bytes.len());
    }

    pub fn close(mut self) -> HashOutputStream {
        crate::keccakmath::pad10n1(
            &mut self.input_buffer[0..self.parameter.byterate() as usize],
            self.input_pos,
            self.parameter.padding_bytes[0],
            self.parameter.padding_bitcount
        );
        self.input_pos = self.parameter.byterate() as usize;

        self.try_permute();

        crate::keccakmath::transpose_state(&mut self.incomplete_state);

        self.input_buffer.fill(0);

        return HashOutputStream {
            parameter: self.parameter,
            max_output_length: self.max_output_length,
            internal_state: self.incomplete_state,
            internal_buffer: crate::keccakmath::state_array_to_bytes(self.incomplete_state),
            total_output_length: 0usize,
            used: 0usize
        };
    }
}

pub struct HashOutputStream {
    pub parameter: KeccakParameter,
    max_output_length: usize,
    internal_state: [u64; 25],
    internal_buffer: [u8; 200],
    total_output_length: usize,
    used: usize
}

impl HashOutputStream {
    pub fn is_squeezable(&self) -> bool {
        return match self.parameter {
            crate::KeccakParameter::SHA3_224 |
            crate::KeccakParameter::SHA3_256 |
            crate::KeccakParameter::SHA3_384 |
            crate::KeccakParameter::SHA3_512 => false,
            _ => true
        }
    }

    pub fn has_next(&self) -> bool {
        return self.is_squeezable() || self.total_output_length < self.max_output_length;
    }

    fn try_squeeze(&mut self)  {
        if self.used < self.parameter.byterate() as usize {
            return;
        }

        //TODO: Fix the need to transpose
        crate::keccakmath::transpose_state(&mut self.internal_state);
        crate::keccakmath::permute(&mut self.internal_state);
        crate::keccakmath::transpose_state(&mut self.internal_state);
        self.internal_buffer.copy_from_slice(&crate::keccakmath::state_array_to_bytes(self.internal_state));

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

        return Some(offset + as_much);
    }

    pub fn next_byte(&mut self) -> Option<u8> {
        if !self.has_next() {
            return None;
        }
        self.try_squeeze();

        self.used = self.used + 1;
        self.total_output_length = self.total_output_length + 1;

        return Some(self.internal_buffer[self.used - 1]);
    }

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

        return None;
    }
}

