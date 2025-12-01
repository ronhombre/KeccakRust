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
use core::mem;
use core::cmp::max;
use zeroize::Zeroize;
use crate::constants::ROUND;

/// This function always assumes that last_index < bytes.len() is always TRUE
pub fn pad10n1(bytes: &mut [u8], last_index: usize, padding: u8, padding_length: u8) -> bool {
    bytes[last_index] = padding | (1 << padding_length);
    bytes[bytes.len() - 1] = bytes[bytes.len() - 1] | 0x80;

    true
}

 /// Does 24 rounds of permutation using in-place mutation. This consumes an additional 216 bytes of
/// memory. Zero-filled after.
#[allow(clippy::zero_prefixed_literal)]
pub fn permute(state: &mut [u64; 25]) {
    let mut c = [0u64; 5];
    let mut d = [0u64; 5];

    let mut intermediate_state = [0u64; 25];

    for iota in &ROUND {
        c[0] = state[00] ^ state[01] ^ state[02] ^ state[03] ^ state[04];
        c[1] = state[05] ^ state[06] ^ state[07] ^ state[08] ^ state[09];
        c[2] = state[10] ^ state[11] ^ state[12] ^ state[13] ^ state[14];
        c[3] = state[15] ^ state[16] ^ state[17] ^ state[18] ^ state[19];
        c[4] = state[20] ^ state[21] ^ state[22] ^ state[23] ^ state[24];

        d[0] = c[4] ^ c[1].rotate_left(1);
        d[1] = c[0] ^ c[2].rotate_left(1);
        d[2] = c[1] ^ c[3].rotate_left(1);
        d[3] = c[2] ^ c[4].rotate_left(1);
        d[4] = c[3] ^ c[0].rotate_left(1);

        intermediate_state[00] = state[00] ^ d[0];
        intermediate_state[01] = (state[15] ^ d[3]).rotate_left(28);
        intermediate_state[02] = (state[05] ^ d[1]).rotate_left(01);
        intermediate_state[03] = (state[20] ^ d[4]).rotate_left(27);
        intermediate_state[04] = (state[10] ^ d[2]).rotate_left(62);
        intermediate_state[05] = (state[06] ^ d[1]).rotate_left(44);
        intermediate_state[06] = (state[21] ^ d[4]).rotate_left(20);
        intermediate_state[07] = (state[11] ^ d[2]).rotate_left(06);
        intermediate_state[08] = (state[01] ^ d[0]).rotate_left(36);
        intermediate_state[09] = (state[16] ^ d[3]).rotate_left(55);
        intermediate_state[10] = (state[12] ^ d[2]).rotate_left(43);
        intermediate_state[11] = (state[02] ^ d[0]).rotate_left(03);
        intermediate_state[12] = (state[17] ^ d[3]).rotate_left(25);
        intermediate_state[13] = (state[07] ^ d[1]).rotate_left(10);
        intermediate_state[14] = (state[22] ^ d[4]).rotate_left(39);
        intermediate_state[15] = (state[18] ^ d[3]).rotate_left(21);
        intermediate_state[16] = (state[08] ^ d[1]).rotate_left(45);
        intermediate_state[17] = (state[23] ^ d[4]).rotate_left(08);
        intermediate_state[18] = (state[13] ^ d[2]).rotate_left(15);
        intermediate_state[19] = (state[03] ^ d[0]).rotate_left(41);
        intermediate_state[20] = (state[24] ^ d[4]).rotate_left(14);
        intermediate_state[21] = (state[14] ^ d[2]).rotate_left(61);
        intermediate_state[22] = (state[04] ^ d[0]).rotate_left(18);
        intermediate_state[23] = (state[19] ^ d[3]).rotate_left(56);
        intermediate_state[24] = (state[09] ^ d[1]).rotate_left(02);

        state[00] = intermediate_state[00] ^ (!intermediate_state[05] & intermediate_state[10]) ^ iota;
        state[01] = intermediate_state[01] ^ (!intermediate_state[06] & intermediate_state[11]);
        state[02] = intermediate_state[02] ^ (!intermediate_state[07] & intermediate_state[12]);
        state[03] = intermediate_state[03] ^ (!intermediate_state[08] & intermediate_state[13]);
        state[04] = intermediate_state[04] ^ (!intermediate_state[09] & intermediate_state[14]);
        state[05] = intermediate_state[05] ^ (!intermediate_state[10] & intermediate_state[15]);
        state[06] = intermediate_state[06] ^ (!intermediate_state[11] & intermediate_state[16]);
        state[07] = intermediate_state[07] ^ (!intermediate_state[12] & intermediate_state[17]);
        state[08] = intermediate_state[08] ^ (!intermediate_state[13] & intermediate_state[18]);
        state[09] = intermediate_state[09] ^ (!intermediate_state[14] & intermediate_state[19]);
        state[10] = intermediate_state[10] ^ (!intermediate_state[15] & intermediate_state[20]);
        state[11] = intermediate_state[11] ^ (!intermediate_state[16] & intermediate_state[21]);
        state[12] = intermediate_state[12] ^ (!intermediate_state[17] & intermediate_state[22]);
        state[13] = intermediate_state[13] ^ (!intermediate_state[18] & intermediate_state[23]);
        state[14] = intermediate_state[14] ^ (!intermediate_state[19] & intermediate_state[24]);
        state[15] = intermediate_state[15] ^ (!intermediate_state[20] & intermediate_state[00]);
        state[16] = intermediate_state[16] ^ (!intermediate_state[21] & intermediate_state[01]);
        state[17] = intermediate_state[17] ^ (!intermediate_state[22] & intermediate_state[02]);
        state[18] = intermediate_state[18] ^ (!intermediate_state[23] & intermediate_state[03]);
        state[19] = intermediate_state[19] ^ (!intermediate_state[24] & intermediate_state[04]);
        state[20] = intermediate_state[20] ^ (!intermediate_state[00] & intermediate_state[05]);
        state[21] = intermediate_state[21] ^ (!intermediate_state[01] & intermediate_state[06]);
        state[22] = intermediate_state[22] ^ (!intermediate_state[02] & intermediate_state[07]);
        state[23] = intermediate_state[23] ^ (!intermediate_state[03] & intermediate_state[08]);
        state[24] = intermediate_state[24] ^ (!intermediate_state[04] & intermediate_state[09]);
    }

    c.zeroize();
    d.zeroize();
    intermediate_state.zeroize();
}

/// Directly convert a state array to a byte array
pub fn state_array_to_bytes(input: [u64; 25]) -> [u8; 200] {
    unsafe { mem::transmute(input) }
}

/// Directly convert a byte array to a state array
pub fn bytes_to_state_array(input: [u8; 200]) -> [u64; 25] {
    unsafe { mem::transmute(input) }
}

/// Transposition is needed since the flat memory layout is in Row-major but we needed Column-major
/// for the permutation algorithm.
pub fn transpose_state(state: &mut [u64; 25]) {
    *state = [
        state[0], state[5], state[10], state[15], state[20],
        state[1], state[6], state[11], state[16], state[21],
        state[2], state[7], state[12], state[17], state[22],
        state[3], state[8], state[13], state[18], state[23],
        state[4], state[9], state[14], state[19], state[24],
    ];
}

/// Transpose and convert to a byte array/
pub fn state_to_output_copy(mut state: [u64; 25]) -> [u8; 200] {
    transpose_state(&mut state);
    
    let result = state_array_to_bytes(state);
    
    state.zeroize();
    
    result
}

// SP 800-185

/// Encodes a u64 value into a u8 value.
pub fn compute_for_n_given_x(x: u64) -> u8 {
    ((64u8 - (x >> 1).leading_zeros() as u8) >> 3) + 1
}

/// This function always assumes that the destination buffer is at least 8 bytes in size
pub fn encode_to_bytes(destination: &mut [u8], number: u64) -> usize {
    let used_bytes = (64 - number.leading_zeros() as usize + 7) >> 3;

    destination[..used_bytes].copy_from_slice(&number.to_be_bytes()[(8 - used_bytes)..8]);

    used_bytes
}

/// This function always assumes that the destination buffer is 9 bytes in size
pub fn left_encode(destination: &mut [u8], x: u64) -> usize {
    let n = compute_for_n_given_x(x);
    let offset = max(encode_to_bytes(&mut destination[1..], x), 1);

    destination[0] = n;

    offset + 1
}

/// This function always assumes that the destination buffer is 9 bytes in size
pub fn right_encode(destination: &mut [u8], x: u64) -> usize {
    let n = compute_for_n_given_x(x);
    let offset = max(encode_to_bytes(&mut destination[..8], x), 1);

    destination[offset] = n;

    offset + 1
}