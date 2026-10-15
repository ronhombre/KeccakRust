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
use crate::constants::ROUND;
use core::cmp::max;
use core::mem;
use zeroize::Zeroize;

/// This function always assumes that last_index < bytes.len() is always TRUE
#[inline]
pub fn pad10n1(bytes: &mut [u8], last_index: usize, padding: u8, padding_length: u8) -> bool {
    bytes[last_index] = padding | (1 << padding_length);
    bytes[bytes.len() - 1] = bytes[bytes.len() - 1] | 0x80;

    true
}

/// Does 24 rounds of permutation using in-place mutation. This consumes an additional 48 bytes of
/// memory. Zero-filled after.
///
/// Gemini 4 Argon optimized. Please scrutinize if you have time.
#[allow(clippy::zero_prefixed_literal)]
#[inline]
pub fn permute(state: &mut [u64; 25]) {
    for iota in &ROUND {
        // Theta Parity: Compute column parities into 5 registers (g0..g4)
        let mut g0 = state[00] ^ state[01] ^ state[02] ^ state[03] ^ state[04];
        let mut g1 = state[05] ^ state[06] ^ state[07] ^ state[08] ^ state[09];
        let mut g2 = state[10] ^ state[11] ^ state[12] ^ state[13] ^ state[14];
        let mut g3 = state[15] ^ state[16] ^ state[17] ^ state[18] ^ state[19];
        let mut g4 = state[20] ^ state[21] ^ state[22] ^ state[23] ^ state[24];

        // Theta Effect: Convert parities C[0..4] into deltas D[0..4] in-register
        // Result mapping: D[0]=g0, D[1]=g2, D[2]=g3, D[3]=g4, D[4]=g5 (leaves g1 free)
        let mut g5 = g0;
        g0 = g4 ^ g1.rotate_left(1); // D[0]
        g4 = g2 ^ g4.rotate_left(1); // D[3] (retires C[4])
        g2 = g5 ^ g2.rotate_left(1); // D[1] (retires C[2])
        g5 = g3 ^ g5.rotate_left(1); // D[4] (retires C[0])
        g3 = g1 ^ g3.rotate_left(1); // D[2] (retires C[3] and C[1])

        // Fused Theta + Rho + Pi: Walk the 24-cycle in-place using g1 as swap register
        state[00] ^= g0;
        g1 = state[01] ^ g0;
        state[01] = (state[15] ^ g4).rotate_left(28);
        state[15] = (state[18] ^ g4).rotate_left(21);
        state[18] = (state[13] ^ g3).rotate_left(15);
        state[13] = (state[07] ^ g2).rotate_left(10);
        state[07] = (state[11] ^ g3).rotate_left(06);
        state[11] = (state[02] ^ g0).rotate_left(03);
        state[02] = (state[05] ^ g2).rotate_left(01);
        state[05] = (state[06] ^ g2).rotate_left(44);
        state[06] = (state[21] ^ g5).rotate_left(20);
        state[21] = (state[14] ^ g3).rotate_left(61);
        state[14] = (state[22] ^ g5).rotate_left(39);
        state[22] = (state[04] ^ g0).rotate_left(18);
        state[04] = (state[10] ^ g3).rotate_left(62);
        state[10] = (state[12] ^ g3).rotate_left(43);
        state[12] = (state[17] ^ g4).rotate_left(25);
        state[17] = (state[23] ^ g5).rotate_left(08);
        state[23] = (state[19] ^ g4).rotate_left(56);
        state[19] = (state[03] ^ g0).rotate_left(41);
        state[03] = (state[20] ^ g5).rotate_left(27);
        state[20] = (state[24] ^ g5).rotate_left(14);
        state[24] = (state[09] ^ g2).rotate_left(02);
        state[09] = (state[16] ^ g4).rotate_left(55);
        state[16] = (state[08] ^ g2).rotate_left(45);
        state[08] = g1.rotate_left(36);

        // Chi + Iota: Update each independent 5-cycle in-place using g0 and g1
        g0 = state[00]; g1 = state[05];
        state[00] = g0 ^ (!g1 & state[10]) ^ iota;
        state[05] = g1 ^ (!state[10] & state[15]);
        state[10] ^= !state[15] & state[20];
        state[15] ^= !state[20] & g0;
        state[20] ^= !g0 & g1;

        g0 = state[01]; g1 = state[06];
        state[01] = g0 ^ (!g1 & state[11]);
        state[06] = g1 ^ (!state[11] & state[16]);
        state[11] ^= !state[16] & state[21];
        state[16] ^= !state[21] & g0;
        state[21] ^= !g0 & g1;

        g0 = state[02]; g1 = state[07];
        state[02] = g0 ^ (!g1 & state[12]);
        state[07] = g1 ^ (!state[12] & state[17]);
        state[12] ^= !state[17] & state[22];
        state[17] ^= !state[22] & g0;
        state[22] ^= !g0 & g1;

        g0 = state[03]; g1 = state[08];
        state[03] = g0 ^ (!g1 & state[13]);
        state[08] = g1 ^ (!state[13] & state[18]);
        state[13] ^= !state[18] & state[23];
        state[18] ^= !state[23] & g0;
        state[23] ^= !g0 & g1;

        g0 = state[04]; g1 = state[09];
        state[04] = g0 ^ (!g1 & state[14]);
        state[09] = g1 ^ (!state[14] & state[19]);
        state[14] ^= !state[19] & state[24];
        state[19] ^= !state[24] & g0;
        state[24] ^= !g0 & g1;
    }
}

/// Directly convert a state array to a byte array
#[inline]
pub fn state_array_to_bytes(input: [u64; 25]) -> [u8; 200] {
    unsafe { mem::transmute(input) }
}

/// Directly convert a byte array to a state array
#[inline]
pub fn bytes_to_state_array(input: [u8; 200]) -> [u64; 25] {
    unsafe { mem::transmute(input) }
}

/// Transposition is needed since the flat memory layout is in Row-major but we needed Column-major
/// for the permutation algorithm.
#[inline]
pub fn transpose_state(state: &mut [u64; 25]) {
    *state = [
        state[0], state[5], state[10], state[15], state[20], state[1], state[6], state[11],
        state[16], state[21], state[2], state[7], state[12], state[17], state[22], state[3],
        state[8], state[13], state[18], state[23], state[4], state[9], state[14], state[19],
        state[24],
    ];
}

/// Transpose and convert to a byte array/
#[inline]
pub fn state_to_output_copy(mut state: [u64; 25]) -> [u8; 200] {
    transpose_state(&mut state);

    let result = state_array_to_bytes(state);

    state.zeroize();

    result
}

// SP 800-185

/// Encodes a u64 value into a u8 value.
#[inline]
pub fn compute_for_n_given_x(x: u64) -> u8 {
    ((64u8 - (x >> 1).leading_zeros() as u8) >> 3) + 1
}

/// This function always assumes that the destination buffer is at least 8 bytes in
#[inline]
pub fn encode_to_bytes(destination: &mut [u8], number: u64) -> usize {
    let used_bytes = (64 - number.leading_zeros() as usize + 7) >> 3;

    destination[..used_bytes].copy_from_slice(&number.to_be_bytes()[(8 - used_bytes)..8]);

    used_bytes
}

/// This function always assumes that the destination buffer is 9 bytes in size
#[inline]
pub fn left_encode(destination: &mut [u8], x: u64) -> usize {
    let n = compute_for_n_given_x(x);
    let offset = max(encode_to_bytes(&mut destination[1..], x), 1);

    destination[0] = n;

    offset + 1
}

/// This function always assumes that the destination buffer is 9 bytes in size
#[inline]
pub fn right_encode(destination: &mut [u8], x: u64) -> usize {
    let n = compute_for_n_given_x(x);
    let offset = max(encode_to_bytes(&mut destination[..8], x), 1);

    destination[offset] = n;

    offset + 1
}
