#![allow(non_snake_case)]

/*
* Based on the C language reference implemementation:
*
* Copyright (c) 2018, Koninklijke Philips N.V. and PQShield
*
* All rights reserved. A copyright license for redistribution and use in
* source and binary forms, with or without modification, is hereby granted for
* non-commercial, experimental, research, public review and evaluation
* purposes, provided that the following conditions are met:
*
* * Redistributions of source code must retain the above copyright notice,
*   this list of conditions and the following disclaimer.
*
* * Redistributions in binary form must reproduce the above copyright notice,
*   this list of conditions and the following disclaimer in the documentation
*   and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*/

use mbedtls::cipher::*;

// Return 0xffu8 if a == b or 0x00u8 otherwise
fn constant_time_memcmp(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0u8;
    }

    let mut z = 0u8;
    for i in 0..a.len() {
        z |= a[i] ^ b[i];
    }

    // now fold down to 0/1 bit
    z = (z >> 4) | (z & 0x0F); // fold top/bottom 4 bits of 8
    z = (z >> 2) | (z & 0x03); // fold top/bottom 2 bits of 4
    z = (z >> 1) | (z & 0x01); // fold top/bottom 1 bit of 2

    // now map 1 -> 0xff and 0 -> 0
    z = 0u8.wrapping_sub(z);
    return z;
}

// if mask == 0x00 do nothing, if mask = 0xFF copy in to out
// all other values of mask do bad things
fn conditional_constant_time_memcpy(output: &mut [u8], input: &[u8], mask: u8) {
    //assert!(mask == 0x00 || mask == 0xFF);
    assert_eq!(output.len(), input.len());

    for i in 0..output.len() {
        output[i] = (output[i] & !mask) | (input[i] & mask);
    }
}

// appropriate types
const PARAMS_PK_SIZE: usize = 1349;
const PARAMS_KAPPA_BYTES: usize = 32;
const PARAMS_H1: u16 = 8;
const PARAMS_P_BITS: usize = 9;
const PARAMS_P: usize = 512;
const PARAMS_Q_BITS: usize = 13;
const PARAMS_ND: usize = 1170;
const PARAMS_NDP_SIZE: usize = 1317;
const PARAMS_H: usize = 222;
const PROBEVEC64: usize = 19;
const PARAMS_RS_DIV: u16 = 56;
const PARAMS_RS_LIM: u16 = 65520;

const PARAMS_CT_SIZE: usize = 1477;
const PARAMS_T_BITS: usize = 5;
const PARAMS_B_BITS: usize = 1;
const PARAMS_H2: u16 = 8;
const PARAMS_MU: usize = 256;
const PARAMS_MUT_SIZE: usize = 160;
const PARAMS_H3: u16 = 128;

const DEM_TAG_LEN: usize = 16;

const SHAKE256_RATE: usize = 136;

// CCA_PKE Variant

pub const SECRETKEYBYTES: usize = (PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE);
pub const PUBLICKEYBYTES: usize = (PARAMS_PK_SIZE);
pub const CTEXT_BYTES: usize = (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES + DEM_TAG_LEN);

// Cache-resistant "occupancy probe". Tests and "occupies" a single slot at x.
// Return value zero (false) indicates the slot was originally empty.
fn probe_cm(v: &mut [u64], x: u16) -> bool {
    // construct the selector
    let y: u64 = 1u64 << (x & 0x3f);
    let mut z: u64 = 1u64 << (x >> 6);
    let mut c: u64 = 0;
    for i in 0..PROBEVEC64 {
        // always scan through all
        let a = v[i]; // set bit if not occupied.
        let b: u64 = a | y & (z & 1u64).wrapping_neg(); // If change, mask.
        c |= a ^ b; // update value of v[i]
        v[i] = b;
        z >>= 1;
    }
    // final comparison doesn't need to be constant time
    return c == 0;
    // return true if was occupied before
}

// create a sparse ternary vector from a seed
fn create_secret_vector(idx: &mut [[u16; 2]; 111], seed: &[u8]) {
    let mut v: [u64; PROBEVEC64] = [0; PROBEVEC64];

    let mut shake = crate::sha3::Shake::new(256).unwrap();
    shake.update(seed);

    let output = shake.finalize(4*SHAKE256_RATE);

    let mut index = 0;

    for i in 0..PARAMS_H {
        let mut x: u16;
        loop {
            loop {
                x = (output[index] as u16) | ((output[index + 1] as u16) << 8);
                index += 2;
                if x < PARAMS_RS_LIM {
                    break;
                }
            }
            x = x / PARAMS_RS_DIV;
            if probe_cm(&mut v, x) == false {
                break;
            }
        }
        idx[i >> 1][i % 2] = x;
    }
}
// multiplication mod q, result length n
fn ringmul_q(d: &mut [u16], a: &[u16], idx: &[[u16; 2]; 111]) {
    let mut p: [u16; 1171] = [0; 1171];
    // Note: order of coefficients a[1..n] is reversed!
    // "lift" -- multiply by (x - 1)
    p[0] = (-(a[0] as i16)) as u16;
    for i in 1..PARAMS_ND {
        p[PARAMS_ND + 1 - i] = a[i - 1].wrapping_sub(a[i]);
    }
    p[1] = a[PARAMS_ND - 1];

    d.copy_from_slice(&[0; PARAMS_ND]);
    // Initialize result
    for i in 0..(PARAMS_H / 2) {
        // Modified to always scan the same ranges

        let mut k = idx[i][0] as usize;
        d[0] = d[0].wrapping_add(p[k]);
        let mut j: usize = 1;
        while k > 0 {
            k -= 1;
            d[j] = d[j].wrapping_add(p[k]);
            j += 1;
        }
        k = PARAMS_ND + 1;
        while j < PARAMS_ND {
            k -= 1;
            d[j] = d[j].wrapping_add(p[k]);
            j += 1;
        }
        k = idx[i][1] as usize;
        d[0] = d[0].wrapping_sub(p[k]);
        j = 1;
        while k > 0 {
            k -= 1;
            d[j] = d[j].wrapping_sub(p[k]);
            j += 1;
        }
        k = PARAMS_ND + 1;
        while j < PARAMS_ND {
            k -= 1;
            d[j] = d[j].wrapping_sub(p[k]);
            j += 1;
        }
    }
    // "unlift"
    d[0] = -(d[0] as i16) as u16;
    for i in 1..PARAMS_ND {
        d[i] = d[i - 1].wrapping_sub(d[i]);
    }
}
// multiplication mod p, result length mu
fn ringmul_p(d_out: &mut [u16], a: &[u16], idx: &[[u16; 2]; 111]) {
    let mut d: [u16; PARAMS_ND] = [0u16; PARAMS_ND];
    ringmul_q(&mut d, a, idx);
    d_out.copy_from_slice(&d[0..PARAMS_MU]);
}

// Creates A random for the given seed and algorithm parameters.
fn create_A_random(A_random: &mut [u16], seed: &[u8]) {
    let mut shake = crate::sha3::Shake::new(256).unwrap();
    shake.update(&seed[0..PARAMS_KAPPA_BYTES]);

    let xof = shake.finalize(A_random.len() * 2);

    for i in 0..A_random.len() {
        A_random[i] = (xof[2 * i] as u16) | ((xof[2 * i + 1] as u16) << 8);
    }
}

// compress ND elements of q bits into p bits and pack into a byte string
fn pack_q_p(pv: &mut [u8], vq: &[u16], rounding_constant: u16) {
    pv.copy_from_slice(&[0; PARAMS_NDP_SIZE]);

    for i in 0..PARAMS_ND {
        let j = i * PARAMS_P_BITS;
        let t = (vq[i].wrapping_add(rounding_constant) >> (PARAMS_Q_BITS - PARAMS_P_BITS))
            & (PARAMS_P - 1) as u16;

        pv[j >> 3] = pv[j >> 3] | ((t << (j % 8)) as u8);
        pv[(j >> 3) + 1] = pv[(j >> 3) + 1] | ((t >> (8 - (j % 8))) as u8);
    }
}
// unpack a byte string into ND elements of p bits
fn unpack_p(vp: &mut [u16], pv: &[u8]) {
    for i in 0..PARAMS_ND {
        let j = PARAMS_P_BITS * i;
        let mut t = (pv[j >> 3] >> (j % 8)) as u16;
        t |= (pv[(j >> 3) + 1] as u16) << (8 - (j % 8));
        vp[i] = t & ((PARAMS_P - 1) as u16);
    }
}
// generate a keypair (sigma, B)
fn r5_cpa_pke_keygen(pk: &mut [u8], sk: &mut [u8], seed: &[u8]) {
    let mut A: [u16; PARAMS_ND] = [0; PARAMS_ND]; // sigma = seed of A
    let mut B: [u16; PARAMS_ND] = [0; PARAMS_ND];
    let mut S_idx: [[u16; 2]; 111] = [[0; 2]; 111];
    pk[0..PARAMS_KAPPA_BYTES].copy_from_slice(&seed[0..PARAMS_KAPPA_BYTES]);
    // A from sigma
    create_A_random(&mut A, pk); // secret key -- Random S

    sk[0..PARAMS_KAPPA_BYTES].copy_from_slice(&seed[PARAMS_KAPPA_BYTES..2 * PARAMS_KAPPA_BYTES]);
    create_secret_vector(&mut S_idx, &sk[0..PARAMS_KAPPA_BYTES]);

    ringmul_q(&mut B, &A, &S_idx);

    // Compress B q_bits -> p_bits, pk = sigma | B
    pack_q_p(
        &mut pk[PARAMS_KAPPA_BYTES..PARAMS_NDP_SIZE + PARAMS_KAPPA_BYTES],
        &B,
        PARAMS_H1,
    );
}

fn r5_cpa_pke_encrypt(ct: &mut [u8], pk: &[u8], m: &[u8], rho: &[u8]) {
    let mut A: [u16; PARAMS_ND] = [0; PARAMS_ND];
    let mut R_idx: [[u16; 2]; 111] = [[0; 2]; 111];
    let mut U_T: [u16; PARAMS_ND] = [0; PARAMS_ND];
    let mut B: [u16; PARAMS_ND] = [0; PARAMS_ND];
    let mut X: [u16; PARAMS_MU] = [0; PARAMS_MU];
    // unpack public key
    unpack_p(&mut B, &pk[PARAMS_KAPPA_BYTES..]);
    // A from sigma
    create_A_random(&mut A, &pk);
    // Create R
    create_secret_vector(&mut R_idx, &rho);
    // U^T == U = A^T * R == A * R (mod q)
    ringmul_q(&mut U_T, &A, &R_idx);
    // X = B^T * R == B * R (mod p)
    ringmul_p(&mut X, &B, &R_idx);
    // ct = U^T | v
    pack_q_p(&mut ct[0..PARAMS_NDP_SIZE], &U_T, PARAMS_H2);
    ct[PARAMS_NDP_SIZE..PARAMS_MUT_SIZE + PARAMS_NDP_SIZE].copy_from_slice(&[0; PARAMS_MUT_SIZE]);

    for i in 0..PARAMS_MU {
        let j = 8 * PARAMS_NDP_SIZE + PARAMS_T_BITS * i;
        // compute, pack v
        // compress p->t
        let mut t = X[i].wrapping_add(PARAMS_H2) >> (PARAMS_P_BITS - PARAMS_T_BITS);
        // add message

        let tm = (m[i * PARAMS_B_BITS >> 3] >> ((i * PARAMS_B_BITS) % 8)) as u16;
        t = ((t + ((tm & (1u16 << PARAMS_B_BITS) - 1) << PARAMS_T_BITS - PARAMS_B_BITS)) as u16
            & (1u16 << PARAMS_T_BITS) - 1) as u16; // ct = U^T | v

        ct[(j >> 3)] |= (t << (j & 7)) as u8; // unpack t bits
        ct[(j >> 3) + 1] |= (t >> (8 - (j % 8))) as u8;
    }
}
fn r5_cpa_pke_decrypt(sk: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut S_idx: [[u16; 2]; 111] = [[0; 2]; 111];
    create_secret_vector(&mut S_idx, &sk[0..PARAMS_KAPPA_BYTES]);

    let mut U_T: [u16; PARAMS_ND] = [0; PARAMS_ND];
    unpack_p(&mut U_T, ct);

    let mut X_prime: [u16; PARAMS_MU] = [0; PARAMS_MU];
    ringmul_p(&mut X_prime, &U_T, &S_idx);

    let mut m1 = vec![0u8; PARAMS_KAPPA_BYTES];
    let mut v: [u16; PARAMS_MU] = [0; PARAMS_MU];
    for i in 0..PARAMS_MU {
        let j = 8 * PARAMS_NDP_SIZE + PARAMS_T_BITS * i;
        let mut t = (ct[(j >> 3)] >> (j % 8)) as u16;
        t |= (ct[(j >> 3) + 1] as u16) << (8 - (j % 8));
        v[i] = (t & (1u16 << PARAMS_T_BITS) - 1) as u16;
    }
    // X' = v - X', compressed to 1 bit
    for i in 0..PARAMS_MU {
        // v - X' as mod p value (to be able to perform the rounding!)
        let mut x_p = ((v[i]) << (PARAMS_P_BITS - PARAMS_T_BITS)).wrapping_sub(X_prime[i]);
        x_p = x_p.wrapping_add(PARAMS_H3) >> (PARAMS_P_BITS - PARAMS_B_BITS)
            & ((1u16 << PARAMS_B_BITS) - 1);
        m1[(i * PARAMS_B_BITS) >> 3] |= (x_p << ((i * PARAMS_B_BITS) % 8)) as u8;
    }
    return m1;
}

fn round5_dem(mut out: &mut [u8], key: &[u8], msg: &[u8]) -> Result<(), mbedtls::Error> {
    let mut shake = crate::sha3::Shake::new(256).unwrap();

    shake.update(key);

    let key_and_iv = shake.finalize(32 + 12);

    let cipher =
        Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, raw::CipherMode::GCM, 256)?;
    let cipher = cipher
        .set_key_iv(&key_and_iv[0..32], &key_and_iv[32..])?;

    let ad = vec![];

    let mut tag = vec![0; DEM_TAG_LEN];

    cipher.encrypt_auth(&ad, &msg, &mut out, &mut tag)?;

    out[msg.len()..].copy_from_slice(&tag);
    Ok(())
}

fn round5_dem_inverse(ctext: &[u8], key: &[u8]) -> Result<Vec<u8>, mbedtls::Error> {
    let mut shake = crate::sha3::Shake::new(256).unwrap();

    shake.update(key);

    let key_and_iv = shake.finalize(32 + 12);

    let cipher =
        Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, raw::CipherMode::GCM, 256)?;
    let cipher = cipher
        .set_key_iv(&key_and_iv[0..32], &key_and_iv[32..])
        ?;

    let ad = vec![];
    let mut ptext = vec![0; ctext.len() - DEM_TAG_LEN];
    let tag = &ctext[ctext.len() - DEM_TAG_LEN..];
    let ctext = &ctext[0..ctext.len() - DEM_TAG_LEN];
    cipher.decrypt_auth(&ad, ctext, &mut ptext, tag)?;

    Ok(ptext)
}

pub fn gen_keypair(coins: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pk = vec![0u8; PUBLICKEYBYTES];
    let mut sk = vec![0u8; SECRETKEYBYTES];
    /* Generate the base key pair */
    r5_cpa_pke_keygen(&mut pk, &mut sk, &coins[0..64]);

    /* Append y and pk to sk */
    sk[PARAMS_KAPPA_BYTES..2 * PARAMS_KAPPA_BYTES].copy_from_slice(&coins[64..]);
    sk[2 * PARAMS_KAPPA_BYTES..].copy_from_slice(&pk);

    return (sk, pk);
}

fn r5_cca_kem_encapsulate(mut ct: &mut [u8], pk: &[u8], coins: &[u8]) -> Vec<u8> {
    let mut shake = crate::sha3::Shake::new(256).unwrap();

    shake.update(coins);
    shake.update(pk);

    let L_g_rho = shake.finalize(3 * PARAMS_KAPPA_BYTES);

    r5_cpa_pke_encrypt(&mut ct, pk, coins, &L_g_rho[2 * PARAMS_KAPPA_BYTES..]);

    /* Append g: ct = (U,v,g) */
    ct[PARAMS_CT_SIZE..PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES]
        .copy_from_slice(&L_g_rho[PARAMS_KAPPA_BYTES..2 * PARAMS_KAPPA_BYTES]);

    /* k = H(L, ct) */
    shake.update(&L_g_rho[0..32]);
    shake.update(&ct[0..PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES]);
    return shake.finalize(PARAMS_KAPPA_BYTES);
}

pub fn encrypt(msg: &[u8], pk: &[u8], coins: &[u8]) -> Result<Vec<u8>, mbedtls::Error> {
    if coins.len() != 32 {
        return Err(mbedtls::Error::PkBadInputData);
    }

    let mut ct = vec![0u8; PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES + msg.len() + DEM_TAG_LEN];

    let c1_len = PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES;

    let k = r5_cca_kem_encapsulate(&mut ct[0..c1_len], pk, coins);

    /* Apply DEM to get second part of ct */
    round5_dem(&mut ct[c1_len..], &k, &msg)?;
    Ok(ct)
}

fn r5_cca_kem_decapsulate(ct: &[u8], sk: &[u8]) -> Vec<u8> {
    let coins = r5_cpa_pke_decrypt(sk, ct);

    let mut shake = crate::sha3::Shake::new(256).unwrap();
    shake.update(&coins[0..PARAMS_KAPPA_BYTES]);
    shake.update(&sk[2 * PARAMS_KAPPA_BYTES..]);
    let L_g_rho_prime = shake.finalize(3 * PARAMS_KAPPA_BYTES);

    let mut ct_prime: [u8; PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES] =
        [0; PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES];

    // Encrypt m: ct' = (U',v')
    r5_cpa_pke_encrypt(
        &mut ct_prime,
        &sk[2 * PARAMS_KAPPA_BYTES..],
        &coins,
        &L_g_rho_prime[2 * PARAMS_KAPPA_BYTES..],
    );

    // ct' = (U',v',g')
    ct_prime[PARAMS_CT_SIZE..]
        .copy_from_slice(&L_g_rho_prime[PARAMS_KAPPA_BYTES..2 * PARAMS_KAPPA_BYTES]);
    // k = H(L', ct')

    // verification ok ?
    let fail = constant_time_memcmp(&ct, &ct_prime);
    // k = H(y, ct') depending on fail state

    let mut hash_in: [u8; PARAMS_KAPPA_BYTES] = [0; PARAMS_KAPPA_BYTES];
    hash_in.copy_from_slice(&L_g_rho_prime[0..PARAMS_KAPPA_BYTES]);
    conditional_constant_time_memcpy(
        &mut hash_in,
        &sk[PARAMS_KAPPA_BYTES..2 * PARAMS_KAPPA_BYTES],
        fail,
    );

    shake.update(&hash_in);
    shake.update(&ct_prime);
    return shake.finalize(PARAMS_KAPPA_BYTES);
}

pub fn decrypt(ctext: &[u8], sk: &[u8]) -> Result<Vec<u8>, mbedtls::Error> {
    let c1_len = PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES;

    if ctext.len() < c1_len + DEM_TAG_LEN {
        return Err(mbedtls::Error::PkBadInputData);
    }

    /* Determine k */
    let k = r5_cca_kem_decapsulate(&ctext[0..c1_len], sk);

    /* Apply DEM-inverse to get m */
    round5_dem_inverse(&ctext[c1_len..], &k)
}
