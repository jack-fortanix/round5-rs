#![allow(
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

use mbedtls::cipher::*;

extern "C" {
    #[no_mangle]
    fn copy_u8(out: *mut u8, in_0: *const u8, len: usize);
    #[no_mangle]
    fn copy_u16(out: *mut u16, in_0: *const u16, len: usize);
    #[no_mangle]
    fn zero_u8(out: *mut u8, len: usize);
    #[no_mangle]
    fn zero_u16(out: *mut u16, len: usize);
}

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
    // map 1 -> 0xff, 0 -> 0
    z = 0 - z;
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
type modq_t = u16;
type modp_t = u16;
const PARAMS_PK_SIZE: usize = 1349;
const PARAMS_KAPPA_BYTES: usize = 32;
const PARAMS_H1: usize = 8;
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
const PARAMS_H2: usize = 8;
const PARAMS_MU: usize = 256;
const PARAMS_MUT_SIZE: usize = 160;
const PARAMS_H3: usize = 128;

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

    let mut shake = crate::sha3::ShakeXof::new(256, seed).unwrap();

    let mut index: usize = SHAKE256_RATE;
    let mut output: [u8; SHAKE256_RATE] = [0u8; SHAKE256_RATE];
    for i in 0..PARAMS_H {
        let mut x: u16 = 0;
        loop {
            loop {
                if index >= SHAKE256_RATE {
                    shake.expand(&mut output);
                    index = 0;
                }
                x = (output[index] as u16) | ((output[index+1] as u16) << 8);
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
unsafe fn ringmul_q(d: &mut [modq_t], a: &[modq_t], idx: &[[u16; 2]; 111]) {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut k: usize = 0;
    let mut p: [modq_t; 1171] = [0; 1171];
    // Note: order of coefficients a[1..n] is reversed!
    // "lift" -- multiply by (x - 1)
    p[0] = -(*a.as_ptr().offset(0) as i32) as modq_t;
    i = 1;
    while i < PARAMS_ND {
        p[((PARAMS_ND as i32 + 1i32) as u64).wrapping_sub(i as u64) as usize] =
            (*a.as_ptr().offset(i.wrapping_sub(1) as isize) as i32 - *a.as_ptr().offset(i as isize) as i32) as modq_t;
        i = i.wrapping_add(1)
    }
    p[1] = *a.as_ptr().offset((PARAMS_ND as i32 - 1i32) as isize);
    // Initialize result
    zero_u16(d.as_mut_ptr(), PARAMS_ND);
    i = 0i32 as usize;
    while i < (PARAMS_H / 2) {
        // Modified to always scan the same ranges
        k = (*idx.as_ptr().offset(i as isize))[0] as usize; // positive coefficients
        *d.as_mut_ptr().offset(0) = (*d.as_mut_ptr().offset(0) as i32 + p[k as usize] as i32) as modq_t; // negative coefficients
        j = 1i32 as usize;
        while k > 0 {
            k = k.wrapping_sub(1);
            *d.as_mut_ptr().offset(j as isize) = (*d.as_mut_ptr().offset(j as isize) as i32 + p[k as usize] as i32) as modq_t;
            j = j.wrapping_add(1)
        }
        k = (PARAMS_ND as i32 + 1i32) as usize;
        while j < PARAMS_ND {
            k = k.wrapping_sub(1);
            *d.as_mut_ptr().offset(j as isize) = (*d.as_mut_ptr().offset(j as isize) as i32 + p[k as usize] as i32) as modq_t;
            j = j.wrapping_add(1)
        }
        k = (*idx.as_ptr().offset(i as isize))[1] as usize;
        *d.as_mut_ptr().offset(0) = (*d.as_mut_ptr().offset(0) as i32 - p[k as usize] as i32) as modq_t;
        j = 1i32 as usize;
        while k > 0 {
            k = k.wrapping_sub(1);
            *d.as_mut_ptr().offset(j as isize) = (*d.as_mut_ptr().offset(j as isize) as i32 - p[k as usize] as i32) as modq_t;
            j = j.wrapping_add(1)
        }
        k = (PARAMS_ND as i32 + 1i32) as usize;
        while j < PARAMS_ND {
            k = k.wrapping_sub(1);
            *d.as_mut_ptr().offset(j as isize) = (*d.as_mut_ptr().offset(j as isize) as i32 - p[k as usize] as i32) as modq_t;
            j = j.wrapping_add(1)
        }
        i = i.wrapping_add(1)
    }
    // "unlift"
    *d.as_mut_ptr().offset(0) = -(*d.as_mut_ptr().offset(0) as i32) as u16;
    i = 1i32 as usize;
    while i < PARAMS_ND {
        *d.as_mut_ptr().offset(i as isize) =
            (*d.as_mut_ptr().offset(i.wrapping_sub(1) as isize) as i32 - *d.as_mut_ptr().offset(i as isize) as i32) as u16;
        i = i.wrapping_add(1)
    }
}
// multiplication mod p, result length mu
unsafe fn ringmul_p(mut d: *mut modp_t, mut a: *mut modp_t, mut idx: *mut [u16; 2]) {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut k: usize = 0;
    let mut p: [modp_t; 1171] = [0; 1171];
    // Note: order of coefficients a[1..n] is reversed!
    // Without error correction we "lift" -- i.e. multiply by (x - 1)
    p[0] = -(*a.offset(0) as i32) as modp_t;
    i = 1i32 as usize;
    while i < PARAMS_ND {
        p[((PARAMS_ND as i32 + 1i32) as u64).wrapping_sub(i as u64) as usize] =
            (*a.offset(i.wrapping_sub(1) as isize) as i32 - *a.offset(i as isize) as i32) as modp_t;
        i = i.wrapping_add(1)
    }
    p[1] = *a.offset((PARAMS_ND as i32 - 1i32) as isize);
    // Initialize result
    let mut tmp_d: [modp_t; PARAMS_ND] = [0u16; PARAMS_ND];

    i = 0i32 as usize;
    while i < (PARAMS_H / 2) {
        // Modified to always scan the same ranges
        k = (*idx.offset(i as isize))[0] as usize; // positive coefficients
        tmp_d[0] = (tmp_d[0] as i32 + p[k as usize] as i32) as modp_t; // negative coefficients
        j = 1i32 as usize;
        while k > 0 {
            k = k.wrapping_sub(1);
            tmp_d[j as usize] = (tmp_d[j as usize] as i32 + p[k as usize] as i32) as modp_t;
            j = j.wrapping_add(1)
        }
        k = (PARAMS_ND as i32 + 1i32) as usize;
        while j < PARAMS_ND {
            k = k.wrapping_sub(1);
            tmp_d[j as usize] = (tmp_d[j as usize] as i32 + p[k as usize] as i32) as modp_t;
            j = j.wrapping_add(1)
        }
        k = (*idx.offset(i as isize))[1] as usize;
        tmp_d[0] = (tmp_d[0] as i32 - p[k as usize] as i32) as modp_t;
        j = 1i32 as usize;
        while k > 0 {
            k = k.wrapping_sub(1);
            tmp_d[j as usize] = (tmp_d[j as usize] as i32 - p[k as usize] as i32) as modp_t;
            j = j.wrapping_add(1)
        }
        k = (PARAMS_ND as i32 + 1i32) as usize;
        while j < PARAMS_ND {
            k = k.wrapping_sub(1);
            tmp_d[j as usize] = (tmp_d[j as usize] as i32 - p[k as usize] as i32) as modp_t;
            j = j.wrapping_add(1)
        }
        i = i.wrapping_add(1)
    }
    // Without error correction we "lifted" so we now need to "unlift"
    tmp_d[0] = -(tmp_d[0] as i32) as modp_t;
    i = 1i32 as usize;
    while i < PARAMS_MU {
        tmp_d[i as usize] =
            (tmp_d[i.wrapping_sub(1) as usize] as i32 - tmp_d[i as usize] as i32) as modp_t;
        i = i.wrapping_add(1)
    }
    // Copy result
    copy_u16(d, tmp_d.as_mut_ptr(), PARAMS_MU as usize);
}

// Creates A random for the given seed and algorithm parameters.
fn create_A_random(A_random: &mut [modq_t], seed: &[u8]) {
    let mut shake = crate::sha3::Shake::new(256).unwrap();
    shake.update(&seed[0..PARAMS_KAPPA_BYTES]);

    let xof = shake.finalize(A_random.len() * 2);

    for i in 0..A_random.len() {
        A_random[i] = (xof[2*i] as u16) | ((xof[2*i+1] as u16) << 8);
    }
}

// compress ND elements of q bits into p bits and pack into a byte string
unsafe fn pack_q_p(mut pv: *mut u8, mut vq: *const modq_t, rounding_constant: modq_t) {
    let mut i: usize = 0; // pack p bits
    let mut j: usize = 0;
    let mut t: modp_t = 0;
    zero_u8(pv, PARAMS_NDP_SIZE as usize);
    j = 0i32 as usize;
    i = 0i32 as usize;
    while i < PARAMS_ND {
        t = (*vq.offset(i as isize) as i32 + rounding_constant as i32
            >> PARAMS_Q_BITS as i32 - PARAMS_P_BITS as i32
            & PARAMS_P as i32 - 1i32) as modp_t;
        *pv.offset((j >> 3i32) as isize) =
            (*pv.offset((j >> 3i32) as isize) as i32 | (t as i32) << (j & 7)) as u8;
        if (j & 7).wrapping_add(PARAMS_P_BITS) > 8 {
            *pv.offset((j >> 3).wrapping_add(1) as isize) =
                (*pv.offset((j >> 3).wrapping_add(1) as isize) as i32
                    | t as i32 >> (8u8).wrapping_sub(j as u8 & 7)) as u8
        }
        j = (j as u64).wrapping_add(PARAMS_P_BITS as i32 as u64) as usize;
        i = i.wrapping_add(1)
    }
}
// unpack a byte string into ND elements of p bits
fn unpack_p(vp: &mut [modp_t], pv: &[u8]) {
    for i in 0..PARAMS_ND {
        let j = PARAMS_P_BITS * i;
        let mut t = (pv[j >> 3] >> (j % 8)) as modp_t;
        t |= (pv[(j >> 3) + 1] as u16) << (8 - (j % 8));
        vp[i] = t & ((PARAMS_P - 1) as modp_t);
    }
}
// generate a keypair (sigma, B)
unsafe fn r5_cpa_pke_keygen(pk: &mut [u8], sk: &mut [u8], seed: &[u8]) {
    let mut A: [modq_t; PARAMS_ND] = [0; PARAMS_ND]; // sigma = seed of A
    let mut B: [modq_t; PARAMS_ND] = [0; PARAMS_ND];
    let mut S_idx: [[u16; 2]; 111] = [[0; 2]; 111];
    pk[0..PARAMS_KAPPA_BYTES].copy_from_slice(&seed[0..PARAMS_KAPPA_BYTES]);
    // A from sigma
    create_A_random(&mut A, pk); // secret key -- Random S

    sk[0..PARAMS_KAPPA_BYTES].copy_from_slice(&seed[PARAMS_KAPPA_BYTES..2 * PARAMS_KAPPA_BYTES]);
    create_secret_vector(&mut S_idx, &sk[0..PARAMS_KAPPA_BYTES]);
    ringmul_q(&mut B, &A, &S_idx);
    // Compress B q_bits -> p_bits, pk = sigma | B
    pack_q_p(
        pk.as_mut_ptr().offset(PARAMS_KAPPA_BYTES as isize),
        B.as_mut_ptr(),
        PARAMS_H1 as i32 as modq_t,
    );
}

unsafe fn r5_cpa_pke_encrypt(ct: &mut [u8], pk: &[u8], m: &[u8], rho: &[u8]) {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut A: [modq_t; PARAMS_ND] = [0; PARAMS_ND];
    let mut R_idx: [[u16; 2]; 111] = [[0; 2]; 111];
    let mut U_T: [modq_t; PARAMS_ND] = [0; PARAMS_ND];
    let mut B: [modp_t; PARAMS_ND] = [0; PARAMS_ND];
    let mut X: [modp_t; 256] = [0; 256];
    let mut t: modp_t = 0;
    let mut tm: modp_t = 0;
    // unpack public key
    unpack_p(&mut B, &pk[PARAMS_KAPPA_BYTES..]);
    // A from sigma
    create_A_random(&mut A, &pk); // add error correction code
    // Create R
    create_secret_vector(&mut R_idx, &rho); // U^T == U = A^T * R == A * R (mod q)
    ringmul_q(&mut U_T, &A, &R_idx); // X = B^T * R == B * R (mod p)
    ringmul_p(X.as_mut_ptr(), B.as_mut_ptr(), R_idx.as_mut_ptr()); // ct = U^T | v
    pack_q_p(ct.as_mut_ptr(), U_T.as_mut_ptr(), PARAMS_H2 as i32 as modq_t);
    zero_u8(
        ct.as_mut_ptr().offset(PARAMS_NDP_SIZE as isize),
        PARAMS_MUT_SIZE as usize,
    );
    j = (8i32 * PARAMS_NDP_SIZE as i32) as usize;
    i = 0i32 as usize;
    while i < PARAMS_MU {
        // compute, pack v
        // compress p->t
        t = (X[i as usize] as i32 + PARAMS_H2 as i32 >> PARAMS_P_BITS as i32 - PARAMS_T_BITS as i32)
            as modp_t;
        // add message
        tm = (m[(i.wrapping_mul(PARAMS_B_BITS) >> 3i32) as usize] as i32
            >> (i.wrapping_mul(PARAMS_B_BITS) & 7)) as modp_t; // pack t bits
        t = ((t as i32
            + ((tm as i32 & (1i32 << PARAMS_B_BITS as i32) - 1i32)
                << PARAMS_T_BITS as i32 - PARAMS_B_BITS as i32)) as modp_t as i32
            & (1i32 << PARAMS_T_BITS as i32) - 1i32) as modp_t; // ct = U^T | v
        *ct.as_mut_ptr().offset((j >> 3i32) as isize) =
            (*ct.as_mut_ptr().offset((j >> 3i32) as isize) as i32 | (t as i32) << (j & 7)) as u8; // unpack t bits
        if (j & 7).wrapping_add(PARAMS_T_BITS) > 8 {
            *ct.as_mut_ptr().offset((j >> 3i32).wrapping_add(1) as isize) =
                (*ct.as_mut_ptr().offset((j >> 3i32).wrapping_add(1) as isize) as i32
                    | t as i32 >> (8u8).wrapping_sub(j as u8 & 7)) as u8
        } // X' = S^T * U == U^T * S (mod p)
        j = (j as u64).wrapping_add(PARAMS_T_BITS as i32 as u64) as usize;
        i = i.wrapping_add(1)
    }
}
unsafe fn r5_cpa_pke_decrypt(sk: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut S_idx: [[u16; 2]; 111] = [[0; 2]; 111];
    let mut U_T: [modp_t; PARAMS_ND] = [0; PARAMS_ND];
    let mut v: [modp_t; 256] = [0; 256];
    let mut t: modp_t = 0;
    let mut m1 = vec![0u8; PARAMS_KAPPA_BYTES];
    create_secret_vector(&mut S_idx, &sk[0..PARAMS_KAPPA_BYTES]);
    unpack_p(&mut U_T, ct);
    j = (8i32 * PARAMS_NDP_SIZE as i32) as usize;
    i = 0i32 as usize;
    while i < PARAMS_MU {
        t = (*ct.as_ptr().offset((j >> 3i32) as isize) as i32 >> (j & 7)) as modp_t;
        if (j & 7).wrapping_add(PARAMS_T_BITS) > 8 {
            t = (t as i32
                | (*ct.as_ptr().offset((j >> 3i32).wrapping_add(1) as isize) as i32)
                    << (8u8).wrapping_sub(j as u8 & 7)) as modp_t
        }
        v[i as usize] = (t as i32 & (1i32 << PARAMS_T_BITS as i32) - 1i32) as modp_t;
        j = (j as u64).wrapping_add(PARAMS_T_BITS as i32 as u64) as usize;
        i = i.wrapping_add(1)
    }
    let mut X_prime: [modp_t; 256] = [0; 256];
    ringmul_p(X_prime.as_mut_ptr(), U_T.as_mut_ptr(), S_idx.as_mut_ptr());
    // X' = v - X', compressed to 1 bit
    let mut x_p: modp_t = 0;
    i = 0i32 as usize;
    while i < PARAMS_MU {
        // v - X' as mod p value (to be able to perform the rounding!)
        x_p = (((v[i as usize] as i32) << PARAMS_P_BITS as i32 - PARAMS_T_BITS as i32)
            - X_prime[i as usize] as i32) as modp_t;
        x_p = (x_p as i32 + PARAMS_H3 as i32 >> PARAMS_P_BITS as i32 - PARAMS_B_BITS as i32
            & (1i32 << PARAMS_B_BITS as i32) - 1i32) as modp_t;
        m1[(i.wrapping_mul(PARAMS_B_BITS as usize) >> 3i32) as usize] =
            (m1[(i.wrapping_mul(PARAMS_B_BITS) >> 3i32) as usize] as i32
                | (x_p as i32) << (i.wrapping_mul(PARAMS_B_BITS) & 7)) as u8;
        i = i.wrapping_add(1)
    }
    return m1;
}

fn round5_dem(mut out: &mut [u8], key: &[u8], msg: &[u8]) {
    let mut shake = crate::sha3::ShakeXof::new(256, &key).unwrap();

    let mut key_and_iv = vec![0; 32 + 12];
    shake.expand(&mut key_and_iv);

    let cipher =
        Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, raw::CipherMode::GCM, 256).unwrap();
    let cipher = cipher
        .set_key_iv(&key_and_iv[0..32], &key_and_iv[32..])
        .unwrap();

    let ad = vec![];

    let mut tag = vec![0; DEM_TAG_LEN];

    cipher.encrypt_auth(&ad, &msg, &mut out, &mut tag).unwrap();

    out[msg.len()..].copy_from_slice(&tag);
}

fn round5_dem_inverse(ctext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut shake = crate::sha3::ShakeXof::new(256, &key).unwrap();

    let mut key_and_iv = vec![0; 32 + 12];
    shake.expand(&mut key_and_iv);

    let cipher =
        Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, raw::CipherMode::GCM, 256).unwrap();
    let cipher = cipher
        .set_key_iv(&key_and_iv[0..32], &key_and_iv[32..])
        .unwrap();

    let ad = vec![];

    let mut ptext = vec![0; ctext.len() - DEM_TAG_LEN];

    cipher
        .decrypt_auth(
            &ad,
            &ctext[0..ctext.len() - DEM_TAG_LEN],
            &mut ptext,
            &ctext[ctext.len() - DEM_TAG_LEN..],
        )
        .unwrap();

    ptext
}

pub fn gen_keypair(coins: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pk = vec![0u8; PUBLICKEYBYTES];
    let mut sk = vec![0u8; SECRETKEYBYTES];
    /* Generate the base key pair */
    unsafe {
        r5_cpa_pke_keygen(&mut pk, &mut sk, &coins[0..64]);
    }
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

    unsafe {
        r5_cpa_pke_encrypt(&mut ct, pk, coins, &L_g_rho[2*PARAMS_KAPPA_BYTES..]);
    }

    /* Append g: ct = (U,v,g) */
    ct[PARAMS_CT_SIZE..PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES]
        .copy_from_slice(&L_g_rho[PARAMS_KAPPA_BYTES..2 * PARAMS_KAPPA_BYTES]);

    /* k = H(L, ct) */
    shake.update(&L_g_rho[0..32]);
    shake.update(&ct[0..PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES]);
    return shake.finalize(PARAMS_KAPPA_BYTES);
}

pub fn encrypt(msg: &[u8], pk: &[u8], coins: &[u8]) -> Vec<u8> {
    if coins.len() != 32 {
        return Vec::new();
    }

    let mut ct = vec![0u8; PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES + msg.len() + DEM_TAG_LEN];

    let c1_len = PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES;

    let k = r5_cca_kem_encapsulate(&mut ct[0..c1_len], pk, coins);

    /* Apply DEM to get second part of ct */
    round5_dem(&mut ct[c1_len..], &k, &msg);
    return ct;
}

fn r5_cca_kem_decapsulate(ct: &[u8], sk: &[u8]) -> Vec<u8> {
    let coins = unsafe { r5_cpa_pke_decrypt(sk, ct) };

    let mut shake = crate::sha3::Shake::new(256).unwrap();
    shake.update(&coins[0..PARAMS_KAPPA_BYTES]);
    shake.update(&sk[2*PARAMS_KAPPA_BYTES..]);
    let L_g_rho_prime = shake.finalize(3*PARAMS_KAPPA_BYTES);

    let mut ct_prime: [u8; PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES] = [0; PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES];

    // Encrypt m: ct' = (U',v')
    unsafe {
        r5_cpa_pke_encrypt(&mut ct_prime, &sk[2*PARAMS_KAPPA_BYTES..], &coins, &L_g_rho_prime[2*PARAMS_KAPPA_BYTES..]);
    }

    // ct' = (U',v',g')
    ct_prime[PARAMS_CT_SIZE..].copy_from_slice(&L_g_rho_prime[PARAMS_KAPPA_BYTES..2*PARAMS_KAPPA_BYTES]);
    // k = H(L', ct')

    // verification ok ?
    let fail = constant_time_memcmp(&ct, &ct_prime);
    // k = H(y, ct') depending on fail state

    let mut hash_in: [u8; PARAMS_KAPPA_BYTES] = [0; PARAMS_KAPPA_BYTES];
    hash_in.copy_from_slice(&L_g_rho_prime[0..PARAMS_KAPPA_BYTES]);
    conditional_constant_time_memcpy(&mut hash_in, &sk[PARAMS_KAPPA_BYTES..2*PARAMS_KAPPA_BYTES], fail);

    shake.update(&hash_in);
    shake.update(&ct_prime);
    return shake.finalize(PARAMS_KAPPA_BYTES);
}

pub fn decrypt(ctext: &[u8], sk: &[u8]) -> Vec<u8> {
    let c1_len = PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES;

    if ctext.len() < c1_len + DEM_TAG_LEN {
        return vec![]; // error
    }

    /* Determine k */
    let k = r5_cca_kem_decapsulate(&ctext[0..c1_len], sk);

    /* Apply DEM-inverse to get m */
    round5_dem_inverse(&ctext[c1_len..], &k)
}
