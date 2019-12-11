#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

use mbedtls::cipher::*;

extern "C" {
    /* *
     * Constant time memory comparison function. Use to replace `memcmp()` when
     * comparing security critical data.
     *
     * @param s1 the byte string to compare to
     * @param s2 the byte string to compare
     * @param n the number of bytes to compare
     * @return 0 if all size bytes are equal, non-zero otherwise
     */
    #[no_mangle]
    fn constant_time_memcmp(
        s1: *const libc::c_void,
        s2: *const libc::c_void,
        n: usize,
    ) -> libc::c_int;
    /* *
     * Conditionally copies the data from the source to the destination in
     * constant time.
     *
     * @param dst the destination of the copy
     * @param src the source of the copy
     * @param n the number of bytes to copy
     * @param flag indicating whether or not the copy should be performed
     */
    #[no_mangle]
    fn conditional_constant_time_memcpy(
        dst: *mut libc::c_void,
        src: *const libc::c_void,
        n: usize,
        flag: u8,
    );
    #[no_mangle]
    fn copy_u8(out: *mut u8, in_0: *const u8, len: usize);
    #[no_mangle]
    fn copy_u16(out: *mut u16, in_0: *const u16, len: usize);
    #[no_mangle]
    fn zero_u8(out: *mut u8, len: usize);
    #[no_mangle]
    fn zero_u16(out: *mut u16, len: usize);

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
const PARAMS_RS_DIV: usize = 56;
const PARAMS_RS_LIM: usize = 65520;

const PARAMS_K: usize = 1;
const PARAMS_D: usize = 1170;
const PARAMS_CT_SIZE: usize = 1477;
const PARAMS_T_BITS: usize = 5;
const PARAMS_B_BITS: usize = 1;
const PARAMS_H2: usize = 8;
const PARAMS_MU: usize = 256;
const PARAMS_MUT_SIZE: usize = 160;
const PARAMS_MUB_SIZE: usize = 32;
const PARAMS_H3: usize = 128;

const DEM_TAG_LEN: usize = 16;

const SHAKE256_RATE: usize = 136;

unsafe fn shake256(out: *mut u8, len: usize, seed: *const u8, seed_len: usize) {
    let mut shake =
        crate::sha3::ShakeXof::new(256, std::slice::from_raw_parts(seed, seed_len))
            .unwrap();
    shake.expand(std::slice::from_raw_parts_mut(out, len));
}

// CCA_PKE Variant

pub const SECRETKEYBYTES: usize = (PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE);
pub const PUBLICKEYBYTES: usize = (PARAMS_PK_SIZE);
pub const CTEXT_BYTES: usize = (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES + DEM_TAG_LEN);
// Size of the vector to pass to probe_cm

// Cache-resistant "occupancy probe". Tests and "occupies" a single slot at x.
// Return value zero (false) indicates the slot was originally empty.
unsafe fn probe_cm(mut v: *mut u64, x: u16) -> i32 {
    // construct the selector
    let y: u64 = (1u64 << (x as i32 & 0x3fi32)) as u64;
    let mut z: u64 = (1u64 << (x as i32 >> 6i32)) as u64;
    let mut c: u64 = 0;
    let mut i: usize = 0;
    while i < PROBEVEC64 {
        // always scan through all
        let mut a: u64 = *v.offset(i as isize); // set bit if not occupied.
        let mut b: u64 = a | y & (z & 1i32 as u64).wrapping_neg(); // If change, mask.
        c |= a ^ b; // update value of v[i]
        *v.offset(i as isize) = b;
        z >>= 1i32;
        i = i.wrapping_add(1)
    }
    // final comparison doesn't need to be constant time
    return (c == 0i32 as u64) as i32;
    // return true if was occupied before
}
// create a sparse ternary vector from a seed
unsafe fn create_secret_vector(mut idx: *mut [u16; 2], mut seed: *const u8) {
    let mut v: [u64; 19] = [0; 19];

    let mut shake =
        crate::sha3::ShakeXof::new(256, std::slice::from_raw_parts(seed, PARAMS_KAPPA_BYTES))
            .unwrap();
    let mut index: usize = SHAKE256_RATE;
    let mut output: [u8; 136] = [0u8; 136];
    let mut i: usize = 0;
    while i < PARAMS_H {
        let mut x: u16 = 0;
        loop {
            loop {
                if index >= SHAKE256_RATE {
                    shake.expand(&mut output);
                    index = 0;
                }
                x = (output[index] as i32
                    | (output[index.wrapping_add(1) as usize] as i32) << 8i32)
                    as u16;
                index = (index as u64).wrapping_add(2i32 as u64) as usize;
                if !(x as i32 >= PARAMS_RS_LIM as i32) {
                    break;
                }
            }
            x = (x as i32 / PARAMS_RS_DIV as i32) as u16;
            if !(probe_cm(v.as_mut_ptr(), x) != 0) {
                break;
            }
        }
        (*idx.offset((i >> 1i32) as isize))[(i & 1) as usize] = x;
        i = i.wrapping_add(1)
        // addition / subtract index
    }
}
// multiplication mod q, result length n
unsafe fn ringmul_q(mut d: *mut modq_t, mut a: *mut modq_t, mut idx: *mut [u16; 2]) {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut k: usize = 0;
    let mut p: [modq_t; 1171] = [0; 1171];
    // Note: order of coefficients a[1..n] is reversed!
    // "lift" -- multiply by (x - 1)
    p[0] = -(*a.offset(0) as i32) as modq_t;
    i = 1i32 as usize;
    while i < PARAMS_ND {
        p[((PARAMS_ND as i32 + 1i32) as u64).wrapping_sub(i as u64) as usize] =
            (*a.offset(i.wrapping_sub(1) as isize) as i32 - *a.offset(i as isize) as i32) as modq_t;
        i = i.wrapping_add(1)
    }
    p[1] = *a.offset((PARAMS_ND as i32 - 1i32) as isize);
    // Initialize result
    zero_u16(d, PARAMS_ND as usize);
    i = 0i32 as usize;
    while i < (PARAMS_H / 2) {
        // Modified to always scan the same ranges
        k = (*idx.offset(i as isize))[0] as usize; // positive coefficients
        *d.offset(0) = (*d.offset(0) as i32 + p[k as usize] as i32) as modq_t; // negative coefficients
        j = 1i32 as usize;
        while k > 0 {
            k = k.wrapping_sub(1);
            *d.offset(j as isize) = (*d.offset(j as isize) as i32 + p[k as usize] as i32) as modq_t;
            j = j.wrapping_add(1)
        }
        k = (PARAMS_ND as i32 + 1i32) as usize;
        while j < PARAMS_ND {
            k = k.wrapping_sub(1);
            *d.offset(j as isize) = (*d.offset(j as isize) as i32 + p[k as usize] as i32) as modq_t;
            j = j.wrapping_add(1)
        }
        k = (*idx.offset(i as isize))[1] as usize;
        *d.offset(0) = (*d.offset(0) as i32 - p[k as usize] as i32) as modq_t;
        j = 1i32 as usize;
        while k > 0 {
            k = k.wrapping_sub(1);
            *d.offset(j as isize) = (*d.offset(j as isize) as i32 - p[k as usize] as i32) as modq_t;
            j = j.wrapping_add(1)
        }
        k = (PARAMS_ND as i32 + 1i32) as usize;
        while j < PARAMS_ND {
            k = k.wrapping_sub(1);
            *d.offset(j as isize) = (*d.offset(j as isize) as i32 - p[k as usize] as i32) as modq_t;
            j = j.wrapping_add(1)
        }
        i = i.wrapping_add(1)
    }
    // "unlift"
    *d.offset(0) = -(*d.offset(0) as i32) as u16;
    i = 1i32 as usize;
    while i < PARAMS_ND {
        *d.offset(i as isize) =
            (*d.offset(i.wrapping_sub(1) as isize) as i32 - *d.offset(i as isize) as i32) as u16;
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
    let mut tmp_d: [modp_t; 1170] = [0u16; 1170];

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
unsafe fn create_A_random(mut A_random: *mut modq_t, mut seed: *const u8) {
    shake256(
        A_random as *mut u8,
        ((PARAMS_D as i32 * PARAMS_K as i32) as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<u16>() as libc::c_ulong) as usize,
        seed,
        PARAMS_KAPPA_BYTES as usize,
    );
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
unsafe fn unpack_p(mut vp: *mut modp_t, mut pv: *const u8) {
    let mut i: usize = 0; // unpack p bits
    let mut j: usize = 0;
    let mut t: modp_t = 0;
    j = 0i32 as usize;
    i = 0i32 as usize;
    while i < PARAMS_ND {
        t = (*pv.offset((j >> 3i32) as isize) as i32 >> (j & 7)) as modp_t;
        if (j & 7).wrapping_add(PARAMS_P_BITS) > 8 {
            t = (t as i32
                | (*pv.offset((j >> 3).wrapping_add(1) as isize) as modp_t as i32)
                    << (8u8).wrapping_sub(j as u8 & 7)) as modp_t
        }
        *vp.offset(i as isize) = (t as i32 & PARAMS_P as i32 - 1i32) as modp_t;
        j = (j as u64).wrapping_add(PARAMS_P_BITS as i32 as u64) as usize;
        i = i.wrapping_add(1)
    }
}
// generate a keypair (sigma, B)
unsafe fn r5_cpa_pke_keygen(pk: &mut [u8], sk: &mut [u8], seed: &[u8]) {
    let mut A: [modq_t; 1170] = [0; 1170]; // sigma = seed of A
    let mut B: [modq_t; 1170] = [0; 1170];
    let mut S_idx: [[u16; 2]; 111] = [[0; 2]; 111];
    pk[0..PARAMS_KAPPA_BYTES].copy_from_slice(&seed[0..PARAMS_KAPPA_BYTES]);
    // A from sigma
    create_A_random(A.as_mut_ptr(), pk.as_ptr()); // secret key -- Random S

    sk[0..PARAMS_KAPPA_BYTES].copy_from_slice(&seed[PARAMS_KAPPA_BYTES..2*PARAMS_KAPPA_BYTES]);
    create_secret_vector(S_idx.as_mut_ptr(), sk.as_ptr());
    ringmul_q(B.as_mut_ptr(), A.as_mut_ptr(), S_idx.as_mut_ptr());
    // Compress B q_bits -> p_bits, pk = sigma | B
    pack_q_p(
        pk.as_mut_ptr().offset(PARAMS_KAPPA_BYTES as isize),
        B.as_mut_ptr(),
        PARAMS_H1 as i32 as modq_t,
    );
}

unsafe fn r5_cpa_pke_encrypt(
    mut ct: *mut u8,
    mut pk: *const u8,
    mut m: *const u8,
    mut rho: *const u8,
) -> i32 {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut A: [modq_t; 1170] = [0; 1170];
    let mut R_idx: [[u16; 2]; 111] = [[0; 2]; 111];
    let mut U_T: [modq_t; 1170] = [0; 1170];
    let mut B: [modp_t; 1170] = [0; 1170];
    let mut X: [modp_t; 256] = [0; 256];
    let mut m1: [u8; 32] = [0; 32];
    let mut t: modp_t = 0;
    let mut tm: modp_t = 0;
    // unpack public key
    unpack_p(
        B.as_mut_ptr(),
        pk.offset(PARAMS_KAPPA_BYTES as isize),
    );
    // A from sigma
    create_A_random(A.as_mut_ptr(), pk); // add error correction code
    copy_u8(m1.as_mut_ptr(), m, PARAMS_KAPPA_BYTES as usize);
    zero_u8(
        m1.as_mut_ptr().offset(PARAMS_KAPPA_BYTES as isize),
        (PARAMS_MUB_SIZE as i32 - PARAMS_KAPPA_BYTES as i32) as usize,
    );
    // Create R
    create_secret_vector(R_idx.as_mut_ptr(), rho); // U^T == U = A^T * R == A * R (mod q)
    ringmul_q(U_T.as_mut_ptr(), A.as_mut_ptr(), R_idx.as_mut_ptr()); // X = B^T * R == B * R (mod p)
    ringmul_p(X.as_mut_ptr(), B.as_mut_ptr(), R_idx.as_mut_ptr()); // ct = U^T | v
    pack_q_p(ct, U_T.as_mut_ptr(), PARAMS_H2 as i32 as modq_t);
    zero_u8(
        ct.offset(PARAMS_NDP_SIZE as isize),
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
        tm = (m1[(i.wrapping_mul(PARAMS_B_BITS) >> 3i32) as usize] as i32
            >> (i.wrapping_mul(PARAMS_B_BITS) & 7)) as modp_t; // pack t bits
        t = ((t as i32
            + ((tm as i32 & (1i32 << PARAMS_B_BITS as i32) - 1i32)
                << PARAMS_T_BITS as i32 - PARAMS_B_BITS as i32)) as modp_t as i32
            & (1i32 << PARAMS_T_BITS as i32) - 1i32) as modp_t; // ct = U^T | v
        *ct.offset((j >> 3i32) as isize) =
            (*ct.offset((j >> 3i32) as isize) as i32 | (t as i32) << (j & 7)) as u8; // unpack t bits
        if (j & 7).wrapping_add(PARAMS_T_BITS) > 8 {
            *ct.offset((j >> 3i32).wrapping_add(1) as isize) =
                (*ct.offset((j >> 3i32).wrapping_add(1) as isize) as i32
                    | t as i32 >> (8u8).wrapping_sub(j as u8 & 7)) as u8
        } // X' = S^T * U == U^T * S (mod p)
        j = (j as u64).wrapping_add(PARAMS_T_BITS as i32 as u64) as usize;
        i = i.wrapping_add(1)
    }
    return 0i32;
}
unsafe fn r5_cpa_pke_decrypt(mut m: *mut u8, mut sk: *const u8, mut ct: *const u8) -> i32 {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut S_idx: [[u16; 2]; 111] = [[0; 2]; 111];
    let mut U_T: [modp_t; 1170] = [0; 1170];
    let mut v: [modp_t; 256] = [0; 256];
    let mut t: modp_t = 0;
    let mut X_prime: [modp_t; 256] = [0; 256];
    let mut m1: [u8; 32] = [
        0i32 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    create_secret_vector(S_idx.as_mut_ptr(), sk);
    unpack_p(U_T.as_mut_ptr(), ct);
    j = (8i32 * PARAMS_NDP_SIZE as i32) as usize;
    i = 0i32 as usize;
    while i < PARAMS_MU {
        t = (*ct.offset((j >> 3i32) as isize) as i32 >> (j & 7)) as modp_t;
        if (j & 7).wrapping_add(PARAMS_T_BITS) > 8 {
            t = (t as i32
                | (*ct.offset((j >> 3i32).wrapping_add(1) as isize) as i32)
                    << (8u8).wrapping_sub(j as u8 & 7)) as modp_t
        }
        v[i as usize] = (t as i32 & (1i32 << PARAMS_T_BITS as i32) - 1i32) as modp_t;
        j = (j as u64).wrapping_add(PARAMS_T_BITS as i32 as u64) as usize;
        i = i.wrapping_add(1)
    }
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
    copy_u8(m, m1.as_mut_ptr(), PARAMS_KAPPA_BYTES as usize);
    return 0i32;
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

    sk[PARAMS_KAPPA_BYTES..2*PARAMS_KAPPA_BYTES].copy_from_slice(&coins[64..]);
    sk[2*PARAMS_KAPPA_BYTES..].copy_from_slice(&pk);

    return (pk,sk)
}

unsafe fn r5_cca_kem_encapsulate(
    mut ct: *mut u8,
    mut k: *mut u8,
    mut pk: *const u8,
    mut coins: *const u8,
) -> i32 {
    let mut hash_in: [u8; 1541] = [0; 1541];
    let mut L_g_rho: [[u8; 32]; 3] = [[0; 32]; 3];
    copy_u8(
        hash_in.as_mut_ptr(),
        coins,
        PARAMS_KAPPA_BYTES as usize,
    );
    copy_u8(
        hash_in
            .as_mut_ptr()
            .offset(PARAMS_KAPPA_BYTES as isize),
        pk,
        PARAMS_PK_SIZE as usize,
    );
    shake256(
        L_g_rho.as_mut_ptr() as *mut u8,
        (3i32 * PARAMS_KAPPA_BYTES as i32) as usize,
        hash_in.as_mut_ptr(),
        (PARAMS_KAPPA_BYTES as i32 + PARAMS_PK_SIZE as i32) as usize,
    );
    /* Encrypt  */
    r5_cpa_pke_encrypt(ct, pk, coins, L_g_rho[2].as_mut_ptr()); // m: ct = (U,v)
                                                                /* Append g: ct = (U,v,g) */
    copy_u8(
        ct.offset(PARAMS_CT_SIZE as isize),
        L_g_rho[1].as_mut_ptr(),
        PARAMS_KAPPA_BYTES as usize,
    );
    /* k = H(L, ct) */
    copy_u8(
        hash_in.as_mut_ptr(),
        L_g_rho[0].as_mut_ptr(),
        PARAMS_KAPPA_BYTES as usize,
    );
    copy_u8(
        hash_in
            .as_mut_ptr()
            .offset(PARAMS_KAPPA_BYTES as isize),
        ct,
        (PARAMS_CT_SIZE as i32 + PARAMS_KAPPA_BYTES as i32) as usize,
    );
    shake256(
        k,
        PARAMS_KAPPA_BYTES as usize,
        hash_in.as_mut_ptr(),
        (PARAMS_KAPPA_BYTES as i32 + PARAMS_CT_SIZE as i32 + PARAMS_KAPPA_BYTES as i32) as usize,
    );
    return 0i32;
}
/* *
 * Encrypts a message.
 *
 * @param[out] ct     the encrypted message
 * @param[out] ct_len the length of the encrypted message (`CRYPTO_CIPHERTEXTBYTES` + `m_len`)
 * @param[in]  m      the message to encrypt
 * @param[in]  m_len  the length of the message to encrypt
 * @param[in]  pk     the public key to use for the encryption
 * @return __0__ in case of success
 */

pub fn encrypt(msg: &[u8], pk: &[u8], coins: &[u8]) -> Vec<u8> {

    if coins.len() != 32 {
        return Vec::new();
    }

    let mut ct = vec![0u8; PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES + msg.len() + DEM_TAG_LEN];

    let c1_len = PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES;

    let mut k: [u8; 32] = [0; 32];

    unsafe {
        r5_cca_kem_encapsulate(ct.as_mut_ptr(), k.as_mut_ptr(), pk.as_ptr(), coins.as_ptr());
    }

    /* Apply DEM to get second part of ct */
    round5_dem(&mut ct[c1_len..], &k, &msg);
    return ct;
}
unsafe fn r5_cca_kem_decapsulate(mut k: *mut u8, mut ct: *const u8, mut sk: *const u8) -> i32 {
    let mut hash_in: [u8; 1541] = [0; 1541];
    let mut m_prime: [u8; 32] = [0; 32];
    let mut L_g_rho_prime: [[u8; 32]; 3] = [[0; 32]; 3];
    let mut ct_prime: [u8; 1509] = [0; 1509];
    r5_cpa_pke_decrypt(m_prime.as_mut_ptr(), sk, ct);
    copy_u8(
        hash_in.as_mut_ptr(),
        m_prime.as_mut_ptr(),
        PARAMS_KAPPA_BYTES as usize,
    );
    copy_u8(
        hash_in
            .as_mut_ptr()
            .offset(PARAMS_KAPPA_BYTES as isize),
        sk.offset(PARAMS_KAPPA_BYTES as isize)
            .offset(PARAMS_KAPPA_BYTES as isize),
        PARAMS_PK_SIZE as usize,
    );
    shake256(
        L_g_rho_prime.as_mut_ptr() as *mut u8,
        (3i32 * PARAMS_KAPPA_BYTES as i32) as usize,
        hash_in.as_mut_ptr(),
        (PARAMS_KAPPA_BYTES as i32 + PARAMS_PK_SIZE as i32) as usize,
    );
    // Encrypt m: ct' = (U',v')
    r5_cpa_pke_encrypt(
        ct_prime.as_mut_ptr(),
        sk.offset(PARAMS_KAPPA_BYTES as isize)
            .offset(PARAMS_KAPPA_BYTES as isize),
        m_prime.as_mut_ptr(),
        L_g_rho_prime[2].as_mut_ptr(),
    );
    // ct' = (U',v',g')
    copy_u8(
        ct_prime.as_mut_ptr().offset(PARAMS_CT_SIZE as isize),
        L_g_rho_prime[1].as_mut_ptr(),
        PARAMS_KAPPA_BYTES as usize,
    );
    // k = H(L', ct')
    copy_u8(
        hash_in.as_mut_ptr(),
        L_g_rho_prime[0].as_mut_ptr(),
        PARAMS_KAPPA_BYTES as usize,
    );
    // verification ok ?
    let fail: u8 = constant_time_memcmp(
        ct as *const libc::c_void,
        ct_prime.as_mut_ptr() as *const libc::c_void,
        (PARAMS_CT_SIZE as i32 + PARAMS_KAPPA_BYTES as i32) as usize,
    ) as u8;
    // k = H(y, ct') depending on fail state
    conditional_constant_time_memcpy(
        hash_in.as_mut_ptr() as *mut libc::c_void,
        sk.offset(PARAMS_KAPPA_BYTES as isize) as *const libc::c_void,
        PARAMS_KAPPA_BYTES as usize,
        fail,
    );
    copy_u8(
        hash_in
            .as_mut_ptr()
            .offset(PARAMS_KAPPA_BYTES as isize),
        ct_prime.as_mut_ptr(),
        (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES) as usize,
    );
    shake256(
        k,
        PARAMS_KAPPA_BYTES as usize,
        hash_in.as_mut_ptr(),
        (PARAMS_KAPPA_BYTES as i32 + PARAMS_CT_SIZE as i32 + PARAMS_KAPPA_BYTES as i32) as usize,
    );
    return 0i32;
}

pub fn decrypt(ctext: &[u8], sk: &[u8]) -> Vec<u8> {
    let c1_len = PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES;

    if ctext.len() < c1_len + DEM_TAG_LEN {
        return vec![]; // error
    }

    /* Determine k */
    let mut k: [u8; 32] = [0; 32];
    unsafe {
        r5_cca_kem_decapsulate(k.as_mut_ptr(), ctext.as_ptr(), sk.as_ptr());
    }
    /* Apply DEM-inverse to get m */

    round5_dem_inverse(&ctext[c1_len..], &k)
}
