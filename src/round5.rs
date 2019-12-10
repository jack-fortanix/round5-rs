#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case,
         non_upper_case_globals, unused_assignments, unused_mut)]
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
    fn constant_time_memcmp(s1: *const libc::c_void, s2: *const libc::c_void,
                            n: size_t) -> libc::c_int;
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
    fn conditional_constant_time_memcpy(dst: *mut libc::c_void,
                                        src: *const libc::c_void, n: size_t,
                                        flag: uint8_t);
    #[no_mangle]
    fn copy_u8(out: *mut uint8_t, in_0: *const uint8_t, len: size_t);
    #[no_mangle]
    fn copy_u16(out: *mut uint16_t, in_0: *const uint16_t, len: size_t);
    #[no_mangle]
    fn zero_u8(out: *mut uint8_t, len: size_t);
    #[no_mangle]
    fn zero_u16(out: *mut uint16_t, len: size_t);

}

fn print_hex(var: *const libc::c_char, data: *const uint8_t,
             nr_elements: size_t, element_size: size_t) {

}

type uint8_t = libc::c_uchar;
type uint16_t = libc::c_ushort;
type uint64_t = libc::c_ulong;
type size_t = libc::c_ulonglong;
// appropriate types
type modq_t = uint16_t;
type modp_t = uint16_t;
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

const SHAKE256_RATE: usize = 136;

unsafe fn shake256(out: *mut uint8_t, len: size_t,
                   seed: *const u8, seed_len: size_t) {
    let mut shake = crate::sha3::ShakeXof::new(256, std::slice::from_raw_parts(seed, seed_len as usize)).unwrap();
    shake.expand(std::slice::from_raw_parts_mut(out, len as usize));
}

// CCA_PKE Variant

pub const SECRETKEYBYTES:usize = (PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE);
pub const PUBLICKEYBYTES:usize = (PARAMS_PK_SIZE);
pub const CTEXT_BYTES:usize = (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES + 16);
// Size of the vector to pass to probe_cm

// Cache-resistant "occupancy probe". Tests and "occupies" a single slot at x.
// Return value zero (false) indicates the slot was originally empty.
unsafe fn probe_cm(mut v: *mut uint64_t, x: uint16_t)
 -> libc::c_int {
    // construct the selector
    let y: uint64_t = (1u64 << (x as libc::c_int & 0x3fi32)) as uint64_t;
    let mut z: uint64_t = (1u64 << (x as libc::c_int >> 6i32)) as uint64_t;
    let mut c: uint64_t = 0i32 as uint64_t;
    let mut i: size_t = 0i32 as size_t;
    while i < PROBEVEC64 as libc::c_int as libc::c_ulonglong {
        // always scan through all
        let mut a: uint64_t =
            *v.offset(i as isize); // set bit if not occupied.
        let mut b: uint64_t =
            a |
                y &
                    (z &
                         1i32 as
                             libc::c_ulong).wrapping_neg(); // If change, mask.
        c |= a ^ b; // update value of v[i]
        *v.offset(i as isize) = b;
        z >>= 1i32;
        i = i.wrapping_add(1)
    }
    // final comparison doesn't need to be constant time
    return (c == 0i32 as libc::c_ulong) as libc::c_int;
    // return true if was occupied before
}
// create a sparse ternary vector from a seed
unsafe fn create_secret_vector(mut idx: *mut [uint16_t; 2],
                                          mut seed: *const uint8_t) {
    let mut v: [uint64_t; 19] = [0; 19];

    let mut shake = crate::sha3::ShakeXof::new(256, std::slice::from_raw_parts(seed, PARAMS_KAPPA_BYTES)).unwrap();
    let mut index: size_t = SHAKE256_RATE as libc::c_int as size_t;
    let mut output: [uint8_t; 136] =
        [0i32 as uint8_t, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0];
    let mut i: size_t = 0i32 as size_t;
    while i < PARAMS_H as libc::c_int as libc::c_ulonglong {
        let mut x: uint16_t = 0;
        loop  {
            loop  {
                if index >= SHAKE256_RATE as libc::c_int as libc::c_ulonglong
                {
                    shake.expand(&mut output);
                    index = 0i32 as size_t
                }
                x =
                    (output[index as usize] as libc::c_int |
                         (output[index.wrapping_add(1i32 as libc::c_ulonglong)
                                     as usize] as libc::c_int) << 8i32) as
                        uint16_t;
                index =
                    (index as
                         libc::c_ulonglong).wrapping_add(2i32 as
                                                             libc::c_ulonglong)
                        as size_t as size_t;
                if !(x as libc::c_int >= PARAMS_RS_LIM as libc::c_int) {
                    break ;
                }
            }
            x = (x as libc::c_int / PARAMS_RS_DIV as libc::c_int) as uint16_t;
            if !(probe_cm(v.as_mut_ptr(), x) != 0) { break ; }
        }
        (*idx.offset((i >> 1i32) as
                         isize))[(i & 1i32 as libc::c_ulonglong) as usize] =
            x;
        i = i.wrapping_add(1)
        // addition / subtract index
    };
}
// multiplication mod q, result length n
unsafe fn ringmul_q(mut d: *mut modq_t, mut a: *mut modq_t,
                               mut idx: *mut [uint16_t; 2]) {
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut k: size_t = 0;
    let mut p: [modq_t; 1171] = [0; 1171];
    // Note: order of coefficients a[1..n] is reversed!
    // "lift" -- multiply by (x - 1)
    p[0] = -(*a.offset(0) as libc::c_int) as modq_t;
    i = 1i32 as size_t;
    while i < PARAMS_ND as libc::c_int as libc::c_ulonglong {
        p[((PARAMS_ND as libc::c_int + 1i32) as
               libc::c_ulonglong).wrapping_sub(i) as usize] =
            (*a.offset(i.wrapping_sub(1i32 as libc::c_ulonglong) as isize) as
                 libc::c_int - *a.offset(i as isize) as libc::c_int) as
                modq_t;
        i = i.wrapping_add(1)
    }
    p[1] = *a.offset((PARAMS_ND as libc::c_int - 1i32) as isize);
    // Initialize result
    zero_u16(d, PARAMS_ND as libc::c_int as size_t);
    i = 0i32 as size_t;
    while i < (PARAMS_H as libc::c_int / 2i32) as libc::c_ulonglong {
        // Modified to always scan the same ranges
        k = (*idx.offset(i as isize))[0] as size_t; // positive coefficients
        *d.offset(0) =
            (*d.offset(0) as libc::c_int + p[k as usize] as libc::c_int) as
                modq_t; // negative coefficients
        j = 1i32 as size_t;
        while k > 0i32 as libc::c_ulonglong {
            k = k.wrapping_sub(1);
            *d.offset(j as isize) =
                (*d.offset(j as isize) as libc::c_int +
                     p[k as usize] as libc::c_int) as modq_t;
            j = j.wrapping_add(1)
        }
        k = (PARAMS_ND as libc::c_int + 1i32) as size_t;
        while j < PARAMS_ND as libc::c_int as libc::c_ulonglong {
            k = k.wrapping_sub(1);
            *d.offset(j as isize) =
                (*d.offset(j as isize) as libc::c_int +
                     p[k as usize] as libc::c_int) as modq_t;
            j = j.wrapping_add(1)
        }
        k = (*idx.offset(i as isize))[1] as size_t;
        *d.offset(0) =
            (*d.offset(0) as libc::c_int - p[k as usize] as libc::c_int) as
                modq_t;
        j = 1i32 as size_t;
        while k > 0i32 as libc::c_ulonglong {
            k = k.wrapping_sub(1);
            *d.offset(j as isize) =
                (*d.offset(j as isize) as libc::c_int -
                     p[k as usize] as libc::c_int) as modq_t;
            j = j.wrapping_add(1)
        }
        k = (PARAMS_ND as libc::c_int + 1i32) as size_t;
        while j < PARAMS_ND as libc::c_int as libc::c_ulonglong {
            k = k.wrapping_sub(1);
            *d.offset(j as isize) =
                (*d.offset(j as isize) as libc::c_int -
                     p[k as usize] as libc::c_int) as modq_t;
            j = j.wrapping_add(1)
        }
        i = i.wrapping_add(1)
    }
    // "unlift"
    *d.offset(0) = -(*d.offset(0) as libc::c_int) as uint16_t;
    i = 1i32 as size_t;
    while i < PARAMS_ND as libc::c_int as libc::c_ulonglong {
        *d.offset(i as isize) =
            (*d.offset(i.wrapping_sub(1i32 as libc::c_ulonglong) as isize) as
                 libc::c_int - *d.offset(i as isize) as libc::c_int) as
                uint16_t;
        i = i.wrapping_add(1)
    };
}
// multiplication mod p, result length mu
unsafe fn ringmul_p(mut d: *mut modp_t, mut a: *mut modp_t,
                               mut idx: *mut [uint16_t; 2]) {
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut k: size_t = 0;
    let mut p: [modp_t; 1171] = [0; 1171];
    // Note: order of coefficients a[1..n] is reversed!
    // Without error correction we "lift" -- i.e. multiply by (x - 1)
    p[0] = -(*a.offset(0) as libc::c_int) as modp_t;
    i = 1i32 as size_t;
    while i < PARAMS_ND as libc::c_int as libc::c_ulonglong {
        p[((PARAMS_ND as libc::c_int + 1i32) as
               libc::c_ulonglong).wrapping_sub(i) as usize] =
            (*a.offset(i.wrapping_sub(1i32 as libc::c_ulonglong) as isize) as
                 libc::c_int - *a.offset(i as isize) as libc::c_int) as
                modp_t;
        i = i.wrapping_add(1)
    }
    p[1] = *a.offset((PARAMS_ND as libc::c_int - 1i32) as isize);
    // Initialize result
    let mut tmp_d: [modp_t; 1170] =
        [0i32 as modp_t, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0];
    i = 0i32 as size_t;
    while i < (PARAMS_H as libc::c_int / 2i32) as libc::c_ulonglong {
        // Modified to always scan the same ranges
        k = (*idx.offset(i as isize))[0] as size_t; // positive coefficients
        tmp_d[0] =
            (tmp_d[0] as libc::c_int + p[k as usize] as libc::c_int) as
                modp_t; // negative coefficients
        j = 1i32 as size_t;
        while k > 0i32 as libc::c_ulonglong {
            k = k.wrapping_sub(1);
            tmp_d[j as usize] =
                (tmp_d[j as usize] as libc::c_int +
                     p[k as usize] as libc::c_int) as modp_t;
            j = j.wrapping_add(1)
        }
        k = (PARAMS_ND as libc::c_int + 1i32) as size_t;
        while j < PARAMS_ND as libc::c_int as libc::c_ulonglong {
            k = k.wrapping_sub(1);
            tmp_d[j as usize] =
                (tmp_d[j as usize] as libc::c_int +
                     p[k as usize] as libc::c_int) as modp_t;
            j = j.wrapping_add(1)
        }
        k = (*idx.offset(i as isize))[1] as size_t;
        tmp_d[0] =
            (tmp_d[0] as libc::c_int - p[k as usize] as libc::c_int) as
                modp_t;
        j = 1i32 as size_t;
        while k > 0i32 as libc::c_ulonglong {
            k = k.wrapping_sub(1);
            tmp_d[j as usize] =
                (tmp_d[j as usize] as libc::c_int -
                     p[k as usize] as libc::c_int) as modp_t;
            j = j.wrapping_add(1)
        }
        k = (PARAMS_ND as libc::c_int + 1i32) as size_t;
        while j < PARAMS_ND as libc::c_int as libc::c_ulonglong {
            k = k.wrapping_sub(1);
            tmp_d[j as usize] =
                (tmp_d[j as usize] as libc::c_int -
                     p[k as usize] as libc::c_int) as modp_t;
            j = j.wrapping_add(1)
        }
        i = i.wrapping_add(1)
    }
    // Without error correction we "lifted" so we now need to "unlift"
    tmp_d[0] = -(tmp_d[0] as libc::c_int) as modp_t;
    i = 1i32 as size_t;
    while i < PARAMS_MU as libc::c_int as libc::c_ulonglong {
        tmp_d[i as usize] =
            (tmp_d[i.wrapping_sub(1i32 as libc::c_ulonglong) as usize] as
                 libc::c_int - tmp_d[i as usize] as libc::c_int) as modp_t;
        i = i.wrapping_add(1)
    }
    // Copy result
    copy_u16(d, tmp_d.as_mut_ptr(), PARAMS_MU as libc::c_int as size_t);
}
// Creates A random for the given seed and algorithm parameters.
unsafe fn create_A_random(mut A_random: *mut modq_t,
                                     mut seed: *const uint8_t) {
    shake256(A_random as *mut uint8_t,
             ((PARAMS_D as libc::c_int * PARAMS_K as libc::c_int) as
                  libc::c_ulong).wrapping_mul(::std::mem::size_of::<uint16_t>()
                                                  as libc::c_ulong) as size_t,
             seed, PARAMS_KAPPA_BYTES as libc::c_int as size_t);
}
// compress ND elements of q bits into p bits and pack into a byte string
unsafe fn pack_q_p(mut pv: *mut uint8_t, mut vq: *const modq_t,
                              rounding_constant: modq_t) {
    let mut i: size_t = 0; // pack p bits
    let mut j: size_t = 0;
    let mut t: modp_t = 0;
    zero_u8(pv, PARAMS_NDP_SIZE as libc::c_int as size_t);
    j = 0i32 as size_t;
    i = 0i32 as size_t;
    while i < PARAMS_ND as libc::c_int as libc::c_ulonglong {
        t =
            (*vq.offset(i as isize) as libc::c_int +
                 rounding_constant as libc::c_int >>
                 PARAMS_Q_BITS as libc::c_int - PARAMS_P_BITS as libc::c_int &
                 PARAMS_P as libc::c_int - 1i32) as modp_t;
        *pv.offset((j >> 3i32) as isize) =
            (*pv.offset((j >> 3i32) as isize) as libc::c_int |
                 (t as libc::c_int) << (j & 7i32 as libc::c_ulonglong)) as
                uint8_t;
        if (j &
                7i32 as
                    libc::c_ulonglong).wrapping_add(PARAMS_P_BITS as
                                                        libc::c_int as
                                                        libc::c_ulonglong) >
               8i32 as libc::c_ulonglong {
            *pv.offset((j >> 3i32).wrapping_add(1i32 as libc::c_ulonglong) as
                           isize) =
                (*pv.offset((j >>
                                 3i32).wrapping_add(1i32 as libc::c_ulonglong)
                                as isize) as libc::c_int |
                     t as libc::c_int >>
                         (8i32 as
                              libc::c_ulonglong).wrapping_sub(j &
                                                                  7i32 as
                                                                      libc::c_ulonglong))
                    as uint8_t
        }
        j =
            (j as
                 libc::c_ulonglong).wrapping_add(PARAMS_P_BITS as libc::c_int
                                                     as libc::c_ulonglong) as
                size_t as size_t;
        i = i.wrapping_add(1)
    };
}
// unpack a byte string into ND elements of p bits
unsafe fn unpack_p(mut vp: *mut modp_t, mut pv: *const uint8_t) {
    let mut i: size_t = 0; // unpack p bits
    let mut j: size_t = 0;
    let mut t: modp_t = 0;
    j = 0i32 as size_t;
    i = 0i32 as size_t;
    while i < PARAMS_ND as libc::c_int as libc::c_ulonglong {
        t =
            (*pv.offset((j >> 3i32) as isize) as libc::c_int >>
                 (j & 7i32 as libc::c_ulonglong)) as modp_t;
        if (j &
                7i32 as
                    libc::c_ulonglong).wrapping_add(PARAMS_P_BITS as
                                                        libc::c_int as
                                                        libc::c_ulonglong) >
               8i32 as libc::c_ulonglong {
            t =
                (t as libc::c_int |
                     (*pv.offset((j >>
                                      3i32).wrapping_add(1i32 as
                                                             libc::c_ulonglong)
                                     as isize) as modp_t as libc::c_int) <<
                         (8i32 as
                              libc::c_ulonglong).wrapping_sub(j &
                                                                  7i32 as
                                                                      libc::c_ulonglong))
                    as modp_t
        }
        *vp.offset(i as isize) =
            (t as libc::c_int & PARAMS_P as libc::c_int - 1i32) as modp_t;
        j =
            (j as
                 libc::c_ulonglong).wrapping_add(PARAMS_P_BITS as libc::c_int
                                                     as libc::c_ulonglong) as
                size_t as size_t;
        i = i.wrapping_add(1)
    };
}
// generate a keypair (sigma, B)
unsafe fn r5_cpa_pke_keygen(mut pk: *mut uint8_t,
                                       mut sk: *mut uint8_t,
                                       mut seed: *const uint8_t)
 -> libc::c_int {
    let mut A: [modq_t; 1170] = [0; 1170]; // sigma = seed of A
    let mut B: [modq_t; 1170] = [0; 1170];
    let mut S_idx: [[uint16_t; 2]; 111] = [[0; 2]; 111];
    copy_u8(pk, seed, 32i32 as size_t);
    print_hex(b"r5_cpa_pke_keygen: sigma\x00" as *const u8 as
                  *const libc::c_char, pk,
              PARAMS_KAPPA_BYTES as libc::c_int as size_t, 1i32 as size_t);
    // A from sigma
    create_A_random(A.as_mut_ptr(), pk); // secret key -- Random S
    copy_u8(sk, seed.offset(32), 32i32 as size_t); // B = A * S
    create_secret_vector(S_idx.as_mut_ptr(), sk as *const uint8_t);
    ringmul_q(B.as_mut_ptr(), A.as_mut_ptr(), S_idx.as_mut_ptr());
    // Compress B q_bits -> p_bits, pk = sigma | B
    pack_q_p(pk.offset(PARAMS_KAPPA_BYTES as libc::c_int as isize),
             B.as_mut_ptr(), PARAMS_H1 as libc::c_int as modq_t);
    return 0i32;
}
unsafe fn r5_cpa_pke_encrypt(mut ct: *mut uint8_t,
                                        mut pk: *const uint8_t,
                                        mut m: *const uint8_t,
                                        mut rho: *const uint8_t)
 -> libc::c_int {
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut A: [modq_t; 1170] = [0; 1170];
    let mut R_idx: [[uint16_t; 2]; 111] = [[0; 2]; 111];
    let mut U_T: [modq_t; 1170] = [0; 1170];
    let mut B: [modp_t; 1170] = [0; 1170];
    let mut X: [modp_t; 256] = [0; 256];
    let mut m1: [uint8_t; 32] = [0; 32];
    let mut t: modp_t = 0;
    let mut tm: modp_t = 0;
    // unpack public key
    unpack_p(B.as_mut_ptr(),
             pk.offset(PARAMS_KAPPA_BYTES as libc::c_int as isize));
    // A from sigma
    create_A_random(A.as_mut_ptr(), pk); // add error correction code
    copy_u8(m1.as_mut_ptr(), m, PARAMS_KAPPA_BYTES as libc::c_int as size_t);
    zero_u8(m1.as_mut_ptr().offset(PARAMS_KAPPA_BYTES as libc::c_int as
                                       isize),
            (PARAMS_MUB_SIZE as libc::c_int -
                 PARAMS_KAPPA_BYTES as libc::c_int) as size_t);
    // Create R
    create_secret_vector(R_idx.as_mut_ptr(),
                         rho); // U^T == U = A^T * R == A * R (mod q)
    ringmul_q(U_T.as_mut_ptr(), A.as_mut_ptr(),
              R_idx.as_mut_ptr()); // X = B^T * R == B * R (mod p)
    ringmul_p(X.as_mut_ptr(), B.as_mut_ptr(),
              R_idx.as_mut_ptr()); // ct = U^T | v
    print_hex(b"r5_cpa_pke_encrypt: rho\x00" as *const u8 as
                  *const libc::c_char, rho,
              PARAMS_KAPPA_BYTES as libc::c_int as size_t, 1i32 as size_t);
    print_hex(b"r5_cpa_pke_encrypt: sigma\x00" as *const u8 as
                  *const libc::c_char, pk,
              PARAMS_KAPPA_BYTES as libc::c_int as size_t, 1i32 as size_t);
    print_hex(b"r5_cpa_pke_encrypt: m1\x00" as *const u8 as
                  *const libc::c_char, m1.as_mut_ptr(),
              PARAMS_MUB_SIZE as libc::c_int as size_t, 1i32 as size_t);
    pack_q_p(ct, U_T.as_mut_ptr(), PARAMS_H2 as libc::c_int as modq_t);
    zero_u8(ct.offset(PARAMS_NDP_SIZE as libc::c_int as isize),
            PARAMS_MUT_SIZE as libc::c_int as size_t);
    j = (8i32 * PARAMS_NDP_SIZE as libc::c_int) as size_t;
    i = 0i32 as size_t;
    while i < PARAMS_MU as libc::c_int as libc::c_ulonglong {
        // compute, pack v
        // compress p->t
        t =
            (X[i as usize] as libc::c_int + PARAMS_H2 as libc::c_int >>
                 PARAMS_P_BITS as libc::c_int - PARAMS_T_BITS as libc::c_int)
                as modp_t;
        // add message
        tm =
            (m1[(i.wrapping_mul(PARAMS_B_BITS as libc::c_int as
                                    libc::c_ulonglong) >> 3i32) as usize] as
                 libc::c_int >>
                 (i.wrapping_mul(PARAMS_B_BITS as libc::c_int as
                                     libc::c_ulonglong) &
                      7i32 as libc::c_ulonglong)) as modp_t; // pack t bits
        t =
            ((t as libc::c_int +
                  ((tm as libc::c_int &
                        (1i32 << PARAMS_B_BITS as libc::c_int) - 1i32) <<
                       PARAMS_T_BITS as libc::c_int -
                           PARAMS_B_BITS as libc::c_int)) as modp_t as
                 libc::c_int & (1i32 << PARAMS_T_BITS as libc::c_int) - 1i32)
                as modp_t; // ct = U^T | v
        *ct.offset((j >> 3i32) as isize) =
            (*ct.offset((j >> 3i32) as isize) as libc::c_int |
                 (t as libc::c_int) << (j & 7i32 as libc::c_ulonglong)) as
                uint8_t; // unpack t bits
        if (j &
                7i32 as
                    libc::c_ulonglong).wrapping_add(PARAMS_T_BITS as
                                                        libc::c_int as
                                                        libc::c_ulonglong) >
               8i32 as libc::c_ulonglong {
            *ct.offset((j >> 3i32).wrapping_add(1i32 as libc::c_ulonglong) as
                           isize) =
                (*ct.offset((j >>
                                 3i32).wrapping_add(1i32 as libc::c_ulonglong)
                                as isize) as libc::c_int |
                     t as libc::c_int >>
                         (8i32 as
                              libc::c_ulonglong).wrapping_sub(j &
                                                                  7i32 as
                                                                      libc::c_ulonglong))
                    as uint8_t
        } // X' = S^T * U == U^T * S (mod p)
        j =
            (j as
                 libc::c_ulonglong).wrapping_add(PARAMS_T_BITS as libc::c_int
                                                     as libc::c_ulonglong) as
                size_t as size_t;
        i = i.wrapping_add(1)
    }
    return 0i32;
}
unsafe fn r5_cpa_pke_decrypt(mut m: *mut uint8_t,
                                        mut sk: *const uint8_t,
                                        mut ct: *const uint8_t)
 -> libc::c_int {
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut S_idx: [[uint16_t; 2]; 111] = [[0; 2]; 111];
    let mut U_T: [modp_t; 1170] = [0; 1170];
    let mut v: [modp_t; 256] = [0; 256];
    let mut t: modp_t = 0;
    let mut X_prime: [modp_t; 256] = [0; 256];
    let mut m1: [uint8_t; 32] =
        [0i32 as uint8_t, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    create_secret_vector(S_idx.as_mut_ptr(), sk);
    unpack_p(U_T.as_mut_ptr(), ct);
    j = (8i32 * PARAMS_NDP_SIZE as libc::c_int) as size_t;
    i = 0i32 as size_t;
    while i < PARAMS_MU as libc::c_int as libc::c_ulonglong {
        t =
            (*ct.offset((j >> 3i32) as isize) as libc::c_int >>
                 (j & 7i32 as libc::c_ulonglong)) as modp_t;
        if (j &
                7i32 as
                    libc::c_ulonglong).wrapping_add(PARAMS_T_BITS as
                                                        libc::c_int as
                                                        libc::c_ulonglong) >
               8i32 as libc::c_ulonglong {
            t =
                (t as libc::c_int |
                     (*ct.offset((j >>
                                      3i32).wrapping_add(1i32 as
                                                             libc::c_ulonglong)
                                     as isize) as libc::c_int) <<
                         (8i32 as
                              libc::c_ulonglong).wrapping_sub(j &
                                                                  7i32 as
                                                                      libc::c_ulonglong))
                    as modp_t
        }
        v[i as usize] =
            (t as libc::c_int & (1i32 << PARAMS_T_BITS as libc::c_int) - 1i32)
                as modp_t;
        j =
            (j as
                 libc::c_ulonglong).wrapping_add(PARAMS_T_BITS as libc::c_int
                                                     as libc::c_ulonglong) as
                size_t as size_t;
        i = i.wrapping_add(1)
    }
    ringmul_p(X_prime.as_mut_ptr(), U_T.as_mut_ptr(), S_idx.as_mut_ptr());
    // X' = v - X', compressed to 1 bit
    let mut x_p: modp_t = 0;
    i = 0i32 as size_t;
    while i < PARAMS_MU as libc::c_int as libc::c_ulonglong {
        // v - X' as mod p value (to be able to perform the rounding!)
        x_p =
            (((v[i as usize] as libc::c_int) <<
                  PARAMS_P_BITS as libc::c_int - PARAMS_T_BITS as libc::c_int)
                 - X_prime[i as usize] as libc::c_int) as modp_t;
        x_p =
            (x_p as libc::c_int + PARAMS_H3 as libc::c_int >>
                 PARAMS_P_BITS as libc::c_int - PARAMS_B_BITS as libc::c_int &
                 (1i32 << PARAMS_B_BITS as libc::c_int) - 1i32) as modp_t;
        m1[(i.wrapping_mul(PARAMS_B_BITS as libc::c_int as libc::c_ulonglong)
                >> 3i32) as usize] =
            (m1[(i.wrapping_mul(PARAMS_B_BITS as libc::c_int as
                                    libc::c_ulonglong) >> 3i32) as usize] as
                 libc::c_int |
                 (x_p as libc::c_int) <<
                     (i.wrapping_mul(PARAMS_B_BITS as libc::c_int as
                                         libc::c_ulonglong) &
                          7i32 as libc::c_ulonglong)) as uint8_t;
        i = i.wrapping_add(1)
    }
    copy_u8(m, m1.as_mut_ptr(), PARAMS_KAPPA_BYTES as libc::c_int as size_t);
    print_hex(b"r5_cpa_pke_decrypt: m\x00" as *const u8 as
                  *const libc::c_char, m,
              PARAMS_KAPPA_BYTES as libc::c_int as size_t, 1i32 as size_t);
    return 0i32;
}
unsafe fn round5_dem(mut c2: *mut uint8_t, mut c2_len: *mut size_t,
                     mut key: *const uint8_t,
                     mut m: *const uint8_t, m_len: size_t)
 -> libc::c_int {

    use mbedtls::cipher::*;

    let raw_key = std::slice::from_raw_parts(key, 32);

    let mut shake = crate::sha3::ShakeXof::new(256, &raw_key).unwrap();

    let mut key_and_iv = vec![0; 32+12];
    shake.expand(&mut key_and_iv);

    let message = std::slice::from_raw_parts(m, m_len as usize);

    let cipher = Cipher::<_, Authenticated, _>::new(
        raw::CipherId::Aes,
        raw::CipherMode::GCM,
        256
    ).unwrap();
    let cipher = cipher.set_key_iv(&key_and_iv[0..32], &key_and_iv[32..]).unwrap();

    let ad = vec![];

    let mut ctext = vec![0; message.len()];
    let mut tag = vec![0; 16];

    cipher.encrypt_auth(&ad, &message, &mut ctext, &mut tag).unwrap();

    copy_u8(c2, ctext.as_ptr(), ctext.len() as u64);
    copy_u8(c2.offset(ctext.len() as isize), tag.as_ptr(), 16);

    return 0i32;
}

unsafe fn round5_dem_inverse(mut m: *mut uint8_t,
                             mut m_len: *mut size_t,
                             mut key: *const uint8_t,
                             mut c2: *const uint8_t,
                             c2_len: size_t) -> libc::c_int {
    use mbedtls::cipher::*;

    let raw_key = std::slice::from_raw_parts(key, 32);

    let mut shake = crate::sha3::ShakeXof::new(256, &raw_key).unwrap();

    let mut key_and_iv = vec![0; 32+12];
    shake.expand(&mut key_and_iv);

    let ctext = std::slice::from_raw_parts(c2, c2_len as usize);

    let cipher = Cipher::<_, Authenticated, _>::new(
        raw::CipherId::Aes,
        raw::CipherMode::GCM,
        256
    ).unwrap();
    let cipher = cipher.set_key_iv(&key_and_iv[0..32], &key_and_iv[32..]).unwrap();

    let ad = vec![];

    let mut ptext = vec![0; ctext.len() - 16];

    cipher.decrypt_auth(&ad, &ctext[0..ctext.len()-16], &mut ptext, &ctext[ctext.len()-16..]).unwrap();

    copy_u8(m, ptext.as_ptr(), ptext.len() as u64);

    *m_len = ptext.len() as u64;

    return 0i32;
}
/* *
     * Generates an ENCRYPT key pair. Uses the fixed parameter configuration.
     *
     * @param[out] pk public key
     * @param[out] sk secret key
     * @return __0__ in case of success
     */

pub unsafe fn crypto_encrypt_keypair(mut pk: *mut uint8_t,
                                                mut sk: *mut uint8_t,
                                                mut coins: *const uint8_t)
 -> libc::c_int {
    /* Generate the base key pair */
    r5_cpa_pke_keygen(pk, sk, coins);
    /* Append y and pk to sk */
    copy_u8(sk.offset(PARAMS_KAPPA_BYTES as libc::c_int as isize),
            &*coins.offset(64),
            PARAMS_KAPPA_BYTES as libc::c_int as
                size_t); // G: (l | g | rho) = h(coins | pk);
    copy_u8(sk.offset(PARAMS_KAPPA_BYTES as libc::c_int as
                          isize).offset(PARAMS_KAPPA_BYTES as libc::c_int as
                                            isize), pk,
            PARAMS_PK_SIZE as libc::c_int as size_t);
    return 0i32;
}
unsafe fn r5_cca_kem_encapsulate(mut ct: *mut uint8_t,
                                            mut k: *mut uint8_t,
                                            mut pk: *const uint8_t,
                                            mut coins: *const uint8_t)
 -> libc::c_int {
    let mut hash_in: [uint8_t; 1541] = [0; 1541];
    let mut L_g_rho: [[uint8_t; 32]; 3] = [[0; 32]; 3];
    copy_u8(hash_in.as_mut_ptr(), coins,
            PARAMS_KAPPA_BYTES as libc::c_int as size_t);
    copy_u8(hash_in.as_mut_ptr().offset(PARAMS_KAPPA_BYTES as libc::c_int as
                                            isize), pk,
            PARAMS_PK_SIZE as libc::c_int as size_t);
    shake256(L_g_rho.as_mut_ptr() as *mut uint8_t,
             (3i32 * PARAMS_KAPPA_BYTES as libc::c_int) as size_t,
             hash_in.as_mut_ptr(),
             (PARAMS_KAPPA_BYTES as libc::c_int +
                  PARAMS_PK_SIZE as libc::c_int) as size_t);
    print_hex(b"r5_cca_kem_encapsulate: m\x00" as *const u8 as
                  *const libc::c_char, coins,
              PARAMS_KAPPA_BYTES as libc::c_int as size_t, 1i32 as size_t);
    print_hex(b"r5_cca_kem_encapsulate: L\x00" as *const u8 as
                  *const libc::c_char, L_g_rho[0].as_mut_ptr(),
              PARAMS_KAPPA_BYTES as libc::c_int as size_t, 1i32 as size_t);
    print_hex(b"r5_cca_kem_encapsulate: g\x00" as *const u8 as
                  *const libc::c_char, L_g_rho[1].as_mut_ptr(),
              PARAMS_KAPPA_BYTES as libc::c_int as size_t, 1i32 as size_t);
    print_hex(b"r5_cca_kem_encapsulate: rho\x00" as *const u8 as
                  *const libc::c_char, L_g_rho[2].as_mut_ptr(),
              PARAMS_KAPPA_BYTES as libc::c_int as size_t, 1i32 as size_t);
    /* Encrypt  */
    r5_cpa_pke_encrypt(ct, pk, coins,
                       L_g_rho[2].as_mut_ptr()); // m: ct = (U,v)
    /* Append g: ct = (U,v,g) */
    copy_u8(ct.offset(PARAMS_CT_SIZE as libc::c_int as isize),
            L_g_rho[1].as_mut_ptr(),
            PARAMS_KAPPA_BYTES as libc::c_int as size_t);
    /* k = H(L, ct) */
    copy_u8(hash_in.as_mut_ptr(), L_g_rho[0].as_mut_ptr(),
            PARAMS_KAPPA_BYTES as libc::c_int as size_t);
    copy_u8(hash_in.as_mut_ptr().offset(PARAMS_KAPPA_BYTES as libc::c_int as
                                            isize), ct,
            (PARAMS_CT_SIZE as libc::c_int +
                 PARAMS_KAPPA_BYTES as libc::c_int) as size_t);
    shake256(k, PARAMS_KAPPA_BYTES as libc::c_int as size_t,
             hash_in.as_mut_ptr(),
             (PARAMS_KAPPA_BYTES as libc::c_int +
                  PARAMS_CT_SIZE as libc::c_int +
                  PARAMS_KAPPA_BYTES as libc::c_int) as size_t);
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

pub unsafe fn crypto_encrypt(mut ct: *mut uint8_t,
                                        mut ct_len: *mut size_t,
                                        mut m: *const uint8_t, m_len: size_t,
                                        mut pk: *const uint8_t,
                                        mut coins: *const uint8_t)
 -> libc::c_int {
    let mut result: libc::c_int = -1i32;
    let c1_len: size_t =
        (PARAMS_CT_SIZE as libc::c_int + PARAMS_KAPPA_BYTES as libc::c_int) as
            size_t;
    let mut c1: [uint8_t; 1509] = [0; 1509];
    let mut c2_len: size_t = 0;
    let mut k: [uint8_t; 32] = [0; 32];
    /* Determine c1 and k */
    r5_cca_kem_encapsulate(c1.as_mut_ptr(), k.as_mut_ptr(), pk, coins);
    /* Copy c1 into first part of ct */
    copy_u8(ct, c1.as_mut_ptr(), c1_len);
    *ct_len = c1_len;
    /* Apply DEM to get second part of ct */
    if !(round5_dem(ct.offset(c1_len as isize), &mut c2_len, k.as_mut_ptr(),
                    m, m_len) != 0) {
        *ct_len =
            (*ct_len as libc::c_ulonglong).wrapping_add(c2_len) as size_t as
                size_t;
        /* All OK */
        result = 0i32
    } // r5_cpa_pke_decrypt m'
    return result;
}
unsafe fn r5_cca_kem_decapsulate(mut k: *mut uint8_t,
                                            mut ct: *const uint8_t,
                                            mut sk: *const uint8_t)
 -> libc::c_int {
    let mut hash_in: [uint8_t; 1541] = [0; 1541];
    let mut m_prime: [uint8_t; 32] = [0; 32];
    let mut L_g_rho_prime: [[uint8_t; 32]; 3] = [[0; 32]; 3];
    let mut ct_prime: [uint8_t; 1509] = [0; 1509];
    r5_cpa_pke_decrypt(m_prime.as_mut_ptr(), sk, ct);
    copy_u8(hash_in.as_mut_ptr(), m_prime.as_mut_ptr(),
            PARAMS_KAPPA_BYTES as libc::c_int as size_t);
    copy_u8(hash_in.as_mut_ptr().offset(PARAMS_KAPPA_BYTES as libc::c_int as
                                            isize),
            sk.offset(PARAMS_KAPPA_BYTES as libc::c_int as
                          isize).offset(PARAMS_KAPPA_BYTES as libc::c_int as
                                            isize),
            PARAMS_PK_SIZE as libc::c_int as size_t);
    shake256(L_g_rho_prime.as_mut_ptr() as *mut uint8_t,
             (3i32 * PARAMS_KAPPA_BYTES as libc::c_int) as size_t,
             hash_in.as_mut_ptr(),
             (PARAMS_KAPPA_BYTES as libc::c_int +
                  PARAMS_PK_SIZE as libc::c_int) as size_t);
    print_hex(b"r5_cca_kem_decapsulate: m_prime\x00" as *const u8 as
                  *const libc::c_char, m_prime.as_mut_ptr(),
              PARAMS_KAPPA_BYTES as libc::c_int as size_t, 1i32 as size_t);
    print_hex(b"r5_cca_kem_decapsulate: L_prime\x00" as *const u8 as
                  *const libc::c_char, L_g_rho_prime[0].as_mut_ptr(),
              PARAMS_KAPPA_BYTES as libc::c_int as size_t, 1i32 as size_t);
    print_hex(b"r5_cca_kem_decapsulate: g_prime\x00" as *const u8 as
                  *const libc::c_char, L_g_rho_prime[1].as_mut_ptr(),
              PARAMS_KAPPA_BYTES as libc::c_int as size_t, 1i32 as size_t);
    print_hex(b"r5_cca_kem_decapsulate: rho_prime\x00" as *const u8 as
                  *const libc::c_char, L_g_rho_prime[2].as_mut_ptr(),
              PARAMS_KAPPA_BYTES as libc::c_int as size_t, 1i32 as size_t);
    // Encrypt m: ct' = (U',v')
    r5_cpa_pke_encrypt(ct_prime.as_mut_ptr(),
                       sk.offset(PARAMS_KAPPA_BYTES as libc::c_int as
                                     isize).offset(PARAMS_KAPPA_BYTES as
                                                       libc::c_int as isize),
                       m_prime.as_mut_ptr(), L_g_rho_prime[2].as_mut_ptr());
    // ct' = (U',v',g')
    copy_u8(ct_prime.as_mut_ptr().offset(PARAMS_CT_SIZE as libc::c_int as
                                             isize),
            L_g_rho_prime[1].as_mut_ptr(),
            PARAMS_KAPPA_BYTES as libc::c_int as size_t);
    // k = H(L', ct')
    copy_u8(hash_in.as_mut_ptr(), L_g_rho_prime[0].as_mut_ptr(),
            PARAMS_KAPPA_BYTES as libc::c_int as size_t);
    // verification ok ?
    let fail: uint8_t =
        constant_time_memcmp(ct as *const libc::c_void,
                             ct_prime.as_mut_ptr() as *const libc::c_void,
                             (PARAMS_CT_SIZE as libc::c_int +
                                  PARAMS_KAPPA_BYTES as libc::c_int) as
                                 size_t) as uint8_t;
    // k = H(y, ct') depending on fail state
    conditional_constant_time_memcpy(hash_in.as_mut_ptr() as
                                         *mut libc::c_void,
                                     sk.offset(PARAMS_KAPPA_BYTES as
                                                   libc::c_int as isize) as
                                         *const libc::c_void,
                                     PARAMS_KAPPA_BYTES as libc::c_int as
                                         size_t, fail);
    copy_u8(hash_in.as_mut_ptr().offset(PARAMS_KAPPA_BYTES as libc::c_int as
                                            isize), ct_prime.as_mut_ptr(),
            (PARAMS_CT_SIZE as libc::c_int +
                 PARAMS_KAPPA_BYTES as libc::c_int) as size_t);
    shake256(k, PARAMS_KAPPA_BYTES as libc::c_int as size_t,
             hash_in.as_mut_ptr(),
             (PARAMS_KAPPA_BYTES as libc::c_int +
                  PARAMS_CT_SIZE as libc::c_int +
                  PARAMS_KAPPA_BYTES as libc::c_int) as size_t);
    return 0i32;
}
/* *
     * Decrypts a message.
     *
     * @param[out] m      the decrypted message
     * @param[out] m_len  the length of the decrypted message (`ct_len` - `CRYPTO_CIPHERTEXTBYTES`)
     * @param[in]  ct     the message to decrypt
     * @param[in]  ct_len the length of the message to decrypt
     * @param[in]  sk     the secret key to use for the decryption
     * @return __0__ in case of success
     */

pub unsafe fn crypto_encrypt_open(mut m: *mut uint8_t,
                                             mut m_len: *mut size_t,
                                             mut ct: *const uint8_t,
                                             ct_len: size_t,
                                             mut sk: *const uint8_t)
 -> libc::c_int {
    let mut k: [uint8_t; 32] = [0; 32];
    let c1_len: size_t =
        (PARAMS_CT_SIZE as libc::c_int + PARAMS_KAPPA_BYTES as libc::c_int) as
            size_t;
    let c2_len: size_t = ct_len.wrapping_sub(c1_len);
    /* Check length, should be at least c1_len + 16 (for the DEM tag) */
    if ct_len < c1_len.wrapping_add(16u32 as libc::c_ulonglong) {
        return -1i32
    }
    /* Determine k */
    r5_cca_kem_decapsulate(k.as_mut_ptr(), &*ct.offset(0), sk);
    /* Apply DEM-inverse to get m */
    if round5_dem_inverse(m, m_len, k.as_mut_ptr(),
                          &*ct.offset(c1_len as isize), c2_len) != 0 {
        return -1i32
    }
    return 0i32;
}
