#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case,
         non_upper_case_globals, unused_assignments, unused_mut)]
#![feature(const_raw_ptr_to_usize_cast, extern_types, main)]

mod sha3;
mod round5;
mod utils;

extern "C" {
    pub type engine_st;
    pub type evp_cipher_ctx_st;
    pub type evp_cipher_st;
    #[no_mangle]
    static mut stderr: *mut _IO_FILE;
    #[no_mangle]
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn fopen(__filename: *const libc::c_char, __modes: *const libc::c_char)
     -> *mut FILE;
    #[no_mangle]
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn sprintf(_: *mut libc::c_char, _: *const libc::c_char, _: ...)
     -> libc::c_int;
    #[no_mangle]
    fn fscanf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn fgetc(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn abort() -> !;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void,
              _: libc::c_ulong) -> libc::c_int;
    #[no_mangle]
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char,
               _: libc::c_ulong) -> libc::c_int;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    /*
 * Copyright (c) 2019, Koninklijke Philips N.V.
 */
    /* *
 * @file
 * Declaration of the NIST API functions and setting of the NIST API
 * algorithm parameters: `CRYPTO_SECRETKEYBYTES`, `CRYPTO_PUBLICKEYBYTES`,
 * `CRYPTO_BYTES`, and `CRYPTO_CIPHERBYTES`.
 */
    /* *
     * Generates an ENCRYPT key pair. Uses the fixed parameter configuration.
     *
     * @param[out] pk public key
     * @param[out] sk secret key
     * @return __0__ in case of success
     */
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
    #[no_mangle]
    fn crypto_encrypt(ct: *mut uint8_t, ct_len: *mut size_t,
                      m: *const uint8_t, m_len: size_t, pk: *const uint8_t,
                      coins: *const uint8_t) -> libc::c_int;
    #[no_mangle]
    fn crypto_encrypt_keypair(pk: *mut uint8_t, sk: *mut uint8_t,
                              coins: *const uint8_t) -> libc::c_int;
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
    #[no_mangle]
    fn crypto_encrypt_open(m: *mut uint8_t, m_len: *mut size_t,
                           ct: *const uint8_t, ct_len: size_t,
                           sk: *const uint8_t) -> libc::c_int;
    #[no_mangle]
    fn copy_u8(out: *mut uint8_t, in_0: *const uint8_t, len: size_t);
    #[no_mangle]
    fn zero_u8(out: *mut uint8_t, len: size_t);
    #[no_mangle]
    fn EVP_EncryptUpdate(ctx: *mut EVP_CIPHER_CTX, out: *mut libc::c_uchar,
                         outl: *mut libc::c_int, in_0: *const libc::c_uchar,
                         inl: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    #[no_mangle]
    fn EVP_EncryptInit_ex(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER,
                          impl_0: *mut ENGINE, key: *const libc::c_uchar,
                          iv: *const libc::c_uchar) -> libc::c_int;
    #[no_mangle]
    fn EVP_aes_256_ecb() -> *const EVP_CIPHER;
    #[no_mangle]
    fn EVP_CIPHER_CTX_free(c: *mut EVP_CIPHER_CTX);
    #[no_mangle]
    fn ERR_print_errors_fp(fp: *mut FILE);
}
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
#[derive ( Copy, Clone )]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub __pad1: *mut libc::c_void,
    pub __pad2: *mut libc::c_void,
    pub __pad3: *mut libc::c_void,
    pub __pad4: *mut libc::c_void,
    pub __pad5: libc::c_int,
    pub _mode: libc::c_int,
    pub _unused2: libc::c_char,
}
pub type _IO_lock_t = ();
#[derive ( Copy, Clone )]
#[repr(C)]
pub struct _IO_marker {
    pub _next: *mut _IO_marker,
    pub _sbuf: *mut _IO_FILE,
    pub _pos: libc::c_int,
}
pub type FILE = _IO_FILE;
//#include <stdint.h>
//#include <stddef.h>
pub type uint8_t = libc::c_uchar;
pub type ENGINE = engine_st;
pub type C2RustUnnamed = libc::c_uint;
pub const _ISalnum: C2RustUnnamed = 8;
pub const _ISpunct: C2RustUnnamed = 4;
pub const _IScntrl: C2RustUnnamed = 2;
pub const _ISblank: C2RustUnnamed = 1;
pub const _ISgraph: C2RustUnnamed = 32768;
pub const _ISprint: C2RustUnnamed = 16384;
pub const _ISspace: C2RustUnnamed = 8192;
pub const _ISxdigit: C2RustUnnamed = 4096;
pub const _ISdigit: C2RustUnnamed = 2048;
pub const _ISalpha: C2RustUnnamed = 1024;
pub const _ISlower: C2RustUnnamed = 512;
pub const _ISupper: C2RustUnnamed = 256;
pub type size_t = libc::c_ulonglong;
#[derive ( Copy, Clone )]
#[repr(C)]
pub struct AES256_CTR_DRBG_struct {
    pub Key: [uint8_t; 32],
    pub V: [uint8_t; 16],
    pub reseed_counter: libc::c_int,
}
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
pub type EVP_CIPHER = evp_cipher_st;
static mut CRYPTO_SECRETKEYBYTES: size_t = 1413i32 as size_t;
static mut CRYPTO_PUBLICKEYBYTES: size_t = 1349i32 as size_t;
static mut CRYPTO_BYTES: size_t = 1525i32 as size_t;
//
//  rng.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#[no_mangle]
pub static mut DRBG_ctx: AES256_CTR_DRBG_struct =
    AES256_CTR_DRBG_struct{Key: [0; 32], V: [0; 16], reseed_counter: 0,};
unsafe extern "C" fn handleErrors() { ERR_print_errors_fp(stderr); abort(); }
// Use whatever AES implementation you have. This uses AES from openSSL library
//    key - 256-bit AES key
//    ctr - a 128-bit plaintext value
//    buffer - a 128-bit ciphertext value
unsafe extern "C" fn AES256_ECB(mut key: *mut uint8_t, mut ctr: *mut uint8_t,
                                mut buffer: *mut uint8_t) {
    let mut ctx: *mut EVP_CIPHER_CTX = 0 as *mut EVP_CIPHER_CTX;
    let mut len: libc::c_int = 0;
    let mut ciphertext_len: libc::c_int = 0;
    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();
    if ctx.is_null() { handleErrors(); }
    if 1i32 !=
           EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), 0 as *mut ENGINE, key,
                              0 as *const libc::c_uchar) {
        handleErrors();
    }
    if 1i32 != EVP_EncryptUpdate(ctx, buffer, &mut len, ctr, 16i32) {
        handleErrors();
    }
    ciphertext_len = len;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}
unsafe extern "C" fn randombytes_init(mut entropy_input: *mut uint8_t,
                                      mut personalization_string:
                                          *mut uint8_t,
                                      mut security_strength: libc::c_int) {
    let mut seed_material: [uint8_t; 48] = [0; 48];
    copy_u8(seed_material.as_mut_ptr(), entropy_input, 48i32 as size_t);
    if !personalization_string.is_null() {
        let mut i: libc::c_int = 0i32;
        while i < 48i32 {
            seed_material[i as usize] =
                (seed_material[i as usize] as libc::c_int ^
                     *personalization_string.offset(i as isize) as
                         libc::c_int) as uint8_t;
            i += 1
        }
    }
    zero_u8(DRBG_ctx.Key.as_mut_ptr(), 32i32 as size_t);
    zero_u8(DRBG_ctx.V.as_mut_ptr(), 16i32 as size_t);
    AES256_CTR_DRBG_Update(seed_material.as_mut_ptr(),
                           DRBG_ctx.Key.as_mut_ptr(),
                           DRBG_ctx.V.as_mut_ptr());
    DRBG_ctx.reseed_counter = 1i32;
}
unsafe extern "C" fn randombytes(mut x: *mut uint8_t, mut xlen: size_t)
 -> libc::c_int {
    let mut block: [uint8_t; 16] = [0; 16];
    let mut i: libc::c_int = 0i32;
    while xlen > 0i32 as libc::c_ulonglong {
        //increment V
        let mut j: libc::c_int = 15i32;
        while j >= 0i32 {
            if DRBG_ctx.V[j as usize] as libc::c_int == 0xffi32 {
                DRBG_ctx.V[j as usize] = 0i32 as uint8_t;
                j -= 1
            } else {
                DRBG_ctx.V[j as usize] =
                    DRBG_ctx.V[j as usize].wrapping_add(1);
                break ;
            }
        }
        AES256_ECB(DRBG_ctx.Key.as_mut_ptr(), DRBG_ctx.V.as_mut_ptr(),
                   block.as_mut_ptr());
        if xlen > 15i32 as libc::c_ulonglong {
            copy_u8(x.offset(i as isize), block.as_mut_ptr(),
                    16i32 as size_t);
            i += 16i32;
            xlen =
                (xlen as
                     libc::c_ulonglong).wrapping_sub(16i32 as
                                                         libc::c_ulonglong) as
                    size_t as size_t
        } else {
            copy_u8(x.offset(i as isize), block.as_mut_ptr(), xlen);
            xlen = 0i32 as size_t
        }
    }
    AES256_CTR_DRBG_Update(0 as *mut uint8_t, DRBG_ctx.Key.as_mut_ptr(),
                           DRBG_ctx.V.as_mut_ptr());
    DRBG_ctx.reseed_counter += 1;
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn AES256_CTR_DRBG_Update(mut provided_data:
                                                    *mut uint8_t,
                                                mut Key: *mut uint8_t,
                                                mut V: *mut uint8_t) {
    let mut temp: [uint8_t; 48] = [0; 48];
    let mut i: libc::c_int = 0i32;
    while i < 3i32 {
        //increment V
        let mut j: libc::c_int = 15i32;
        while j >= 0i32 {
            if *V.offset(j as isize) as libc::c_int == 0xffi32 {
                *V.offset(j as isize) = 0i32 as uint8_t;
                j -= 1
            } else {
                let ref mut fresh0 = *V.offset(j as isize);
                *fresh0 = (*fresh0).wrapping_add(1);
                break ;
            }
        }
        AES256_ECB(Key, V, temp.as_mut_ptr().offset((16i32 * i) as isize));
        i += 1
    }
    if !provided_data.is_null() {
        let mut i_0: libc::c_int = 0i32;
        while i_0 < 48i32 {
            temp[i_0 as usize] =
                (temp[i_0 as usize] as libc::c_int ^
                     *provided_data.offset(i_0 as isize) as libc::c_int) as
                    uint8_t;
            i_0 += 1
        }
    }
    copy_u8(Key, temp.as_mut_ptr(), 32i32 as size_t);
    copy_u8(V, temp.as_mut_ptr().offset(32), 16i32 as size_t);
}
unsafe fn main_0() -> libc::c_int {
    let mut fn_req: [libc::c_char; 32] = [0; 32];
    let mut fn_rsp: [libc::c_char; 32] = [0; 32];
    let mut fp_req: *mut FILE = 0 as *mut FILE;
    let mut fp_rsp: *mut FILE = 0 as *mut FILE;
    let mut seed: [uint8_t; 48] = [0; 48];
    let mut msg: [uint8_t; 3300] = [0; 3300];
    let mut entropy_input: [uint8_t; 48] = [0; 48];
    let mut m: *mut uint8_t = 0 as *mut uint8_t;
    let mut c: *mut uint8_t = 0 as *mut uint8_t;
    let mut m1: *mut uint8_t = 0 as *mut uint8_t;
    let mut mlen: size_t = 0;
    let mut clen: size_t = 0;
    let mut mlen1: size_t = 0;
    let mut count: libc::c_int = 0;
    let mut done: libc::c_int = 0;
    let mut pk: [uint8_t; 1349] = [0; 1349];
    let mut sk: [uint8_t; 1413] = [0; 1413];
    let mut ret_val: libc::c_int = 0;
    // Create the REQUEST file
    sprintf(fn_req.as_mut_ptr(),
            b"PQCencryptKAT_%d.req\x00" as *const u8 as *const libc::c_char,
            CRYPTO_SECRETKEYBYTES);
    fp_req =
        fopen(fn_req.as_mut_ptr(),
              b"w\x00" as *const u8 as *const libc::c_char);
    if fp_req.is_null() {
        printf(b"Couldn\'t open <%s> for write\n\x00" as *const u8 as
                   *const libc::c_char, fn_req.as_mut_ptr());
        return -1i32
    }
    sprintf(fn_rsp.as_mut_ptr(),
            b"PQCencryptKAT_%d.rsp\x00" as *const u8 as *const libc::c_char,
            CRYPTO_SECRETKEYBYTES);
    fp_rsp =
        fopen(fn_rsp.as_mut_ptr(),
              b"w\x00" as *const u8 as *const libc::c_char);
    if fp_rsp.is_null() {
        printf(b"Couldn\'t open <%s> for write\n\x00" as *const u8 as
                   *const libc::c_char, fn_rsp.as_mut_ptr());
        return -1i32
    }
    let mut i: libc::c_int = 0i32;
    while i < 48i32 { entropy_input[i as usize] = i as uint8_t; i += 1 }
    randombytes_init(entropy_input.as_mut_ptr(), 0 as *mut uint8_t, 256i32);
    let mut i_0: libc::c_int = 0i32;
    while i_0 < 3i32 {
        let mut j: libc::c_int = 0i32;
        while j < 25i32 {
            fprintf(fp_req,
                    b"count = %d\n\x00" as *const u8 as *const libc::c_char,
                    i_0 * 25i32 + j);
            randombytes(seed.as_mut_ptr(), 48i32 as size_t);
            fprintBstr(fp_req,
                       b"seed = \x00" as *const u8 as *const libc::c_char,
                       seed.as_mut_ptr(), 48i32 as size_t);
            mlen = (16i32 + i_0 * 8i32) as size_t;
            fprintf(fp_req,
                    b"mlen = %zu\n\x00" as *const u8 as *const libc::c_char,
                    mlen);
            randombytes(msg.as_mut_ptr(), mlen);
            fprintBstr(fp_req,
                       b"msg = \x00" as *const u8 as *const libc::c_char,
                       msg.as_mut_ptr(), mlen);
            fprintf(fp_req,
                    b"pk =\n\x00" as *const u8 as *const libc::c_char);
            fprintf(fp_req,
                    b"sk =\n\x00" as *const u8 as *const libc::c_char);
            fprintf(fp_req,
                    b"clen =\n\x00" as *const u8 as *const libc::c_char);
            fprintf(fp_req,
                    b"c =\n\n\x00" as *const u8 as *const libc::c_char);
            j += 1
        }
        i_0 += 1
    }
    fclose(fp_req);
    //Create the RESPONSE file based on what's in the REQUEST file
    fp_req =
        fopen(fn_req.as_mut_ptr(),
              b"r\x00" as *const u8 as *const libc::c_char);
    if fp_req.is_null() {
        printf(b"Couldn\'t open <%s> for read\n\x00" as *const u8 as
                   *const libc::c_char, fn_req.as_mut_ptr());
        return -1i32
    }
    fprintf(fp_rsp, b"# %s\n\n\x00" as *const u8 as *const libc::c_char,
            b"R5ND_5PKE_0d\x00" as *const u8 as *const libc::c_char);
    done = 0i32;
    loop  {
        if FindMarker(fp_req,
                      b"count = \x00" as *const u8 as *const libc::c_char) !=
               0 {
            fscanf(fp_req, b"%d\x00" as *const u8 as *const libc::c_char,
                   &mut count as *mut libc::c_int);
            fprintf(fp_rsp,
                    b"count = %d\n\x00" as *const u8 as *const libc::c_char,
                    count);
            if ReadHex(fp_req, seed.as_mut_ptr(), 48i32,
                       b"seed = \x00" as *const u8 as *const libc::c_char) ==
                   0 {
                printf(b"ERROR: unable to read \'seed\' from <%s>\n\x00" as
                           *const u8 as *const libc::c_char,
                       fn_req.as_mut_ptr());
                return -3i32
            }
            fprintBstr(fp_rsp,
                       b"seed = \x00" as *const u8 as *const libc::c_char,
                       seed.as_mut_ptr(), 48i32 as size_t);
            randombytes_init(seed.as_mut_ptr(), 0 as *mut uint8_t, 256i32);
            if FindMarker(fp_req,
                          b"mlen = \x00" as *const u8 as *const libc::c_char)
                   != 0 {
                fscanf(fp_req, b"%zu\x00" as *const u8 as *const libc::c_char,
                       &mut mlen as *mut size_t);
            } else {
                printf(b"ERROR: unable to read \'mlen\' from <%s>\n\x00" as
                           *const u8 as *const libc::c_char,
                       fn_req.as_mut_ptr());
                return -3i32
            }
            fprintf(fp_rsp,
                    b"mlen = %zu\n\x00" as *const u8 as *const libc::c_char,
                    mlen);
            m =
                calloc(mlen as libc::c_ulong,
                       ::std::mem::size_of::<uint8_t>() as libc::c_ulong) as
                    *mut uint8_t;
            m1 =
                calloc(mlen.wrapping_add(CRYPTO_BYTES) as libc::c_ulong,
                       ::std::mem::size_of::<uint8_t>() as libc::c_ulong) as
                    *mut uint8_t;
            c =
                calloc(mlen.wrapping_add(CRYPTO_BYTES) as libc::c_ulong,
                       ::std::mem::size_of::<uint8_t>() as libc::c_ulong) as
                    *mut uint8_t;
            if ReadHex(fp_req, m, mlen as libc::c_int,
                       b"msg = \x00" as *const u8 as *const libc::c_char) == 0
               {
                printf(b"ERROR: unable to read \'msg\' from <%s>\n\x00" as
                           *const u8 as *const libc::c_char,
                       fn_req.as_mut_ptr());
                return -3i32
            }
            fprintBstr(fp_rsp,
                       b"msg = \x00" as *const u8 as *const libc::c_char, m,
                       mlen);
            let mut keygen_coins: [uint8_t; 96] = [0; 96];
            randombytes(keygen_coins.as_mut_ptr(), 32i32 as size_t);
            randombytes(keygen_coins.as_mut_ptr().offset(32),
                        32i32 as size_t);
            randombytes(keygen_coins.as_mut_ptr().offset(64),
                        32i32 as size_t);
            // Generate the public/private keypair
            ret_val =
                crypto_encrypt_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(),
                                       keygen_coins.as_mut_ptr() as
                                           *const uint8_t);
            if ret_val != 0i32 {
                printf(b"crypto_encrypt_keypair returned <%d>\n\x00" as
                           *const u8 as *const libc::c_char, ret_val);
                return -4i32
            }
            fprintBstr(fp_rsp,
                       b"pk = \x00" as *const u8 as *const libc::c_char,
                       pk.as_mut_ptr(), CRYPTO_PUBLICKEYBYTES);
            fprintBstr(fp_rsp,
                       b"sk = \x00" as *const u8 as *const libc::c_char,
                       sk.as_mut_ptr(), CRYPTO_SECRETKEYBYTES);
            let mut enc_coins: [uint8_t; 32] = [0; 32];
            randombytes(enc_coins.as_mut_ptr(), 32i32 as size_t);
            ret_val =
                crypto_encrypt(c, &mut clen, m, mlen, pk.as_mut_ptr(),
                               enc_coins.as_mut_ptr() as *const uint8_t);
            if ret_val != 0i32 {
                printf(b"crypto_encrypt returned <%d>\n\x00" as *const u8 as
                           *const libc::c_char, ret_val);
                return -4i32
            }
            fprintf(fp_rsp,
                    b"clen = %zu\n\x00" as *const u8 as *const libc::c_char,
                    clen);
            fprintBstr(fp_rsp,
                       b"c = \x00" as *const u8 as *const libc::c_char, c,
                       clen);
            fprintf(fp_rsp, b"\n\x00" as *const u8 as *const libc::c_char);
            ret_val =
                crypto_encrypt_open(m1, &mut mlen1, c, clen, sk.as_mut_ptr());
            if ret_val != 0i32 {
                printf(b"crypto_encrypt_open returned <%d>\n\x00" as *const u8
                           as *const libc::c_char, ret_val);
                return -4i32
            }
            if mlen != mlen1 {
                printf(b"crypto_encrypt_open returned bad \'mlen\': Got <%zu>, expected <%zu>\n\x00"
                           as *const u8 as *const libc::c_char, mlen1, mlen);
                return -4i32
            }
            if memcmp(m as *const libc::c_void, m1 as *const libc::c_void,
                      mlen as libc::c_ulong) != 0 {
                printf(b"crypto_encrypt_open returned bad \'m\' value\n\x00"
                           as *const u8 as *const libc::c_char);
                return -4i32
            }
            free(m as *mut libc::c_void);
            free(m1 as *mut libc::c_void);
            free(c as *mut libc::c_void);
            if !(done == 0) { break ; }
        } else { done = 1i32; break ; }
    }
    fclose(fp_req);
    fclose(fp_rsp);
    return 0i32;
}
//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
#[no_mangle]
pub unsafe extern "C" fn FindMarker(mut infile: *mut FILE,
                                    mut marker: *const libc::c_char)
 -> libc::c_int {
    let mut line: [libc::c_char; 50] = [0; 50];
    let mut i: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut curr_line: libc::c_int = 0;
    len = strlen(marker) as libc::c_int;
    if len > 50i32 - 1i32 { len = 50i32 - 1i32 }
    i = 0i32;
    while i < len {
        curr_line = fgetc(infile);
        line[i as usize] = curr_line as libc::c_char;
        if curr_line == -1i32 { return 0i32 }
        i += 1
    }
    line[len as usize] = '\u{0}' as i32 as libc::c_char;
    loop  {
        if strncmp(line.as_mut_ptr(), marker, len as libc::c_ulong) == 0 {
            return 1i32
        }
        i = 0i32;
        while i < len - 1i32 {
            line[i as usize] = line[(i + 1i32) as usize];
            i += 1
        }
        curr_line = fgetc(infile);
        line[(len - 1i32) as usize] = curr_line as libc::c_char;
        if curr_line == -1i32 { return 0i32 }
        line[len as usize] = '\u{0}' as i32 as libc::c_char
    };
}
//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
#[no_mangle]
pub unsafe extern "C" fn ReadHex(mut infile: *mut FILE, mut A: *mut uint8_t,
                                 mut Length: libc::c_int,
                                 mut str: *const libc::c_char)
 -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut ch: libc::c_int = 0;
    let mut started: libc::c_int = 0;
    let mut ich: uint8_t = 0;
    if Length == 0i32 { *A.offset(0) = 0i32 as uint8_t; return 1i32 }
    memset(A as *mut libc::c_void, 0i32, Length as libc::c_ulong);
    started = 0i32;
    if FindMarker(infile, str) != 0 {
        loop  {
            ch = fgetc(infile);
            if !(ch != -1i32) { break ; }
            if *(*__ctype_b_loc()).offset(ch as isize) as libc::c_int &
                   _ISxdigit as libc::c_int as libc::c_ushort as libc::c_int
                   == 0 {
                if !(started == 0) { break ; }
                if ch == '\n' as i32 { break ; }
            } else {
                started = 1i32;
                if ch >= '0' as i32 && ch <= '9' as i32 {
                    ich = (ch - '0' as i32) as uint8_t
                } else if ch >= 'A' as i32 && ch <= 'F' as i32 {
                    ich = (ch - 'A' as i32 + 10i32) as uint8_t
                } else if ch >= 'a' as i32 && ch <= 'f' as i32 {
                    ich = (ch - 'a' as i32 + 10i32) as uint8_t
                } else {
                    // shouldn't ever get here
                    ich = 0i32 as uint8_t
                }
                i = 0i32;
                while i < Length - 1i32 {
                    *A.offset(i as isize) =
                        ((*A.offset(i as isize) as libc::c_int) << 4i32 |
                             *A.offset((i + 1i32) as isize) as libc::c_int >>
                                 4i32) as uint8_t;
                    i += 1
                }
                *A.offset((Length - 1i32) as isize) =
                    ((*A.offset((Length - 1i32) as isize) as libc::c_int) <<
                         4i32 | ich as libc::c_int) as uint8_t
            }
        }
    } else { return 0i32 }
    return 1i32;
}
#[no_mangle]
pub unsafe extern "C" fn fprintBstr(mut fp: *mut FILE,
                                    mut S: *const libc::c_char,
                                    mut A: *mut uint8_t, mut L: size_t) {
    let mut i: size_t = 0;
    fprintf(fp, b"%s\x00" as *const u8 as *const libc::c_char, S);
    i = 0i32 as size_t;
    while i < L {
        fprintf(fp, b"%02X\x00" as *const u8 as *const libc::c_char,
                *A.offset(i as isize) as libc::c_int);
        i = i.wrapping_add(1)
    }
    if L == 0i32 as libc::c_ulonglong {
        fprintf(fp, b"00\x00" as *const u8 as *const libc::c_char);
    }
    fprintf(fp, b"\n\x00" as *const u8 as *const libc::c_char);
}
#[main]
pub fn main() { unsafe { ::std::process::exit(main_0() as i32) } }
