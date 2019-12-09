#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case,
         non_upper_case_globals, unused_assignments, unused_mut)]
//#include <stdint.h>
//#include <stddef.h>
pub type uint8_t = libc::c_uchar;
pub type size_t = libc::c_ulonglong;
/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */
/* *
 * @file
 * Declaration of the SHAKE128, SHAKE256, cSHAKE128, and cSHAKE256 hash
 * functions.
 *
 * Note: all sizes are in bytes, not bits!
 */
pub type shake_ctx = [uint8_t; 224];
/* *
     * Performs the initialisation step of the SHAKE-256 XOF.
     *
     * @param ctx the shake context
     */
//extern "C" {
//#include <libkeccak.a.headers/KeccakHash.h>
//}
//static_assert(sizeof(Keccak_HashInstance) == sizeof(shake_ctx), "Expected size");
#[no_mangle]
pub unsafe extern "C" fn shake256_init(mut ctx: *mut shake_ctx) {
    /*
        if (Keccak_HashInitialize_SHAKE256((Keccak_HashInstance*)ctx) != 0) {
            crash_immediately();
        }
    */
}
/* *
     * Performs the absorb step of the SHAKE-256 XOF.
     *
     * @param ctx the shake context
     * @param input the input absorbed into the state
     * @param input_len the length of the input
     */
/* *
     * Performs the absorb step of the SHAKE-256 XOF.
     *
     * @param ctx the shake context
     * @param input the input absorbed into the state
     * @param input_len the length of the input
     */
#[no_mangle]
pub unsafe extern "C" fn shake256_absorb(mut ctx: *mut shake_ctx,
                                         mut input: *const uint8_t,
                                         input_len: size_t) {
    /*
        if (Keccak_HashUpdate((Keccak_HashInstance*)ctx, input, input_len * 8) != 0) {
            crash_immediately();
        }
        if (Keccak_HashFinal((Keccak_HashInstance*)ctx, NULL) != 0) {
            crash_immediately();
        }
    */
}
/* *
     * Performs the squeeze step of the SHAKE-256 XOF. Squeezes full blocks of
     * SHAKE256_RATE bytes each. Can be called multiple times to keep squeezing
     * (i.e. this function is incremental).
     *
     * @param ctx the shake context
     * @param output the output
     * @param nr_blocks the number of blocks to squeeze
     */
/* *
     * Performs the squeeze step of the SHAKE-256 XOF. Squeezes full blocks of
     * SHAKE256_RATE bytes each. Can be called multiple times to keep squeezing
     * (i.e. this function is incremental).
     *
     * @param ctx the shake context
     * @param output the output
     * @param nr_blocks the number of blocks to squeeze
     */
#[no_mangle]
pub unsafe extern "C" fn shake256_squeezeblocks(mut ctx: *mut shake_ctx,
                                                mut output: *mut uint8_t,
                                                nr_blocks: size_t) {
    /*
        if (Keccak_HashSqueeze((Keccak_HashInstance*)ctx, output, nr_blocks * SHAKE256_RATE * 8) != 0) {
            crash_immediately();
        }
    */
}
/* *
     * Performs the full SHAKE-256 XOF to the given input.
     * @param output the final output
     * @param output_len the length of the output
     * @param input the input
     * @param input_len the length of the input
     */
/* *
     * Performs the full SHAKE-256 XOF to the given input.
     * @param output the final output
     * @param output_len the length of the output
     * @param input the input
     * @param input_len the length of the input
     */
#[no_mangle]
pub unsafe extern "C" fn shake256(mut output: *mut uint8_t,
                                  mut output_len: size_t,
                                  mut input: *const uint8_t,
                                  input_len: size_t) {
    /*
    shake_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, input, input_len);
    if (Keccak_HashSqueeze((Keccak_HashInstance*)&ctx, output, output_len * 8) != 0) {
        crash_immediately();
    }
    */
}
