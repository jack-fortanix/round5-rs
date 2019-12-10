#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case,
         non_upper_case_globals, unused_assignments, unused_mut)]
//#include <stdint.h>
//#include <stddef.h>
#[no_mangle]
pub unsafe extern "C" fn crash_immediately() { }
#[no_mangle]
pub unsafe extern "C" fn copy_u8(mut out: *mut u8,
                                 mut in_0: *const u8, mut len: usize) {
    let mut i: usize = 0i32 as usize;
    while i != len {
        *out.offset(i as isize) = *in_0.offset(i as isize);
        i = i.wrapping_add(1)
    };
}
#[no_mangle]
pub unsafe extern "C" fn zero_u8(mut out: *mut u8, mut len: usize) {
    let mut i: usize = 0i32 as usize;
    while i != len {
        *out.offset(i as isize) = 0i32 as u8;
        i = i.wrapping_add(1)
    };
}
#[no_mangle]
pub unsafe extern "C" fn copy_u16(mut out: *mut u16,
                                  mut in_0: *const u16,
                                  mut len: usize) {
    let mut i: usize = 0i32 as usize;
    while i != len {
        *out.offset(i as isize) = *in_0.offset(i as isize);
        i = i.wrapping_add(1)
    };
}
#[no_mangle]
pub unsafe extern "C" fn zero_u16(mut out: *mut u16, mut len: usize) {
    let mut i: usize = 0i32 as usize;
    while i != len {
        *out.offset(i as isize) = 0i32 as u16;
        i = i.wrapping_add(1)
    };
}
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
pub unsafe extern "C" fn constant_time_memcmp(mut s1: *const libc::c_void,
                                              mut s2: *const libc::c_void,
                                              mut n: usize) -> libc::c_int {
    let mut a: *const u8 = s1 as *const u8;
    let mut b: *const u8 = s2 as *const u8;
    let mut ret: libc::c_int = 0i32;
    let mut i: usize = 0;
    i = 0i32 as usize;
    while i < n {
        let fresh0 = a;
        a = a.offset(1);
        let fresh1 = b;
        b = b.offset(1);
        ret |= *fresh0 as libc::c_int ^ *fresh1 as libc::c_int;
        i = i.wrapping_add(1)
    }
    return ret;
}
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
pub unsafe extern "C" fn conditional_constant_time_memcpy(mut dst:
                                                              *mut libc::c_void,
                                                          mut src:
                                                              *const libc::c_void,
                                                          mut n: usize,
                                                          mut flag: u8) {
    let mut d: *mut u8 =
        dst as *mut u8; // Force flag into 0x00 or 0xff
    let mut s: *const u8 = src as *const u8;
    flag =
        (-(flag as libc::c_int | -(flag as libc::c_int)) >> 7i32) as u8;
    let mut i: usize = 0;
    i = 0i32 as usize;
    while i < n {
        *d.offset(i as isize) =
            (*d.offset(i as isize) as libc::c_int ^
                 flag as libc::c_int &
                     (*d.offset(i as isize) as libc::c_int ^
                          *s.offset(i as isize) as libc::c_int)) as u8;
        i = i.wrapping_add(1)
    };
}
