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
