#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case,
         non_upper_case_globals, unused_assignments, unused_mut)]
pub type uint8_t = libc::c_uchar;
pub type uint16_t = libc::c_ushort;
pub type size_t = libc::c_ulonglong;
pub type int16_t = libc::c_short;
/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */
/* *
 * @file
 * Declaration of miscellaneous macros and functions.
 */
/* * Macro for printing errors. */
/* *
     * Prints the given data as hex digits.
     *
     * @param[in] var          the name of the data variable, printed before the data followed by an `=`,
     *                         can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] data         the data to print
     * @param[in] nr_elements  the number of elements in the data
     * @param[in] element_size the size of the elements in bytes (bytes will be reversed inside element)
     */
/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */
/* *
 * @file
 * Implementation of the miscellaneous functions.
 */
//#include <stdio.h>
#[no_mangle]
pub unsafe extern "C" fn print_hex(mut var: *const libc::c_char,
                                   mut data: *const uint8_t,
                                   nr_elements: size_t,
                                   element_size: size_t) {
    /*
    size_t i, ii;
    if (var != NULL) {
        printf("%s[%zu]=", var, nr_elements);
    }
    for (i = 0; i < nr_elements; ++i) {
        if (i > 0) {
            printf(" ");
        }
        for (ii = element_size; ii > 0; --ii) {
            printf("%02hhX", data[i * element_size + ii - 1]);
        }
    }
    if (var != NULL) {
        printf("\n");
    }
*/
}
#[no_mangle]
pub unsafe extern "C" fn print_sage_u_vector(mut var: *const libc::c_char,
                                             mut vector: *const uint16_t,
                                             nr_elements: size_t) {
    /*
    size_t i;
    if (var != NULL) {
        printf("%s[%zu]=", var, nr_elements);
    }
    printf("[ ");
    for (i = 0; i < nr_elements; ++i) {
        if (i > 0) {
            printf(", ");
        }
        printf("%hu", vector[i]);
    }
    printf(" ]");
    if (var != NULL) {
        printf("\n");
    }
*/
}
#[no_mangle]
pub unsafe extern "C" fn print_sage_u_matrix(mut var: *const libc::c_char,
                                             mut matrix: *const uint16_t,
                                             nr_rows: size_t,
                                             nr_columns: size_t) {
    /*
    size_t i;
    if (var != NULL) {
        printf("%s[%zu][%zu]=", var, nr_rows, nr_columns);
    }
    printf("Matrix([");
    for (i = 0; i < nr_rows; ++i) {
        if (i > 0) {
            printf(",");
        }
        if (nr_rows > 1) {
            printf("\n");
        } else {
            printf(" ");
        }
        print_sage_u_vector(NULL, matrix + i*nr_columns, nr_columns);
    }
    if (nr_rows > 1) {
        printf("\n])");
    } else {
        printf(" ])");
    }
    if (var != NULL) {
        printf("\n");
    }
*/
}
#[no_mangle]
pub unsafe extern "C" fn print_sage_u_vector_matrix(mut var:
                                                        *const libc::c_char,
                                                    mut matrix:
                                                        *const uint16_t,
                                                    nr_rows: size_t,
                                                    nr_columns: size_t,
                                                    nr_elements: size_t) {
    /*
    size_t i, j;
    if (nr_elements == 1) {
        print_sage_u_matrix(var, matrix, nr_rows, nr_columns);
    } else if (nr_rows == 1 && nr_columns == 1) {
        print_sage_u_vector(var, matrix, nr_elements);
    } else {
        if (var != NULL) {
            printf("%s[%zu][%zu][%zu]=", var, nr_rows, nr_columns, nr_elements);
        }
        printf("Matrix([");
        for (i = 0; i < nr_rows; ++i) {
            if (i > 0) {
                printf(",");
            }
            if (nr_rows > 1) {
                printf("\n[");
            } else {
                printf(" [");
            }
            for (j = 0; j < nr_columns; ++j) {
                if (j > 0) {
                    printf(",");
                }
                if (nr_columns > 1 && nr_elements > 1) {
                    printf("\n  ");
                } else {
                    printf(" ");
                }
                print_sage_u_vector(NULL, matrix + (i * nr_columns + j) * nr_elements, nr_elements);
            }
            if (nr_columns > 1 && nr_elements > 1) {
                printf("\n]");
            } else {
                printf(" ]");
            }
        }
        if (nr_rows > 1) {
            printf("\n])");
        } else {
            printf(" ])");
        }
        if (var != NULL) {
            printf("\n");
        }
    }
*/
}
#[no_mangle]
pub unsafe extern "C" fn print_sage_s_vector(mut var: *const libc::c_char,
                                             mut poly: *const int16_t,
                                             nr_elements: size_t) {
    /*
    size_t i;
    if (var != NULL) {
        printf("%s[%zu]=", var, nr_elements);
    }
    printf("[ ");
    for (i = 0; i < nr_elements; ++i) {
        if (i > 0) {
            printf(", ");
        }
        printf("%hd", poly[i]);
    }
    printf(" ]");
    if (var != NULL) {
        printf("\n");
    }
*/
}
#[no_mangle]
pub unsafe extern "C" fn print_sage_s_matrix(mut var: *const libc::c_char,
                                             mut matrix: *const int16_t,
                                             nr_rows: size_t,
                                             nr_columns: size_t) {
    /*
    size_t i;
    if (var != NULL) {
        printf("%s[%zu][%zu]=", var, nr_rows, nr_columns);
    }
    printf("Matrix([");
    for (i = 0; i < nr_rows; ++i) {
        if (i > 0) {
            printf(",");
        }
        if (nr_rows > 1) {
            printf("\n");
        } else {
            printf(" ");
        }
        print_sage_s_vector(NULL, matrix + i*nr_columns, nr_columns);
    }
    if (nr_rows > 1) {
        printf("\n])");
    } else {
        printf(" ])");
    }
    if (var != NULL) {
        printf("\n");
    }
*/
}
/* *
     * Prints the given vector in a format usable within sage.
     *
     * @param[in] var         the name of the variable, printed before the vector content followed by an `=`,
     *                        can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] vector      the vector
     * @param[in] nr_elements the number of elements of the vector
     */
/* *
     * Prints the given scalar matrix in a format usable within sage.
     *
     * @param[in] var        the name of the variable, printed before the matrix content followed by an `=`,
     *                       can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] matrix     the matrix
     * @param[in] nr_rows    the number of rows
     * @param[in] nr_columns the number of columns
     */
/* *
     * Prints the given matrix of vectors in a format usable within sage.
     *
     * @param[in] var         the name of the variable, printed before the matrix content followed by an `=`,
     *                        can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] matrix      the matrix
     * @param[in] nr_rows     the number of rows
     * @param[in] nr_columns  the number of columns
     * @param[in] nr_elements the number of elements of the vectors
     */
/* *
     * Prints the given vector in a format usable within sage.
     *
     * @param[in] var         the name of the variable, printed before the vector content followed by an `=`,
     *                        can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] vector      the vector
     * @param[in] nr_elements the number of elements of the vector
     */
/* *
     * Prints the given scalar matrix in a format usable within sage.
     *
     * @param[in] var        the name of the variable, printed before the matrix content followed by an `=`,
     *                       can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] matrix     the matrix
     * @param[in] nr_rows    the number of rows
     * @param[in] nr_columns the number of columns
     */
/* *
     * Prints the given matrix of vectors in a format usable within sage.
     *
     * @param[in] var         the name of the variable, printed before the matrix content followed by an `=`,
     *                        can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] matrix      the matrix
     * @param[in] nr_rows     the number of rows
     * @param[in] nr_columns  the number of columns
     * @param[in] nr_elements the number of elements of the vectors
     */
#[no_mangle]
pub unsafe extern "C" fn print_sage_s_vector_matrix(mut var:
                                                        *const libc::c_char,
                                                    mut matrix:
                                                        *const int16_t,
                                                    nr_rows: size_t,
                                                    nr_columns: size_t,
                                                    nr_elements: size_t) {
    /*
    size_t i, j;
    if (nr_elements == 1) {
        print_sage_s_matrix(var, matrix, nr_rows, nr_columns);
    } else if (nr_rows == 1 && nr_columns == 1) {
        print_sage_s_vector(var, matrix, nr_elements);
    } else {
        if (var != NULL) {
            printf("%s[%zu][%zu][%zu]=", var, nr_rows, nr_columns, nr_elements);
        }
        printf("Matrix([");
        for (i = 0; i < nr_rows; ++i) {
            if (i > 0) {
                printf(",");
            }
            if (nr_rows > 1) {
                printf("\n[");
            } else {
                printf(" [");
            }
            for (j = 0; j < nr_columns; ++j) {
                if (j > 0) {
                    printf(",");
                }
                if (nr_columns > 1 && nr_elements > 1) {
                    printf("\n  ");
                } else {
                    printf(" ");
                }
                print_sage_s_vector(NULL, matrix + (i * nr_columns + j) * nr_elements, nr_elements);
            }
            if (nr_columns > 1 && nr_elements > 1) {
                printf("\n]");
            } else {
                printf(" ]");
            }
        }
        if (nr_rows > 1) {
            printf("\n])");
        } else {
            printf(" ])");
        }
        if (var != NULL) {
            printf("\n");
        }
    }
*/
}
