// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_tunittest;

use sgx_types::*;
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
use sgx_tunittest::*;

extern crate aes_ctr;
extern crate cfb8;
extern crate cfb_mode;
extern crate chacha20;
extern crate ctr;
extern crate ofb;
extern crate salsa20;
extern crate salsa20_core;
extern crate aes;
extern crate hc_256;
extern crate generic_array;
extern crate block_cipher_trait;

#[macro_use]
extern crate stream_cipher;
#[macro_use]
extern crate hex_literal;
extern crate blobby;

mod aes_ctr_test;
mod cfb8_test;
mod cfb_mode_test;
mod chacha20_test;
mod ctr_test;
mod ofb_test;
mod salsa20_test;
mod hc_256_test;

#[no_mangle]
pub extern "C" fn say_something(some_string: *const u8, some_len: usize) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);

    // A sample &'static string
    let rust_raw_string = "This is a in-Enclave ";
    // An array
    let word:[u8;4] = [82, 117, 115, 116];
    // An vector
    let word_vec:Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];

    // Construct a string from &'static string
    let mut hello_string = String::from(rust_raw_string);

    // Iterate on word array
    for c in word.iter() {
        hello_string.push(*c as char);
    }

    // Rust style convertion
    hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8")
                                               .as_str();

    // Ocall to normal world for output
    println!("{}", &hello_string);

    rsgx_unit_tests!(
aes_ctr_test::aes128_ctr_core,
aes_ctr_test::aes128_ctr_seek,
aes_ctr_test::aes256_ctr_core,
aes_ctr_test::aes256_ctr_seek,
cfb8_test::cfb8_aes128,
cfb8_test::cfb8_aes192,
cfb8_test::cfb8_aes256,
cfb_mode_test::cfb_aes128,
cfb_mode_test::cfb_aes192,
cfb_mode_test::cfb_aes256,
chacha20_test::chacha20_core,
chacha20_test::chacha20_seek,
chacha20_test::xchacha20::xchacha20_keystream,
chacha20_test::xchacha20::xchacha20_encryption,
chacha20_test::legacy::chacha20_legacy_core,
chacha20_test::legacy::chacha20_legacy_seek,
chacha20_test::legacy::chacha20_offsets,
ctr_test::aes128_ctr_core,
ctr_test::aes128_ctr_seek,
ctr_test::aes256_ctr_core,
ctr_test::aes256_ctr_seek,
ctr_test::test_from_cipher,
ofb_test::ofb_aes128,
salsa20_test::salsa20_key1_iv0,
salsa20_test::salsa20_key0_iv1,
salsa20_test::salsa20_key0_ivhi,
salsa20_test::salsa20_long,
salsa20_test::salsa20_offsets,
hc_256_test::test_key0_iv0,
hc_256_test::test_key0_iv0_offset_1,
hc_256_test::test_key0_iv0_offset_2,
hc_256_test::test_key0_iv0_offset_3,
hc_256_test::test_key0_iv0_offset_4,
hc_256_test::test_key0_iv0_offset_5,
hc_256_test::test_key0_iv0_offset_6,
hc_256_test::test_key0_iv0_offset_7,
hc_256_test::test_key0_iv0_offset_8,
hc_256_test::test_key1_iv0,
hc_256_test::test_key0_iv1,
);
    sgx_status_t::SGX_SUCCESS
}
