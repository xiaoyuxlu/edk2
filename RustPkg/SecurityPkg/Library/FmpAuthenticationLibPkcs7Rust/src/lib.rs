// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![crate_type = "staticlib"]

#![cfg_attr(not(test), no_std)]

#![allow(unused)]

mod fmp;
mod win_cert;

use core::panic::PanicInfo;
use core::ffi::c_void;

use r_efi::efi;
use r_efi::efi::{Status};

use crate::fmp::FirmwareImageAuthentication;

#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[export_name = "AuthenticateFmpImage"]
pub extern "win64" fn authenticate_fmp_image (
    image : *mut FirmwareImageAuthentication,
    image_size: usize,
    public_key_data: *const u8,
    public_key_data_lenght: usize,
    ) -> Status
{
    Status::SUCCESS
}
