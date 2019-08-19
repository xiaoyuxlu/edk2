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

#![feature(alloc_layout_extra)]
#![feature(allocator_api)]
#![feature(alloc_error_handler)]
#![feature(core_panic_info)]
#![feature(asm)]

#![cfg_attr(not(test), no_std)]
#![no_main]

#![allow(unused)]

mod mem;

extern crate test_rust_lang_lib;

use r_efi::efi;
use r_efi::efi::{Status};

use core::panic::PanicInfo;
use core::ffi::c_void;

use core::mem::size_of;
use core::mem::transmute;

use core::slice::from_raw_parts;

//#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { asm!("int3"); }
    loop {}
}

use core::alloc::{GlobalAlloc, Layout, Alloc};

pub struct MyAllocator;

pub static mut ST : *mut efi::SystemTable = core::ptr::null_mut();
pub static mut BS : *mut efi::BootServices = core::ptr::null_mut();

unsafe impl GlobalAlloc for MyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
      let size = layout.size();
      let align = layout.align();
      if align > 8 {
        return core::ptr::null_mut();
      }

      let mut address : *mut c_void = core::ptr::null_mut();
      let allocate_pool : extern "C" fn (
        efi::MemoryType,
        usize,
        *mut *mut core::ffi::c_void,
        ) -> efi::Status = (*BS).allocate_pool;
      let status = allocate_pool (
                     efi::MemoryType::BootServicesData,
                     size,
                     &mut address as *mut *mut c_void
                     );
      if status != Status::SUCCESS {
        return core::ptr::null_mut();
      }
      address as *mut u8
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
      let free_pool : extern "C" fn(
        *mut core::ffi::c_void,
        ) -> efi::Status = (*BS).free_pool;
      free_pool (ptr as *mut c_void);
    }
}

//#[global_allocator]
static ALLOCATOR: MyAllocator = MyAllocator;

extern crate alloc;

use alloc::vec::Vec;
use alloc::boxed::Box;

//#[alloc_error_handler]
fn alloc_error_handler(layout: core::alloc::Layout) -> !
{
    unsafe { asm!("int3"); }
    loop {}
}


// NOTE: It should be vararg. But vararg is unsupported.
#[no_mangle]
#[export_name = "DebugPrint"]
extern "C" fn DebugPrint(error_level: usize, format: *const u8, arg: usize)
{
}
#[no_mangle]
#[export_name = "AllocatePool"]
extern "C" fn AllocatePool (size: usize) -> *mut c_void
{
      let mut address : *mut c_void = core::ptr::null_mut();
      let allocate_pool : extern "C" fn (
        efi::MemoryType,
        usize,
        *mut *mut core::ffi::c_void,
        ) -> efi::Status = unsafe {(*BS).allocate_pool};
      let status = allocate_pool (
                     efi::MemoryType::BootServicesData,
                     size,
                     &mut address as *mut *mut c_void
                     );
      if status != Status::SUCCESS {
        return core::ptr::null_mut();
      }
      address as *mut c_void
}
#[no_mangle]
#[export_name = "AllocateZeroPool"]
extern "C" fn AllocateZeroPool (size: usize) -> *mut c_void
{
    let buffer = AllocatePool (size);
    if buffer == core::ptr::null_mut() {
      return core::ptr::null_mut();
    }

    unsafe {core::ptr::write_bytes (buffer, 0, size);}

    buffer as *mut c_void
}
#[no_mangle]
#[export_name = "FreePool"]
extern "C" fn FreePool (buffer: *mut c_void)
{
      let free_pool : extern "C" fn(
        *mut core::ffi::c_void,
        ) -> efi::Status = unsafe { (*BS).free_pool };
      free_pool (buffer as *mut c_void);
}
#[no_mangle]
#[export_name = "ExternInit"]
extern "C" fn ExternInit(data: *mut usize)
{
}


#[no_mangle]
pub extern "C" fn efi_main(handle: efi::Handle, system_table: *mut efi::SystemTable) -> Status
{
    unsafe {
      ST = system_table;
      BS = (*ST).boot_services;
    }

    // L"Hello World!/r/n"
    let string_name = [
      0x48u16, 0x65u16, 0x6cu16, 0x6cu16, 0x6fu16, 0x20u16,
      0x57u16, 0x6fu16, 0x72u16, 0x6cu16, 0x64u16, 0x21u16,
      0x0Au16, 0x0Du16, 0x00u16
      ];
    let output_string : extern "C" fn(
        *mut efi::protocols::simple_text_output::Protocol,
        *mut efi::Char16,
        ) -> efi::Status = unsafe { (*((*ST).con_out)).output_string };
    output_string (
        unsafe {(*ST).con_out},
        string_name.as_ptr() as *mut efi::Char16,
        );

    test_rust_lang_lib::test_integer_overflow (0x10000, 0xFFFFFFFF, 0xFFFFFFFF);

    Status::SUCCESS
}
