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

mod mem;

use r_efi::efi;
use r_efi::efi::{Status};

extern "win64" {
  // NOTE: It should be vararg. But vararg is unsupported.
  fn DebugPrint(ErrorLevel: usize, Format: *const u8, Arg: usize);

  fn AllocatePool (Size: usize) -> *mut c_void;
  fn AllocateZeroPool (Size: usize) -> *mut c_void;
  fn FreePool (Buffer: *mut c_void);
}

use core::panic::PanicInfo;
use core::ffi::c_void;

use core::mem::size_of;
use core::mem::transmute;

use core::slice::from_raw_parts;

#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {DebugPrint (0x80000000, b"Panic ...\n" as *const u8, 0);};
    loop {}
}

#[no_mangle]
#[export_name = "TestIntegerOverflow"]
pub extern "win64" fn test_integer_overflow (
    buffer: *const c_void,
    buffer_size: usize,
    width : u32,
    height : u32,
    ) -> Status
{
    let data_size = width * height * 4;

    if data_size as usize > buffer_size {
      return Status::UNSUPPORTED;
    }

    Status::SUCCESS
}

extern "win64" {
  // NOTE: It should be vararg. But vararg is unsupported.
  fn ExternInit(Data: *mut usize);
}

#[no_mangle]
#[export_name = "TestUninitializedVariable"]
pub extern "win64" fn test_uninitializd_variable (
    index: usize,
    ) -> usize
{
    let mut data : usize = 1;

    if index > 10 {
      data = 0;
    }

    unsafe { ExternInit (&mut data ); }

    data = data + 1;

    data
}

#[no_mangle]
#[export_name = "TestArrayOutOfRange"]
pub extern "win64" fn test_array_out_of_range (
    index: usize,
    ) -> usize
{
    let mut data : [u8; 8] = [0; 8];

    data[index] = 1;

    data[index + 1] as usize
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TestTable {
    pub r#type: u32,
    pub length: u32,
    pub value: [u8; 0],
}

#[no_mangle]
#[export_name = "TestBufferOverflow"]
pub extern "win64" fn test_buffer_overflow (
    buffer: &mut [u8; 0],
    buffer_size: usize,
    table: &TestTable,
    table_size: usize,
    )
{
    let mut dest = crate::mem::MemoryRegion::new(buffer as *mut [u8; 0] as usize as u64, buffer_size as u64);
    let mut source = crate::mem::MemoryRegion::new(&table.value as *const [u8; 0] as usize as u64, table_size as u64);

    for index in 0_u64 .. table.length as u64 {
      dest.write_u8(index, source.read_u8(index));
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TestTableFixed {
    pub r#type: u32,
    pub length: u32,
    pub value: [u8; 64],
}

#[no_mangle]
#[export_name = "TestBufferOverflowFixed"]
pub extern "win64" fn test_buffer_overflow_fixed (
    buffer: &mut [u8; 32],
    table: &TestTableFixed,
    )
{
    (*buffer)[0_usize..(table.length as usize)].copy_from_slice(
      &table.value[0_usize..(table.length as usize)]
      );
}

pub fn get_buffer<'a> () -> Option<&'a mut TestTableFixed>
{
    let ptr : *mut c_void = unsafe { AllocatePool (size_of::<TestTableFixed>()) };
    if ptr.is_null() {
      return None;
    }
    let buffer : &mut TestTableFixed = unsafe { core::mem::transmute::<*mut c_void, &mut TestTableFixed>(ptr) };
    Some(buffer)
}

pub fn release_buffer (test_table : &mut TestTableFixed)
{
  test_table.r#type = 0;
  unsafe { FreePool (test_table as *mut TestTableFixed as *mut c_void) ; }
}

#[no_mangle]
#[export_name = "TestBufferDrop"]
pub extern "win64" fn test_buffer_drop (
    
    )
{
    match get_buffer () {
      Some(buffer) => {
        buffer.r#type = 1;
        release_buffer(buffer);
        drop (buffer); // This is required.
        //buffer.r#type = 1; // error
      },
      None => {},
    }
}

#[no_mangle]
#[export_name = "TestBufferBorrow"]
pub extern "win64" fn test_buffer_borrow (
    test_table : &mut TestTableFixed
    )
{
    let test_table2 : &mut TestTableFixed = test_table;
    test_table2.r#type = 1;

    let test_table3 : &mut [u8; 64] = &mut test_table.value;
    test_table3[63] = 0;

    //test_table2.r#type = 2; // error
}
