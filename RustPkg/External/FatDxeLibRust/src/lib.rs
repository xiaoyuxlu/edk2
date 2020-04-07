#![no_std]
extern crate uefi_rust_panic_lib;

use r_efi::efi;

#[export_name = "FatEntryPoint"]
pub extern fn fat_entry_point(_h: efi::Handle, _st: *mut efi::SystemTable) -> efi::Status
{
    debug_lib::print!("fat_entry_point\n");
    efi::Status::SUCCESS
}

#[export_name = "FatUnload"]
pub extern fn fat_unload(_h: efi::Handle) -> efi::Status {
    debug_lib::print!("fat_unload\n");
    efi::Status::SUCCESS
}
