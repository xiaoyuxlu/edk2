#![cfg_attr(not(test), no_std)]

mod fat;

#[cfg(not(test))]
extern crate debug_lib;

#[cfg(not(test))]
use debug_lib::{print, println};

use r_efi::efi;

extern "C" {
    #[no_mangle]
    static gBS: *const core::ffi::c_void;
}

#[export_name = "FatEntryPoint"]
pub extern fn fat_entry_point(_h: efi::Handle, _st: *mut efi::SystemTable) -> efi::Status
{
    print!("fat_entry_point\n");
    efi::Status::SUCCESS
}

#[export_name = "FatUnload"]
pub extern fn fat_unload(_h: efi::Handle) -> efi::Status {
    println!("fat_unload");
    efi::Status::SUCCESS
}

pub fn fat_driver_binding_supported(this: *mut efi::protocols::driver_binding::Protocol, controller_handle: efi::Handle, _remaining_device_path: *mut efi::protocols::device_path::Protocol) -> efi::Status {
    let this: &mut efi::protocols::driver_binding::Protocol = unsafe{&mut *(this as *mut efi::protocols::driver_binding::Protocol)};
    let bs = unsafe{&*(gBS as *mut efi::BootServices)};
    let mut disk_io: *mut efi::protocols::disk_io::Protocol = core::ptr::null_mut();
    let mut status = (bs.open_protocol)(
        controller_handle,
        &efi::protocols::disk_io::PROTOCOL_GUID as *const efi::Guid as *mut efi::Guid,
        &mut disk_io as *mut *mut efi::protocols::disk_io::Protocol as *mut *mut core::ffi::c_void,
        (this).driver_binding_handle,
        controller_handle,
        efi::OPEN_PROTOCOL_BY_DRIVER);
    if status.is_error() {
        return status;
    }

    (bs.close_protocol)(controller_handle, &efi::protocols::disk_io::PROTOCOL_GUID as *const efi::Guid as *mut efi::Guid, (this).driver_binding_handle, controller_handle);

    // open block io protocols
    status =  (bs.open_protocol)(
        controller_handle,
        &efi::protocols::block_io::PROTOCOL_GUID as *const efi::Guid as *mut efi::Guid,
        &mut core::ptr::null_mut() as *mut *mut efi::protocols::disk_io::Protocol as *mut *mut core::ffi::c_void,
        this.driver_binding_handle,
        controller_handle,
        efi::OPEN_PROTOCOL_TEST_PROTOCOL);

    status
}

pub fn fat_driver_binding_start(
    this: *mut efi::protocols::driver_binding::Protocol,
    controller_handle: efi::Handle,
    _remaining_device_path: *mut efi::protocols::device_path::Protocol
) -> efi::Status
{
    let bs = unsafe{ &*(gBS as *mut efi::BootServices)};
    let this = unsafe{&*this};

    let mut status = efi::Status::SUCCESS;

    let mut block_io: *mut efi::protocols::block_io::Protocol = core::ptr::null_mut();
    let mut disk_io: *mut efi::protocols::disk_io::Protocol = core::ptr::null_mut();
    let mut disk_io2: *mut efi::protocols::disk_io2::Protocol = core::ptr::null_mut();


    if status.is_ok() {
        status = (bs.open_protocol)(
            controller_handle,
            &efi::protocols::block_io::PROTOCOL_GUID as *const efi::Guid as *mut efi::Guid,
            &mut block_io as *mut *mut efi::protocols::block_io::Protocol as *mut *mut core::ffi::c_void,
            (this).driver_binding_handle,
            controller_handle,
            efi::OPEN_PROTOCOL_GET_PROTOCOL
        );
    }

    if status.is_ok() {
        status = (bs.open_protocol)(
            controller_handle,
            &efi::protocols::disk_io::PROTOCOL_GUID as *const efi::Guid as *mut efi::Guid,
            &mut disk_io as *mut *mut efi::protocols::disk_io::Protocol as *mut *mut core::ffi::c_void,
            this.driver_binding_handle,
            controller_handle,
            efi::OPEN_PROTOCOL_BY_DRIVER
        );
    }

    if status.is_ok() {
        let status_tmp = (bs.open_protocol)(
            controller_handle,
            &efi::protocols::disk_io2::PROTOCOL_GUID as *const efi::Guid as *mut efi::Guid,
            &mut disk_io2 as *mut *mut efi::protocols::disk_io2::Protocol as *mut *mut core::ffi::c_void,
            (this).driver_binding_handle,
            controller_handle,
            efi::OPEN_PROTOCOL_BY_DRIVER
        );
        if status_tmp.is_error() {
            disk_io2 = core::ptr::null_mut();
        }
    }

    // TODO simple file system initialize
    // 1.  is fat?
    // 2.  install simple file system protocol

    status
}

#[cfg(test)]
pub mod tests {
    #[test]
    pub fn test_lib(){

    }
}