#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(not(test))]
extern crate debug_lib;

#[cfg(not(test))]
extern crate uefi_rust_allocation_lib;

#[macro_use]
mod common;

mod fat;

#[cfg(not(test))]
use debug_lib::{print, println};

use r_efi::efi;

extern "C" {
    #[no_mangle]
    static gBS: *const core::ffi::c_void;

    fn EfiLibInstallDriverBindingComponentName2 (
        image_handle: efi::Handle,
        system_table: *const efi::SystemTable,
        driver_binding: *const efi::protocols::driver_binding::Protocol,
        driver_binding_handle:  efi::Handle,
        component_name: *const efi::protocols::component_name::Protocol,
        component_name2: *const efi::protocols::component_name2::Protocol
    ) -> efi::Status;

    fn AllocatePool (Size: usize) -> *mut core::ffi::c_void;
    //fn FreePool (Buffer: *mut core::ffi::c_void);
}

// static fat_driver_binding: efi::protocols::driver_binding::Protocol = efi::protocols::driver_binding::Protocol {
//     supported: fat_driver_binding_supported,
//     start: fat_driver_binding_start,
//     stop: fat_driver_binding_stop,
//     version: 0xau32,
//     image_handle: core::ptr::null_mut() as efi::Handle,
//     driver_binding_handle: core::ptr::null_mut() as efi::Handle
// };

#[export_name = "FatEntryPoint"]
pub extern "win64" fn fat_entry_point(h: efi::Handle, st: *mut efi::SystemTable) -> efi::Status
{
    let size = core::mem::size_of::<efi::protocols::driver_binding::Protocol>();

    print!("fat_entry_point\n");
    let _status = unsafe {
        let address = AllocatePool(size);
        let fat_driver_binding = address as *mut efi::protocols::driver_binding::Protocol;
        (*fat_driver_binding).supported = fat_driver_binding_supported;
        (*fat_driver_binding).start = fat_driver_binding_start;
        (*fat_driver_binding).stop = fat_driver_binding_stop;
        (*fat_driver_binding).version = 0xAu32;
        (*fat_driver_binding).image_handle = core::ptr::null_mut() as efi::Handle;
        (*fat_driver_binding).driver_binding_handle = core::ptr::null_mut() as efi::Handle;

        EfiLibInstallDriverBindingComponentName2(
            h,
            st,
            fat_driver_binding as *const efi::protocols::driver_binding::Protocol,
            h,
            core::ptr::null_mut() as *const efi::protocols::component_name::Protocol,
            core::ptr::null_mut() as *const efi::protocols::component_name2::Protocol);
    };
    println!("install driver binding component name");
    efi::Status::SUCCESS
}

#[export_name = "FatUnload"]
pub extern "win64" fn fat_unload(_h: efi::Handle) -> efi::Status {
    println!("fat_unload");
    efi::Status::SUCCESS
}

pub extern "win64" fn fat_driver_binding_supported(this: *mut efi::protocols::driver_binding::Protocol, controller_handle: efi::Handle, _remaining_device_path: *mut efi::protocols::device_path::Protocol) -> efi::Status {
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
        efi::OPEN_PROTOCOL_TEST_PROTOCOL
    );
    println!("fat_driver_binding supported {:?}", status);
    status
}

pub extern "win64" fn fat_driver_binding_start(
    this: *mut efi::protocols::driver_binding::Protocol,
    controller_handle: efi::Handle,
    _remaining_device_path: *mut efi::protocols::device_path::Protocol) -> efi::Status {
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

        }
    }

    // TODO simple file system initialize
    // 1.  is fat?
    // 2.  install simple file system protocol

    print!("fat_entry_point\n");

    let tmpfs = fat::Filesystem::new(unsafe{&mut *block_io}, unsafe{&mut *disk_io});

    let fs: &mut fat::Filesystem;
    unsafe {
        let size = core::mem::size_of::<fat::Filesystem>();
        let address = AllocatePool(size) as *mut fat::Filesystem;
        *address = tmpfs;
        fs = &mut (*address);
    }
    let res = fs.init();
    if res.is_err() {
        println!("filesystem not support");
        return efi::Status::UNSUPPORTED;
    }
    println!("filesystem create file system wrapper");
    let tmpfs_wrapper = crate::fat::file::FileSystemWrapper::new(&fs, Some(0));
    let fs_wrapper: &mut fat::file::FileSystemWrapper;
    unsafe {
        let size = core::mem::size_of::<fat::file::FileSystemWrapper>();
        let address = AllocatePool(size) as *mut fat::file::FileSystemWrapper;
        *address = tmpfs_wrapper;
        fs_wrapper = &mut (*address);
    }

    let status = (bs.install_protocol_interface)(
        &controller_handle as *const efi::Handle as *mut efi::Handle,
        &mut r_efi::protocols::simple_file_system::PROTOCOL_GUID as *mut efi::Guid,
        efi::InterfaceType::NativeInterface,
        &mut fs_wrapper.proto as *mut r_efi::protocols::simple_file_system::Protocol as *mut core::ffi::c_void
    );
    println!("filesystem install protocol result: {:?}", status.value());

    status
}

pub extern "win64" fn fat_driver_binding_stop(
    _this: *mut efi::protocols::driver_binding::Protocol,
    _controller_handle: efi::Handle,
    _number_of_children: usize,
    _child_handle_buffer: *mut efi::Handle) -> efi::Status {
        efi::Status::SUCCESS
}

#[cfg(test)]
pub mod tests {
    #[test]
    pub fn test_lib(){

    }
}