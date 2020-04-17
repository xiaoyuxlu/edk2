#![cfg_attr(not(test), no_std)]

#[macro_use]
mod log;

use r_efi::efi;

mod alloc;
mod block;
mod part;
mod fat;

unsafe fn dump_disk_512(bs: &mut efi::BootServices) {
    let _address = bs.locate_protocol as *const ();
    log!("boot service: {:p}", _address);
    let mut interface = core::ptr::null_mut();
    let status = (bs.locate_protocol)(
        &efi::protocols::block_io::PROTOCOL_GUID as *const efi::Guid as *mut efi::Guid,
        core::ptr::null_mut(),
        &mut interface as *mut *mut core::ffi::c_void
    );
    if status.is_error() {
        log!("locate protocol failed");
    }
    let res = block::BlockIoDevice::new(interface as *mut efi::protocols::block_io::Protocol).ok();
    if let Some(device) = res {
        let _part = part::find_efi_partition(&(*device));
        log!("parted info: {:?}", _part);
    }
}

#[export_name = "FatEntryPoint"]
pub extern fn fat_entry_point(_h: efi::Handle, st: *mut efi::SystemTable) -> efi::Status {
    log!("fat_entry");

    unsafe{dump_disk_512(&mut *((*st).boot_services))}
    efi::Status::SUCCESS
}

#[export_name = "FatUnload"]
pub extern fn fat_unload(_h: efi::Handle) -> efi::Status {
    log!("fat_unload");
    efi::Status::SUCCESS
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {

    }
}