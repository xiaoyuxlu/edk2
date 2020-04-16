#![cfg_attr(not(test), no_std)]

#[macro_use]
mod log;

use r_efi::efi;

mod block;
mod part;
mod fat;

fn dump_disk_512(bs: &mut efi::BootServices) {
    let _address = bs.locate_protocol as *const ();
    log!("boot service: {:p}", _address);
}

#[export_name = "FatEntryPoint"]
pub extern fn fat_entry_point(_h: efi::Handle, st: *mut efi::SystemTable) -> efi::Status {
    log!("fat_entry");

    dump_disk_512(unsafe{&mut *((*st).boot_services)});
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