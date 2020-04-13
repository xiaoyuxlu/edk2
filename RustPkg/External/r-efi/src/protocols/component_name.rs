//! Driver Binding Protocol
//!
//! Provides the `open_volume` function returning a file protocol representing the root directory
//! of a filesystem.

pub const PROTOCOL_GUID: crate::base::Guid = crate::base::Guid::from_fields(
    0x107a772c, 0xd5e1, 0x11d4, 0x9a, 0x46,  &[0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d]
);

#[repr(C)]
pub struct Protocol {
    pub get_driver_name: eficall!{fn(
        *mut Protocol,
        *mut crate::efi::Char8,
        *mut *mut crate::efi::Char16
    ) -> crate::base::Status},
    pub get_controller_name: eficall!{fn(
        *mut Protocol,
        crate::efi::Handle,
        crate::efi::Handle,
        *mut crate::efi::Char8,
        *mut *mut crate::efi::Char16
    ) -> crate::base::Status},
    pub supported_languages: *mut crate::efi::Char8
}
