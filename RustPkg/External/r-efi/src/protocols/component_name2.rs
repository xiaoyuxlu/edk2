//! Driver Binding Protocol
//!
//! Provides the `open_volume` function returning a file protocol representing the root directory
//! of a filesystem.

pub const PROTOCOL_GUID: crate::base::Guid = crate::base::Guid::from_fields(
    0x6a7a5cff, 0xe8d9, 0x4f70,  0xba, 0xda,  &[0x75, 0xab, 0x30, 0x25, 0xce, 0x14]
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
