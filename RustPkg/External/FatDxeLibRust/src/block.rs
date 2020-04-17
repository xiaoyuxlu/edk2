
#![allow(unused)]

use r_efi::protocols::block_io::Protocol as EfiBlockIoProtocol;
use r_efi::protocols::block_io::PROTOCOL_GUID as EfiBlockIoProtocolGuid;
use r_efi::efi;
use core::fmt;

pub type Error = efi::Status;

pub trait SectorRead {
    /// Read a single sector (512 bytes) from the block device. `data` must be
    /// exactly 512 bytes long.
    fn read(&self, sector: u64, data: &mut [u8]) -> Result<(), Error>;
}

pub trait SectorWrite {
    /// Write a single sector (512 bytes) from the block device. `data` must be
    /// exactly 512 bytes long.
    fn write(&self, sector: u64, data: &mut [u8]) -> Result<(), Error>;
    fn flush(&self) -> Result<(), Error>;
}

pub struct BlockIoDevice {
    inner: Option<*mut EfiBlockIoProtocol>,
}

impl BlockIoDevice {
    pub unsafe fn new(block_io: *mut EfiBlockIoProtocol) -> Result<*mut BlockIoDevice, Error> {
        let res = crate::alloc::malloc::<BlockIoDevice>()?;
        (*res).inner = Some(block_io);
        Ok(res)
    }
}

impl SectorRead for BlockIoDevice {
    fn read(&self, sector: u64, data: &mut [u8]) -> Result<(), Error> {
        if let Some(mut block_io) = self.inner {
            unsafe {
                let media_id = (*((*block_io).media)).media_id;
                let status = ((*block_io).read_blocks)(
                    block_io, media_id, sector, data.len(),
                    data as *mut [u8] as *mut core::ffi::c_void
                );
                if status.is_error() {
                    crate::log!("block io read error: {:x}", status.value());
                    return Err(status);
                }
            }
            Ok(())
        } else {
            Err(efi::Status::DEVICE_ERROR)
        }
    }
}


impl SectorWrite for BlockIoDevice {
    fn write(&self, _sector: u64, _data: &mut [u8]) -> Result<(), Error> {
        if let Some(mut block_io) = self.inner {
            Ok(())
        } else {
            Err(efi::Status::DEVICE_ERROR)
        }
    }

    fn flush(&self) -> Result<(), Error> {
        if let Some(mut block_io) = self.inner {
            Ok(())
        } else {
            Err(efi::Status::DEVICE_ERROR)
        }
    }
}