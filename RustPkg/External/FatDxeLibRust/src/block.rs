
pub enum Error {
    BlockIOError,

    #[cfg(not(test))]
    BlockNotSupported,
}

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
