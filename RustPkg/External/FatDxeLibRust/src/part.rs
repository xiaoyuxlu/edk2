#![allow(unused)]

use crate::block::SectorRead;

#[repr(packed)]
/// GPT header
struct Header {
    signature: u64,
    _revision: u32,
    _header_size: u32,
    _header_crc: u32,
    _reserved: u32,
    _current_lba: u64,
    _backup_lba: u64,
    first_usable_lba: u64,
    _last_usable_lba: u64,
    _disk_guid: [u8; 16],
    first_part_lba: u64,
    part_count: u32,
    _part_entry_size: u32,
    _part_crc: u32,
}

#[repr(packed)]
#[derive(Clone, Copy)]
pub struct PartitionEntry {
    pub type_guid: [u8; 16],
    pub guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    _flags: u64,
    _partition_name: [u32; 18],
}

impl PartitionEntry {
    pub fn is_efi_partition(&self) -> bool {
        // GUID is C12A7328-F81F-11D2-BA4B-00A0C93EC93B in mixed-endian
        // 0-3, 4-5, 6-7 are LE, 8-19, and 10-15 are BE
        self.type_guid
            == [
                0x28, 0x73, 0x2a, 0xc1, // LE C12A7328
                0x1f, 0xf8, // LE F81F
                0xd2, 0x11, // LE 11D2
                0xba, 0x4b, // BE BA4B
                0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b, // BE 00A0C93EC93B
            ]
    }
}

#[derive(Debug)]
pub enum Error {
    BlockError,
    HeaderNotFound,
    ViolatesSpecification,
    ExceededPartitionCount,
    NoEFIPartition,
}

pub fn get_partitions(r: &dyn SectorRead, parts_out: &mut [PartitionEntry]) -> Result<u32, Error> {
    let mut data: [u8; 512] = [0; 512];
    match r.read(1, &mut data) {
        Ok(_) => {}
        Err(_) => return Err(Error::BlockError),
    };

    // Safe as sizeof header is less than 512 bytes (size of data)
    let h = unsafe { &*(data.as_ptr() as *const Header) };

    // GPT magic constant
    if h.signature != 0x5452_4150_2049_4645u64 {
        return Err(Error::HeaderNotFound);
    }

    if h.first_usable_lba < 34 {
        return Err(Error::ViolatesSpecification);
    }

    let part_count = h.part_count;
    let mut checked_part_count = 0;

    let first_usable_lba = h.first_usable_lba;
    let first_part_lba = h.first_part_lba;

    let mut current_part = 0u32;

    for lba in first_part_lba..first_usable_lba {
        match r.read(lba, &mut data) {
            Ok(_) => {}
            Err(_) => return Err(Error::BlockError),
        }

        // Safe as size of partition struct * 4 is 512 bytes (size of data)
        let parts =
            unsafe { core::slice::from_raw_parts(data.as_ptr() as *const PartitionEntry, 4) };

        for p in parts {
            if p.guid == [0; 16] {
                continue;
            }
            parts_out[current_part as usize] = *p;
            current_part += 1;
        }

        checked_part_count += 4;
        if checked_part_count >= part_count {
            break;
        }
    }

    Ok(current_part)
}

/// Find EFI partition
pub fn find_efi_partition(r: &dyn SectorRead) -> Result<(u64, u64, u32), Error> {
    let mut data: [u8; 512] = [0; 512];
    match r.read(1, &mut data) {
        Ok(_) => {}
        Err(_) => return Err(Error::BlockError),
    };

    // Safe as sizeof header is less than 512 bytes (size of data)
    let h = unsafe { &*(data.as_ptr() as *const Header) };

    // GPT magic constant
    if h.signature != 0x5452_4150_2049_4645u64 {
        return Err(Error::HeaderNotFound);
    }

    if h.first_usable_lba < 34 {
        return Err(Error::ViolatesSpecification);
    }

    let mut checked_part_count = 0u32;
    let part_count = h.part_count;
    let first_usable_lba = h.first_usable_lba;
    let first_part_lba = h.first_part_lba;

    for lba in first_part_lba..first_usable_lba {
        match r.read(lba, &mut data) {
            Ok(_) => {}
            Err(_) => return Err(Error::BlockError),
        }

        // Safe as size of partition struct * 4 is 512 bytes (size of data)
        let parts =
            unsafe { core::slice::from_raw_parts(data.as_ptr() as *const PartitionEntry, 4) };

        for p in parts {
            if p.is_efi_partition() {
                return Ok((p.first_lba, p.last_lba, checked_part_count + 1));
            }
            checked_part_count += 1;
            if checked_part_count == part_count {
                return Err(Error::ExceededPartitionCount);
            }
        }
    }

    Err(Error::NoEFIPartition)
}

#[cfg(test)]
pub mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::fs::File;
    use std::fs::Metadata;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;

    use crate::block;
    use crate::block::SectorRead;

    #[derive(Debug)]
    pub struct FakeDisk {
        file: RefCell<File>,
        metadata: Metadata,
    }

    impl FakeDisk {
        pub fn new(path: &str) -> FakeDisk {
            let file = File::open(path).expect("missing disk image");
            let metadata = fs::metadata(path).expect("error getting file metadata");
            FakeDisk {
                file: RefCell::new(file),
                metadata,
            }
        }

        pub fn len(&self) -> u64 {
            self.metadata.len()
        }

        pub fn total_sectors(&self) -> u64 {
            self.len() / 512
        }
    }

    impl SectorRead for FakeDisk {
        fn read(&self, sector: u64, data: &mut [u8]) -> Result<(), block::Error> {
            let mut file = self.file.borrow_mut();
            match file.seek(SeekFrom::Start(sector * 512)) {
                Ok(_) => {}
                Err(_) => return Err(block::Error::DEVICE_ERROR),
            }
            match file.read(data) {
                Ok(_) => {}
                Err(_) => return Err(block::Error::DEVICE_ERROR),
            }
            Ok(())
        }
    }

    #[test]
    fn test_find_efi_partition() {
        let d = FakeDisk::new("test\\clear-31380-kvm.img");
        println!("disk.len is {}", d.len());

        assert_eq!(d.len(), 9_169_755_648);

        match super::find_efi_partition(&d) {
            Ok((start, end, part_id)) => {
                println!("start: {}, end: {}, part_id: {}", start, end, part_id);
                assert_eq!(start, 2048);
                assert_eq!(end, 1_046_527);
                assert_eq!(part_id, 1);
            }
            Err(e) => panic!(e),
        }
    }
}