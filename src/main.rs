use std::borrow::Borrow;
use std::io;
use std::fs::File;
use std::io::prelude::*;
use std::io::{SeekFrom};
use binread::{BinReaderExt, BinRead, io::Cursor};

#[derive(BinRead)]
#[br(magic = b"\x11\xF1\x12\xF2\x13\xF3\x14\xF4\x15\xF5\x16\xF6\x17\xF7\x18\xF8")]
struct RSHeader {
    count: u32,

    #[br(count = 1)]
    certs: Vec<RSCert>
}

#[derive(BinRead)]
struct RSCert {
    nameHash: u8,
    start: RSTime,
    end: RSTime,

    data: RSCertData,
}

#[derive(BinRead, Clone, PartialEq)]
struct RSCertData {
    // #[br(little, magic = 1u32)] RSA {
        T: u32,
        Nsz: u16,
        Esz: u16,

        #[br(count = Nsz)]
        N: Vec<u8>,
        #[br(count = Esz)]
        E: Vec<u8>
    // },
    // #[br(little, magic = 2u32)] ECDSA {
    //     CurveID: u16,
    //     KeySz: u16,

    //     #[br(count = KeySz)]
    //     D: Vec<u8>,
    // },
}

#[derive(BinRead)]
struct RSTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    #[br(pad_after = 1)]
    second: u8
}

fn main() -> io::Result<()> {
    let file_path = "firmware/atwinc1500-original.bin";

    // Open firmware file
    println!("Opening file {file_path}");
    let mut f= File::open(file_path)?;

    // Seek to Root Cert Store offset
    f.seek(SeekFrom::Start(0x4000))
        .expect("error reading file!");

    let mut rs = [0; 4096];
    f.read(&mut rs);

    // Parse Root Cert Store
    let mut reader = Cursor::new(rs);
    let rs: RSHeader = reader.read_le().unwrap();

    println!("Found {} certs!", rs.count);

    Ok(())
}
