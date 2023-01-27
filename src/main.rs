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

    #[br(count = count)]
    certs: Vec<RSCert>
}

#[derive(BinRead)]
struct RSCert {
    name_hash: [u8; 20],
    start: RSTime,
    end: RSTime,

    data: RSCertData,
}

#[derive(BinRead, Clone, PartialEq)]
enum RSCertData {
    #[br(little, magic = 1u32)] RSA {
        // T: u32,
        n_sz: u16,
        e_sz: u16,

        #[br(count = n_sz, align_after=4)]
        n: Vec<u8>,
        #[br(count = e_sz, align_after=4)]
        e: Vec<u8>
    },
    #[br(little, magic = 2u32)] ECDSA {
        curve_id: u16,
        key_sz: u16,

        #[br(count = key_sz)]
        d: Vec<u8>,
    },
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

    println!("Opening file {file_path}");
    let mut f= File::open(file_path)
        .expect("Error opening file!");

    let mut rs = [0; 4096];
    f.seek(SeekFrom::Start(0x4000))
        .expect("Error locating Root Cert Store!");
    f.read(&mut rs)
        .expect("Error reading file!");

    // Parse Root Cert Store
    let mut reader = Cursor::new(rs);
    let rs: RSHeader = reader.read_le().unwrap();

    println!("Found {} certs!", rs.count);

    for (i, c) in rs.certs.into_iter().enumerate() {
        match c.data {
            RSCertData::RSA { n_sz, e_sz, n, e }        => println!("Cert {}: Name: {:?} / Nsz: {} / Esz: {}!", i, c.name_hash, n_sz, e_sz),
            RSCertData::ECDSA { curve_id, key_sz, d }   => println!("Cert {}: Name: {:?} / KeySz: {}!", i, c.name_hash, key_sz),
        }
    }

    Ok(())
}
