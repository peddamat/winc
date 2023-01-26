use std::io;
use std::fs::File;
use std::io::prelude::*;
use std::io::{SeekFrom};
use binread::{BinReaderExt, BinRead, io::Cursor};

#[derive(BinRead)]
#[br(magic = b"\x11\xF1\x12\xF2\x13\xF3\x14\xF4\x15\xF5\x16\xF6\x17\xF7\x18\xF8")]
struct RSHeader {
    count: u32,

    #[br(big, count = count)]
    certs: Vec<RSCert>
}

#[derive(BinRead)]
struct RSCert {
    nameHash: u8,
    start: RSTime,
    end: RSTime,
    keyType: RSKeyType,
    keySize: CertInfo,
    keyData: CertData
}

#[derive(BinRead)]
enum RSKeyType {
    #[br(magic = 1u16)] RSA,
    #[br(magic = 2u16)] ECDSA,
}

union CertInfo {
    RSAkey: RSAInfo,
    ECDSAkey: EcdsaInfo
}

struct RSAInfo {
    Nsz: u16,
    Esz: u16
}

struct EcdsaInfo {
    CurveID: u16,
    KeySz: u16
}

union CertData {
    RSAdata: RSAData,
    ECDSAdata: EcdsaData
}

#[derive(BinRead)]
struct RSAData {
    #[br(big, count = count)]
    N: Vec<u8>,
    #[br(big, count = count)]
    E: Vec<u8>
}

#[derive(BinRead)]
struct EcdsaData {
    #[br(big, count = count)]
    D: Vec<u8>,
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

    // Seek to Root Cert store offset
    f.seek(SeekFrom::Start(0x4000))
        .expect("error reading file!");

    let mut rs = [0; 100];
    f.read(&mut rs);

    // Parse magic pattern
    let mut reader = Cursor::new(rs);
    let rs: RSHeader = reader.read_ne().unwrap();

    println!("Found {} certs!", rs.count);

    Ok(())
}
