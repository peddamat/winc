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

    #[br(args(keyType))]
    keySize: SizeInfo,

    #[br(args(keyType, keySize))]
    keyData: CertData
}

#[derive(BinRead, Clone, Copy, PartialEq)]
#[repr(u16)]
enum RSKeyType {
    #[br(magic = 1u16)] RSAm(u16),
    #[br(magic = 2u16)] ECDSAm(u16),
}

#[derive(BinRead, Clone, Copy, PartialEq)]
#[br(import(ty: RSKeyType))]
enum SizeInfo {
    #[br(pre_assert(ty == RSKeyType::RSAm(1)))] RSAn(RSAInfo),
    #[br(pre_assert(ty == RSKeyType::ECDSAm(2)))] ECDSAn(EcdsaInfo)
}

#[derive(BinRead, Clone, Copy, PartialEq)]
struct RSAInfo {
    Nsz: u16,
    Esz: u16
}

#[derive(BinRead, Clone, Copy, PartialEq)]
struct EcdsaInfo {
    CurveID: u16,
    KeySz: u16
}

#[derive(BinRead, PartialEq)]
#[br(import(ty: RSKeyType, sy: SizeInfo))]
enum CertData {
    #[br(pre_assert(ty == RSKeyType::RSAm(1)))] RSAq(RSAData),
    #[br(pre_assert(ty == RSKeyType::ECDSAm(2)))] ECDSAq(EcdsaData)
}

#[derive(BinRead, PartialEq)]
#[br(import(sy: SizeInfo))]
struct RSAData {
    #[br(big, count = sy.Nsz)]
    N: Vec<u8>,
    E: Vec<u8>
}

#[derive(BinRead, PartialEq)]
struct EcdsaData {
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
