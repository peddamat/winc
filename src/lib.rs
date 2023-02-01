use binrw::{ BinRead, NullString, FilePtr32 };
use openssl::bn::BigNum;
use std::io::SeekFrom;

///////////////////////////////////////////////////////////////////////////////
// Root Cert Store
///////////////////////////////////////////////////////////////////////////////

#[derive(BinRead)]
#[br(magic = b"\x11\xF1\x12\xF2\x13\xF3\x14\xF4\x15\xF5\x16\xF6\x17\xF7\x18\xF8")]
pub struct RootCertStore {
    pub count: u32,

    #[br(count = count)]
    pub certs: Vec<RcsHeader>,
}

#[derive(BinRead)]
#[allow(dead_code)]
pub struct RcsHeader {
    pub name_hash: [u8; 20],
    pub start: RcsTime,
    pub end: RcsTime,
    pub data: RcsCert,
}

#[derive(BinRead)]
#[allow(dead_code)]
pub struct RcsTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    #[br(pad_after = 1)]
    second: u8,
}

#[binrw::binread]
#[allow(dead_code)]
pub enum RcsCert {
    #[br(little, magic = 1u32)]
    RsaPublicKey {
        n_sz: u16,
        e_sz: u16,

        #[br(align_after = 4, count = n_sz, map = |s: Vec<u8>| BigNum::from_slice(&s).unwrap())]
        n: BigNum,
        #[br(align_after = 4, count = e_sz, map = |s: Vec<u8>| BigNum::from_slice(&s).unwrap())]
        e: BigNum,
    },
    #[br(little, magic = 2u32)]
    EcdsaPublicKey {
        curve_id: u16,

        key_sz: u16,

        #[br(count = key_sz)]
        d: Vec<u8>,
    },
}

///////////////////////////////////////////////////////////////////////////////
// TLS Cert Store
///////////////////////////////////////////////////////////////////////////////
#[binrw::binread]
#[br(magic = b"\xab\xfe\x18\x5b\x70\xc3\x46\x92")]
pub struct TlsStore {
    #[br(offset = 0x5008)]
    pub count: u32,

    next_write_addr: u32,

    #[br(count = count)]
    pub certs: Vec<TSCertEntry>,

    crc: u32,
}

#[binrw::binread]
pub struct TSCertEntry {
    #[br(pad_size_to(48))]
    pub file_name: NullString,

    file_size: u32,
    file_addr: u32,

    // file_addr: FilePtr32<u8>,

    #[br(restore_position, seek_before(SeekFrom::Start(file_addr as u64)), count = file_size)]
    pub data: Vec<u8>,
}


#[binrw::binread]
#[allow(dead_code)]
pub struct RSAPrivKey {
    n_sz: u16,
    e_sz: u16,
    d_sz: u16,
    p_sz: u16,
    q_sz: u16,
    dp_sz: u16,
    dq_sz: u16,
    qinv_sz: u16,

    version: u32,

    #[br(count = n_sz, map = |s: Vec<u8>| BigNum::from_slice(&s).unwrap())]
    pub n: BigNum,
    #[br(count = e_sz, map = |s: Vec<u8>| BigNum::from_slice(&s).unwrap())]
    pub e: BigNum,
    #[br(count = d_sz, map = |s: Vec<u8>| BigNum::from_slice(&s).unwrap())]
    pub d: BigNum,
    #[br(count = p_sz, map = |s: Vec<u8>| BigNum::from_slice(&s).unwrap())]
    pub p: BigNum,
    #[br(count = q_sz, map = |s: Vec<u8>| BigNum::from_slice(&s).unwrap())]
    pub q: BigNum,
    #[br(count = dp_sz, map = |s: Vec<u8>| BigNum::from_slice(&s).unwrap())]
    pub dp: BigNum,
    #[br(count = dq_sz, map = |s: Vec<u8>| BigNum::from_slice(&s).unwrap())]
    pub dq: BigNum,
    #[br(count = qinv_sz, map = |s: Vec<u8>| BigNum::from_slice(&s).unwrap())]
    pub qinv: BigNum,
}