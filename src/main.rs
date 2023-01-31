use binread::NullString;
use binread::{io::Cursor, BinRead, BinReaderExt, FilePtr8, FilePtr32};
use std::borrow::Borrow;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;

#[derive(BinRead)]
#[br(magic = b"\xab\xfe\x18\x5b\x70\xc3\x46\x92")]
struct TSHeader {
    #[br(offset=0x5008)]
    count: u32,

    next_write_addr: u32,

    #[br(count = count)]
    certs: Vec<TSCertEntry>,

    crc: u32,
}

#[derive(BinRead, Debug)]
struct TSCertEntry {
    #[br(pad_size_to(48))]
    file_name: NullString,
    file_size: u32,
    // file_addr: FilePtr32<u8>
    file_addr: u32
}

#[derive(BinRead)]
struct RSAPrivKey {
    u16NSize: u16,
    u16eSize: u16,
    u16dSize: u16,
    u16PSize: u16,
    u16QSize: u16,
    u16dPSize: u16,
    u16dQSize: u16,
    u16QInvSize: u16,
    u32Version: u32,

    #[br(count = u16NSize)]
    N: Vec<u8>,
    #[br(count = u16eSize)]
    e: Vec<u8>,
    #[br(count = u16dSize)]
    d: Vec<u8>,
    #[br(count = u16PSize)]
    p: Vec<u8>,
    #[br(count = u16QSize)]
    q: Vec<u8>,
    #[br(count = u16dPSize)]
    dP: Vec<u8>,
    #[br(count = u16dQSize)]
    dQ: Vec<u8>,
    #[br(count = u16QInvSize)]
    QInv: Vec<u8>,
}

#[derive(BinRead)]
#[br(magic = b"\x11\xF1\x12\xF2\x13\xF3\x14\xF4\x15\xF5\x16\xF6\x17\xF7\x18\xF8")]
struct RSHeader {
    count: u32,

    #[br(count = count)]
    certs: Vec<RSCert>,
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
    #[br(little, magic = 1u32)]
    RSA {
        // T: u32,
        n_sz: u16,
        e_sz: u16,

        #[br(count = n_sz, align_after=4)]
        n: Vec<u8>,
        #[br(count = e_sz, align_after=4)]
        e: Vec<u8>,
    },
    #[br(little, magic = 2u32)]
    ECDSA {
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
    second: u8,
}

fn main() -> io::Result<()> {
    let file_path = "firmware/atwinc1500-original.bin";

    println!("Opening file {file_path}");
    let mut f = File::open(file_path).expect("Error opening file!");

    let mut rs = [0; 4096];
    f.seek(SeekFrom::Start(0x4000))
        .expect("Error locating Root Cert Store!");
    f.read(&mut rs).expect("Error reading file!");

    // Parse Root Cert Store
    let mut reader = Cursor::new(rs);
    let rs: RSHeader = reader.read_le().unwrap();

    println!("Found {} Root Store certs!", rs.count);

    for (i, c) in rs.certs.into_iter().enumerate() {
        match c.data {
            RSCertData::RSA { n_sz, e_sz, n, e } => println!(
                "Cert {}: Name: {:?} / Nsz: {} / Esz: {}!",
                i, c.name_hash, n_sz, e_sz
            ),
            RSCertData::ECDSA {
                curve_id,
                key_sz,
                d,
            } => println!("Cert {}: Name: {:?} / KeySz: {}!", i, c.name_hash, key_sz),
        }
    }

    println!("Opening file {file_path}");
    let mut f = File::open(file_path).expect("Error opening file!");

    let mut ts_buf: [u8; 8192] = [0; 8192];
    f.seek(SeekFrom::Start(0x5000))
        .expect("Error locating Root Cert Store!");
    f.read(&mut ts_buf).expect("Error reading file!");

    // Parse TLS Cert Store
    let mut reader = Cursor::new(ts_buf);
    let ts: TSHeader = reader.read_le().unwrap();

    println!("Found {} TLS Store certs!", ts.count);

    for (i, c) in ts.certs.into_iter().enumerate() {
        let offset = c.file_addr - 0x5000;
        let end = offset + c.file_size;
        let file = &ts_buf[offset as usize..end as usize];
        println!("{:?}: offset: {} / size: {}", c.file_name, c.file_addr-0x5000, c.file_size);
        // println!("{:02X?}", file);
        if ( c.file_name[0] == 67 )
        {
            let x509 = openssl::x509::X509::from_der(&file).expect("error opening x509");
            let foo = x509.to_text().unwrap();
            println!("{}", String::from_utf8(foo).unwrap());
        }
        else if (c.file_name[0] == 80)
        {
            let mut fart = Cursor::new(file);
            let shit: RSAPrivKey = fart.read_le().unwrap();
            println!("{:?}", shit.N);

        }
    }

    Ok(())
}
