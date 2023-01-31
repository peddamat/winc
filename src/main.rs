use binrw::NullString;
use binrw::{io::Cursor, BinRead, BinReaderExt, io::Read, BinResult, ReadOptions};
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;

#[binrw::binread]
#[br(magic = b"\xab\xfe\x18\x5b\x70\xc3\x46\x92")]
struct TlsStore {
    #[br(offset=0x5008)]
    count: u32,

    #[br(temp)]
    next_write_addr: u32,

    #[br(count = count)]
    certs: Vec<TSCertEntry>,

    #[br(temp)]
    crc: u32,
}

#[derive(BinRead, Debug)]
struct TSCertEntry {
    #[br(pad_size_to(48))]
    file_name: NullString,
    file_size: u32,
    // file_addr: FilePtr32<u8>
    file_addr: u32,

    #[br(restore_position, seek_before(SeekFrom::Start(file_addr as u64)), count = file_size)]
    data: Vec<u8>,
}

#[binrw::binread]
#[allow(dead_code)]
struct RSAPrivKey {
    #[br(temp)]
    n_sz: u16,
    #[br(temp)]
    e_sz: u16,
    #[br(temp)]
    d_sz: u16,
    #[br(temp)]
    p_sz: u16,
    #[br(temp)]
    q_sz: u16,
    #[br(temp)]
    dp_sz: u16,
    #[br(temp)]
    dq_sz: u16,
    #[br(temp)]
    qinv_sz: u16,

    version: u32,

    #[br(count = n_sz)]
    n: Vec<u8>,
    #[br(count = e_sz)]
    e: Vec<u8>,
    #[br(count = d_sz)]
    d: Vec<u8>,
    #[br(count = p_sz)]
    p: Vec<u8>,
    #[br(count = q_sz)]
    q: Vec<u8>,
    #[br(count = dp_sz)]
    dp: Vec<u8>,
    #[br(count = dq_sz)]
    dq: Vec<u8>,
    #[br(count = qinv_sz)]
    qinv: Vec<u8>,
}


#[derive(BinRead)]
#[br(magic = b"\x11\xF1\x12\xF2\x13\xF3\x14\xF4\x15\xF5\x16\xF6\x17\xF7\x18\xF8")]
struct RootCertStore {
    count: u32,

    #[br(count = count)]
    certs: Vec<RSCert>,
}

#[derive(BinRead)]
#[allow(dead_code)]
struct RSCert {
    name_hash: [u8; 20],
    start: RSTime,
    end: RSTime,

    data: RSCertData,
}

#[binrw::binread]
enum RSCertData {
    #[br(little, magic = 1u32)]
    Rsa {
        #[br(temp)]
        n_sz: u16,

        #[br(temp)]
        e_sz: u16,

        #[br(count = n_sz, align_after=4)]
        n: Vec<u8>,
        #[br(count = e_sz, align_after=4)]
        e: Vec<u8>,
    },
    #[br(little, magic = 2u32)]
    Ecdsa {
        curve_id: u16,

        #[br(temp)]
        key_sz: u16,

        #[br(count = key_sz)]
        d: Vec<u8>,
    },
}

#[derive(BinRead)]
#[allow(dead_code)]
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

    let mut reader = {
        println!("Opening file {file_path}");

        let mut f = File::open(file_path).expect("Error opening file!");

        let mut buf = [0; 512*1024];
        f.read_exact(&mut buf).expect("Error reading file!");

        let reader = Cursor::new(buf);
        reader
    };

    // Locate and parse TLS Store
    reader.seek(SeekFrom::Start(0x5000)).expect("Error finding TLS Cert Store!");
    {
        let ts: TlsStore = reader.read_le().unwrap();

        println!("Found {} TLS Store certs!", ts.count);

        for (i, cert) in ts.certs.into_iter().enumerate() {
            if cert.file_name.to_string().starts_with("CERT")
            {
                let x509 = openssl::x509::X509::from_der(&cert.data).expect("error opening x509");
                let x509_text = x509.to_text().unwrap();
                println!("TLS Certificate {}: {}\n {}", i, cert.file_name, String::from_utf8(x509_text).unwrap());
            }
            else if cert.file_name.to_string().starts_with("PRIV")
            {
                let mut c = Cursor::new(&cert.data);
                let pk: RSAPrivKey = c.read_le().unwrap();
                let n = openssl::bn::BigNum::from_slice(&pk.n).unwrap();
                let e = openssl::bn::BigNum::from_slice(&pk.e).unwrap();
                let d = openssl::bn::BigNum::from_slice(&pk.d).unwrap();
                let p = openssl::bn::BigNum::from_slice(&pk.p).unwrap();
                let q = openssl::bn::BigNum::from_slice(&pk.q).unwrap();
                let dp = openssl::bn::BigNum::from_slice(&pk.dp).unwrap();
                let dq = openssl::bn::BigNum::from_slice(&pk.dq).unwrap();
                let qinv = openssl::bn::BigNum::from_slice(&pk.qinv).unwrap();

                let pkk = openssl::rsa::Rsa::from_private_components(n, e, d, p, q, dp, dq, qinv).unwrap();
                let pkk = pkk.private_key_to_pem().unwrap();
                println!("TLS Private Key {}: {}\n {}", i, cert.file_name, String::from_utf8(pkk).unwrap());
            }
        }
    }

    // Locate and parse Root Cert Store
    reader.seek(SeekFrom::Start(0x4000)).expect("Error finding Root Cert Store!");
    {
        let rs: RootCertStore = reader.read_le().unwrap();

        println!("Found {} Root Store certs!", rs.count);

        for (i, cert) in rs.certs.into_iter().enumerate() {
            match cert.data {
                RSCertData::Rsa { n, e } => {
                    let n = openssl::bn::BigNum::from_slice(&n).unwrap();
                    let e = openssl::bn::BigNum::from_slice(&e).unwrap();
                    let pk = openssl::rsa::Rsa::from_public_components(n, e).unwrap();
                    let pkk = pk.public_key_to_pem_pkcs1().unwrap();
                    println!( "Root Certificate (RSA) {}: {}", i, String::from_utf8(pkk).unwrap());
                },
                RSCertData::Ecdsa { curve_id: _, d: _, } => {
                    println!("Root Certificate (ECDSA) {}: Name: {:?}!", i, cert.name_hash);
                }
            }
        }
    }


    Ok(())
}
