use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use binrw::{io::Cursor, io::Read, BinReaderExt};

use winc::*;

fn main() -> Result<(), String> {
    let file_path = "firmware/atwinc1500-original.bin";

    let mut reader = {
        println!("Opening file {file_path}");

        File::open(file_path)
            .map_err(|err| err.to_string())
            .and_then(|mut file| {
                let mut buf = [0; 512 * 1024];
                file.read_exact(&mut buf)
                    .map_err(|err| err.to_string())
                    .map(|_| buf)
            })
            .map(|buf| Cursor::new(buf))
            .unwrap()
    };

    read_root_cert_store(&mut reader);
    read_tls_store(&mut reader);

    Ok(())
}

// The Root Cert Store starts at 0x4000 in the binary, as documented in the
//   ATWINC1500 documentation
fn read_root_cert_store(reader: &mut Cursor<[u8; 524288]>) {
    reader.seek(SeekFrom::Start(0x4000)).expect("Error finding Root Cert Store at 0x4000!");

    // The ATWINC1500 is little-endian, though the Cortus can be
    //   configured as either big-endian or little-endian
    let store: RootCertStore = reader.read_le().expect("Error parsing Root Cert Store!");

    println!("Found {} Root Store certs!", store.count);

    for (i, cert) in store.certs.into_iter().enumerate() {
        match cert.data {
            RcsCert::RsaPublicKey { n, e } => process_rsa_public_key(n, e, i),
            RcsCert::EcdsaPublicKey { curve_id: _, d: _ } => process_ecdsa_public_key(i, cert),
        }
    }

    fn process_rsa_public_key(n: openssl::bn::BigNum, e: openssl::bn::BigNum, i: usize) {
        let pk_string = {
            let pk = Rsa::from_public_components(n, e).expect("Error parsing public key!");
            let pem = pk.public_key_to_pem_pkcs1().expect("Error converting public key to pem!");
            String::from_utf8(pem).expect("Error converting pem to string!")
        };

        println!("Root Certificate (RSA) {}:\n {}", i, pk_string);
    }

    fn process_ecdsa_public_key(i: usize, cert: RcsHeader) {
        println!(
            "Root Certificate (ECDSA) {}:\n Name: {:?}!",
            i, cert.name_hash
        );
    }
}

// The TLS Cert Store starts at 0x5000 in the binary, as documented in the
//   ATWINC1500 documentation.
fn read_tls_store(reader: &mut Cursor<[u8; 524288]>) {
    reader.seek(SeekFrom::Start(0x5000)).expect("Error finding TLS Cert Store at 0x5000!");

    let store: TlsStore = reader.read_le().expect("Error parsting TLS Cert Store!");

    println!("Found {} items in TLS Store!", store.count);

    for (i, cert) in store.certs.into_iter().enumerate() {
        match &cert.file_name.to_string()[..4] {
            "CERT" => process_x509_cert(&cert, i),
            "PRIV" => process_private_key(&cert, i),
            _ => println!("Unknown file found in TLS Cert Store: {}!", cert.file_name),
        };
    }

    fn process_x509_cert(cert: &TSCertEntry, i: usize) {
        let x509_string = {
            let x509 = X509::from_der(&cert.data).expect("Error parsing X509 certificate!");
            let x509_text = x509.to_text().expect("Error converting X509 certificate to string!");
            String::from_utf8(x509_text).expect("Error!")
        };

        println!("TLS Certificate {}: {}\n {}", i, cert.file_name, x509_string);
    }

    fn process_private_key(cert: &TSCertEntry, i: usize) {
        let priv_key_as_pem = {
            let pk: RSAPrivKey = Cursor::new(&cert.data).read_le().expect("Error parsing RSA private key!");

            let pk_text = Rsa::from_private_components(pk.n, pk.e, pk.d, pk.p, pk.q, pk.dp, pk.dq, pk.qinv)
                            .expect("Error converting RSA private key!")
                            .private_key_to_pem()
                            .expect("Error converting RSA private key to pem!");

            String::from_utf8(pk_text).expect("Error!")
        };

        println!("TLS Private Key {}: {}\n {}", i, cert.file_name, priv_key_as_pem);
    }
}