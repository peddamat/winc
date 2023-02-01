use binrw::{io::Cursor, io::Read, BinRead, BinReaderExt};
use openssl::rsa::Rsa;
use openssl::x509::X509;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;

use winc::*;


fn main() -> io::Result<()> {
    let file_path = "firmware/atwinc1500-original.bin";

    let mut reader = {
        println!("Opening file {file_path}");

        let mut f = File::open(file_path).expect("Error opening file!");

        let mut buf = [0; 512 * 1024];
        f.read_exact(&mut buf).expect("Error reading file!");

        let reader = Cursor::new(buf);
        reader
    };

    // Locate and parse Root Cert Store
    reader
        .seek(SeekFrom::Start(0x4000))
        .expect("Error finding Root Cert Store!");
    {
        let rs: RootCertStore = reader.read_le().unwrap();

        println!("Found {} Root Store certs!", rs.count);

        for (i, cert) in rs.certs.into_iter().enumerate() {
            match cert.data {
                RSCertData::Rsa { n, e } => {
                    let pk = openssl::rsa::Rsa::from_public_components(n, e).unwrap();
                    let pkk = pk.public_key_to_pem_pkcs1().unwrap();
                    println!(
                        "Root Certificate (RSA) {}:\n {}",
                        i,
                        String::from_utf8(pkk).unwrap()
                    );
                }
                RSCertData::Ecdsa { curve_id: _, d: _ } => {
                    println!(
                        "Root Certificate (ECDSA) {}:\n Name: {:?}!",
                        i, cert.name_hash
                    );
                }
            }
        }
    }

    // Locate and parse TLS Store
    reader
        .seek(SeekFrom::Start(0x5000))
        .expect("Error finding TLS Cert Store!");
    {
        let ts: TlsStore = reader.read_le().unwrap();

        println!("Found {} items in TLS Store!", ts.count);

        for (i, cert) in ts.certs.into_iter().enumerate() {

            match &cert.file_name.to_string()[..4] {
                "CERT" => println!("hi"),
                _ => println!("Other!")

            };

            if cert.file_name.to_string().starts_with("CERT") {
                let x509 = X509::from_der(&cert.data)
                    .expect("error opening x509")
                    .to_text()?;
                // let x509_text = x509.to_text().unwrap();
                println!(
                    "TLS Certificate {}: {}\n {}",
                    i,
                    cert.file_name,
                    String::from_utf8(x509).unwrap()
                );
            } else if cert.file_name.to_string().starts_with("PRIV") {
                let priv_key_as_pem = {
                    let pk_raw: RSAPrivKey = Cursor::new(&cert.data).read_le().unwrap();

                    Rsa::from_private_components(
                        pk_raw.n,
                        pk_raw.e,
                        pk_raw.d,
                        pk_raw.p,
                        pk_raw.q,
                        pk_raw.dp,
                        pk_raw.dq,
                        pk_raw.qinv,
                    )
                    .unwrap()
                    .private_key_to_pem()
                    .unwrap()
                };
                println!(
                    "TLS Private Key {}: {}\n {}",
                    i,
                    cert.file_name,
                    String::from_utf8(priv_key_as_pem).unwrap()
                );
            }
        }
    }

    Ok(())
}
