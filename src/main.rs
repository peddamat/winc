use binrw::{io::Cursor, io::Read, BinRead, BinReaderExt};
use openssl::rsa::Rsa;
use openssl::x509::X509;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;

use winc::*;


fn main() -> Result<(), String> {
    let file_path = "firmware/atwinc1500-original.bin";

    let mut reader = {
        println!("Opening file {file_path}");

        File::open(file_path)
            .map_err(|err| err.to_string() )
            .and_then(|mut file| {
                let mut buf = [0; 512 * 1024];
                file.read_exact(&mut buf)
                    .map_err(|err| err.to_string())
                    .map(|_| buf)
            })
            .map(|buf| { Cursor::new(buf) })
            .unwrap()
    };

    // The Root Cert Store starts at 0x4000 in the binary,
    //   as documented in the ATWINC1500 documentation
    match reader.seek(SeekFrom::Start(0x4000)) {
        Ok(_) => println!("Seeking to Root Cert Store offset 0x4000"),
        Err(err) => return Err(err.to_string())
    }

    // The ATWINC1500 is little-endian, though the Cortus can be
    //   configured as either big-endian or little-endian
    let rcs = match reader.read_le::<RootCertStore>() {
        Ok(r) => {
            println!("Found {} Root Store certs!", r.count);
            r
        },
        Err(err) => return Err(err.to_string())
    };

    for (i, cert) in rcs.certs.into_iter().enumerate() {
        match cert.data {
            RcsCert::RsaPrivKey { n, e } => {
                Rsa::from_public_components(n, e)
                    .map_err(|err| err.to_string() )
                    .and_then(|pk| {
                        pk.public_key_to_pem_pkcs1()
                            .map_err(|err| err.to_string() )
                            .and_then(|pk_as_pem| {
                                String::from_utf8(pk_as_pem)
                                    .map_err(|err| err.to_string() )
                                    .map(|fuck| {
                                        println!(
                                            "Root Certificate (RSA) {}:\n {}",
                                            i,
                                            fuck
                                        );
                                    })
                            })
                    })
                    .unwrap()
            }
            RcsCert::Ecdsa { curve_id: _, d: _ } => {
                println!(
                    "Root Certificate (ECDSA) {}:\n Name: {:?}!",
                    i, cert.name_hash
                );
            }
        }
    }

    // Locate and parse TLS Store
    reader
        .seek(SeekFrom::Start(0x3000))
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
                    .expect("error opening x509");

                let x509_text = x509.to_text().unwrap();
                println!(
                    "TLS Certificate {}: {}\n {}",
                    i,
                    cert.file_name,
                    String::from_utf8(x509_text).unwrap()
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
