use base64;
use std::fs;
use std::io::Write;
use crate::msgs::base::{PayloadU16, PayloadU8};


/// This client usable function takes two filenames and a ServerPublicKey structure
/// elements. It overwrites what has been written in the filenames with the new
/// SPK data
pub fn write_spk(efilename: &str, pkfilename: &str, 
                public_key: PayloadU16, epoch:  PayloadU8,){

    let mut epochfile = fs::File::create(efilename).expect("cannot create epoch file");
    let mut pkfile = fs::File::create(pkfilename).expect("cannot create public key file");

    let pk_buf = create_pk_pem_buff(public_key);
    let epoch_buf = create_epoch_pem_buff(epoch);
    
    pkfile.write_all(pk_buf.as_bytes())
            .expect("error in writing the public key");
    epochfile.write_all(epoch_buf.as_bytes())
            .expect("error in writing the epoch");
}


fn create_pk_pem_buff(public_key: PayloadU16,) -> String {
    let mut buf: String =  "-----BEGIN PUBLIC KEY-----\n".to_owned();
    let mut public_key = base64::encode(&public_key.0);
    let len = public_key.len();
    let mut cnt = 0;
    for i in 1..len+1 {
        if i%64==0 {
            cnt = cnt + 1;
            public_key.insert(i+cnt-1,'\n');
        }
    }
    buf.push_str(&public_key);
    buf.push_str("\n-----END PUBLIC KEY-----");
    buf
}

fn create_epoch_pem_buff(epoch: PayloadU8,) -> String {
    let mut buf: String =  "-----BEGIN EPOCH-----\n".to_owned();
    let mut epoch = base64::encode(&epoch.0);
    let len = epoch.len();
    let mut cnt = 0;
    for i in 1..len+1 {
        if i%64==0 {
            cnt = cnt + 1;
            epoch.insert(i+cnt-1,'\n');
        }
    }
    buf.push_str(&epoch);
    buf.push_str("\n-----END EPOCH-----");
    buf
}

