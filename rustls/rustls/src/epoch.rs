/// 1RTT-KEMTLS

use std::fmt;

/// This type contains an epoch value.
///
/// The epoch must be DER-encoded ASN.1 in base64 where the file starts with
/// -----BEGIN EPOCH----- and ends with -----END EPOCH-----
///
/// `rustls::pemfile::extract_epoch`
/// could be used to extract epochs from a PEM file in this format.
#[derive(Clone, Eq, PartialEq)]
pub struct Epoch(pub Vec<u8>);


impl fmt::Debug for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use super::bs_debug::BsDebug;
        f.debug_tuple("Epoch").field(&BsDebug(&self.0)).finish()
    }
}


#[cfg(test)]
mod test {
    use super::Epoch;

    #[test]
    fn epoch_debug() {
        assert_eq!("Epoch(b\"ab\")", format!("{:?}", Epoch(b"ab".to_vec())));
    }
}
