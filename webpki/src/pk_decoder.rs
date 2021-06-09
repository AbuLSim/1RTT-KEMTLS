use crate::{der, Error};
use crate::signed_data::SubjectPublicKeyInfo;


// This file is used for 1RTT-KEMTLS
pub (crate) fn parse_public_key<'a>(pk_der: &'a [u8]) -> Result<SubjectPublicKeyInfo<'a>, Error> {
    // transform pk_der into untrusted Input
    let pk = untrusted::Input::from(pk_der);
    // parse public key into der
    let spki = parse_internal_public_key(pk);
    // return SubjectPublicKeyInfo
    spki
}

pub(crate) fn parse_internal_public_key<'a>(pk_der: untrusted::Input<'a>)
                            -> Result<SubjectPublicKeyInfo<'a>, Error> {
    let pk = pk_der.read_all(Error::BadDER, |pk_der| {
        der::nested(
            pk_der,
            der::Tag::Sequence,
            Error::BadDER,
            pk_decoder,
        )
    })?;
    Ok(pk)
}


pub(crate) fn pk_decoder<'a>(der: &mut untrusted::Reader<'a>)-> Result<SubjectPublicKeyInfo<'a>, Error> {

    let algorithm = der::expect_tag_and_get_value(der, der::Tag::Sequence)?;
    let key_value = der::bit_string_with_no_unused_bits(der)?;

    Ok(SubjectPublicKeyInfo {
        algorithm_id_value: algorithm,
        key_value,
        })
}