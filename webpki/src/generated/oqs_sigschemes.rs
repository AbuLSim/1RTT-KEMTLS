
const DILITHIUM2_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-dilithium2.der")),
};

/// dilithium2 signatures
pub static DILITHIUM2: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: DILITHIUM2_ID,
    signature_alg_id: DILITHIUM2_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::Dilithium2),
};

const DILITHIUM3_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-dilithium3.der")),
};

/// dilithium3 signatures
pub static DILITHIUM3: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: DILITHIUM3_ID,
    signature_alg_id: DILITHIUM3_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::Dilithium3),
};

const DILITHIUM5_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-dilithium5.der")),
};

/// dilithium5 signatures
pub static DILITHIUM5: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: DILITHIUM5_ID,
    signature_alg_id: DILITHIUM5_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::Dilithium5),
};

const FALCON512_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-falcon512.der")),
};

/// falcon512 signatures
pub static FALCON512: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: FALCON512_ID,
    signature_alg_id: FALCON512_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::Falcon512),
};

const FALCON1024_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-falcon1024.der")),
};

/// falcon1024 signatures
pub static FALCON1024: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: FALCON1024_ID,
    signature_alg_id: FALCON1024_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::Falcon1024),
};

const RAINBOWICLASSIC_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-rainbowiclassic.der")),
};

/// rainbowiclassic signatures
pub static RAINBOWICLASSIC: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RAINBOWICLASSIC_ID,
    signature_alg_id: RAINBOWICLASSIC_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::RainbowIClassic),
};

const RAINBOWICIRCUMZENITHAL_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-rainbowicircumzenithal.der")),
};

/// rainbowicircumzenithal signatures
pub static RAINBOWICIRCUMZENITHAL: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RAINBOWICIRCUMZENITHAL_ID,
    signature_alg_id: RAINBOWICIRCUMZENITHAL_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::RainbowICircumzenithal),
};

const RAINBOWICOMPRESSED_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-rainbowicompressed.der")),
};

/// rainbowicompressed signatures
pub static RAINBOWICOMPRESSED: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RAINBOWICOMPRESSED_ID,
    signature_alg_id: RAINBOWICOMPRESSED_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::RainbowICompressed),
};

const RAINBOWIIICLASSIC_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-rainbowiiiclassic.der")),
};

/// rainbowiiiclassic signatures
pub static RAINBOWIIICLASSIC: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RAINBOWIIICLASSIC_ID,
    signature_alg_id: RAINBOWIIICLASSIC_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::RainbowIiiClassic),
};

const RAINBOWIIICIRCUMZENITHAL_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-rainbowiiicircumzenithal.der")),
};

/// rainbowiiicircumzenithal signatures
pub static RAINBOWIIICIRCUMZENITHAL: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RAINBOWIIICIRCUMZENITHAL_ID,
    signature_alg_id: RAINBOWIIICIRCUMZENITHAL_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::RainbowIiiCircumzenithal),
};

const RAINBOWIIICOMPRESSED_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-rainbowiiicompressed.der")),
};

/// rainbowiiicompressed signatures
pub static RAINBOWIIICOMPRESSED: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RAINBOWIIICOMPRESSED_ID,
    signature_alg_id: RAINBOWIIICOMPRESSED_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::RainbowIiiCompressed),
};

const RAINBOWVCLASSIC_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-rainbowvclassic.der")),
};

/// rainbowvclassic signatures
pub static RAINBOWVCLASSIC: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RAINBOWVCLASSIC_ID,
    signature_alg_id: RAINBOWVCLASSIC_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::RainbowVClassic),
};

const RAINBOWVCIRCUMZENITHAL_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-rainbowvcircumzenithal.der")),
};

/// rainbowvcircumzenithal signatures
pub static RAINBOWVCIRCUMZENITHAL: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RAINBOWVCIRCUMZENITHAL_ID,
    signature_alg_id: RAINBOWVCIRCUMZENITHAL_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::RainbowVCircumzenithal),
};

const RAINBOWVCOMPRESSED_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-rainbowvcompressed.der")),
};

/// rainbowvcompressed signatures
pub static RAINBOWVCOMPRESSED: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RAINBOWVCOMPRESSED_ID,
    signature_alg_id: RAINBOWVCOMPRESSED_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::RainbowVCompressed),
};

const SPHINCSHARAKA128FSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsharaka128fsimple.der")),
};

/// sphincsharaka128fsimple signatures
pub static SPHINCSHARAKA128FSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSHARAKA128FSIMPLE_ID,
    signature_alg_id: SPHINCSHARAKA128FSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsHaraka128fSimple),
};

const SPHINCSHARAKA128FROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsharaka128frobust.der")),
};

/// sphincsharaka128frobust signatures
pub static SPHINCSHARAKA128FROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSHARAKA128FROBUST_ID,
    signature_alg_id: SPHINCSHARAKA128FROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsHaraka128fRobust),
};

const SPHINCSHARAKA128SSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsharaka128ssimple.der")),
};

/// sphincsharaka128ssimple signatures
pub static SPHINCSHARAKA128SSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSHARAKA128SSIMPLE_ID,
    signature_alg_id: SPHINCSHARAKA128SSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsHaraka128sSimple),
};

const SPHINCSHARAKA128SROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsharaka128srobust.der")),
};

/// sphincsharaka128srobust signatures
pub static SPHINCSHARAKA128SROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSHARAKA128SROBUST_ID,
    signature_alg_id: SPHINCSHARAKA128SROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsHaraka128sRobust),
};

const SPHINCSHARAKA192FSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsharaka192fsimple.der")),
};

/// sphincsharaka192fsimple signatures
pub static SPHINCSHARAKA192FSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSHARAKA192FSIMPLE_ID,
    signature_alg_id: SPHINCSHARAKA192FSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsHaraka192fSimple),
};

const SPHINCSHARAKA192FROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsharaka192frobust.der")),
};

/// sphincsharaka192frobust signatures
pub static SPHINCSHARAKA192FROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSHARAKA192FROBUST_ID,
    signature_alg_id: SPHINCSHARAKA192FROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsHaraka192fRobust),
};

const SPHINCSHARAKA192SSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsharaka192ssimple.der")),
};

/// sphincsharaka192ssimple signatures
pub static SPHINCSHARAKA192SSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSHARAKA192SSIMPLE_ID,
    signature_alg_id: SPHINCSHARAKA192SSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsHaraka192sSimple),
};

const SPHINCSHARAKA192SROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsharaka192srobust.der")),
};

/// sphincsharaka192srobust signatures
pub static SPHINCSHARAKA192SROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSHARAKA192SROBUST_ID,
    signature_alg_id: SPHINCSHARAKA192SROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsHaraka192sRobust),
};

const SPHINCSHARAKA256FSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsharaka256fsimple.der")),
};

/// sphincsharaka256fsimple signatures
pub static SPHINCSHARAKA256FSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSHARAKA256FSIMPLE_ID,
    signature_alg_id: SPHINCSHARAKA256FSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsHaraka256fSimple),
};

const SPHINCSHARAKA256FROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsharaka256frobust.der")),
};

/// sphincsharaka256frobust signatures
pub static SPHINCSHARAKA256FROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSHARAKA256FROBUST_ID,
    signature_alg_id: SPHINCSHARAKA256FROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsHaraka256fRobust),
};

const SPHINCSHARAKA256SSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsharaka256ssimple.der")),
};

/// sphincsharaka256ssimple signatures
pub static SPHINCSHARAKA256SSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSHARAKA256SSIMPLE_ID,
    signature_alg_id: SPHINCSHARAKA256SSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsHaraka256sSimple),
};

const SPHINCSHARAKA256SROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsharaka256srobust.der")),
};

/// sphincsharaka256srobust signatures
pub static SPHINCSHARAKA256SROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSHARAKA256SROBUST_ID,
    signature_alg_id: SPHINCSHARAKA256SROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsHaraka256sRobust),
};

const SPHINCSSHA256128FSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256128fsimple.der")),
};

/// sphincssha256128fsimple signatures
pub static SPHINCSSHA256128FSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256128FSIMPLE_ID,
    signature_alg_id: SPHINCSSHA256128FSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256128fSimple),
};

const SPHINCSSHA256128FROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256128frobust.der")),
};

/// sphincssha256128frobust signatures
pub static SPHINCSSHA256128FROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256128FROBUST_ID,
    signature_alg_id: SPHINCSSHA256128FROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256128fRobust),
};

const SPHINCSSHA256128SSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256128ssimple.der")),
};

/// sphincssha256128ssimple signatures
pub static SPHINCSSHA256128SSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256128SSIMPLE_ID,
    signature_alg_id: SPHINCSSHA256128SSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256128sSimple),
};

const SPHINCSSHA256128SROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256128srobust.der")),
};

/// sphincssha256128srobust signatures
pub static SPHINCSSHA256128SROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256128SROBUST_ID,
    signature_alg_id: SPHINCSSHA256128SROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256128sRobust),
};

const SPHINCSSHA256192FSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256192fsimple.der")),
};

/// sphincssha256192fsimple signatures
pub static SPHINCSSHA256192FSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256192FSIMPLE_ID,
    signature_alg_id: SPHINCSSHA256192FSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256192fSimple),
};

const SPHINCSSHA256192FROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256192frobust.der")),
};

/// sphincssha256192frobust signatures
pub static SPHINCSSHA256192FROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256192FROBUST_ID,
    signature_alg_id: SPHINCSSHA256192FROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256192fRobust),
};

const SPHINCSSHA256192SSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256192ssimple.der")),
};

/// sphincssha256192ssimple signatures
pub static SPHINCSSHA256192SSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256192SSIMPLE_ID,
    signature_alg_id: SPHINCSSHA256192SSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256192sSimple),
};

const SPHINCSSHA256192SROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256192srobust.der")),
};

/// sphincssha256192srobust signatures
pub static SPHINCSSHA256192SROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256192SROBUST_ID,
    signature_alg_id: SPHINCSSHA256192SROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256192sRobust),
};

const SPHINCSSHA256256FSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256256fsimple.der")),
};

/// sphincssha256256fsimple signatures
pub static SPHINCSSHA256256FSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256256FSIMPLE_ID,
    signature_alg_id: SPHINCSSHA256256FSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256256fSimple),
};

const SPHINCSSHA256256FROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256256frobust.der")),
};

/// sphincssha256256frobust signatures
pub static SPHINCSSHA256256FROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256256FROBUST_ID,
    signature_alg_id: SPHINCSSHA256256FROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256256fRobust),
};

const SPHINCSSHA256256SSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256256ssimple.der")),
};

/// sphincssha256256ssimple signatures
pub static SPHINCSSHA256256SSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256256SSIMPLE_ID,
    signature_alg_id: SPHINCSSHA256256SSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256256sSimple),
};

const SPHINCSSHA256256SROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256256srobust.der")),
};

/// sphincssha256256srobust signatures
pub static SPHINCSSHA256256SROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256256SROBUST_ID,
    signature_alg_id: SPHINCSSHA256256SROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256256sRobust),
};

const SPHINCSSHAKE256128FSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsshake256128fsimple.der")),
};

/// sphincsshake256128fsimple signatures
pub static SPHINCSSHAKE256128FSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHAKE256128FSIMPLE_ID,
    signature_alg_id: SPHINCSSHAKE256128FSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsShake256128fSimple),
};

const SPHINCSSHAKE256128FROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsshake256128frobust.der")),
};

/// sphincsshake256128frobust signatures
pub static SPHINCSSHAKE256128FROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHAKE256128FROBUST_ID,
    signature_alg_id: SPHINCSSHAKE256128FROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsShake256128fRobust),
};

const SPHINCSSHAKE256128SSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsshake256128ssimple.der")),
};

/// sphincsshake256128ssimple signatures
pub static SPHINCSSHAKE256128SSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHAKE256128SSIMPLE_ID,
    signature_alg_id: SPHINCSSHAKE256128SSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsShake256128sSimple),
};

const SPHINCSSHAKE256128SROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsshake256128srobust.der")),
};

/// sphincsshake256128srobust signatures
pub static SPHINCSSHAKE256128SROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHAKE256128SROBUST_ID,
    signature_alg_id: SPHINCSSHAKE256128SROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsShake256128sRobust),
};

const SPHINCSSHAKE256192FSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsshake256192fsimple.der")),
};

/// sphincsshake256192fsimple signatures
pub static SPHINCSSHAKE256192FSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHAKE256192FSIMPLE_ID,
    signature_alg_id: SPHINCSSHAKE256192FSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsShake256192fSimple),
};

const SPHINCSSHAKE256192FROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsshake256192frobust.der")),
};

/// sphincsshake256192frobust signatures
pub static SPHINCSSHAKE256192FROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHAKE256192FROBUST_ID,
    signature_alg_id: SPHINCSSHAKE256192FROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsShake256192fRobust),
};

const SPHINCSSHAKE256192SSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsshake256192ssimple.der")),
};

/// sphincsshake256192ssimple signatures
pub static SPHINCSSHAKE256192SSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHAKE256192SSIMPLE_ID,
    signature_alg_id: SPHINCSSHAKE256192SSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsShake256192sSimple),
};

const SPHINCSSHAKE256192SROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsshake256192srobust.der")),
};

/// sphincsshake256192srobust signatures
pub static SPHINCSSHAKE256192SROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHAKE256192SROBUST_ID,
    signature_alg_id: SPHINCSSHAKE256192SROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsShake256192sRobust),
};

const SPHINCSSHAKE256256FSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsshake256256fsimple.der")),
};

/// sphincsshake256256fsimple signatures
pub static SPHINCSSHAKE256256FSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHAKE256256FSIMPLE_ID,
    signature_alg_id: SPHINCSSHAKE256256FSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsShake256256fSimple),
};

const SPHINCSSHAKE256256FROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsshake256256frobust.der")),
};

/// sphincsshake256256frobust signatures
pub static SPHINCSSHAKE256256FROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHAKE256256FROBUST_ID,
    signature_alg_id: SPHINCSSHAKE256256FROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsShake256256fRobust),
};

const SPHINCSSHAKE256256SSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsshake256256ssimple.der")),
};

/// sphincsshake256256ssimple signatures
pub static SPHINCSSHAKE256256SSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHAKE256256SSIMPLE_ID,
    signature_alg_id: SPHINCSSHAKE256256SSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsShake256256sSimple),
};

const SPHINCSSHAKE256256SROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincsshake256256srobust.der")),
};

/// sphincsshake256256srobust signatures
pub static SPHINCSSHAKE256256SROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHAKE256256SROBUST_ID,
    signature_alg_id: SPHINCSSHAKE256256SROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsShake256256sRobust),
};
