match group {

        NamedGroup::Kyber512 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Kyber768 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber768).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Kyber1024 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber1024).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece348864 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece348864).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece348864f => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece348864f).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece460896 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece460896).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece460896f => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece460896f).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece6688128 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece6688128).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece6688128f => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece6688128f).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece6960119 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece6960119).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece6960119f => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece6960119f).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece8192128 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece8192128).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece8192128f => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece8192128f).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Lightsaber => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Lightsaber).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Saber => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Saber).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Firesaber => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Firesaber).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruHps2048509 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruHps2048509).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruHps2048677 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruHps2048677).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruHps4096821 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruHps4096821).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruHrss701 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruHrss701).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruPrimeNtrulpr653 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeNtrulpr653).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruPrimeNtrulpr761 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeNtrulpr761).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruPrimeNtrulpr857 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeNtrulpr857).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruPrimeSntrup653 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeSntrup653).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruPrimeSntrup761 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeSntrup761).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruPrimeSntrup857 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeSntrup857).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FrodoKem640Aes => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem640Aes).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FrodoKem640Shake => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem640Shake).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FrodoKem976Aes => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem976Aes).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FrodoKem976Shake => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem976Shake).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FrodoKem1344Aes => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem1344Aes).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FrodoKem1344Shake => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem1344Shake).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP434 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP434).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP434Compressed => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP434Compressed).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP503 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP503).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP503Compressed => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP503Compressed).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP610 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP610).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP610Compressed => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP610Compressed).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP751 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP751).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP751Compressed => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP751Compressed).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::BikeL1Fo => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::BikeL1Fo).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::BikeL3Fo => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::BikeL3Fo).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Hqc128 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Hqc128).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Hqc192 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Hqc192).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Hqc256 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Hqc256).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },
_ => None,
}