// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include <oqs/kem_hqc.h>

#if defined(OQS_ENABLE_KEM_hqc_192)

OQS_KEM *OQS_KEM_hqc_192_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = OQS_KEM_alg_hqc_192;
	kem->alg_version = "hqc-submission_2020-10-01 via https://github.com/jschanck/package-pqclean/tree/9c4e109d/hqc";

	kem->claimed_nist_level = 3;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_hqc_192_length_public_key;
	kem->length_secret_key = OQS_KEM_hqc_192_length_secret_key;
	kem->length_ciphertext = OQS_KEM_hqc_192_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_hqc_192_length_shared_secret;

	kem->keypair = OQS_KEM_hqc_192_keypair;
	kem->encaps = OQS_KEM_hqc_192_encaps;
	kem->decaps = OQS_KEM_hqc_192_decaps;

	return kem;
}

extern int PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
extern int PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
extern int PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#if defined(OQS_ENABLE_KEM_hqc_192_avx2)
extern int PQCLEAN_HQCRMRS192_AVX2_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
extern int PQCLEAN_HQCRMRS192_AVX2_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
extern int PQCLEAN_HQCRMRS192_AVX2_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
#endif

OQS_API OQS_STATUS OQS_KEM_hqc_192_keypair(uint8_t *public_key, uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_hqc_192_avx2)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI1) && OQS_CPU_has_extension(OQS_CPU_EXT_PCLMULQDQ)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_HQCRMRS192_AVX2_crypto_kem_keypair(public_key, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_keypair(public_key, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_keypair(public_key, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_hqc_192_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
#if defined(OQS_ENABLE_KEM_hqc_192_avx2)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI1) && OQS_CPU_has_extension(OQS_CPU_EXT_PCLMULQDQ)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_HQCRMRS192_AVX2_crypto_kem_enc(ciphertext, shared_secret, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_enc(ciphertext, shared_secret, public_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_enc(ciphertext, shared_secret, public_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_hqc_192_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_hqc_192_avx2)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI1) && OQS_CPU_has_extension(OQS_CPU_EXT_PCLMULQDQ)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_HQCRMRS192_AVX2_crypto_kem_dec(shared_secret, ciphertext, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_dec(shared_secret, ciphertext, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_dec(shared_secret, ciphertext, secret_key);
#endif
}

#endif
