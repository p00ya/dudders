/* crypt_openssl.c -- OpenSSL crypto interface
 *
 * Copyright Dean Scarff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdint.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>

#include "hope.h"
#include "parse_pk.h"

/* Footprint in host byte-order. */
static uint16_t footprint;

/* OpenSSL key handle. */
static RSA *rsa_key;

/** Key parameters read in through `load_line'. */
static BIGNUM *kparts[PKFK_SIZE];

// See crypt.h
void
crypt_init()
{
	ERR_load_crypto_strings();
}

// See crypt.h
void
crypt_finish()
{
	RSA_free(rsa_key);
}

/* Decode and store `data' into `kparts'. */
static void
load_line(enum pk_field_key field, const char *data)
{
	unsigned char *buf = xmalloc(decode64_length(data));
	size_t octet_count = decode64((char *)buf, data);
	BIGNUM *bn = BN_bin2bn(buf, octet_count, NULL);
	free(buf);
	kparts[field] = bn;
	switch (field) {
	case PKFK_MODULUS:
		footprint = (uint16_t)(buf[octet_count - 3]) << 8;
		footprint |= buf[octet_count - 2];
		break;
	default:
		break;
	}
}

/** Derives the CRT parameters from `kparts' and stores them to `rsa_key'. */
static void
derive_crt()
{
	assert(kparts[PKFK_PUBLIC_EXPONENT]);
	assert(kparts[PKFK_PRIME1]);
	assert(kparts[PKFK_PRIME2]);

	BIGNUM *p1 = BN_new(), *q1 = BN_new();
	BN_sub(p1, kparts[PKFK_PRIME1], BN_value_one());
	BN_sub(q1, kparts[PKFK_PRIME2], BN_value_one());

	BN_CTX *bn_ctx = BN_CTX_new();
	BN_mod_inverse(p1, kparts[PKFK_PUBLIC_EXPONENT], p1, bn_ctx);
	BN_mod_inverse(q1, kparts[PKFK_PUBLIC_EXPONENT], q1, bn_ctx);
	BIGNUM *iqmp = BN_mod_inverse(
	    NULL, kparts[PKFK_PRIME2], kparts[PKFK_PRIME1], bn_ctx);
	BN_CTX_free(bn_ctx);

	if (1 != RSA_set0_crt_params(rsa_key, p1, q1, iqmp)) {
		unsigned long err = ERR_get_error();
		nohope2(
		    "loading private key: CRT", ERR_error_string(err, NULL));
	}
}

// See crypt.h
void
crypt_load_key(FILE *privkey)
{
	rsa_key = RSA_new();
	assert(rsa_key);

	parse_pk_file(privkey, &load_line);
	if (1 != RSA_set0_key(rsa_key, kparts[PKFK_MODULUS],
	             kparts[PKFK_PUBLIC_EXPONENT],
	             kparts[PKFK_PRIVATE_EXPONENT])) {
		unsigned long err = ERR_get_error();
		nohope2("loading private key: exponents",
		    ERR_error_string(err, NULL));
	}

	if (1 != RSA_set0_factors(
	             rsa_key, kparts[PKFK_PRIME1], kparts[PKFK_PRIME2])) {
		unsigned long err = ERR_get_error();
		nohope2("loading private key: factors",
		    ERR_error_string(err, NULL));
	}

	derive_crt();


	if (1 != RSA_check_key(rsa_key)) {
		unsigned long err = ERR_get_error();
		nohope2("checking private key", ERR_error_string(err, NULL));
	}
}

// See crypt.h
uint16_t
crypt_footprint()
{
	return footprint;
}

// See crypt.h
size_t
crypt_sign_length()
{
	return (size_t)RSA_size(rsa_key);
}

enum
{
	MD5_LENGTH = 16 // digest length in octets
};

// See crypt.h
char *
crypt_sign(char *dst, const char *src, size_t length)
{
	int err;
	unsigned char digest[MD5_LENGTH];
	MD5((const unsigned char *)src, length, digest);

	unsigned siglen;
	err = RSA_sign(NID_md5, digest, MD5_LENGTH, (unsigned char *)dst,
	    &siglen, rsa_key);
	hope(1 == err, "could not write signature");
	return dst + siglen;
}
