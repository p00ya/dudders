/* crypt_gcrypt.c -- libgcrypt (of GnuPG) crypto interface
 *
 * Copyright 2007 Dean Scarff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You
 * may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#include "hope.h"
#include "parse_pk.h"

/* Footprint in host byte-order. */
static uint16_t footprint;

/* Modulus length in octets. */
static size_t modulus_length;

/* RSA key sexp "(private-key (rsa ...))". */
static gcry_sexp_t rsa_key;

static int ksizes[PKFK_SIZE]; // key field sizes
static char *kparts[PKFK_SIZE]; // key field values

/* Hope an expression `e' of type `gcry_error_t' has non-error
 * status. */
#define CHECK(e) {					\
		gcry_error_t err = e;			\
		hope(!err, gcry_strerror(err));		\
	}

// See crypt.h
void
crypt_init()
{
	gcry_check_version(GCRYPT_VERSION);
	// Secure memory is somewhat overrated: we're usually reading
	// a private key in over stdio's unsecure buffers.
	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_INIT_SECMEM, 2048, 0);
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#ifndef NDEBUG
	hope(!gcry_md_test_algo(GCRY_MD_MD5), "libgcrypt's MD5 unavailable");
	hope(!gcry_pk_test_algo(GCRY_AC_RSA), "libgcrypt's RSA unavailable");
	size_t usage = GCRY_PK_USAGE_SIGN;
	hope(!gcry_pk_algo_info(GCRY_AC_RSA, GCRYCTL_TEST_ALGO,
		NULL, &usage), "libgcrypt RSA can't sign");
#endif
}

// See crypt.h
void
crypt_finish()
{
	gcry_sexp_release(rsa_key);
}

/* Store `data' to the appropriate `ksizes' and 'kparts' members. */
static
void
load_line(enum pk_field_key field, const char *data)
{
	assert(PKFK_SIZE > field);
	char *buf = gcry_malloc_secure(decode64_length(data));
	hope(buf, "Out of memory.");
	size_t octet_count = decode64(buf, data);

	if (PKFK_MODULUS == field) {
		footprint = (uint16_t)(buf[octet_count - 3]) << 8;
		footprint |= (unsigned char)buf[octet_count - 2];
		modulus_length = octet_count;
	}
	ksizes[field] = octet_count;
	kparts[field] = buf;
}

// See crypt.h
void
crypt_load_key(FILE *privkey)
{
	parse_pk_file(privkey, &load_line);
	// the primes are swapped and thus the CRT coefficient is invalid
	gcry_mpi_t u, p, q;
	gcry_mpi_scan(&q, GCRYMPI_FMT_USG,
	    kparts[PKFK_PRIME1], ksizes[PKFK_PRIME1], NULL);
	gcry_mpi_scan(&p, GCRYMPI_FMT_USG,
	    kparts[PKFK_PRIME2], ksizes[PKFK_PRIME2], NULL);
	hope(0 < gcry_mpi_cmp(q, p), "key primes out of order");
	u = gcry_mpi_new(ksizes[PKFK_COEFFICIENT] * CHAR_BIT);
	gcry_mpi_invm(u, p, q);
	gcry_sexp_build(&rsa_key, NULL,
	    "(private-key (rsa "
	    "(n %b) (e %b) (d %b) (p %m) (q %m) (u %m)))",
	    ksizes[PKFK_MODULUS], kparts[PKFK_MODULUS],
	    ksizes[PKFK_PUBLIC_EXPONENT], kparts[PKFK_PUBLIC_EXPONENT],
	    ksizes[PKFK_PRIVATE_EXPONENT], kparts[PKFK_PRIVATE_EXPONENT],
	    p, q, u);

	CHECK(gcry_pk_testkey(rsa_key));
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
	return modulus_length;
}

// See crypt.h
char *
crypt_sign(char *dst, const char *src, size_t length)
{
	gcry_sexp_t data, sig, s;
	gcry_mpi_t sig_mpi;
	size_t written;

	size_t digest_length = gcry_md_get_algo_dlen(GCRY_MD_MD5);
	unsigned char *digest = malloc(digest_length);
	gcry_md_hash_buffer(GCRY_MD_MD5, digest, src, length);
	CHECK(gcry_sexp_build(&data, NULL,
	    "(data (flags pkcs1 no-blinding) (hash md5 %b))",
		digest_length, digest));
	CHECK(gcry_pk_sign(&sig, data, rsa_key));

	s = gcry_sexp_find_token(sig, "s", 0);
	assert(s);
	sig_mpi = gcry_sexp_nth_mpi(s, 1, GCRYMPI_FMT_USG);
	assert(NULL != sig_mpi);

	CHECK(gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)dst,
		modulus_length, &written, sig_mpi));
	gcry_mpi_release(sig_mpi);
	gcry_sexp_release(s);
	gcry_sexp_release(sig);
	gcry_sexp_release(data);
	return dst + written;
}
