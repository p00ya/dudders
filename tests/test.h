/* test.h -- test data
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

#ifndef TEST_H
# define TEST_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

# ifdef NDEBUG
#  undef NDEBUG
# endif

# include <stdint.h>
# include <stdlib.h>

/* Like abort(3), but expression evaluates as 0. */
# define iabort() (abort(), 0)

/* Filename of dnssec-keygen format private key file. */
const char *keyfile();

/* The modulus from `keyfile'. */
extern const unsigned char test_modulus[];

/* The length in octets of `test_modulus'. */
size_t test_modulus_size;

/* The host-order footprint of `TEST_PRIVKEY'. */
uint16_t test_footprint;

/* A DNS query constructed to include a SIG(0) RR, but without the
 * actual SIG(0) signature field. */
extern const unsigned char test_query[];

/* Length of `test_query' (the offset of the SIG(0) signature). */
size_t test_query_size;

/* The offset of the start of the SIG(0) RR in `test_query'. */
size_t test_query_sig0_offset;

/* The offset of the key's footprint in `test_query'. */
size_t test_query_footprint_offset;

/* The payload to be hashed for the signature operation. */
extern const unsigned char test_hash_payload[];

/* Length of `test_hash_payload'. */
size_t test_hash_payload_size;

/* The correct PKCS#1/RSAMD5 signature for `test_query' according to the
 * reference implementation. */
extern const unsigned char test_signature[];

#endif /* !defined(TEST_H) */
