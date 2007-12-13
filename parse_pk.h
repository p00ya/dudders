/* parse_pk.h -- parse a dnssec-keygen RSA/MD5 private key
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

#ifndef PARSE_PK_H
# define PARSE_PK_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

# include <stdio.h>
# include <string.h>
# include <stddef.h>

/* RSA private key fields.  These numbers are guaranteed to be 0-based
 * and contiguous, suitable for a lookup table, but have no reliable
 * order, except that PKFK_SIZE is the greatest value. */
enum pk_field_key {
	PKFK_MODULUS,
	PKFK_PUBLIC_EXPONENT,
	PKFK_PRIVATE_EXPONENT,
	PKFK_PRIME1,
	PKFK_PRIME2,
	PKFK_COEFFICIENT,
	PKFK_EXPONENT1,
	PKFK_EXPONENT2,
	PKFK_SIZE
};

/* Callback function signature for parsing. */
typedef void (parse_pk_cbf)(enum pk_field_key, const char *data);

/* Number of octets required to decode the MIME base-64 sequence `str'
 * into. */
inline
size_t
decode64_length(const char *str)
{
	return 3 + strlen(str) * 3 / 4;
}

/* Decode the MIME base-64 sequence `str' (NUL-terminated) to a
 * big-endian octet sequence in `dst'.  Hope `str' is valid (multiple
 * of 4 octets length using padding, no uncoded symbols).  `dst' must
 * be large enough to hold `decode64_length(str)' octets.  Return
 * value is the number of decoded octets. */
size_t decode64(char *dst, const char *str);

/* Parse the dnssec-keygen(8) private key file from `fp', calling `cb'
 * for each line whose key is recognised.  The parameters to `cb' are
 * an encoding of the field key and the field data. */
void parse_pk_file(FILE *fp, parse_pk_cbf *cb);

#endif /* !defined(PARSE_PK_H) */
