/* test-crypt.c
 *
 * Copyright Dean Scarff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 */

#include "crypt.h"

#include <stdio.h>
#include <string.h>

#include "hope.h"
#include "test.h"

int
main()
{
	crypt_init();
	FILE *f = fopen(keyfile(), "r");
	crypt_load_key(f);
	fclose(f);
	fprintf(stderr, "Key length should be %u: %u\n",
	    (unsigned)test_modulus_size, (unsigned)crypt_sign_length());
	test_modulus_size == crypt_sign_length() || iabort();
	fprintf(stderr, "Footprint should be 0x%hx: 0x%hx\n", test_footprint,
	    crypt_footprint());
	test_footprint == crypt_footprint() || iabort();

	unsigned char *buf = xmalloc(test_modulus_size);
	unsigned char *end = (unsigned char *)crypt_sign(
	    (char *)buf, (char *)test_hash_payload, test_hash_payload_size);
	fprintf(stderr, "Signature should be %u octets: %u\n",
	    (unsigned)test_modulus_size, (unsigned)(end - buf));
	(test_modulus_size == end - buf) || iabort();

	int d = memcmp(buf, test_signature, test_modulus_size);
	fprintf(stderr, "Signature difference should be 0: %i\n", d);
	!d || iabort();
	free(buf);
	crypt_finish();
	return 0;
}
