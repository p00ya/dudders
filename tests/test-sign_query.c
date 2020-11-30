/* test-dnsupdate.c -- Write DNS UPDATE + SIG(0) message
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

#include "dnsupdate.h"

#include <stdio.h>
#include <string.h>

#include "crypt.h"
#include "hope.h"
#include "test.h"

int
main(int argc, char *argv[])
{
	crypt_init();
	FILE *f = fopen(keyfile(), "r");
	crypt_load_key(f);
	fclose(f);
	size_t correct_size = test_query_size + test_modulus_size;
	char *buf = (char *)calloc(test_query_size + crypt_sign_length(), 1);
	char *ref = (char *)calloc(correct_size, 1);
	memcpy(buf, test_query, test_query_size);
	memcpy(ref, test_query, test_query_size);
	memcpy(ref + test_query_size, test_signature, test_modulus_size);

	(0x52 == buf[test_query_footprint_offset] &&
	    0x6e == buf[test_query_footprint_offset + 1]) ||
	    iabort();

	char *end = (char *)sign_query((unsigned char *)buf + test_query_size,
	    buf, buf + test_query_sig0_offset);
	(end - buf == correct_size) || iabort();
	int d = memcmp(buf, ref, correct_size);
	if (0 != d) {
		char *fme = xmalloc(strlen(argv[0]) + 5);
		char *fref = xmalloc(strlen(argv[0]) + 5);
		strcpy(fme, argv[0]);
		strcat(fme, ".out");
		strcpy(fref, argv[0]);
		strcat(fref, ".ref");
		printf("FAIL.\nWriting calculated message to %s,\n"
		       "reference message to %s\n",
		    fme, fref);
		FILE *f = fopen(fme, "w");
		f || iabort();
		fwrite(buf, end - buf, 1, f);
		f || iabort();
		f = fopen(fref, "w");
		f || iabort();
		fwrite(ref, correct_size, 1, f);
		fclose(f);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
