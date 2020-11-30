/* test-decode64.c
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

#include "parse_pk.h"

#include <stdio.h>
#include <stdlib.h>

#include "hope.h"
#include "test.h"

int
main()
{
	const char clear[] = { 0xde, 0xad, 0xbe, 0xef, 0xde, 0xed };
	const char *encoded_1 = "3q2+797t";
	const char *encoded_2 = "3q2+794=";
	const char *encoded_3 = "3q2+7w==";
	unsigned z;
	char *buf = xmalloc(7);

	memset(buf, 0xaa, 7);
	z = decode64(buf, encoded_1);
	fprintf(stderr, "Decrypted length should be 6: %u\n", z);
	(6 == z) || iabort();
	int d = memcmp(clear, buf, 6);
	fprintf(stderr, "Difference should be 0: %i\n", d);
	(!d && '\xaa' == buf[6]) || iabort();

	memset(buf, 0xaa, 7);
	z = decode64(buf, encoded_2);
	fprintf(stderr, "Decrypted length should be 5: %u\n", z);
	(5 == z) || iabort();
	d = memcmp(clear, buf, 5);
	fprintf(stderr, "Difference should be 0: %i\n", d);
	(!d && '\xaa' == buf[5]) || iabort();


	memset(buf, 0xaa, 7);
	z = decode64(buf, encoded_3);
	fprintf(stderr, "Decrypted length should be 4: %u\n", z);
	(4 == z) || iabort();
	d = memcmp(clear, buf, 4);
	fprintf(stderr, "Difference should be 0: %i\n", d);
	(!d && '\xaa' == buf[4]) || iabort();

	return 0;
}
