/* test-parse_pk.c
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

#include <stdint.h>
#include <stdio.h>

#include "hope.h"
#include "test.h"

static
void
test_cb(enum pk_field_key field, const char *data)
{
	if (PKFK_PUBLIC_EXPONENT == field) {
		uint32_t x = 0;
		decode64((char *) &x, data);
		fprintf(stderr,
		    "PublicExponent should be 0x10001: 0x%x\n", x);
	}
}

int
main()
{
	FILE *f = fopen(keyfile(), "r");
	if (!f)
		return -1;
	parse_pk_file(f, &test_cb);
	fclose(f);
	return 0;
}
