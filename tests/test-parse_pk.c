/* test-parse_pk.c
 *
 * Copyright Dean Scarff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 */

#include "parse_pk.h"

#include <stdint.h>
#include <stdio.h>

#include "hope.h"
#include "test.h"

static void
test_cb(enum pk_field_key field, const char *data)
{
	if (PKFK_PUBLIC_EXPONENT == field) {
		uint32_t x = 0;
		decode64((char *)&x, data);
		fprintf(stderr, "PublicExponent should be 0x10001: 0x%x\n", x);
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
