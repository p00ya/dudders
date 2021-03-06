/* hope.c -- runtime diagnostics
 *
 * Copyright Dean Scarff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *program_invocation = "";

#ifndef NDEBUG
#define FL , const char *file, unsigned line
#define PFL() fprintf(stderr, "(From %s:%u)\n", file, line)
#else
#define FL
#define PFL()
#endif

#pragma GCC visibility push(hidden)
void
hope_(const char *e FL)
{
	fprintf(stderr, "%s: %s\n", program_invocation, e);
	PFL();
	exit(EXIT_FAILURE);
}

void
hope2_(const char *e, const char *strerr FL)
{
	fprintf(stderr, "%s: %s: %s\n", program_invocation, e, strerr);
	PFL();
	exit(EXIT_FAILURE);
}

void *
xmalloc_(size_t size FL)
{
	void *p = malloc(size);
	if (!p) {
		fprintf(
		    stderr, "%s: %s\n", program_invocation, strerror(errno));
		PFL();
		exit(EXIT_FAILURE);
	}
	return p;
}
#pragma GCC visibility pop
