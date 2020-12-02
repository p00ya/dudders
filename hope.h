/* hope.h -- runtime diagnostics
 *
 * Copyright Dean Scarff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 */

#ifndef HOPE_H
#define HOPE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Program invocation name for diagnostic output. */
extern const char *program_invocation;

/* If the macro `NDEBUG' is not defined, `FL' expands to a string
 * literal consisting of of the file and line number in the current
 * source file.  If `NDEBUG' is defined, `FL' expands to a NULL
 * pointer. */
#ifndef NDEBUG
#define IFL , __FILE__, __LINE__
#define FL , const char *, unsigned
#else
#define IFL
#define FL
#endif

/* Helper function, use the `hope' and `nohope' macros instead. */
void hope_(const char *FL);

/* Helper function, use the `hope2' and `nohope2' macros instead. */
void hope2_(const char *, const char *FL);

/* Helper function, use the `xmalloc' macro instead. */
void *xmalloc_(size_t FL);

/* If the scalar `expr' is true, do nothing.  Otherwise, write an
 * error message to the standard error stream and exit with non-zero
 * status.  If the const char * `explain' is non-NULL, print `explain'
 * with the error message.  If `explain' is NULL, then `expr' is
 * printed instead. */
#define hope(expr, explain)                                                   \
	((void)((expr) ? 0 : (hope_((explain) ? (explain) : #expr IFL))))

/* Like `hope', but assume error unconditonally, and evaluate to 0. */
#define nohope(explain) (hope_((explain) ? (explain) : "error" IFL), 0)

/* If the scalar `expr' is true, do nothing.  Otherwise, write an
 * error message `strerr' to the standard error stream and exit with
 * non-zero status.  If the const char * `explain' is non-NULL, print
 * `explain' with the error message.  If `explain' is NULL, then it is
 * omitted.  It is appropriate to use the return value of the standard
 * library's `strerror(errno)' for the `strerr' parameter. */
#define hope2(expr, explain, strerr)                                          \
	((void)((expr) ? 0                                                    \
	               : hope2_((explain) ? (explain) : #expr, strerr IFL)))

/* Like `hope2', but assume error unconditionally, and evaluate to
 * 0. */
#define nohope2(explain, strerr)                                              \
	(hope2_((explain) ? (explain) : "error", strerr IFL), 0)

/* Like standard `malloc', but hope that the memory is actually
 * allocated. */
#define xmalloc(size) xmalloc_(size IFL)

#endif /* !defined(HOPE_H) */
