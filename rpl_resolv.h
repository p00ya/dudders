/* rpl_resolv.h -- replacement resolver functions
 *
 * Copyright Dean Scarff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 */

#ifndef RPL_RESOLV_H
#define RPL_RESOLV_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_DN_SKIPNAME
#undef dn_skipname
int dn_skipname(const unsigned char *comp_dn, const unsigned char *eom);
#endif

#ifndef HAVE_DN_COMP
#undef dn_comp
int dn_comp(const char *exp_dn, unsigned char *comp_dn, int length,
    unsigned char **dnptrs, unsigned char **lastdnptr);
#endif

#ifndef HAVE_P_RCODE
#undef p_rcode
extern const char *rcode_strings[];
static inline const char *
p_rcode(unsigned char rcode)
{
	return rcode_strings[(rcode > 5) ? 5 : rcode];
}
#endif

#if !HAVE_DECL_RES_TIMEOUT
#define RES_TIMEOUT 5
#endif

#if !HAVE_DECL_RES_DFLRETRY
#define RES_DFLRETRY 2
#endif

#endif /* !defined(RPL_RESOLV_H) */
