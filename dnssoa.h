/* dnssoa.h -- DNS SOA request parsing
 *
 * Copyright Dean Scarff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 */

#ifndef DNSSOA_H
#define DNSSOA_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

/* Extract the zone and the zone master server (MNAME) from a DNS SOA
 * response `response' to `zone' and `mname' respectively.  The
 * response should have length `rlen'.  If the header doesn't look
 * right or a SOA can't be found, set the first character of `mname'
 * to 0 but do nothing else.  Hope there's no trouble. */
void dnssoa_parse(
    char *zone, char *mname, const unsigned char *response, size_t rlen);

#endif /* !defined(DNSSOA_H) */
