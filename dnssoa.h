/* dnssoa.h -- DNS SOA request parsing
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
