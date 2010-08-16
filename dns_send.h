/* dnssend.c -- send DNS messages
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

#ifndef DNSSEND_H
# define DNSSEND_H

# ifdef HAVE_CONFIG_H
#  include "config.h"
# endif

/* Send the `length' octets of the DNS message `msg' to the nameserver
 * at `addr'.  The response, if any, is written to `dst', and the
 * minimum address after the response is returned.  The buffer `dst'
 * must be sufficiently long to receive a DNS message.  If `use_tcp'
 * is non-zero, use TCP/IP to send the message, otherwise use UDP. */
unsigned char *dns_send_addr(unsigned char *dst,
    const unsigned char *msg, size_t length,
    struct sockaddr_in *addr, int use_tcp);

#endif /* !defined(DNSSEND_H) */
