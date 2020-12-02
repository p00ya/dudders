/* dns_send.h -- send DNS messages
 *
 * Copyright Dean Scarff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 */

#ifndef DNSSEND_H
#define DNSSEND_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Send the `length' octets of the DNS message `msg' to the nameserver
 * at `addr'.  The response, if any, is written to `dst', and the
 * minimum address after the response is returned.  The buffer `dst'
 * must be sufficiently long to receive a DNS message.  If `use_tcp'
 * is non-zero, use TCP/IP to send the message, otherwise use UDP.
 *
 * The `dst' buffer should have a capacity of at least NS_PACKETSZ
 * octets. */
unsigned char *dns_send_addr(unsigned char *dst, const unsigned char *msg,
    size_t length, struct sockaddr_in *addr, int use_tcp);

#endif /* !defined(DNSSEND_H) */
