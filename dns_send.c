/* dns_send.c -- send DNS messages
 *
 * Copyright Dean Scarff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#include <resolv.h>
#include "rpl_nameser.h"

#if defined(HAVE_RES_SEND) && HAVE_DECL__RES_NSADDR_LIST
#define USE_RES_SEND 1
#else
#define USE_RES_SEND 0
#endif

#include <fcntl.h>
#include <sys/select.h>

#include "hope.h"

/* Check that `dst' looks like a response to `msg'. */
static int
check_response(const unsigned char *dst, const unsigned char *msg)
{
	uint32_t qhead = ns_get32(msg);
	uint32_t anshead = ns_get32(dst);

	// mask out RCODE and Z (including RA bit)
	qhead &= 0xffffff00;
	anshead &= 0xffffff00; // sometimes RA gets set spuriously

	anshead ^= 0x00008000; // flip QR bit

	return qhead == anshead;
}

#if !USE_RES_SEND
/* Like `dns_send_addr', but always use UDP. */
static unsigned char *
dns_send_addr_udp(unsigned char *dst, const unsigned char *msg, size_t msglen,
    struct sockaddr_in *addr)
{
	int sd;
	sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	hope(-1 != sd, strerror(errno));

	int err = fcntl(sd, F_SETFL, fcntl(sd, F_GETFL) | O_NONBLOCK);
	err = connect(sd, (struct sockaddr *)addr, sizeof(*addr));
	hope(-1 != err, strerror(errno));

	struct timeval timeout;
	fd_set fds;
	FD_ZERO(&fds);
	for (int i = 0; i < RES_DFLRETRY; ++i) {
		ssize_t length;
		length = send(sd, msg, msglen, 0);
		hope(-1 != length, strerror(errno));

		FD_SET(sd, &fds);
		timeout.tv_sec = RES_TIMEOUT;
		timeout.tv_usec = 0;
		do
			err = select(sd + 1, &fds, NULL, NULL, &timeout);
		while (0 > err && EAGAIN == errno);
		hope(0 <= err, strerror(errno));
		if (0 == err)
			continue;

		length = recv(sd, dst, NS_PACKETSZ, 0);
		hope(-1 != length, strerror(errno));
		hope(check_response(dst, msg), "response did not match query");

		close(sd);
		return dst + length;
	}
	close(sd);
	nohope("request timed out");

	return NULL;
}

/* Like `dns_send_addr', but always use TCP. */
static unsigned char *
dns_send_addr_tcp(unsigned char *dst, const unsigned char *msg, size_t msglen,
    struct sockaddr_in *addr)
{
	int sd;
	sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	hope(-1 != sd, strerror(errno));

	int err;
	err = connect(sd, (struct sockaddr *)addr, sizeof(*addr));
	hope(-1 != err, strerror(errno));

	ssize_t length;
	uint16_t length_header = htons(msglen);
	length = write(sd, &length_header, 2);
	hope(-1 != length, strerror(errno));
	length = write(sd, msg, msglen);
	hope(-1 != length, strerror(errno));

	length = read(sd, &length_header, 2);
	hope(2 == length, "couldn't read length field");
	length_header = ntohs(length_header);
	if (length_header > NS_PACKETSZ)
		length_header = NS_PACKETSZ;
	length = read(sd, dst, length_header);
	hope(-1 != length, strerror(errno));
	hope(length_header == length, "truncated response");
	hope(check_response(dst, msg), "response did not match query");

	close(sd);
	return dst + length;
}
#endif /* USE_RES_SEND */

// See dns_send.h
unsigned char *
dns_send_addr(unsigned char *dst, const unsigned char *msg, size_t msglen,
    struct sockaddr_in *addr, int use_tcp)
{
	dst[0] = ~msg[0];
	dst[1] = ~msg[1];
	memset(dst + 2, 0xff, NS_HFIXEDSZ - 2);
#if USE_RES_SEND
	// fill dst so we can detect if it has been written to
	res_init();
	struct sockaddr_in save = _res.nsaddr_list[0];
	int save_count = _res.nscount;
	_res.nsaddr_list[0] = *addr;
	_res.nscount = 1;
	if (use_tcp)
		_res.options |= RES_USEVC;
	int i = res_send(msg, msglen, dst, NS_PACKETSZ);

	// Some resolvers are erroneously reporting ETIMEDOUT even
	// with a valid response.  We'll accept a packet providing it
	// looks like a response has been written to the dst buffer.
	if (-1 == i && (ETIMEDOUT == errno || ECONNREFUSED == errno) &&
	    check_response(dst, msg) && 0xff != dst[NS_HFIXEDSZ - 1])
		return dst + NS_HFIXEDSZ;

	_res.nsaddr_list[0] = save;
	_res.nscount = save_count;
	hope(i != -1, strerror(errno));
	return dst + i;
#else  /* !USE_RES_SEND */
	if (use_tcp)
		return dns_send_addr_tcp(dst, msg, msglen, addr);
	else
		return dns_send_addr_udp(dst, msg, msglen, addr);
#endif /* !USE_RES_SEND */
}
