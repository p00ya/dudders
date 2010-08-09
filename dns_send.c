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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif
#include "rpl_nameser.h"
#include <resolv.h>

#include <sys/select.h>
#include <fcntl.h>

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

unsigned char *
dns_send_addr(unsigned char *dst, const unsigned char *msg, size_t msglen,
    struct sockaddr_in *addr)
{
#if defined(HAVE_RES_SEND) && HAVE_DECL__RES_NSADDR_LIST
	// fill dst so we can detect if it has been written to
	dst[0] = ~msg[0];
	dst[1] = ~msg[1];
	memset(dst + 2, 0xff, NS_HFIXEDSZ - 2);
	res_init();
	struct sockaddr_in save = _res.nsaddr_list[0];
	int save_count = _res.nscount;
	_res.nsaddr_list[0] = *addr;
	_res.nscount = 1;
	int i = res_send(msg, msglen, dst, NS_PACKETSZ);

	// Some resolvers are erroneously reporting ETIMEDOUT even
	// with a valid response.  We'll accept a packet providing it
	// looks like a response has been written to the dst buffer.
	if (-1 == i && ETIMEDOUT == errno &&
	    check_response(dst, msg) &&
	    0xff != dst[NS_HFIXEDSZ - 1])
		return dst + NS_HFIXEDSZ;

	_res.nsaddr_list[0] = save;
	_res.nscount = save_count;
	hope(i != -1, strerror(errno));
	return dst + i;
#else /* !defined(HAVE_RES_SEND) || !HAVE_DECL__RES_NSADDR_LIST */
	int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	hope(-1 != sd, strerror(errno));

	int err = fcntl(sd, F_SETFL, fcntl(sd, F_GETFL) | O_NONBLOCK);
	hope(-1 != err, strerror(errno));

	struct timeval timeout;
	fd_set fds;
	FD_ZERO(&fds);
	for (int i = 0; i < RES_DFLRETRY; ++i) {
		ssize_t send = sendto(sd, msg, msglen, 0,
		    (struct sockaddr *) addr, sizeof(*addr));
		hope(-1 != send, strerror(errno));

		FD_SET(sd, &fds);
		timeout.tv_sec = RES_TIMEOUT;
		timeout.tv_usec = 0;
		do
			err = select(sd + 1, &fds, NULL, NULL, &timeout);
		while (0 > err && EAGAIN == errno);
		hope(0 <= err, strerror(errno));
		if (0 == err)
			continue;

		struct sockaddr_in from_addr;
		socklen_t addr_length = sizeof(from_addr);
		ssize_t recv_length;
		recv_length = recvfrom(sd, dst, NS_PACKETSZ, 0,
		    (struct sockaddr *) &from_addr, &addr_length);

		hope(-1 != recv_length, strerror(errno));
		hope(check_response(dst, msg),
		    "response did not match query");

		close(sd);
		return dst + recv_length;
	}
	close(sd);
	nohope("request timed out");

	return NULL;
#endif /* !defined(HAVE_RES_SEND) || !HAVE_DECL__RES_NSADDR_LIST */
}
