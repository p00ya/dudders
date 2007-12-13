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

#include "hope.h"

unsigned char *
dns_send_addr(unsigned char *dst, const unsigned char *msg, size_t msglen,
    struct sockaddr_in *addr)
{
#if defined(HAVE_RES_SEND) && HAVE_DECL__RES_NSADDR_LIST
	res_init();
	struct sockaddr_in save = _res.nsaddr_list[0];
	_res.nsaddr_list[0] = *addr;
	int i = res_send(msg, msglen, dst, NS_PACKETSZ);
	_res.nsaddr_list[0] = save;
	hope(i != -1, strerror(errno));
	return dst + i;
#else
	int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	hope(-1 != sd, strerror(errno));
	ssize_t send = sendto(sd, msg, msglen, 0,
	    (struct sockaddr *) addr, sizeof(*addr));
	hope(-1 != send, strerror(errno));
	uint16_t transaction_id = *((uint16_t *)msg);

	enum {
		RES_RETRY = 4, // times to retry sending
		RES_RETRANS = 4, // seconds to sleep between retries
	};
	for (int i = 0; i < RES_RETRY; sleep(RES_RETRANS), ++i) {
		struct sockaddr_in from_addr;
		socklen_t addr_length = sizeof(from_addr);
		ssize_t recv_length;
		recv_length = recvfrom(sd, dst, NS_PACKETSZ, 0,
		    (struct sockaddr *) &from_addr, &addr_length);

		if (-1 == recv_length && EAGAIN == errno)
			continue;
		hope(-1 != recv_length, strerror(errno));
		hope(transaction_id == *((uint16_t *)dst),
		    "erroneous transaction id");

		close(sd);
		return dst + recv_length;
	}
	close(sd);
	return NULL;
#endif
}

unsigned char *
dns_send(unsigned char *dst, const unsigned char *msg, size_t msglen)
{
#ifdef HAVE_RES_SEND
	int i = res_send(msg, msglen, dst, NS_PACKETSZ);
	hope(-1 != i, strerror(errno));
	return dst + i;
#elif HAVE_DECL__RES_NSADDR_LIST
	res_init();
	struct sockaddr_in *addr = _res.nsaddr_list;
	return dns_send_addr(dst, msg, msglen, addr);
#endif
}
