/* dudders.c -- Use SIG(0) key to renew a dynamic DNS domain
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

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <netdb.h>
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#include <resolv.h>
#include "rpl_nameser.h"

#include <libgen.h>
#include <unistd.h>

#include "crypt.h"
#include "dns_send.h"
#include "dnssoa.h"
#include "dnsupdate.h"
#include "hope.h"

enum
{
	ARGV_INVOCATION = 0,
	// *after* options parsing:
	ARGV_DOMAIN = 0,
	ARGV_TTL = 1,
	ARGV_ADDRESS = 2,
	ARGV_END = 3
};

static void
usage()
{
	printf("%s\n\nReport bugs to <%s>.\n",
	    "Usage:\n"
	    "dudders [-T] [-k KEYFILE] [-n KEYNAME] [-m MNAME] [-z ZONE]"
	    " DOMAIN TTL ADDRESS\n\n"
	    "Sign a DNS UPDATE of DOMAIN to ADDRESS with KEYFILE.",
	    PACKAGE_BUGREPORT);
}

static void
version()
{
	printf("%s\n\n%s\n", PACKAGE_STRING, "Copyright Dean Scarff");
}

static const char *key_filename; // filename for inference
static FILE *keyfile;            // stream to parse key from
static char *keyname;            // key owner name
static const char *domain;       // domain name
static uint32_t ttl;             // TTL for new RR
static struct in_addr addr;      // address for DOMAIN's new A RR
static char *zone;               // DOMAIN's zone
static char *mname;              // ZONE's primary name server
struct sockaddr_in ns_addr;      // MNAME's IP address
static int use_tcp;              // true to use TCP/IP

/* Try to infer the key name from a dnssec-keygen(8) style private key
 * file's name in `filename', and copy the result to `keyname'.
 * Return 0 on failure. */
static void
infer_keyname(const char *filename)
{
	const char *base = basename((char *)filename);
	hope2(base, filename, strerror(errno));
	hope2('K' == *base, filename, "not a dnssec-keygen(8) filename");
	char *p = strchr(base++, '+');
	hope2(p, filename, "not a dnssec-keygen(8) filename");
	size_t namelen = p - base - 1; // remove trailing .
	keyname = xmalloc(namelen + 1);
	strncpy(keyname, base, namelen);
	keyname[namelen] = 0;
}

/* Parse options from the command line. */
void
parse_options(int argc, char **argv)
{
	int c;
	while (-1 != (c = getopt(argc, argv, "Tk:n:m:z:"))) {
		switch (c) {
		case 'T':
			use_tcp = 1;
			break;
		case 'k':
			key_filename = optarg;
			keyfile = fopen(optarg, "r");
			hope2(keyfile, optarg, strerror(errno));
			break;
		case 'n':
			keyname = optarg;
			break;
		case 'm':
			mname = optarg;
			break;
		case 'z':
			zone = optarg;
			break;
		case '?':
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}
}

/* Set `zone' and `mname' to the zone and primary name server of
 * `domain' respectively. */
void
get_zone()
{
	int err;
	unsigned char *qbuf = xmalloc(NS_PACKETSZ);   // query
	unsigned char *ansbuf = xmalloc(NS_PACKETSZ); // answer

	// get zone and primary name server.  We search up the domain
	// tree until a SOA is found.  This is the zone (see RFC1034
	// 4.2p4).
	char *zonebuf = xmalloc(NS_MAXDNAME);
	char *mnamebuf = xmalloc(NS_MAXDNAME);
	for (const char *xzone = domain;; ++xzone) {
		memset(ansbuf, 0, NS_HFIXEDSZ); // helps dnssoa_parse
		err = res_query(xzone, ns_c_in, ns_t_soa, ansbuf, NS_PACKETSZ);
		hope(-1 != err || NO_RECOVERY != h_errno, hstrerror(h_errno));
		if (0 < err) {
			dnssoa_parse(zonebuf, mnamebuf, ansbuf, err);
			break;
		} else if (TRY_AGAIN == h_errno || NO_DATA == h_errno) {
			// an authority may still be present despite
			// these errors
			dnssoa_parse(zonebuf, mnamebuf, ansbuf, NS_PACKETSZ);
			if (*zonebuf && *mnamebuf)
				break;
		}
		xzone = strchr(xzone, '.');
		hope2(xzone && xzone[1], domain, "no zone record");
	}
	free(qbuf);
	free(ansbuf);
	if (zone)
		free(zonebuf);
	else
		zone = zonebuf;
	if (mname)
		free(mnamebuf);
	else
		mname = mnamebuf;
}

/* Set `ns_addr' to the IP address of `mname'. */
void
get_ns_addr()
{
	struct hostent *ns_hostent = gethostbyname(mname);
	hope2(ns_hostent && AF_INET == ns_hostent->h_addrtype &&
	          sizeof(struct in_addr) == ns_hostent->h_length,
	    "Cannot find primary name server", hstrerror(h_errno));

	ns_addr.sin_family = AF_INET;
	ns_addr.sin_port = htons(NS_DEFAULTPORT);
	memcpy(&(ns_addr.sin_addr), ns_hostent->h_addr_list[0],
	    ns_hostent->h_length);
	int err = inet_aton(ns_hostent->h_addr_list[0], &(ns_addr.sin_addr));
	hope(-1 != err, strerror(errno));
}

int
main(int argc, char *argv[])
{
	int err;
	program_invocation = argv[ARGV_INVOCATION];
	for (int i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "--help"))
			return usage(), EXIT_SUCCESS;
		if (!strcmp(argv[i], "--version"))
			return version(), EXIT_SUCCESS;
	}
	parse_options(argc, argv);
	if (!keyfile)
		keyfile = stdin;
	if (!keyname && key_filename)
		infer_keyname(key_filename);
	if (!keyname) {
		fprintf(stderr, "%s: %s\n", program_invocation,
		    "keyname neither explicitly provided nor inferable");
		return usage(), EXIT_FAILURE;
	}
	hope2(NS_MAXDNAME >= strlen(keyname), keyname, "keyname too long");

	argc -= optind;
	argv += optind;
	if (ARGV_END != argc)
		return usage(), EXIT_FAILURE;
	// get domain
	domain = argv[ARGV_DOMAIN];
	hope2(NS_MAXDNAME >= strlen(domain), domain, "domain too long");
	// parse ttl
	err = sscanf(argv[ARGV_TTL], "%" SCNi32, &ttl);
	hope2(1 == err, argv[ARGV_TTL], "TTL not an unsigned 32-bit integer");
	// parse address
	err = inet_aton(argv[ARGV_ADDRESS], &addr);
	hope2(1 == err, argv[ARGV_ADDRESS], strerror(errno));

	// get master server
	if (!mname || !zone)
		get_zone();
	else {
		hope2(NS_MAXDNAME >= strlen(mname), mname,
		    "master domain too long");
		hope2(
		    NS_MAXDNAME >= strlen(zone), zone, "zone domain too long");
	}
	hope(mname && zone, "could not find zone");
	get_ns_addr();

	// initialise key
	srand(time(0));
	crypt_init();
	atexit(&(crypt_finish));
	crypt_load_key(keyfile);
	fclose(keyfile);

	unsigned char *dst;
	unsigned char *qbuf = xmalloc(NS_PACKETSZ);   // query
	unsigned char *ansbuf = xmalloc(NS_PACKETSZ); // answer

	dst = wire_dnsupdate_message(qbuf, zone, argv[ARGV_DOMAIN], addr, ttl);
	dst = sign_dnsupdate_message(dst, qbuf, keyname);

	// send update request
	dst = dns_send_addr(ansbuf, qbuf, dst - qbuf, &ns_addr, use_tcp);
	free(qbuf);
	check_dnsupdate_response(ansbuf, dst - ansbuf);
	free(ansbuf);

	return EXIT_SUCCESS;
}
