# dudders

## Users

Dudders is a utility for updating DNS records.  It points a domain
name to a given IP address, using the RFC2136 DNS UPDATE protocol and
a SIG(0) signature.  It is designed with embedded systems in mind.

This has several implications for users:

 - you can't use it to do all the things DNS UPDATE can do,
 - it will error and exit rather than dealing with problems;
 - it will fit and work on your embedded device!

For a general purpose DNS UPDATE utility where space is not a concern,
use ISC's nsupdate, which is distributed with BIND.  Other free clients
with similar functionality include ddclient, ez-ipupdate, updatedd,
ipupdate, and dnssec-tools's ifup-dyndns.

The ISC BIND 9 Administrator Reference Manual contains instructions
for configuring your zone's DNS server to support a SIG(0) update,
under the DNSSEC section.

For instructions on how to invoke the program, consult the dudders(8)
manual page, which is built by configure.

With some poetic license, dudders spells "Dynamically Updating DNS
Duly Embracing RSA SIG(0)".

## License

Dudders is licensed under the Apache License, Version 2.0, the text of
which is included in the file COPYING.

## Installation

A POSIX-like standard C library is expected, complete with resolver.
The BSD, uClibc, and glibc libraries should all work.

### Cryptography dependencies

An external library is required by dudders for cryptography.
The following packages are supported to provide crypto libraries:

 - openssl: The OpenSSL project's libcrypto
 - gcrypt: The GnuPG spinoff crypto library libgcrypt

Specify the crypto library to use at build time by calling configure
with:

```
--with-crypto=PACKAGE
```

Alternatively, dudders can build support for both the libraries as
"plugins".  By calling configure with:

```
--with-crypto=dl --with-dlcrypto=LIST
```
dudders will try to dynamically load each of the plugins using
dlopen(3), in the order specified by LIST, until one works.  All
packages in LIST must be available at compile-time and at least one at
runtime.

For each of the specified plugins, a shared library will be installed
in the plugin directory (`/usr/local/lib/dudders` by default).  To run
dudders from the build directory (without running `make install`), you
will need to add `.libs` in the build directory to dlopen's search
paths.  The mechanism for this depends on the system's implementation
of dlopen, but on Linux one can run something like:

```
LD_LIBRARY_PATH=.libs:$LD_LIBRARY_PATH ./dudders
```

### Other build options

By default, the program is built with a meagre amount of debugging
information.  To make it leaner, call configure with:

```
CFLAGS="-DNDEBUG -Osize"
```

Consult the INSTALL file for additional instructions on building and
installing dudders.

## Contact

Visit the dudders homepage at <https://github.com/p00ya/dudders>.
