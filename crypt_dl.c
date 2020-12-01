/* crypt_dl.c -- dynamically loaded crypto proxy
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
#include "config.h"
#endif

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "hope.h"

static void *dl; // dlopen handle

// Pointers to the module's implementations of the crypt.h functions.
static void (*crypt_init_impl)();
static void (*crypt_finish_impl)();
static void (*crypt_load_key_impl)(FILE *);
static uint16_t (*crypt_footprint_impl)();
static size_t (*crypt_sign_length_impl)();
static char *(*crypt_sign_impl)(char *, const char *, size_t);

/* Return non-zero iff all the impl pointers are set. */
static int
have_all()
{
	return crypt_init_impl && crypt_finish_impl && crypt_load_key_impl &&
	       crypt_footprint_impl && crypt_sign_length_impl &&
	       crypt_sign_impl;
}

/* Set all implementation pointers to NULL. */
static void
reset_all()
{
	crypt_init_impl = NULL;
	crypt_finish_impl = NULL;
	crypt_load_key_impl = NULL;
	crypt_footprint_impl = NULL;
	crypt_sign_length_impl = NULL;
	crypt_sign_impl = NULL;
}

void
crypt_find_module()
{
	const char *modules[CRYPT_DL_COUNT];
#ifdef CRYPT_DL_OPENSSL
	modules[CRYPT_DL_OPENSSL] = PLUGIN_DIR "/crypt_openssl" LT_MODULE_EXT;
#endif
#ifdef CRYPT_DL_GCRYPT
	modules[CRYPT_DL_GCRYPT] = PLUGIN_DIR "/crypt_gcrypt" LT_MODULE_EXT;
#endif
	for (int i = 0; i < CRYPT_DL_COUNT; ++i) {
		dl = dlopen(modules[i], RTLD_LAZY | RTLD_LOCAL);
		if (NULL == dl)
			continue;
		crypt_init_impl = dlsym(dl, "crypt_init");
		crypt_finish_impl = dlsym(dl, "crypt_finish");
		crypt_load_key_impl = dlsym(dl, "crypt_load_key");
		crypt_footprint_impl = dlsym(dl, "crypt_footprint");
		crypt_sign_length_impl = dlsym(dl, "crypt_sign_length");
		crypt_sign_impl = dlsym(dl, "crypt_sign");
		if (!have_all()) {
			reset_all();
			dlclose(dl);
		}
	}
	hope(have_all(), "no useable cryptography library found");
}

// See crypt.h
void
crypt_init()
{
	crypt_find_module();
	(*crypt_init_impl)();
}

void
crypt_finish()
{
	(*crypt_finish_impl)();
	dlclose(dl);
}

void
crypt_load_key(FILE *privkey)
{
	(*crypt_load_key_impl)(privkey);
}

uint16_t
crypt_footprint()
{
	return (*crypt_footprint_impl)();
}

size_t
crypt_sign_length()
{
	return (*crypt_sign_length_impl)();
}

char *
crypt_sign(char *dst, const char *src, size_t length)
{
	return (*crypt_sign_impl)(dst, src, length);
}
