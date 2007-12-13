/* rpl_resolv.h -- replacement resolver functions
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

#ifndef RPL_RESOLV_H
# define RPL_RESOLV_H

# ifdef HAVE_CONFIG_H
#  include "config.h"
# endif

# include <stdint.h>

# ifndef HAVE_DN_SKIPNAME
#  undef dn_skipname
int dn_skipname(const unsigned char *comp_dn, const unsigned char *eom);
# endif

# ifndef HAVE_DN_COMP
#  undef dn_comp
int dn_comp(const char *exp_dn, unsigned char *comp_dn, int length,
    unsigned char **dnptrs, unsigned char **lastdnptr);
# endif

# ifndef HAVE_NS_GET16
#  undef ns_get16
static inline
uint16_t
ns_get16(const unsigned char *src)
{
#  ifdef WORDS_BIGENDIAN
	return *((uint16_t *) src);
#  else
	uint16_t x = (uint16_t)(*src) << 8;
	x |= (uint16_t)(src[1]);
	return x;
#  endif /* !defined(WORDS_BIGENDIAN) */
}
# endif

# ifndef HAVE_NS_PUT16
#  undef ns_put16
static inline
void
ns_put16(uint16_t src, unsigned char *dst)
{
	dst[1] = (unsigned char)src;
	dst[0] = (unsigned char)(src >> 8);
}
# endif  /* !defined(HAVE_NS_PUT16) */

# ifndef HAVE_NS_PUT32
#  undef ns_put32
static inline
void
ns_put32(uint32_t src, unsigned char *dst)
{
	dst[3] = (unsigned char)src;
	src >>= 8;
	dst[2] = (unsigned char)src;
	src >>= 8;
	dst[1] = (unsigned char)src;
	src >>= 8;
	dst[0] = (unsigned char)src;
}
# endif /* !defined(HAVE_NS_PUT32) */

#ifndef HAVE_P_RCODE
# undef p_rcode
extern const char *rcode_strings[];
static inline
const char *
p_rcode(unsigned char rcode)
{
	return rcode_strings[(rcode > 5) ? 5 : rcode];
}
#endif

#endif /* !defined(RPL_RESOLV_H) */
