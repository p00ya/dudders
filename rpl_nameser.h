/* rpl_nameser.h -- replacement nameserver declarations
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

#ifndef RPL_NAMESER_H
# define RPL_NAMESER_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#if !HAVE_DECL_NS_MAXDNAME
# define NS_MAXDNAME 255 /* RFC3696 p. 4 */
#endif

#if !HAVE_DECL_NS_MAXCDNAME
# define NS_MAXCDNAME 255 /* RFC1035 */
#endif

#if !HAVE_DECL_NS_MAXLABEL
# define NS_MAXLABEL 63 /* RFC1035 */
#endif

#if !HAVE_DECL_NS_HFIXEDSZ
# define NS_HFIXEDSZ 12 /* RFC1035 4.1.1 */
#endif

#if !HAVE_DECL_NS_PACKETSZ
# define NS_PACKETSZ 512 /* RFC1035 2.3.4 */
#endif

#if !HAVE_DECL_NS_DEFAULTPORT
# define NS_DEFAULTPORT 53 /* RFC1035 4.2.1 */
#endif

#if !HAVE_DECL_NS_CMPRSFLGS
# define NS_CMPRSFLGS 0xc0 /* RFC1035 4.1.4 */
#endif

#if !HAVE_DECL_NS_SIG_EXPIR
# define NS_SIG_EXPIR 8 /* RFC2535 4.1.5 */
#endif

#if !HAVE_DECL_NS_SIG_SIGNED
# define NS_SIG_SIGNED 12 /* RFC2535 4.1.5 */
#endif

#if !HAVE_DECL_NS_SIG_FOOT
# define NS_SIG_FOOT 16 /* RFC2535 4.1.6 */
#endif

#if !HAVE_DECL_NS_ALG_MD5RSA
# define NS_ALG_MD5RSA 1 /* RFC2535 3.2 */
#endif

#if !HAVE_DECL_NS_MD5RSA_MAX_BASE64
# define NS_MD5RSA_MAX_BASE64 684 /* RFC2537 2 */
#endif

#if !HAVE_DECLS_NS_O_QUERY
# define ns_o_query 0 /* RFC1035 4.1.1 */
#endif

#if !HAVE_DECL_NS_C_IN
# define ns_c_in 1 /* RFC1035 3.2.4 */
#endif

#if !HAVE_DECL_NS_T_SOA
# define ns_t_soa 6 /* RFC1035 3.2.2 */
#endif

#if !HAVE_DECL_NS_T_SOA
# define ns_t_sig 24 /* RFC2535 4 */
#endif

#endif /* !defined(RPL_NAMESER_H) */
