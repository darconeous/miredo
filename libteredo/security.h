/*
 * security.h - helpers for security-related stuff
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license.         *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               *
 *  See the GNU General Public License for more details.               *
 *                                                                     *
 *  You should have received a copy of the GNU General Public License  *
 *  along with this program; if not, you can get it from:              *
 *  http://www.gnu.org/copyleft/gpl.html                               *
 ***********************************************************************/

#ifndef __LIBTEREDO_SECURITY_H
# define __LIBTEREDO_SECURITY_H

struct in6_addr;

# ifdef __cplusplus
extern "C" {
# endif

#define LIBTEREDO_NONCE_LEN 8
#define LIBTEREDO_HMAC_LEN 22

int teredo_init_nonce_generator (void);
void teredo_deinit_nonce_generator (void);
void teredo_generate_nonce (unsigned char *b);

int teredo_init_HMAC (void);
void teredo_deinit_HMAC (void);
int teredo_generate_HMAC (time_t now, const struct in6_addr *src,
                          const struct in6_addr *dst, uint8_t *restrict hash);
int teredo_compare_HMAC (time_t now, const struct in6_addr *src,
                         const struct in6_addr *dst, const uint8_t *hash);

# ifdef __cplusplus
}
# endif
#endif
