/*
 * hmac.c - Libteredo HMAC tests
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2005-2006 Rémi Denis-Courmont.                         *
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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#undef NDEBUG
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#if HAVE_STDINT_H
# include <stdint.h> /* Mac OS X needs that */
#endif
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h> /* sleep () */
#include <sys/select.h> /* fd_set */

#include "teredo.h"
#include "tunnel.h"
#include "security.h"

int main (void)
{
	struct in6_addr src, dst;
	uint8_t hmac[LIBTEREDO_HMAC_LEN];
	const uint32_t stamp = 0x12345678;

	if (teredo_init_random () || teredo_init_HMAC ())
		return 1;
	teredo_deinit_random ();

	memcpy (&src, "\x20\x01\x00\x00\x8a\xc3\x9d\xdd"
			"\x80\x00\xf2\x27\x75\x3c\x67\x74", 16);
	memcpy (&dst, "\x20\x02\xc0\x00\x02\x42\x12\x42"
			"\x13\x43\x14\x44\x15\x45\x16\x46", 16);
	teredo_get_pinghash (stamp, &src, &dst, hmac);
	if (teredo_verify_pinghash (stamp, &src, &dst, hmac))
		return 1;

	/* retry after first run */
	teredo_get_pinghash (stamp, &dst, &src, hmac);
	if (teredo_verify_pinghash (stamp, &dst, &src, hmac))
		return 1;
	if (teredo_verify_pinghash (stamp, &src, &dst, hmac) == 0)
		/* mixed addresses : should fail */
		return 1;

	for (unsigned i = 0; i < sizeof (hmac); i++)
	{
		hmac[i] ^= 0x40;
		if (teredo_verify_pinghash (stamp, &dst, &src, hmac) == 0)
			/* altered hash : should fail */
			return 1;
		hmac[i] ^= 0x40;
	}

	for (unsigned delay = 0; delay < 30; delay++)
		/* should still be valid after <30 seconds */
		if (teredo_verify_pinghash (stamp + delay, &dst, &src, hmac))
			return 1;

	/* should no longer be valid after 30 seconds, or in the past */
	if ((teredo_verify_pinghash (stamp + 30, &dst, &src, hmac) == 0)
	 || (teredo_verify_pinghash (stamp + 31, &dst, &src, hmac) == 0)
	 || (teredo_verify_pinghash (stamp - 1, &dst, &src, hmac) == 0))
		return 1;

	teredo_deinit_HMAC ();
	return 0;
}
