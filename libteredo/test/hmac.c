/*
 * hmac.c - Libteredo HMAC tests
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2005 Rémi Denis-Courmont.                              *
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

#include "teredo.h"
#include "relay.h"
#include "security.h"

int main (void)
{
	struct in6_addr src, dst;
	uint8_t hmac[LIBTEREDO_HMAC_LEN];

	puts ("Checking libteredo HMAC...");
	puts ("That should take about 30 seconds...");
	assert (libteredo_preinit (true) == 0);

	memcpy (&src, "\x3f\xfe\x83\x1f\x8a\xc3\x9d\xdd"
			"\x80\x00\xf2\x27\x75\x3c\x67\x74", 16);
	memcpy (&dst, "\x20\x02\xc0\x00\x02\x42\x12\x42"
			"\x13\x43\x14\x44\x15\x45\x16\x46", 16);
	if (!GenerateHMAC (&src, &dst, hmac))
		return -1;
	if (!CompareHMAC (&src, &dst, hmac))
		return -1;

	/* retry after first run */
	if (!GenerateHMAC (&dst, &src, hmac))
		return -1;
	if (!CompareHMAC (&dst, &src, hmac))
		return -1;
	if (CompareHMAC (&src, &dst, hmac))
		/* mixed addresses : should fail */
		return -1;

	hmac[4] ^= 0x40;
	if (CompareHMAC (&dst, &src, hmac))
		/* altered hash : should fail */
		return -1;

	hmac[4] ^= 0x40;
	if (!CompareHMAC (&dst, &src, hmac))
		return -1;

	sleep (3);
	if (!CompareHMAC (&dst, &src, hmac))
		return -1;
	/* should still be valid after 3 seconds */

	sleep (28);
	/* should no longer be valid after 31 seconds */
	if (CompareHMAC (&dst, &src, hmac))
		return -1;

	libteredo_terminate (true);

	return 0;
}
