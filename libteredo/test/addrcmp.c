/*
 * addrcmp.c - Libteredo addresses comparison regression tests
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

#include <string.h>

#if HAVE_STDINT_H
# include <stdint.h> /* Mac OS X needs that */
#endif
#include <sys/types.h>
#include <netinet/in.h>

#include <libteredo/teredo.h>

int main (void)
{
	struct in6_addr a1;

	memcpy (&a1, "\x20\x01\x00\x00\xc0\x00\x02\x01"
	             "\x80\x00\xcf\xc6\x3f\xff\xfd\x74", 16);

	if ((IN6_TEREDO_PORT (&a1) != htons (12345))
	 || (IN6_TEREDO_IPV4 (&a1) != htonl (0xc000028b))
	 || (IN6_TEREDO_SERVER (&a1) != htonl (0xc0000201))
	 || (!IN6_IS_TEREDO_ADDR_CONE (&a1))
	 || (!IN6_MATCHES_TEREDO_CLIENT (&a1, htonl (0xc000028b), htons (12345)))
	 || IN6_MATCHES_TEREDO_CLIENT (&a1, htonl (0xc000028b), htons (12346))
	 || IN6_MATCHES_TEREDO_CLIENT (&a1, htonl (0xc000028c), htons (12345)))
			return 1;

	return 0;
}
