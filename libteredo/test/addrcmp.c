/*
 * addrcmp.c - Libteredo addresses comparison regression tests
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2005 Remi Denis-Courmont.                            *
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
#else
# include <inttypes.h>
#endif
#include <sys/types.h>
#include <netinet/in.h>

#include <libteredo/teredo.h>

int main (void)
{
	union teredo_addr a1, a2;

	memcpy (&a1, "\x3f\xfe\x83\x1f\x8a\xc3\x9d\xdd"
	             "\x80\x00\xf2\x27\x75\x3c\x67\x74", 16);

	memcpy (&a2, "\x3f\xfe\x83\x1f\x8a\xc3\x9d\xdd"
	             "\x80\x00\xf2\x27\x75\x3c\x67\x75", 16);
	if (t6cmp (&a1, &a2) == 0)
		return 1;
	
	memcpy (&a2, "\x3f\xfe\x83\x1f\x8a\xc3\x9d\xdd"
	             "\x80\x00\xf2\x28\x75\x3c\x67\x74", 16);
	if (t6cmp (&a1, &a2) == 0)
		return 1;

	memcpy (&a2, &a1, 16);
	if (t6cmp (&a1, &a2) != 0)
		return 1;

	return 0;
}
