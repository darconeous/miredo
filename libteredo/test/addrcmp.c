/*
 * addrcmp.c - Libteredo addresses comparison regression tests
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

#include <string.h>

#if HAVE_STDINT_H
# include <stdint.h> /* Mac OS X needs that */
#endif
#include <sys/types.h>
#include <netinet/in.h>

#include <libteredo/teredo.h>

int main (void)
{
	union teredo_addr a1, a2;

	memcpy (&a1, "\x20\x01\x00\x00\xc0\x00\x02\x01"
	             "\x80\x00\xf2\x27\x3f\xff\xfd\x74", 16);

	memcpy (&a2, "\x20\x01\x00\x00\xc0\x00\x02\x01"
	             "\x80\x00\xf2\x27\x3f\xff\xfd\x75", 16);
	if (t6cmp (&a1, &a2) == 0)
		return 1;
	
	memcpy (&a2, "\x20\x01\x00\x00\xc0\x00\x02\x01"
	             "\x80\x00\xf2\x28\x3f\xff\xfd\x74", 16);
	if (t6cmp (&a1, &a2) == 0)
		return 1;

	memcpy (&a2, &a1, 16);
	if (t6cmp (&a1, &a2) != 0)
		return 1;

	return 0;
}
