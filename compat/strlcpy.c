/*
 * strlcpy.c - strlcpy() replacement
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2006 Rémi Denis-Courmont.                              *
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

#include <stddef.h>
#include <string.h>

extern size_t strlcpy (char *tgt, const char *src, size_t bufsize)
{
	size_t length;

	for (length = 0; *src && (length < bufsize); length++)
		*tgt++ = *src++;

	if (bufsize)
		*tgt = '\0';

	while (*src++)
		length++;

	return length;
}
