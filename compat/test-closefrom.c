/*
 * test-closefrom.c - closefrom() replacement test
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2007 Rémi Denis-Courmont.                              *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license, or (at  *
 *  your option) any later version.                                    *
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#undef NDEBUG
#include <assert.h>

#include <unistd.h>
#include <errno.h>

int main (void)
{
	int fd[2];
	int val;

	val = pipe (fd);
	assert (val == 0);
	assert (fd[0] >= 3);

	closefrom (3);

	val = close (3);
	assert ((val == -1) && (errno = EBADF));
	return 0;
}
