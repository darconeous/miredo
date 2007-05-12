/*
 * clock.c - Libteredo clock tests
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2007 Rémi Denis-Courmont.                              *
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#undef NDEBUG
#include <assert.h>
#include <sched.h>

#include "clock.h"

int main (void)
{
	int val = teredo_clock_create ();
	assert (val == 0);

	teredo_clock_t start = teredo_clock (), now;

	do
	{
		now = teredo_clock ();
		sched_yield ();
	}
	while (now == start);

	assert (now > start);

	teredo_clock_destroy ();
	return 0;
}
