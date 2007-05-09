/*
 * teredo.c - Libteredo global tests
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
#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>
#include <netinet/in.h>

#include "teredo.h"
#include "tunnel.h"

static teredo_tunnel *tunnel;


int main (void)
{
	int val;

#ifdef MIREDO_TEREDO_CLIENT
	val = teredo_startup (true);
	assert (val == 0);
	teredo_cleanup (true);
#else
	val = teredo_startup (true);
	assert (val == -1);
#endif

	val = teredo_startup (false);
	assert (val == 0);

	tunnel = teredo_create (0, 0);
	assert (tunnel != NULL);
	teredo_destroy (tunnel);

	teredo_cleanup (false);
	return 0;
}
