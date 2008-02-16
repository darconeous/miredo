/*
 * teredo.c - Libteredo global tests
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
	void *pval;

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

	// 192.0.2.1 can never be assigned to any host
	tunnel = teredo_create (htonl (0xC0000201), 0);
	assert (tunnel == NULL);

	tunnel = teredo_create (0, 0);
	assert (tunnel != NULL);

	val = teredo_set_relay_mode (tunnel);
	assert (val == 0);

	teredo_run (tunnel);
	teredo_run (tunnel);

	val = teredo_set_prefix (tunnel, htonl (0xff020000));
	val = teredo_set_prefix (tunnel, htonl (TEREDO_PREFIX));
	assert (val == 0);

	val = teredo_set_cone_flag (tunnel, false);
	assert (val == 0);
	val = teredo_set_cone_flag (tunnel, true);
	assert (val == 0);
	teredo_set_cone_ignore (tunnel, true);

	pval = teredo_set_privdata (tunnel, tunnel);
	assert (pval == NULL);
	pval = teredo_get_privdata (tunnel);
	assert (pval == tunnel);

	teredo_set_recv_callback (tunnel, NULL);
	teredo_set_icmpv6_callback (tunnel, NULL);
	teredo_set_state_cb (tunnel, NULL, NULL);

	teredo_destroy (tunnel);

	teredo_cleanup (false);
	return 0;
}
