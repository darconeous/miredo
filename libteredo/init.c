/*
 * init.c
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2005-2006 Rémi Denis-Courmont.                         *
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

#include <stdbool.h>
#include <gettext.h>

#include <assert.h>

#include <inttypes.h>
#include "security.h"
#include "tunnel.h"


int teredo_startup (bool use_client)
{
	(void)bindtextdomain (PACKAGE_NAME, LOCALEDIR);

#ifdef MIREDO_TEREDO_CLIENT
	(void)use_client;
#else
	if (use_client)
		return -1;
#endif

	if (teredo_init_HMAC () == 0)
		return 0;
	return -1;
}


void teredo_cleanup (bool use_client)
{
	(void)use_client;
#ifndef MIREDO_TEREDO_CLIENT
	assert (!use_client);
#endif

	teredo_deinit_HMAC ();
}
