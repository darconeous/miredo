/*
 * init.c
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2005 Rémi Denis-Courmont.                            *
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

#include <stdbool.h>
#include <gettext.h>

#ifdef HAVE_STDINT_H
# include <stdint.h>
#else
# include <inttypes.h>
#endif
#include <assert.h>

#ifdef MIREDO_TEREDO_CLIENT
# include "security.h"
#endif

/**
 * Initializes libteredo. That function must be called before any other
 * libteredo functions. It can safely be called multiple times and is
 * thread-safe. If the process is to be chrooted(), it should be called
 * before chroot().
 *
 * @param use_client true if libteredo is to be used in client-mode
 *
 * @return 0 on success, -1 on failure.
 * -1 is also returned when use_client is true while libteredo was
 *  compiled without client support.
 */
int libteredo_preinit (bool use_client)
{
	bindtextdomain (PACKAGE_NAME, LOCALEDIR);

	if (use_client)
	{
#ifdef MIREDO_TEREDO_CLIENT
		if (InitHMAC ())
		{
			if (libteredo_init_nonce_generator () == 0)
				return 0;
			DeinitHMAC();
		}
#endif
		return -1;
	}
	return 0;
}

/**
 * Releases resources allocated with libteredo_preinit().
 * Should be called as many times as libteredo_preinit() was called.
 * Thread-safe.
 *
 * @param use_client true if the matching libteredo_preinit call
 * had the use_client parameter set.
 */
void libteredo_terminate (bool use_client)
{
#ifdef MIREDO_TEREDO_CLIENT
	if (use_client)
	{
		DeinitHMAC ();
		libteredo_deinit_nonce_generator ();
	}
#else
	assert (!use_client);
#endif
}
