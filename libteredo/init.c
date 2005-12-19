/*
 * init.c
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

#include <stdbool.h>

#ifdef HAVE_STDINT_H
# include <stdint.h>
#else
# include <inttypes.h>
#endif

#ifdef MIREDO_TEREDO_CLIENT
# include "security.h"
#endif

/**
 * Initializes libteredo. That function must be called before any other
 * libteredo functions. It can safely be called multiple times and is
 * thread-safe. If the process is to be chrooted(), it should be called
 * before chroot().
 *
 * @return 0 on success, -1 on failure.
 */
int libteredo_preinit (void)
{
	return 0;
}

/**
 * Performs client-mode specific libteredo initialization.
 * Must be called before any Teredo client is to be created.
 * Thread-safe, can be called multiple times. Should be called
 * before chroot() if it is used.
 *
 * Note that Teredo client-mode relies on libgcrypt. Libgcrypt will
 * be initialized with pthread as a threading package, and without secure
 * memory. If another library used in the same process uses libgcrypt, it
 * must also use pthread, and must not expect secure memory to be provided.
 *
 * @return 0 on success, -1 on failure.
 */
int libteredo_client_preinit (void)
{
#ifdef MIREDO_TEREDO_CLIENT
	return (InitHMAC () && InitNonceGenerator ()) ? 0 : -1;
#else
	return -1;
#endif
}


/**
 * Releases resources allocated with libteredo_preinit() and
 * libteredo_client_preinit(). Should be called as many times as
 * libteredo_preinit() was called. Thread-safe.
 */
void libteredo_terminate (void)
{
#ifdef MIREDO_TEREDO_CLIENT
	DeinitHMAC ();
	DeinitNonceGenerator ();
#endif
}
