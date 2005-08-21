/*
 * security.h - helpers for security-related stuff
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2004 Remi Denis-Courmont.                            *
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

#ifndef __LIBTEREDO_SECURITY_H
# define __LIBTEREDO_SECURITY_H

# ifdef __cplusplus
extern "C" {
# endif

/**
 * Has to be called before any call to GenerateNonce() can succeed.
 * It should additionnaly be called before calling chroot().
 * Thread-safe. Can be called multiple times with no side effect.
 */
void InitNonceGenerator (void);

/**
 * Should be called after use of GenerateNonce().
 * Thread-safe. Can be called as many times.
 */
void DeinitNonceGenerator (void);

/**
 * Generates a random nonce value (8 bytes). Thread-safe.
 *
 * @param b pointer to a 8-bytes buffer [OUT]
 * @param critical true if the random value has to be unpredictible
 * for security reasons. If false, the function will not block, otherwise
 * it might have to wait until enough randomness entropy was gathered by the
 * system.
 * @return false on error, true on success
 */
bool GenerateNonce (unsigned char *b, bool critical);

# ifdef __cplusplus
}
# endif
#endif
