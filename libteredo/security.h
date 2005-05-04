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

# ifndef __cplusplus
#  error C++ header
# endif

/*
 * MUST be called before any call to GenerateNonce().
 * Not thread-safe.
 */
void InitNonceGenerator (void);

/*
 * Should be called after use of GenerateNonce().
 * Not thread-safe.
 */
void DeinitNonceGenerator (void);

/*
 * Generates a random nonce value (8 bytes). Thread-safe.
 */
bool GenerateNonce (unsigned char *b, bool critical = false);

#endif
