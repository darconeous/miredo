/*
 * miredo.h - header for miredo.cpp
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright (C) 2004-2005 Remi Denis-Courmont.                       *
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

#ifndef MIREDO_MIREDO_H
# define MIREDO_MIREDO_H

# ifdef __cplusplus
extern "C"
{
# endif

# include <sys/types.h> // uid_t

int miredo (const char *conffile, const char *server_name);
int drop_privileges (void);

# ifdef __cplusplus
}
# endif

extern uid_t unpriv_uid;

#endif /* ifndef MIREDO_CONF_H */

