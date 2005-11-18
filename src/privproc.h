/*
 * privproc.h - Privileged process for Miredo
 * $Id$
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

#ifndef __MIREDO_PRIVPROC_H
# define __MIREDO_PRIVPROC_H

# ifndef __cplusplus
#  error C++ header
# endif

/* FIXME: port to C */

struct in6_addr;
typedef struct tun6 tun6;

int
miredo_privileged_process (tun6 *tunnel, bool default_route);

int
miredo_configure_tunnel (int fd, const struct in6_addr *addr, unsigned mtu);

#endif
