/*
 * privproc.h - Privileged process for Miredo
 * $Id: privproc.h,v 1.3 2004/08/18 09:42:35 rdenisc Exp $
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

#ifndef __MIREDO_PRIVPROC_H
# define __MIREDO_PRIVPROC_H

# ifndef __cplusplus
#  error C++ header
# endif

# include <sys/types.h>
# include <libtun6/ipv6-tunnel.h>


struct in6_addr;

int
miredo_privileged_process (IPv6Tunnel& tunnel,
				const struct in6_addr *initial_addr);

#endif
