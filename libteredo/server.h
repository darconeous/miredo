/*
 * server.h - Declarations for server.c
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright (C) 2004-2005 Rémi Denis-Courmont.                       *
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

#ifndef LIBTEREDO_SERVER_H
# define LIBTEREDO_SERVER_H


typedef struct libteredo_server libteredo_server;

#ifdef __cplusplus
extern "C" {
#endif

int libteredo_server_check (char *errmsg, size_t len);

libteredo_server *libteredo_server_create (uint32_t ip1, uint32_t ip2);

int libteredo_server_set_prefix (libteredo_server *s, uint32_t prefix);
uint32_t libteredo_server_get_prefix (const libteredo_server *s);
int libteredo_server_set_MTU (libteredo_server *s, uint16_t mtu);
uint16_t libteredo_server_get_MTU (const libteredo_server *s);

int libteredo_server_start (libteredo_server *s);
void libteredo_server_stop (libteredo_server *s);

void libteredo_server_destroy (libteredo_server *s);

#ifdef __cplusplus
}
# endif

#endif /* ifndef MIREDO_SERVER_H */

