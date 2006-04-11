/*
 * server.h - Declarations for server.c
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright © 2004-2005 Rémi Denis-Courmont.                         *
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


typedef struct teredo_server teredo_server;

#ifdef __cplusplus
extern "C" {
#endif

int teredo_server_check (char *errmsg, size_t len);

teredo_server *teredo_server_create (uint32_t ip1, uint32_t ip2);

int teredo_server_set_prefix (teredo_server *s, uint32_t prefix);
uint32_t teredo_server_get_prefix (const teredo_server *s);
int teredo_server_set_MTU (teredo_server *s, uint16_t mtu);
uint16_t teredo_server_get_MTU (const teredo_server *s);

int teredo_server_start (teredo_server *s);
void teredo_server_stop (teredo_server *s);

void teredo_server_destroy (teredo_server *s);

#ifdef __cplusplus
}
# endif

#endif /* ifndef MIREDO_SERVER_H */

