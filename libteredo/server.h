/**
 * @file server.h
 * @brief Public libteredo server API
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

/**
 * Creates a Teredo server handler. You should then drop your
 * privileges and call teredo_server_start().
 *
 * @note Only one thread should use a given server handle at a time 
 *
 * @param ip1 server primary IPv4 address (network byte order),
 * @param ip2 server secondary IPv4 address (network byte order).
 *
 * @return NULL on error.
 */
teredo_server *teredo_server_create (uint32_t ip1, uint32_t ip2);

/**
 * Changes the Teredo prefix to be advertised by a Teredo server.
 * If not set, the internal default will be used.
 *
 * @param s server handler as returned from teredo_server_create(),
 * @param prefix 32-bits IPv6 address prefix (network byte order).
 *
 * @return 0 on success, -1 if the prefix is not acceptable.
 */
int teredo_server_set_prefix (teredo_server *s, uint32_t prefix);

/**
 * Returns the Teredo prefix currently advertised by the server (in network
 * byte order).
 *
 * @param s server handler as returned from teredo_server_create(),
 */
uint32_t teredo_server_get_prefix (const teredo_server *s);

/**
 * Changes the link MTU advertised by the Teredo server.
 * If not set, the internal default will be used (currently 1280 bytes).
 *
 * @param s server handler as returned from teredo_server_create(),
 * @param prefix MTU (in bytes) (host byte order).
 *
 * @return 0 on success, -1 if the MTU is not acceptable.
 */
int teredo_server_set_MTU (teredo_server *s, uint16_t mtu);

/**
 * Returns the link MTU currently advertised by the server in host byte order.
 *
 * @param s server handler as returned from teredo_server_create(),
 */
uint16_t teredo_server_get_MTU (const teredo_server *s);

/**
 * Starts a Teredo server processing.
 *
 * @param s server handler as returned from teredo_server_create(),
 *
 * @return 0 on success, -1 on error.
 */
int teredo_server_start (teredo_server *s);

/**
 * Stops a Teredo server. Behavior is not defined if it was not started first.
 *
 * @param s server handler as returned from teredo_server_create(),
 */
void teredo_server_stop (teredo_server *s);

/**
 * Destroys a Teredo server handle. Behavior is not defined if the associated
 * server is currently running - you must stop it with teredo_server_stop()
 * first, if it is running.
 *
 * @param s server handler as returned from teredo_server_create(),
 */
void teredo_server_destroy (teredo_server *s);

#ifdef __cplusplus
}
# endif

#endif /* ifndef MIREDO_SERVER_H */

