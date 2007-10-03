/**
 * @file maintain.h
 * @brief Teredo client qualification & maintenance
 *
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004-2005 Rémi Denis-Courmont.                         *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license, or (at  *
 *  your option) any later version.                                    *
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

#ifndef MIREDO_LIBTEREDO_MAINTAIN_H
# define MIREDO_LIBTEREDO_MAINTAIN_H

/**
 * Externally visible state maintained by the Teredo client maintenance
 * procedure and passed to state change callbacks.
 */
typedef struct teredo_state
{
	/** Teredo client IPv6 address */
	union teredo_addr addr;

	/** Teredo tunnel Maximum Transmission Unit (bytes) */
	uint16_t mtu; 

	/** whether the Teredo tunnel is up and running */
	bool up; 
} teredo_state;

# ifdef __cplusplus
extern "C" {
# endif

/**
 * Teredo client maintenance procedure internal state.
 */
typedef struct teredo_maintenance teredo_maintenance;

/**
 * Callback prototype for the maintenance procedure to notify about Teredo
 * client tunnel state changes.
 * @param s new state of the Teredo tunnel
 * @param opaque data pointer as specified in teredo_maintenance_start()
 */
typedef void (*teredo_state_cb) (const struct teredo_state *s, void *opaque);

/**
 * Creates and starts a Teredo client maintenance procedure thread.
 *
 * @param fd socket to send router solicitation with
 * @param cb status change notification callback
 * @param opaque data for @a cb callback
 * @param s1 primary server address/hostname
 * @param s2 secondary server address/hostname
 * @param q_sec qualification time out (seconds), 0 = default
 * @param q_retries qualification retries, 0 = default
 * @param refresh_sec qualification refresh interval (seconds), 0 = default
 * @param restart_sec qualification failure interval (seconds), 0 = default
 *
 * @return NULL on error.
 */
teredo_maintenance *
teredo_maintenance_start (int fd, teredo_state_cb cb, void *opaque,
                          const char *s1, const char *s2,
                          unsigned q_sec, unsigned q_retries,
                          unsigned refresh_sec, unsigned restart_sec);

/**
 * Stops and destroys a maintenance thread created by
 * teredo_maintenance_start()
 *
 * @param m non-NULL pointer from teredo_maintenance_start()
 */
void teredo_maintenance_stop (teredo_maintenance *m);


/**
 * Passes a Teredo packet to a maintenance thread for processing.
 * Thread-safe, not async-cancel safe.
 *
 * @return 0 if processed, -1 if not a valid router solicitation.
 */
int teredo_maintenance_process (teredo_maintenance *restrict m,
                                const teredo_packet *restrict packet);

# ifdef __cplusplus
}
# endif

#endif
