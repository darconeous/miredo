/*
 * maintain.c - Teredo client qualification & maintenance
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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#define _XOPEN_SOURCE 600
#include <gettext.h>

#include <string.h> /* memcmp() */
#include <assert.h>

#include <stdbool.h>
#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h> /* struct in6_addr */
#include <syslog.h>
#include <stdlib.h> /* malloc() */
#include <errno.h> /* EINTR */
#include <pthread.h>

#include "teredo.h"
#include "teredo-udp.h"
#include "packets.h"

#include "security.h"
#include "relay.h" // struct teredo_state
#include "maintain.h"

#define QUALIFIED	0
#define PROBE_CONE	1
#define PROBE_RESTRICT	2
#define PROBE_SYMMETRIC	3
#define NOT_RUNNING	(-1)


struct teredo_maintenance
{
	pthread_t thread;
	pthread_mutex_t lock;
	pthread_cond_t received;
	const teredo_packet *incoming;
	pthread_barrier_t processed;

	int fd;
	struct
	{
		teredo_state state;
		teredo_state_change cb;
		void *opaque;
	} state;
	uint32_t server;
	uint32_t server2;
};


/* It is assumed that the calling thread holds the maintenance lock */
static bool
maintenance_recv (const teredo_packet *packet, uint32_t server_ip,
                  uint8_t *nonce, bool cone, uint16_t *mtu,
                  union teredo_addr *newaddr)
{
	/*
	* We don't accept router advertisement without nonce.
	* It is far too easy to spoof such packets.
	*/
	if ((packet->auth_nonce == NULL)
	 || memcmp (packet->auth_nonce, nonce, 8))
		return false;

	if (packet->auth_conf_byte)
	{
		syslog (LOG_ERR, _("Authentication with server failed."));
		return false;
	}

	if (ParseRA (packet, newaddr, cone, mtu)
	/* TODO: try to work-around incorrect server IP */
	 || (newaddr->teredo.server_ip != server_ip))
		return false;

	/* Valid router advertisement received! */
	return true;
}


/**
 * Make sure tv is in the future. If not, set it to the current time.
 * @return false if (*tv) was changed, true otherwise.
 */
static bool
checkTimeDrift (struct timespec *tv)
{
	struct timeval now;

	(void)gettimeofday (&now, NULL);
	if ((now.tv_sec > tv->tv_sec)
	 || ((now.tv_sec == tv->tv_sec) && (now.tv_sec >= (tv->tv_nsec / 1000))))
	{
		/* process stopped, CPU starved, or (ACPI, APM, etc) suspend */
		syslog (LOG_WARNING, _("Too much time drift. Resynchronizing."));
		tv->tv_sec = now.tv_sec;
		tv->tv_nsec = now.tv_usec * 1000;
		return false;
	}
	return true;
}


static void
cleanup_unlock (void *o)
{
	(void)pthread_mutex_unlock ((pthread_mutex_t *)o);
}


#define SERVER_PING_DELAY 30

/* TODO: allow modification of these values ? */
static unsigned QualificationTimeOut = 4; // seconds
static unsigned QualificationRetries = 3;

static unsigned ServerNonceLifetime = 3600; // seconds
static unsigned RestartDelay = 100; // seconds

/**
 * Teredo client maintenance procedure
 */
static inline void maintenance_thread (teredo_maintenance *m)
{
	struct
	{
		uint8_t value[8];
		struct timeval expiry;
	} nonce = { { 0, 0 } };
	struct timespec deadline = { 0, 0 };
	teredo_state *c_state = &m->state.state;
	unsigned count = 0;
	int state = PROBE_CONE;

	pthread_mutex_lock (&m->lock);
	c_state->cone = true;

	/*
	 * Qualification/maintenance procedure
	 */
	pthread_cleanup_push (cleanup_unlock, &m->lock);
	while (1)
	{
		if (deadline.tv_sec >= nonce.expiry.tv_sec)
		{
			/* The lifetime of the nonce is not second-critical
			 => we don't check/set tv_usec */
			GenerateNonce (nonce.value, true);

			/* avoid lost connectivity and RS flood if nonce generation has
			 * been blocking for a long time -> resync timer */
			gettimeofday (&nonce.expiry, NULL);

			deadline.tv_sec = nonce.expiry.tv_sec;
			deadline.tv_nsec = nonce.expiry.tv_usec * 1000;

			nonce.expiry.tv_sec += ServerNonceLifetime;
		}

		/* SEND ROUTER SOLICATION */
		do
			deadline.tv_sec += QualificationTimeOut;
		while (!checkTimeDrift (&deadline));

		SendRS (m->fd, (state == PROBE_RESTRICT) ? m->server2 : m->server,
		        nonce.value, c_state->cone);

		/* RECEIVE ROUTER ADVERTISEMENT */
		union teredo_addr newaddr;
		int val;
		uint16_t mtu = 1280;
		do
		{
			val = pthread_cond_timedwait (&m->received, &m->lock, &deadline);

			if (val == 0)
			{
				bool accept;
				/* check received packet */
				accept = maintenance_recv (m->incoming,
				                           m->server,
				                           nonce.value, c_state->cone,
				                           &mtu, &newaddr);

				(void)pthread_barrier_wait (&m->processed);
				if (accept)
					break;
			}
		}
		while (val == EINTR);

		unsigned sleep = 0;

		/* UPDATE FINITE STATE MACHINE */
		if (val)
		{
			/* no response */
			if (state == PROBE_SYMMETRIC)
				state = PROBE_RESTRICT;
			else
				count++;

			if (count >= QualificationRetries)
			{
				if (state == QUALIFIED)
				{
					syslog (LOG_NOTICE, _("Lost Teredo connectivity"));
					c_state->up = false;
					m->state.cb (c_state, m->state.opaque);
				}

				count = 0;
				if (state == PROBE_CONE)
				{
					state = PROBE_RESTRICT;
					c_state->cone = false;
				}
				else /* PROBE_(RESTRICT|SYMMETRIC) or QUALIFIED */
				{
					/* No response from server */
					syslog (LOG_INFO, _("No reply from Teredo server"));
					/* Wait some time before retrying */
					state = PROBE_CONE;
					c_state->cone = true;
					sleep = RestartDelay;
				}
			}
		}
		else
		switch (state)
		{
			case QUALIFIED:
				/* packet received, already qualified */
				count = 0;
				/* Success: schedule next NAT binding maintenance */
				sleep = SERVER_PING_DELAY;
				if (memcmp (&c_state->addr, &newaddr, sizeof (newaddr))
				|| (c_state->mtu != mtu))
				{
					memcpy (&c_state->addr, &newaddr, sizeof (c_state->addr));
					c_state->mtu = mtu;
		
					syslog (LOG_NOTICE, _("Teredo address/MTU changed"));
					m->state.cb (c_state, m->state.opaque);
				}
				break;

			case PROBE_RESTRICT:
				state = PROBE_SYMMETRIC;
				memcpy (&c_state->addr, &newaddr, sizeof (c_state->addr));
				break;

			case PROBE_SYMMETRIC:
				if ((c_state->addr.teredo.client_port != newaddr.teredo.client_port)
				 || (c_state->addr.teredo.client_ip != newaddr.teredo.client_ip))
				{
					/* Symmetric NAT failure */
					/* Wait some time before retrying */
					syslog (LOG_ERR,
					        _("Unsupported symmetric NAT detected."));
					count = 0;
					state = PROBE_CONE;
					c_state->cone = true;
					sleep = RestartDelay;
					break;
				}
				/* DO NOT break; */
			case PROBE_CONE:
				syslog (LOG_INFO, _("Qualified (NAT type: %s)"),
				        gettext (c_state->cone
			                      ? N_("cone") : N_("restricted")));
				count = 0;
				state = QUALIFIED;
				memcpy (&c_state->addr, &newaddr, sizeof (c_state->addr));
				c_state->mtu = mtu;
				c_state->up = true;
				m->state.cb (c_state, m->state.opaque);

				/* Success: schedule NAT binding maintenance */
				sleep = SERVER_PING_DELAY;
				break;
		}

		/* WAIT UNTIL NEXT SOLICITATION */
		/* TODO refresh interval optimization */
		/* TODO: watch for new interface events
		 * (netlink on Linux, PF_ROUTE on BSD) */
		if (sleep)
		{
			deadline.tv_sec -= QualificationTimeOut;
			deadline.tv_sec += sleep;
			do
			{
				/* we should not be signaled any way */
				val = pthread_cond_timedwait (&m->received,
				                              &m->lock, &deadline);
				if (val == 0)
					/* ignore unexpected packet */
					(void)pthread_barrier_wait (&m->processed);
			}
			while (val != ETIMEDOUT);
		}
	}
	/* dead code */
	pthread_cleanup_pop (1);
}


static void *do_maintenance (void *opaque)
{
	maintenance_thread ((teredo_maintenance *)opaque);
	return NULL;
}

/**
 * Creates and starts a Teredo client maintenance procedure thread
 *
 * @return NULL on error.
 */
teredo_maintenance *
libteredo_maintenance_start (int fd, teredo_state_change cb, void *opaque,
                             uint32_t s1, uint32_t s2)
{
	int err;
	teredo_maintenance *m = (teredo_maintenance *)malloc (sizeof (*m));

	if (m == NULL)
		return NULL;

	memset (m, 0, sizeof (*m));
	m->fd = fd;
	m->state.cb = cb;
	m->state.opaque = opaque;
	m->server = s1;
	m->server2 = s2;

	err = pthread_mutex_init (&m->lock, NULL);
	if (err == 0)
	{
		err = pthread_cond_init (&m->received, NULL);
		if (err == 0)
		{
			err = pthread_barrier_init (&m->processed, NULL, 2);
			if (err == 0)
			{
				err = pthread_create (&m->thread, NULL, do_maintenance, m);
				if (err == 0)
					return m;

				pthread_barrier_destroy (&m->processed);
			}
			pthread_cond_destroy (&m->received);
		}
		pthread_mutex_destroy (&m->lock);
	}
	syslog (LOG_ALERT, _("Error (%s): %s\n"), "pthread_create",
	        strerror (err));
	free (m);
	return NULL;
}

/**
 * Stops and destroys a maintenance thread created by
 * libteredo_maintenance_start()
 */
void libteredo_maintenance_stop (teredo_maintenance *m)
{
	pthread_cancel (m->thread);
	pthread_join (m->thread, NULL);
	pthread_cond_destroy (&m->received);
	pthread_mutex_destroy (&m->lock);
	free (m);
}


/**
 * Passes a Teredo packet to a maintenance thread for processing.
 */
void libteredo_maintenance_process (teredo_maintenance *m,
                                    const teredo_packet *packet)
{
	(void)pthread_mutex_lock (&m->lock);
	m->incoming = packet;
	(void)pthread_cond_signal (&m->received);
	(void)pthread_mutex_unlock (&m->lock);
	(void)pthread_barrier_wait (&m->processed);
}
