/*
 * maintain.cpp - Teredo client qualification & maintenance
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

#include <gettext.h>

#include <string.h> /* memcmp() */
#include <assert.h>

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
#include <errno.h> /* EINTR */

#include <libteredo/teredo.h>

#include <libteredo/relay-udp.h> /* required for packets.h */
#include "packets.h"

#include "security.h"
#include <libteredo/relay.h>

#define QUALIFIED	0
#define PROBE_CONE	1
#define PROBE_RESTRICT	2
#define PROBE_SYMMETRIC	3
#define NOT_RUNNING	(-1)


bool TeredoRelay::IsServerPacket (const TeredoPacket *packet) const
{
	uint32_t ip = packet->GetClientIP ();

	return (packet->GetClientPort () == htons (IPPORT_TEREDO))
	 && ((ip == GetServerIP ()) || (ip == GetServerIP2 ()));
}


/* It is assumed that the calling thread holds the maintenance lock */
static bool
maintenance_recv (const TeredoPacket *packet, uint32_t server_ip, uint8_t *nonce,
                  bool cone, uint16_t *mtu, union teredo_addr *newaddr)
{
	assert (packet->GetAuthNonce () != NULL);

	if (memcmp (packet->GetAuthNonce (), nonce, 8))
		return false;

	if (packet->GetConfByte ())
	{
		syslog (LOG_ERR, _("Authentication with server failed."));
		return false;
	}

	if ((!ParseRA (*packet, newaddr, cone, mtu))
	/* TODO: try to work-around incorrect server IP */
	 || (newaddr->teredo.server_ip != server_ip /*GetServerIP ()*/))
		return false;

	/* Valid router advertisement received! */
	return true;
}


/* Make sure tv is in the future. If not set it to the current time.
 * Returns false if *tv was changed. */
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

unsigned TeredoRelay::QualificationTimeOut = 4; // seconds
unsigned TeredoRelay::QualificationRetries = 3;

unsigned TeredoRelay::ServerNonceLifetime = 3600; // seconds
unsigned TeredoRelay::RestartDelay = 100; // seconds


static inline void maintenance_thread (teredo_maintenance *m)
{
	struct
	{
		uint8_t value[8];
		struct timeval expiry;
	} nonce = { { 0, 0 } };
	struct timespec deadline = { 0, 0 };
	unsigned count = 0;
	int state = PROBE_CONE;

	pthread_mutex_lock (&m->lock);
	m->state.cone = true;

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

			nonce.expiry.tv_sec += TeredoRelay::ServerNonceLifetime;
		}

		/* SEND ROUTER SOLICATION */
		do
			deadline.tv_sec += TeredoRelay::QualificationTimeOut;
		while (!checkTimeDrift (&deadline));

		SendRS (m->relay->sock, state == PROBE_RESTRICT /* secondary */
		              ? m->relay->GetServerIP2 () : m->relay->GetServerIP (),
		        nonce.value, m->state.cone);

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
				                           m->relay->GetServerIP (),
				                           nonce.value, m->state.cone, &mtu,
				                           &newaddr);

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

			if (count >= TeredoRelay::QualificationRetries)
			{
				if (state == QUALIFIED)
				{
					syslog (LOG_NOTICE, _("Lost Teredo connectivity"));
					m->state.up = false;
					m->relay->NotifyDown ();
				}

				count = 0;
				if (state == PROBE_CONE)
				{
					state = PROBE_RESTRICT;
					m->state.cone = false;
				}
				else /* PROBE_(RESTRICT|SYMMETRIC) or QUALIFIED */
				{
					/* No response from server */
					syslog (LOG_INFO, _("No reply from Teredo server"));
					/* Wait some time before retrying */
					state = PROBE_CONE;
					m->state.cone = true;
					sleep = TeredoRelay::RestartDelay;
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
				if (memcmp (&m->state.addr, &newaddr, sizeof (newaddr))
				|| (m->state.mtu != mtu))
				{
					memcpy (&m->state.addr, &newaddr, sizeof (newaddr));
					m->state.mtu = mtu;
		
					syslog (LOG_NOTICE, _("Teredo address/MTU changed"));
					m->relay->NotifyUp (&newaddr.ip6, mtu);
					m->state.up = true;
				}
				break;

			case PROBE_RESTRICT:
				state = PROBE_SYMMETRIC;
				memcpy (&m->state.addr, &newaddr, sizeof (m->state.addr));
				break;

			case PROBE_SYMMETRIC:
				if ((m->state.addr.teredo.client_port != newaddr.teredo.client_port)
				 || (m->state.addr.teredo.client_ip != newaddr.teredo.client_ip))
				{
					/* Symmetric NAT failure */
					/* Wait some time before retrying */
					syslog (LOG_ERR,
					        _("Unsupported symmetric NAT detected."));
					count = 0;
					state = PROBE_CONE;
					m->state.cone = true;
					sleep = TeredoRelay::RestartDelay;
					break;
				}
			case PROBE_CONE:
				syslog (LOG_INFO, _("Qualified (NAT type: %s)"),
				        gettext (m->state.cone
			                      ? N_("cone") : N_("restricted")));

				count = 0;
				state = QUALIFIED;
				memcpy (&m->state.addr, &newaddr, sizeof (m->state.addr));
				m->state.mtu = mtu;
				m->relay->NotifyUp (&newaddr.ip6, mtu);
				m->state.up = true;

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
			deadline.tv_sec -= TeredoRelay::QualificationTimeOut;
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


extern "C"
int teredo_maintenance_start (struct teredo_maintenance *m)
{
	int err;

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
					return 0;

				pthread_barrier_destroy (&m->processed);
			}
			pthread_cond_destroy (&m->received);
		}
		pthread_mutex_destroy (&m->lock);
	}
	syslog (LOG_ALERT, _("pthread_create failure: %s"), strerror (err));
	return 0;
}


extern "C"
void teredo_maintenance_stop (struct teredo_maintenance *m)
{
	pthread_cancel (m->thread);
	pthread_join (m->thread, NULL);
	pthread_cond_destroy (&m->received);
	pthread_mutex_destroy (&m->lock);
}


/* Handle router advertisement for qualification */
static void
maintenance_process (const TeredoPacket *packet, teredo_maintenance *m)
{
	(void)pthread_mutex_lock (&m->lock);
	m->incoming = packet;
	(void)pthread_cond_signal (&m->received);
	(void)pthread_mutex_unlock (&m->lock);
	(void)pthread_barrier_wait (&m->processed);
}


void TeredoRelay::ProcessQualificationPacket (const TeredoPacket *packet)
{
	/*
	 * We don't accept router advertisement without nonce.
	 * It is far too easy to spoof such packets.
	 */
	if ((IsServerPacket (packet)) && (packet->GetAuthNonce () != NULL))
		maintenance_process (packet, &maintenance);
}


bool TeredoRelay::ProcessMaintenancePacket (const TeredoPacket *packet)
{
	union teredo_addr newaddr;
	uint16_t new_mtu;

	if ((packet->GetAuthNonce () == NULL)
	 || !ParseRA (*packet, &newaddr, IsCone (), &new_mtu))
		return false;

	maintenance_process (packet, &maintenance);
	return true;
}
