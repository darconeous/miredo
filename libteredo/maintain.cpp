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

#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h> // struct in6_addr
#include <syslog.h>
#include <errno.h> // ETIMEDOUT

#include <libteredo/teredo.h>

#include <libteredo/relay-udp.h> /* required for packets.h */
#include "packets.h"

#include "security.h"
#include <libteredo/relay.h>

#define PROBE_CONE	1
#define PROBE_RESTRICT	2
#define PROBE_SYMMETRIC	3

#define QUALIFIED	0


bool TeredoRelay::IsServerPacket (const TeredoPacket *packet) const
{
	uint32_t ip = packet->GetClientIP ();

	return (packet->GetClientPort () == htons (IPPORT_TEREDO))
	 && ((ip == GetServerIP ()) || (ip == GetServerIP2 ()));
}


/* Handle router advertisement for qualification */
int TeredoRelay::ProcessQualificationPacket (const TeredoPacket *packet)
{
	if (!IsServerPacket (packet))
		return 0;

	/*
	 * We don't accept router advertisement without nonce.
	 * It is far too easy to spoof such packets.
	 */
	const uint8_t *s_nonce = packet->GetAuthNonce ();

	if (s_nonce == NULL)
		return 0;

	union teredo_addr newaddr;
	newaddr.teredo.server_ip = GetServerIP ();
 
	pthread_mutex_lock (&maintenance.lock);
	if (!maintenance.attended || memcmp (s_nonce, maintenance.nonce, 8))
	{
		pthread_mutex_unlock (&maintenance.lock);
		return 0;
	}

	if (packet->GetConfByte ())
	{
		pthread_mutex_unlock (&maintenance.lock);
		syslog (LOG_ERR, _("Authentication refused by server."));
		return 0;
	}

	if (!ParseRA (*packet, &newaddr, maintenance.state == PROBE_CONE, &mtu))
	{
		pthread_mutex_unlock (&maintenance.lock);
		return 0;
	}

	/* Valid router advertisement received! */
	pthread_cond_signal (&maintenance.received);

	switch (maintenance.state)
	{
		case PROBE_SYMMETRIC:
			maintenance.success =
				(addr.teredo.client_port == newaddr.teredo.client_port)
				&& (addr.teredo.client_ip == newaddr.teredo.client_ip);
			break;

		case PROBE_RESTRICT:
			maintenance.success = false;
			break;

		case PROBE_CONE:
			maintenance.success = true;
			break;
	}

	memcpy (&addr, &newaddr, sizeof (addr));
	pthread_mutex_unlock (&maintenance.lock);

	return 0;
}


static void
cleanup_unlock (void *o)
{
	pthread_mutex_unlock ((pthread_mutex_t *)o);
}


#define SERVER_PING_DELAY 30

unsigned TeredoRelay::QualificationTimeOut = 4; // seconds
unsigned TeredoRelay::QualificationRetries = 3;

unsigned TeredoRelay::ServerNonceLifetime = 3600; // seconds
unsigned TeredoRelay::RestartDelay = 30; // seconds


void TeredoRelay::MaintenanceThread (void)
{
	unsigned count = 0;
	struct timeval nonce_expiry = { 0, 0 };
	struct timespec deadline = { 0, 0 };

	isCone = true;
	pthread_mutex_lock (&maintenance.lock);
	maintenance.state = PROBE_CONE;

	/*
	 * Qualification/maintenance procedure
	 */
	pthread_cleanup_push (cleanup_unlock, &maintenance.lock);
	while (1)
	{
		if (deadline.tv_sec >= nonce_expiry.tv_sec)
		{
			/* The lifetime of the nonce is not second-critical
			 => we don't check/set tv_usec */
			GenerateNonce (maintenance.nonce, true);

			/* avoid lost connectivity and RS flood if nonce generation has
			 * been blocking for a long time -> resync timer */
			gettimeofday (&nonce_expiry, NULL);

			deadline.tv_sec = nonce_expiry.tv_sec;
			deadline.tv_nsec = nonce_expiry.tv_usec * 1000;

			nonce_expiry.tv_sec += ServerNonceLifetime;
		}

		SendRS (sock, maintenance.state == PROBE_RESTRICT /* secondary */
		              ? GetServerIP2 () : GetServerIP (),
		        maintenance.nonce, isCone);

		deadline.tv_sec += QualificationTimeOut;
		maintenance.attended = true;

		int val;
		do
		{
			val = pthread_cond_timedwait (&maintenance.received,
			                              &maintenance.lock, &deadline);
		}
		while (val && (val != ETIMEDOUT));
		maintenance.attended = false;

		unsigned sleep = 0;

		if (val)
		{
			/* no response */
			if (maintenance.state == PROBE_SYMMETRIC)
				maintenance.state = PROBE_RESTRICT;
			else
				count++;

			if (count >= QualificationRetries)
			{
				if (maintenance.state == 0)
				{
					syslog (LOG_NOTICE, _("Lost Teredo connectivity"));
					NotifyDown ();
				}

				count = 0;
				if (maintenance.state == PROBE_CONE)
				{
					maintenance.state = PROBE_RESTRICT;
					isCone = false;
				}
				else
				{
					/* Wait some time before retrying */
					maintenance.state = PROBE_CONE;
					isCone = true;
					sleep = RestartDelay;
				}
			}
		}
		else
		if (maintenance.state)
		{
			/* packet received, not qualified yet */
			if (maintenance.success)
			{
				syslog (LOG_INFO, _("Qualified (NAT type: %s)"),
				        gettext (isCone ? N_("cone") : N_("restricted")));

				count = 0;
				maintenance.state = 0;
				NotifyUp (&addr.ip6, mtu);

				/* Success: schedule NAT binding maintenance */
				sleep = SERVER_PING_DELAY;
			}
			else
			if (maintenance.state == PROBE_RESTRICT)
			{
				maintenance.state = PROBE_SYMMETRIC;
			}
			else
			{
				/* Symmetric NAT failure */
				/* Wait some time before retrying */
				syslog (LOG_ERR, _("Unsupported symmetric NAT detected."));

				count = 0;
				maintenance.state = PROBE_CONE;
				isCone = true;
				sleep = RestartDelay;
			}
		}
		else
		{
			count = 0;
			/* Success: schedule next NAT binding maintenance */
			sleep = SERVER_PING_DELAY;
		}

		// TODO refresh interval optimization
		/* TODO: watch for new interface events
		 * (netlink on Linux, PF_ROUTE on BSD) */
		if (sleep)
		{
			deadline.tv_sec -= QualificationTimeOut;
			deadline.tv_sec += sleep;
			do
				/* we should not be signaled any way */
				val = pthread_cond_timedwait (&maintenance.received,
				                              &maintenance.lock, &deadline);
			while (val != ETIMEDOUT);
		}
	}
	/* dead code */
	pthread_cleanup_pop (1);
}


void *
TeredoRelay::do_maintenance (void *data)
{
	((TeredoRelay *)data)->MaintenanceThread ();
	return NULL;
}
