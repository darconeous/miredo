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

#include <libteredo/teredo.h>

#include <libteredo/relay-udp.h> /* required for packets.h */
#include "packets.h"

#include "security.h"
#include <libteredo/relay.h>

#define PROBE_CONE	1
#define PROBE_RESTRICT	2
#define PROBE_SYMMETRIC	3

#define QUALIFIED	0


int TeredoRelay::NotifyUp (const struct in6_addr *, uint16_t)
{
	return 0;
}


int TeredoRelay::NotifyDown (void)
{
	return 0;
}


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
	if (memcmp (s_nonce, maintenance.nonce, 8))
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
			if (!maintenance.success)
				syslog (LOG_ERR, _("Unsupported symmetric NAT detected."));
			break;

		case PROBE_RESTRICT:
			maintenance.success = false;
			break;

		case PROBE_CONE:
			maintenance.success = true;
	}

	memcpy (&addr, &newaddr, sizeof (addr));

	if (maintenance.success && NotifyUp (&addr.ip6, mtu))
	{
		syslog (LOG_ERR, _("Teredo tunnel fatal error"));
		maintenance.success = false;
	}
	pthread_mutex_unlock (&maintenance.lock);

	return 0;
}


static void
asyncsafe_sleep (unsigned sec)
{
	struct timespec ts;
	int oldstate;

	ts.tv_sec = sec;
	ts.tv_nsec = 0;
	pthread_setcanceltype (PTHREAD_CANCEL_ASYNCHRONOUS, &oldstate);
	nanosleep (&ts, NULL);
	pthread_setcanceltype (oldstate, NULL);
	pthread_testcancel ();
}


#define SERVER_PING_DELAY 30

unsigned TeredoRelay::QualificationTimeOut = 4; // seconds
unsigned TeredoRelay::QualificationRetries = 3;
unsigned TeredoRelay::RestartDelay = 300; // seconds

unsigned TeredoRelay::ServerNonceLifetime = 3600; // seconds


void TeredoRelay::MaintenanceThread (void)
{
	unsigned count = 0;
	struct timeval nonce_death = { 0, 0 };

	isCone = true;
	pthread_mutex_lock (&maintenance.lock);
	maintenance.state = PROBE_CONE;

	/*
	 * Qualification/maintenance procedure
	 */
	while (1)
	{
		if ((maintenance.state == 0) && (count == 0))
		{
			pthread_mutex_unlock (&maintenance.lock);
			// TODO refresh interval optimization
			asyncsafe_sleep (SERVER_PING_DELAY);
			pthread_mutex_lock (&maintenance.lock);
		}

		struct timeval now;
		gettimeofday (&now, NULL);
		if (now.tv_sec > nonce_death.tv_sec)
		{
			/* The lifetime of the nonce is not critical
			 => no need to check tv_usec */
			GenerateNonce (maintenance.nonce, true);
			gettimeofday (&nonce_death, NULL);
			nonce_death.tv_sec += ServerNonceLifetime;
		}

		SendRS (sock, maintenance.state == PROBE_RESTRICT /* secondary */
		              ? GetServerIP2 () : GetServerIP (),
		        maintenance.nonce, isCone);

		struct timespec deadline;
		gettimeofday (&now, NULL);
		deadline.tv_sec = now.tv_sec + QualificationTimeOut;
		deadline.tv_nsec = now.tv_usec * 1000;

		if (pthread_cond_timedwait (&maintenance.received, &maintenance.lock,
		                            &deadline))
		{
			/* no response */
			if (maintenance.state == PROBE_SYMMETRIC)
				maintenance.state = PROBE_RESTRICT;
			else
				count++;

			if (count >= QualificationRetries)
			{
				bool down = (maintenance.state == 0);

				count = 0;
				if (maintenance.state == PROBE_CONE)
				{
					isCone = false;
					maintenance.state = PROBE_RESTRICT;
				}
				else
				{
					isCone = true;
					maintenance.state = PROBE_CONE;
				}

				if (down)
				{
					pthread_mutex_unlock (&maintenance.lock);
					syslog (LOG_NOTICE, _("Lost Teredo connectivity"));
					// FIXME: some tunnel implementations might not handle
					// asynchronous NotifyDown properly
					NotifyDown ();

					/* Sleep some time */
					asyncsafe_sleep (SERVER_PING_DELAY);
					pthread_mutex_lock (&maintenance.lock);
				}
			}
		}
		else
		if (maintenance.state)
		{
			if (maintenance.success)
			{
				syslog (LOG_INFO, _("Qualified (NAT type: %s)"),
				        gettext (isCone ? N_("cone") : N_("restricted")));
				count = 0;
				maintenance.state = 0;
			}
			else
			if (maintenance.state == PROBE_RESTRICT)
			{
				maintenance.state = PROBE_SYMMETRIC;
			}
			else
			{
				/* FAIL */
				count = 0;
				maintenance.state = PROBE_CONE;

				/* Sleep five minutes */
				pthread_mutex_unlock (&maintenance.lock);
				asyncsafe_sleep (RestartDelay);
				pthread_mutex_lock (&maintenance.lock);
			}
		}
	}
}


void *
TeredoRelay::do_maintenance (void *data)
{
	((TeredoRelay *)data)->MaintenanceThread ();
	return NULL;
}
