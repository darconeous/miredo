/*
 * relay.cpp - Linux Teredo relay implementation
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

#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <sys/types.h>
#include <unistd.h> // close()
#include <sys/wait.h> // wait()
#include <syslog.h>


#include <libtun6/ipv6-tunnel.h>
#include "privproc.h"
#include "relay.h"
#include "miredo.h"
#include "conf.h"
#include <libteredo/security.h>

MiredoRelay::MiredoRelay (const IPv6Tunnel *tun, uint32_t prefix,
                          uint16_t port, uint32_t ipv4, bool cone)
	: TeredoRelay (prefix, port, ipv4, cone), tunnel (tun), priv_fd (-1)
{
}


int MiredoRelay::SendIPv6Packet (const void *packet, size_t length)
{
	return tunnel->SendPacket (packet, length);
}


#ifdef MIREDO_TEREDO_CLIENT
MiredoRelay::MiredoRelay (int fd, const IPv6Tunnel *tun, uint32_t server_ip,
                          uint32_t server_ip2, uint16_t port, uint32_t ipv4)
	: TeredoRelay (server_ip, server_ip2, port, ipv4), tunnel (tun),
	  priv_fd (fd)
{
}


int MiredoRelay::NotifyUp (const struct in6_addr *addr, uint16_t mtu)
{
	return miredo_configure_tunnel (priv_fd, addr, mtu);
}


int MiredoRelay::NotifyDown (void)
{
	return NotifyUp (&in6addr_any);
}
#endif /* ifdef MIREDO_TEREDO_CLIENT */


/*
 * Main server function, with UDP datagrams receive loop.
 */
static void
teredo_relay (IPv6Tunnel& tunnel, TeredoRelay *relay = NULL)
{
	/* Main loop */
	while (1)
	{
		/* Registers file descriptors */
		fd_set readset;
		struct timeval tv;
		FD_ZERO (&readset);

		int maxfd = signalfd[0];
		FD_SET(signalfd[0], &readset);

		int val = tunnel.RegisterReadSet (&readset);
		if (val > maxfd)
			maxfd = val;

		val = relay->RegisterReadSet (&readset);
		if (val > maxfd)
			maxfd = val;

		/*
		 * Short time-out to call relay->Proces () quite often.
		 */
		tv.tv_sec = 0;
		tv.tv_usec = 250000;

		/* Wait until one of them is ready for read */
		maxfd = select (maxfd + 1, &readset, NULL, NULL, &tv);
		if ((maxfd < 0)
		 || ((maxfd >= 1) && FD_ISSET (signalfd[0], &readset)))
			// interrupted by signal
			break;

		/* Handle incoming data */
		char pbuf[65535];
		int len;

#ifdef MIREDO_TEREDO_CLIENT
		relay->Process ();
#endif

		/* Forwards IPv6 packet to Teredo
		 * (Packet transmission) */
		len = tunnel.ReceivePacket (&readset, pbuf, sizeof (pbuf));
		if (len > 0)
			relay->SendPacket (pbuf, len);

		/* Forwards Teredo packet to IPv6
		 * (Packet reception) */
		relay->ReceivePacket (&readset);
	}
}


extern int
miredo_run (const struct miredo_conf *conf)
{
#ifdef MIREDO_TEREDO_CLIENT
	if (conf->mode == TEREDO_CLIENT)
		InitNonceGenerator ();
#endif

	/*
	 * Tunneling interface initialization
	 *
	 * NOTE: The Linux kernel does not allow setting up an address
	 * before the interface is up, and it tends to complain about its
	 * inability to set a link-scope address for the interface, as it
	 * lacks an hardware layer address.
	 */

	/*
	 * Must likely be root (unless the user was granted access to the
	 * device file).
	 */
	IPv6Tunnel tunnel (conf->ifname);

	if (!tunnel)
	{
		syslog (LOG_ALERT, _("Teredo tunnel setup failed:\n %s"),
				_("You should be root to do that."));
		return -1;
	}

	MiredoRelay *relay;
	int fd = -1, retval = -1;

	/*
	 * Must be root to do that.
	 */
#ifdef MIREDO_TEREDO_RELAY
#ifdef MIREDO_TEREDO_CLIENT
	if (conf->mode == TEREDO_CLIENT)
	{
		fd = miredo_privileged_process (tunnel, conf->default_route);
		if (fd == -1)
		{
			syslog (LOG_ALERT,
				_("Privileged process setup failed: %m"));
			goto abort;
		}
	}
	else
#endif
	if (conf->mode != TEREDO_DISABLED)
	{
		if (tunnel.SetMTU (conf->adv_mtu) || tunnel.BringUp ()
		 || tunnel.AddAddress (conf->mode == TEREDO_RESTRICT
		 			? &teredo_restrict : &teredo_cone)
		 || (conf->mode != TEREDO_DISABLED
		  && tunnel.AddRoute (&conf->prefix.ip6, 32)))
		{
			syslog (LOG_ALERT, _("Teredo routing failed:\n %s"),
				_("You should be root to do that."));
			goto abort;
		}
	}
#endif

	if (drop_privileges ())
		goto abort;

	// Sets up relay or client

#ifdef MIREDO_TEREDO_RELAY
# ifdef MIREDO_TEREDO_CLIENT
	if (conf->mode == TEREDO_CLIENT)
	{
		// Sets up client
		try
		{
			relay = new MiredoRelay (fd, &tunnel,
			                         conf->server_ip, conf->server_ip2,
			                         conf->bind_port, conf->bind_ip);
		}
		catch (...)
		{
			relay = NULL;
		}
	}
	else
# endif /* ifdef MIREDO_TEREDO_CLIENT */
	if (conf->mode != TEREDO_DISABLED)
	{
		// Sets up relay
		try
		{
			// FIXME: read union teredo_addr instead of prefix ?
			relay = new MiredoRelay (&tunnel, conf->prefix.teredo.prefix,
			                         conf->bind_port, conf->bind_ip,
			                         conf->mode == TEREDO_CONE);
		}
		catch (...)
		{
			relay = NULL;
		}
	}

	if (conf->mode != TEREDO_DISABLED)
	{
		if (relay == NULL)
		{
			syslog (LOG_ALERT, _("Teredo service failure"));
			goto abort;
		}

		if (!*relay)
		{
			if (conf->bind_port)
				syslog (LOG_ALERT,
					_("Teredo service port failure: "
					"cannot open UDP port %u"),
					(unsigned int)ntohs (conf->bind_port));
			else
				syslog (LOG_ALERT,
					_("Teredo service port failure: "
					"cannot open an UDP port"));

			syslog (LOG_NOTICE, _("Make sure another instance "
				"of the program is not already running."));
			goto abort;
		}
	}
#endif /* ifdef MIREDO_TEREDO_RELAY */

	retval = 0;
	teredo_relay (tunnel, relay);

abort:
	if (fd != -1)
		close (fd);
	if (relay != NULL)
		delete relay;
#ifdef MIREDO_TEREDO_CLIENT
	if (conf->mode == TEREDO_CLIENT)
		DeinitNonceGenerator ();
#endif

	if (fd != -1)
		wait (NULL); // wait for privsep process

	return retval;
}
