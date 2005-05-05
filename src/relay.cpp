/*
 * relay.cpp - Unix Teredo relay implementation core functions
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

#include <stdlib.h> // free()
#include <sys/types.h>
#include <unistd.h> // close()
#include <sys/wait.h> // wait()
#include <syslog.h>

#include <string.h>
#include <netdb.h> // gai_strerror()

#include <libtun6/ipv6-tunnel.h>

#include <libteredo/relay.h>
#include <libteredo/security.h>

#include "privproc.h"
#include "miredo.h"
#include "conf.h"

extern "C" const char *const miredo_conffile = SYSCONFDIR"/miredo.conf";
extern "C" const char *const miredo_pidfile = LOCALSTATEDIR"/run/miredo.pid";


extern "C" int
miredo_diagnose (void)
{
	char errbuf[LIBTUN6_ERRBUF_SIZE];
	if (libtun6_driver_diagnose (errbuf))
	{
		fputs (errbuf, stderr);
		return -1;
	}
	
	return 0;
}



class MiredoRelay : public TeredoRelay
{
	private:
		const IPv6Tunnel *tunnel;
		int priv_fd;

		virtual int SendIPv6Packet (const void *packet, size_t length)
		{
			return tunnel->SendPacket (packet, length);
		}

	public:
		MiredoRelay (const IPv6Tunnel *tun, uint32_t prefix,
		             uint16_t port = 0, uint32_t ipv4 = 0,
		             bool cone = true)
			: TeredoRelay (prefix, port, ipv4, cone), tunnel (tun),
			  priv_fd (-1)
		{
		}

		//virtual void ~MiredoRelay (void);

#ifdef MIREDO_TEREDO_CLIENT
		MiredoRelay (int fd, const IPv6Tunnel *tun,
		             uint32_t server_ip, uint32_t server_ip2,
		             uint16_t port = 0, uint32_t ipv4 = 0)
			: TeredoRelay (server_ip, server_ip2, port, ipv4), tunnel (tun),
			  priv_fd (fd)
		{
		}

	private:
		virtual int NotifyUp (const struct in6_addr *addr,
		                      uint16_t mtu = 1280)
		{
			return miredo_configure_tunnel (priv_fd, addr, mtu);
		}

		virtual int NotifyDown (void)
		{
			return NotifyUp (&in6addr_any);
		}
#endif /* ifdef MIREDO_TEREDO_CLIENT */
};


/*
 * Main server function, with UDP datagrams receive loop.
 */
static void
teredo_relay (int sigfd, IPv6Tunnel& tunnel, TeredoRelay *relay = NULL)
{
	/* Main loop */
	while (1)
	{
		/* Registers file descriptors */
		fd_set readset;
		FD_ZERO (&readset);
		FD_SET(sigfd, &readset);

		int val = tunnel.RegisterReadSet (&readset);
		int maxfd = (val > maxfd) ? val : maxfd;

		val = relay->RegisterReadSet (&readset);
		if (val > maxfd)
			maxfd = val;

		/* Wait until one of them is ready for read */
		maxfd = select (maxfd + 1, &readset, NULL, NULL, NULL);
		if ((maxfd < 0) || ((maxfd >= 1) && FD_ISSET (sigfd, &readset)))
			// interrupted by signal
			break;

		/* Handle incoming data */
		char pbuf[65535];
		int len;

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


#define TEREDO_CLIENT   1
#define TEREDO_RELAY    2
#define TEREDO_CONE     2
#define TEREDO_RESTRICT 3

static bool
ParseRelayType (MiredoConf& conf, const char *name, int *type)
{
	unsigned line;
	char *val = conf.GetRawValue (name, &line);

	if (val == NULL)
		return true;

	if (strcasecmp (val, "client") == 0)
		*type = TEREDO_CLIENT;
	else if (strcasecmp (val, "cone") == 0)
		*type = TEREDO_CONE;
	else if (strcasecmp (val, "restricted") == 0)
		*type = TEREDO_RESTRICT;
	else
	{
		syslog (LOG_ERR, _("Invalid relay type \"%s\" at line %u"),
			val, line);
		free (val);
		return false;
	}
	free (val);
	return true;
}


extern int
miredo_run (int sigfd, MiredoConf& conf, const char *server_name)
{
	int mode = TEREDO_CLIENT;
	char *ifname = NULL;
	union teredo_addr prefix = { 0 };
	uint32_t bind_ip = INADDR_ANY;
	uint16_t mtu = 1280, bind_port = 
#if 0
		/*
		 * We use 3545 as a Teredo service port.
		 * It is better to use a fixed port number for the
		 * purpose of firewalling, rather than a pseudo-random
		 * one (all the more as it might be a "dangerous"
		 * often firewalled port, such as 1214 as it happened
		 * to me once).
		 */
		IPPORT_TEREDO + 1;
#else
		0;
#endif
#ifdef MIREDO_TEREDO_CLIENT
	uint32_t server_ip = INADDR_ANY, server_ip2 = INADDR_ANY;
	bool default_route = true;
#endif

	/*
	 * CONFIGURATION
	 */
	prefix.teredo.prefix = htonl (DEFAULT_TEREDO_PREFIX);

	if (!ParseRelayType (conf, "RelayType", &mode))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
	}

	if (mode == TEREDO_CLIENT)
	{
#ifdef MIREDO_TEREDO_CLIENT
		if (!conf.GetBoolean ("DefaultRoute", &default_route))
		{
			syslog (LOG_ALERT, _("Fatal configuration error"));
			return -2;
		}

		if (server_name != NULL)
		{
			int check = GetIPv4ByName (server_name, &server_ip);
			if (check)
			{
				syslog (LOG_ALERT, _("Invalid server hostname \"%s\": %s"),
				        server_name, gai_strerror (check));
				syslog (LOG_ALERT, _("Fatal configuration error"));
				return -2;
			}
		}
		else
		{
			if (!ParseIPv4 (conf, "ServerAddress", &server_ip)
			 || !ParseIPv4 (conf, "ServerAddress2", &server_ip2))
			{
				syslog (LOG_ALERT, _("Fatal configuration error"));
				return -2;
			}
		}

		if (server_ip == INADDR_ANY)
		{
			syslog (LOG_ALERT, _("Server address not specified"));
			syslog (LOG_ALERT, _("Fatal configuration error"));
			return -2;
		}

		/*
		 * NOTE:
		 * While it is not specified in the draft Teredo
		 * specification, it really seems that the secondary
		 * server IPv4 address has to be the one just after
		 * the primary server IPv4 address.
		 */
		if (server_ip2 == INADDR_ANY)
			server_ip2 = htonl (ntohl (server_ip) + 1);
#else
		syslog (LOG_ALERT, _("Unsupported Teredo client mode"));
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
#endif
	}
	else
	{
		mtu = 1280;

		if (!ParseIPv6 (conf, "Prefix", &prefix.ip6)
		 || !conf.GetInt16 ("InterfaceMTU", &mtu))
		{
			syslog (LOG_ALERT, _("Fatal configuration error"));
			return -2;
		}
	}

	if (!ParseIPv4 (conf, "BindAddress", &bind_ip)
	 || !conf.GetInt16 ("BindPort", &bind_port))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
	}

	bind_port = htons (bind_port);

	ifname = conf.GetRawValue ("InterfaceName");

	conf.Clear (5);

	/*
	 * SETUP
	 */

#ifdef MIREDO_TEREDO_CLIENT
	if (mode == TEREDO_CLIENT)
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
	IPv6Tunnel tunnel (ifname);
	if (ifname != NULL)
		free (ifname);

	if (!tunnel)
	{
		syslog (LOG_ALERT, _("Teredo tunnel fatal error"));
		syslog (LOG_NOTICE, _("Make sure another instance of the program is "
		                      "not already running."));
		return -1;
	}

	MiredoRelay *relay = NULL;
	int retval = -1;

	/*
	 * Must be root to do that.
	 */
#ifdef MIREDO_TEREDO_CLIENT
	int fd = -1;

	if (mode == TEREDO_CLIENT)
	{
		fd = miredo_privileged_process (tunnel, default_route);
		if (fd == -1)
		{
			syslog (LOG_ALERT, "%s: %m", _("Teredo tunnel fatal error"));
			goto abort;
		}
	}
	else
#endif
	{
		if (tunnel.SetMTU (mtu) || tunnel.BringUp ()
		 || tunnel.AddAddress (mode == TEREDO_RESTRICT
		 			? &teredo_restrict : &teredo_cone)
		 || tunnel.AddRoute (&prefix.ip6, 32))
		{
			syslog (LOG_ALERT, _("Teredo tunnel fatal error"));
			goto abort;
		}
	}

	if (drop_privileges ())
		goto abort;

#ifdef MIREDO_TEREDO_CLIENT
	if (mode == TEREDO_CLIENT)
	{
		// Sets up client
		try
		{
			relay = new MiredoRelay (fd, &tunnel, server_ip, server_ip2,
			                         bind_port, bind_ip);
		}
		catch (...)
		{
			relay = NULL;
		}
	}
	else
# endif /* ifdef MIREDO_TEREDO_CLIENT */
	{
		// Sets up relay
		try
		{
			relay = new MiredoRelay (&tunnel, prefix.teredo.prefix,
			                         bind_port, bind_ip, mode == TEREDO_CONE);
		}
		catch (...)
		{
			relay = NULL;
		}
	}

	if (relay == NULL)
	{
		syslog (LOG_ALERT, _("Teredo tunnel fatal error"));
		goto abort;
	}

	if (!*relay)
	{
		const char *msg = _("Teredo tunnel fatal error");
		if (bind_port)
			syslog (LOG_ALERT, _("%s:\n cannot open UDP port %u"), msg,
			        (unsigned int)ntohs (bind_port));
		else
			syslog (LOG_ALERT, _("%s:\n cannot open an UDP port"), msg);

		syslog (LOG_NOTICE, _("Make sure another instance of the program is "
		                      "not already running."));
		goto abort;
	}

	retval = 0;
	teredo_relay (sigfd, tunnel, relay);

abort:
	if (relay != NULL)
		delete relay;

#ifdef MIREDO_TEREDO_CLIENT
	if (fd != -1)
	{
		close (fd);
		wait (NULL); // wait for privsep process
	}

	if (mode == TEREDO_CLIENT)
		DeinitNonceGenerator ();
#endif

	return retval;
}
