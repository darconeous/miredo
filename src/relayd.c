/*
 * relayd.c - Miredo: binding between libtun6 and libteredo
 */

/***********************************************************************
 *  Copyright © 2004-2007 Rémi Denis-Courmont.                         *
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <assert.h>
#include <gettext.h>

#include <inttypes.h>
#include <stdlib.h> // free()
#include <stdio.h> // fputs()
#include <sys/types.h>
#include <string.h> // strerror()
#include <errno.h>
#include <unistd.h> // close()
#include <fcntl.h>
#include <sys/wait.h> // wait()
#include <signal.h> // sigemptyset()
#include <syslog.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h> // inet_ntop()
#include <netdb.h> // NI_MAXHOST
#ifdef HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif
#ifndef SOL_IPV6
# define SOL_IPV6 IPPROTO_IPV6
#endif
#ifndef SOL_ICMPV6
# define SOL_ICMPV6 IPPROTO_ICMPV6
#endif

#include <libtun6/tun6.h>

#include <libteredo/teredo.h>
#include <libteredo/tunnel.h>

#include "privproc.h"
#include "miredo.h"
#include "conf.h"


static int relay_diagnose (void)
{
	char errbuf[LIBTUN6_ERRBUF_SIZE];
	if (tun6_driver_diagnose (errbuf))
	{
		fputs (errbuf, stderr);
		return -1;
	}

	return 0;
}


typedef struct miredo_tunnel
{
	tun6 *tunnel;
	int priv_fd;
	teredo_tunnel *relay;
} miredo_tunnel;

static int icmp6_fd = -1;

static int miredo_init (bool client)
{
	if (teredo_startup (client))
		return -1;

	assert (icmp6_fd == -1);

	icmp6_fd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (icmp6_fd == -1)
		return -1;

	miredo_setup_nonblock_fd (icmp6_fd);

	setsockopt (icmp6_fd, SOL_IPV6, IPV6_CHECKSUM, &(int){2}, sizeof (int));

	/* We don't use the socket for receive -> block all */
	struct icmp6_filter filt;
	ICMP6_FILTER_SETBLOCKALL (&filt);
	setsockopt (icmp6_fd, SOL_ICMPV6, ICMP6_FILTER, &filt, sizeof (filt));
	return 0;
}


static void miredo_deinit (bool client)
{
	assert (icmp6_fd != -1);
	close (icmp6_fd);
	teredo_cleanup (client);
}


/**
 * Callback to transmit decapsulated Teredo IPv6 packets to the kernel.
 */
static void
miredo_recv_callback (void *data, const void *packet, size_t length)
{
	assert (data != NULL);

	(void)tun6_send (((miredo_tunnel *)data)->tunnel, packet, length);
}


/**
 * Callback to emit an ICMPv6 error message through a raw ICMPv6 socket.
 */
static void
miredo_icmp6_callback (void *data, const void *packet, size_t length,
                        const struct in6_addr *dst)
{
	(void)data;
	assert (icmp6_fd != -1);

	struct sockaddr_in6 addr =
	{
		.sin6_family = AF_INET6,
#ifdef HAVE_SA_LEN
		.sin6_len = sizeof (struct sockaddr_in6),
#endif
		.sin6_addr = *dst
	};

	/* TODO: use sendmsg and don't memcpy in BuildICMPv6Error */
	(void)sendto (icmp6_fd, packet, length, 0,
	              (struct sockaddr *)&addr, sizeof (addr));
}


#define TEREDO_CONE     0
#define TEREDO_RESTRICT 1
#define TEREDO_CLIENT   2

static bool
ParseRelayType (miredo_conf *conf, const char *name, int *type)
{
	unsigned line;
	char *val = miredo_conf_get (conf, name, &line);

	if (val == NULL)
		return true;

	if ((strcasecmp (val, "client") == 0)
	 || (strcasecmp (val, "autoclient") == 0))
		*type = TEREDO_CLIENT;
	else
	if (strcasecmp (val, "restricted") == 0)
	{
		syslog (LOG_WARNING, _("Using deprecated \"restricted\" relay type "
		        "which is STRONGLY DISCOURAGED (at line %u)."), line);
		*type = TEREDO_RESTRICT;
	}
	else
	if ((strcasecmp (val, "relay") == 0)
	 || (strcasecmp (val, "cone") == 0))
		*type = TEREDO_CONE;
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


#ifdef MIREDO_TEREDO_CLIENT
static void privproc_clean (void *tunnel)
{
	tun6_destroy ((tun6 *)tunnel);
}

static tun6 *
create_dynamic_tunnel (const char *ifname, int *fd)
{
	tun6 *tunnel = tun6_create (ifname);
	if (tunnel == NULL)
		return NULL;

	/* FIXME: we leak all heap-allocated settings in the child process */
	int res = miredo_privileged_process (tun6_getId (tunnel),
	                                     privproc_clean, tunnel);
	if (res == -1)
	{
		tun6_destroy (tunnel);
		return NULL;
	}
	*fd = res;
	return tunnel;
}


static void
destroy_dynamic_tunnel (tun6 *tunnel, int fd)
{
	assert (fd != -1);
	close (fd);

	wait (NULL); // wait for privsep process

	tun6_destroy (tunnel);
}


/**
 * Callback to configure a Teredo tunneling interface.
 */
static void
miredo_up_callback (void *data, const struct in6_addr *addr, uint16_t mtu)
{
	char str[INET6_ADDRSTRLEN];

	syslog (LOG_NOTICE, _("Teredo pseudo-tunnel started"));
	if (inet_ntop (AF_INET6, addr, str, sizeof (str)) != NULL)
		syslog (LOG_INFO, _(" (address: %s, MTU: %"PRIu16")"),
		        str, mtu);

	assert (data != NULL);

	miredo_configure_tunnel (((miredo_tunnel *)data)->priv_fd, addr, mtu);
}


/**
 * Callback to deconfigure a Teredo tunneling interface.
 */
static void
miredo_down_callback (void *data)
{
	assert (data != NULL);

	miredo_configure_tunnel (((miredo_tunnel *)data)->priv_fd, &in6addr_any,
	                         1280);
	syslog (LOG_NOTICE, _("Teredo pseudo-tunnel stopped"));
}


static int
setup_client (teredo_tunnel *client, const char *server, const char *server2)
{
	teredo_set_state_cb (client, miredo_up_callback, miredo_down_callback);
	return teredo_set_client_mode (client, server, server2);
}
#else
# define create_dynamic_tunnel( a, b )   NULL
# define destroy_dynamic_tunnel( a, b )   (void)0
# define setup_client( a, b, c )         (-1)
#endif


static tun6 *
create_static_tunnel (const char *restrict ifname,
                      const struct in6_addr *restrict prefix,
                      uint16_t mtu)
{
	tun6 *tunnel = tun6_create (ifname);

	if ((tunnel == NULL) && (ifname != NULL) && (errno == ENOSYS))
		tunnel = tun6_create (NULL);
	if (tunnel == NULL)
		return NULL;

	if (tun6_setMTU (tunnel, mtu) || tun6_bringUp (tunnel)
	 || tun6_addAddress (tunnel, &teredo_restrict, 64)
	 || tun6_addRoute (tunnel, prefix, 32, 0))
	{
		tun6_destroy (tunnel);
		return NULL;
	}
	return tunnel;
}


#if 0 && !defined (MIREDO_DEFAULT_USERNAME)
static void
destroy_static_tunnel (tun6 *restrict tunnel,
                       const struct in6_addr *restrict prefix)
{
	/*
	 * Manual clean up of the tunnel device is only possible if we retain root
	 * privileges. Unfortunately, if we don't do this, it becomes impossible
	 * to restart Miredo on FreeBSD. The proper fix belongs in the FreeBSD
	 * kernel - that's the only way to handle kills (or would-be crashes) of
	 * Miredo; that's part of the standard job of a solid kernel process
	 * killer.
	 */
	tun6_delRoute (tunnel, prefix, 32, 0);
	tun6_delAddress (tunnel, &teredo_restrict, 64);
	tun6_bringDown (tunnel);
	tun6_destroy (tunnel);
}
#else
# define destroy_static_tunnel( t, p ) tun6_destroy( t )
#endif


static int
setup_relay (teredo_tunnel *relay, uint32_t prefix, bool cone)
{
	teredo_set_prefix (relay, prefix);
	teredo_set_cone_flag (relay, cone);
	return teredo_set_relay_mode (relay);
}


/**
 * Thread to encapsulate IPv6 packets into UDP.
 * Cancellation safe.
 */
static LIBTEREDO_NORETURN void *miredo_encap_thread (void *d)
{
	teredo_tunnel *relay = ((miredo_tunnel *)d)->relay;
	tun6 *tunnel = ((miredo_tunnel *)d)->tunnel;

	for (;;)
	{
		/* Handle incoming data */
		struct
		{
			struct ip6_hdr ip6;
			uint8_t fill[65467];
		} pbuf;

		/* Forwards IPv6 packet to Teredo
		 * (Packet transmission) */
		int val = tun6_wait_recv (tunnel, &pbuf.ip6, sizeof (pbuf));
		if (val >= 40)
		{
			pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, NULL);
			teredo_transmit (relay, &pbuf.ip6, val);
			pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
		}
		else
			pthread_testcancel ();
	}
}


/**
 * Miredo main daemon function, with UDP datagrams and IPv6 packets
 * receive loop.
 */
static int
run_tunnel (miredo_tunnel *tunnel)
{
	pthread_t encap_th;
	if (teredo_run_async (tunnel->relay)
	 || pthread_create (&encap_th, NULL, miredo_encap_thread, tunnel))
		return -1;

	sigset_t dummyset, set;
	sigemptyset (&dummyset);
	pthread_sigmask (SIG_BLOCK, &dummyset, &set);
	while (sigwait (&set, &(int){ 0 }));

	pthread_cancel (encap_th);
	pthread_join (encap_th, NULL);
	return 0;
}


static int
relay_run (miredo_conf *conf, const char *server_name)
{
	/*
	 * CONFIGURATION
	 */
	union teredo_addr prefix;
	memset (&prefix, 0, sizeof (prefix));
	prefix.teredo.prefix = htonl (TEREDO_PREFIX);

	int mode = TEREDO_CLIENT;
	if (!ParseRelayType (conf, "RelayType", &mode))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
	}

#ifdef MIREDO_TEREDO_CLIENT
	const char *server_name2 = NULL;
	char namebuf[NI_MAXHOST], namebuf2[NI_MAXHOST];
#endif
	uint16_t mtu = 1280;
	bool cone = false;

	if (mode & TEREDO_CLIENT)
	{
#ifdef MIREDO_TEREDO_CLIENT
		if (server_name == NULL)
		{
			char *name = miredo_conf_get (conf, "ServerAddress", NULL);
			if (name == NULL)
			{
				syslog (LOG_ALERT, _("Server address not specified"));
				syslog (LOG_ALERT, _("Fatal configuration error"));
				return -2;
			}
			strlcpy (namebuf, name, sizeof (namebuf));
			free (name);
			server_name = namebuf;

			name = miredo_conf_get (conf, "ServerAddress2", NULL);
			if (name != NULL)
			{
				strlcpy (namebuf2, name, sizeof (namebuf2));
				free (name);
				server_name2 = namebuf2;
			}
		}
#else
		syslog (LOG_ALERT, _("Unsupported Teredo client mode"));
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
#endif
	}
	else
	{
		server_name = NULL;
		mtu = 1280;
		cone = (mode == TEREDO_CONE);

		if (!miredo_conf_parse_teredo_prefix (conf, "Prefix",
		                                      &prefix.teredo.prefix)
		 || !miredo_conf_get_int16 (conf, "InterfaceMTU", &mtu, NULL))
		{
			syslog (LOG_ALERT, _("Fatal configuration error"));
			return -2;
		}
	}

	uint32_t bind_ip = INADDR_ANY;
	uint16_t bind_port = 
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

	if (!miredo_conf_parse_IPv4 (conf, "BindAddress", &bind_ip)
	 || !miredo_conf_get_int16 (conf, "BindPort", &bind_port, NULL))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
	}

	bind_port = htons (bind_port);

	char *ifname = miredo_conf_get (conf, "InterfaceName", NULL);

	miredo_conf_clear (conf, 5);

	/*
	 * SETUP
	 */

	// Tunneling interface initialization
	int privfd = -1;
	tun6 *tunnel = (mode & TEREDO_CLIENT)
		? create_dynamic_tunnel (ifname, &privfd)
		: create_static_tunnel (ifname, &prefix.ip6, mtu);

	if (ifname != NULL)
		free (ifname);

	int retval = -1;

	if (tunnel == NULL)
	{
		syslog (LOG_ALERT, _("Miredo setup failure: %s"),
		        _("Cannot create IPv6 tunnel"));
		return -1;
	}

	if (miredo_init ((mode & TEREDO_CLIENT) != 0))
		syslog (LOG_ALERT, _("Miredo setup failure: %s"),
		        _("libteredo cannot be initialized"));
	else
	{
		if (drop_privileges () == 0)
		{
			teredo_tunnel *relay = teredo_create (bind_ip, bind_port);
			if (relay != NULL)
			{
				miredo_tunnel data = { tunnel, privfd, relay };
				teredo_set_privdata (relay, &data);
				teredo_set_recv_callback (relay, miredo_recv_callback);
				teredo_set_icmpv6_callback (relay, miredo_icmp6_callback);

				retval = (mode & TEREDO_CLIENT)
					? setup_client (relay, server_name, server_name2)
					: setup_relay (relay, prefix.teredo.prefix, cone);
	
				/*
				 * RUN
				 */
				if (retval == 0)
					retval = run_tunnel (&data);
				teredo_destroy (relay);
			}

			if (retval)
				syslog (LOG_ALERT, _("Miredo setup failure: %s"),
				        _("libteredo cannot be initialized"));
		}
		miredo_deinit ((mode & TEREDO_CLIENT) != 0);
	}

	if (mode & TEREDO_CLIENT)
		destroy_dynamic_tunnel (tunnel, privfd);
	else
		destroy_static_tunnel (tunnel, &prefix.ip6);

	return retval;
}


extern void miredo_setup_fd (int fd)
{
	(void) fcntl (fd, F_SETFD, FD_CLOEXEC);
}


extern void miredo_setup_nonblock_fd (int fd)
{
	int flags = fcntl (fd, F_GETFL);
	if (flags == -1)
		flags = 0;
	(void) fcntl (fd, F_SETFL, O_NONBLOCK | flags);
	miredo_setup_fd (fd);
}


int main (int argc, char *argv[])
{
#ifdef HAVE_LIBCAP
	static const cap_value_t capv[] =
	{
		CAP_NET_ADMIN, /* required by libtun6 */
		CAP_NET_RAW /* required for raw ICMPv6 socket */
	};

	miredo_capv = capv;
	miredo_capc = sizeof (capv) / sizeof (capv[0]);
#endif

	miredo_name = "miredo";
	miredo_diagnose = relay_diagnose;
	miredo_run = relay_run;

	return miredo_main (argc, argv);
}

