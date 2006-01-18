/*
 * tun6.c - IPv6 tunnel interface definition
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2004-2006 Remi Denis-Courmont.                       *
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

#include <assert.h>

#include <stdio.h> // snprintf() for BSD drivers
#include <string.h>
#include <stdlib.h> // free()
#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYES_H
# include <inttypes.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include <sys/socket.h> // socket(AF_INET6, SOCK_DGRAM, 0)
#include <netinet/in.h> // htons()

#include <net/if.h> // struct ifreq, if_nametoindex()

#if defined (HAVE_LINUX)
/*
 * Linux tunneling driver
 */
# include <linux/if_tun.h> // TUNSETIFF - Linux tunnel driver
/*
 * <linux/ipv6.h> conflicts with <netinet/in.h> and <arpa/inet.h>,
 * so we've got to declare this structure by hand.
 */
struct in6_ifreq {
	struct in6_addr ifr6_addr;
	uint32_t ifr6_prefixlen;
	int ifr6_ifindex;
};

# include <net/route.h> // struct in6_rtmsg

# define USE_TUNHEAD
static const char *os_driver = "Linux";

#elif defined (HAVE_FREEBSD) || defined (HAVE_OPENBSD) || \
	defined (HAVE_NETBSD) || defined (HAVE_DARWIN)
/*
 * BSD tunneling driver
 * NOTE: the driver does NOT really work on NetBSD
 * because NetBSD tun driver only accepts IPv4 packets.
 * NOTE: the driver is NOT tested on Darwin (Mac OS X).
 */

# if defined (HAVE_FREEBSD)
#  include <net/if_var.h>
#  include <net/if_tun.h> // TUNSIFHEAD - FreeBSD tunnel driver
# define USE_TUNHEAD
static const char *os_driver = "FreeBSD";

# elif defined (HAVE_OPENBSD)
#  define USE_TUNHEAD
static const char *os_driver = "OpenBSD";

# elif defined (HAVE_NETBSD)
static const char *os_driver = "NetBSD";

# elif defined (HAVE_DARWIN)
static const char *os_driver = "Darwin";

# else
# error FIXME: Unknown BSD variant!
# endif /* if HAVE_*BSD */

# include <net/if_dl.h> // struct sockaddr_dl
# include <net/route.h> // AF_ROUTE things
# include <errno.h> // errno

# include <netinet6/in6_var.h> // struct in6_aliasreq
# include <netinet6/nd6.h> // ND6_INFINITE_LIFETIME

# define HAVE_BSD

#else
static const char *os_driver = "Generic";

# warn Unknown host OS. The driver will probably not work.
#endif

#ifdef USE_TUNHEAD
# include <sys/uio.h> // readv() & writev()
#endif

#ifndef ETH_P_IPV6
# define ETH_P_IPV6 0x86DD
#endif

#include "tun6.h"

static inline void
secure_strncpy (char *tgt, const char *src, size_t len)
{
#ifndef HAVE_STRLCPY
	strncpy (tgt, src, --len);
	tgt[len] = '\0';
#else
	strlcpy (tgt, src, len);
#endif
}


struct tun6
{
	char name[IFNAMSIZ];
	int  fd, reqfd;
};

/*
 * Allocates a tunnel network interface from the kernel
 */
tun6 *tun6_create (const char *req_name)
{
	int fd, reqfd;

	tun6 *t = (tun6 *)malloc (sizeof (*t));
	if (t == NULL)
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %m"), "malloc");
		return NULL;
	}

	t->reqfd = reqfd = socket (AF_INET6, SOCK_DGRAM, 0);
	if (reqfd == -1)
	{
		free (t);
		return NULL;
	}

#if defined (HAVE_LINUX)
	/*
	 * TUNTAP (Linux) tunnel driver initialization
	 */
	static const char tundev[] = "/dev/net/tun";
	struct ifreq req;

	fd = open (tundev, O_RDWR);
	if (fd == -1)
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %m"), tundev);
		close (reqfd);
		free (t);
		return NULL;
	}

	// Allocates the tunneling virtual network interface
	memset (&req, 0, sizeof (req));
	if (req_name != NULL)
		secure_strncpy (req.ifr_name, req_name, IFNAMSIZ);
	req.ifr_flags = IFF_TUN;

	if (ioctl (fd, TUNSETIFF, (void *)&req))
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %m"), "TUNSETIFF");
		goto error;
	}

	secure_strncpy (t->name, req.ifr_name, sizeof (t->name));
#elif defined (HAVE_BSD)
	/*
	 * BSD tunnel driver initialization
	 */
	char tundev[12];

	for (unsigned i = 0; (i < 256) && (fd == -1); i++)
	{
		const int dummy = 1;

		snprintf (tundev, sizeof (tundev), "/dev/tun%u", i);
		tundev[sizeof (tundev) - 1] = '\0';

		fd = open (tundev, O_RDWR);
		if (fd == -1)
			continue;

# if 0
		/* TODO: have this work on FreeBSD
		 * Overrides the interface name */
		struct ifreq req;
		memset (&req, 0, sizeof (req));
		ifname = strdup (req_name);
		req.ifr_data = ifname;

		if (ioctl (reqfd, SIOCSIFNAME, &req))
		{
			syslog (LOG_ERR,
			        _("Tunneling driver error (%s): %m"), "SIOCSIFNAME");
			fd = -1;
			continue;
		}
# else /* SIOCSIFNAME */
		secure_strncpy (t->name, tundev + 5, sizeof (t->name));
		/* strlen ("/dev/") == 5 */
# endif /* SIOCSIFNAME */

# ifdef TUNSIFHEAD
		/* Enables TUNSIFHEAD */
		if (ioctl (fd, TUNSIFHEAD, &dummy))
		{
			syslog (LOG_ERR, _("Tunneling driver error (%s): %m"),
			        "TUNSIFHEAD");
			fd = -1;
		}
# endif /* TUNSIFHEAD */
	}

	if (fd == -1)
		goto error;
#else
# error No tunneling driver implemented on your platform!
#endif

	t->fd = fd;
	return t;

error:
	close (reqfd);
	if (fd != -1)
		close (fd);
	syslog (LOG_ERR, _("%s tunneling interface creation failure"), os_driver);
	free (t);
	return NULL;
}


/*
 * Removes the tunnel interface from the current process context.
 * The tunnel will be removed by the kernel once all processes which have
 * access to it called the destructor or exited.
 */
void tun6_destroy (tun6* t)
{
	assert (t != NULL);
	assert (t->fd != -1);
	assert (t->reqfd != -1);

	close (t->fd);
	close (t->reqfd);
	free (t);
}


/*
 * Unless otherwise stated, all the methods thereafter should return -1 on
 * error, and 0 on success. Similarly, they should require root privileges.
 */

#if defined (HAVE_LINUX)
static void
proc_write_zero (const char *path)
{
	int fd;

	fd = open (path, O_WRONLY);
	if (fd != -1)
	{
		write (fd, "0", 1);
		close (fd);
	}
}
#endif


/*
 * Brings the tunnel interface up or down.
 */
int
tun6_setState (tun6 *t, bool up)
{
	struct ifreq req;
	const char *ifname;

	assert (t != NULL);

	ifname = t->name;

	/* Sets up the interface */
	memset (&req, 0, sizeof (req));	
	secure_strncpy (req.ifr_name, ifname, IFNAMSIZ);
	if (ioctl (t->reqfd, SIOCGIFFLAGS, &req))
		return -1;

	secure_strncpy (req.ifr_name, ifname, IFNAMSIZ);
	/* settings we want/don't want: */
	req.ifr_flags |= IFF_NOARP | IFF_POINTOPOINT;
	if (up)
		req.ifr_flags |= IFF_UP | IFF_RUNNING;
	else
		req.ifr_flags &= ~IFF_UP | IFF_RUNNING;
	req.ifr_flags &= ~(IFF_MULTICAST | IFF_BROADCAST);

	if (ioctl (t->reqfd, SIOCSIFFLAGS, &req) == 0)
		return 0;

	return -1;

}


#ifdef HAVE_BSD
/*
 * Converts a prefix length to a netmask (used for the BSD routing)
 */
static void
plen_to_mask (unsigned plen, struct in6_addr *mask)
{
	memset (&mask->s6_addr, 0x00, 16);

	div_t d = div (plen, 8);
	int i;

	for (i = 0; i < d.quot; i ++)
		mask->s6_addr[i] = 0xff;

	if (d.rem)
		mask->s6_addr[i] = 0xff << (8 - d.rem);
}

static void
plen_to_sin6 (unsigned plen, struct sockaddr_in6 *sin6)
{
	memset (sin6, 0, sizeof (struct sockaddr_in6));

	/* NetBSD kernel strangeness:
	 sin6->sin6_family = AF_INET6;*/
# if HAVE_SA_LEN
	sin6->sin6_len = sizeof (struct sockaddr_in6);
# endif
	plen_to_mask (plen, &sin6->sin6_addr);
}
#endif /* ifdef SOCAIFADDR_IN6 */

/*
 * Adds or removes an address and a prefix to the tunnel interface.
 */
static int
_iface_addr (int reqfd, const char *ifname, bool add,
             const struct in6_addr *addr, unsigned prefix_len)
{
	void *req = NULL;
	long cmd = 0;

	assert (reqfd != -1);
	assert (ifname != NULL);

	if ((prefix_len > 128) || (addr == NULL))
		return -1;

#if defined (HAVE_LINUX)
	/*
	 * Linux ioctl interface
	 */
	union
	{
		struct in6_ifreq req6;
		struct ifreq req;
	} r;

	memset (&r, 0, sizeof (r));
	r.req6.ifr6_ifindex = if_nametoindex (ifname);
	memcpy (&r.req6.ifr6_addr, addr, sizeof (r.req6.ifr6_addr));
	r.req6.ifr6_prefixlen = prefix_len;

	cmd = add ? SIOCSIFADDR : SIOCDIFADDR;
	req = &r;
#elif defined (HAVE_BSD)
	/*
	 * BSD ioctl interface
	 */
	union
	{
		struct in6_aliasreq addreq6;
		struct in6_ifreq delreq6;
	} r;

	if (add)
	{
		memset (&r.addreq6, 0, sizeof (r.addreq6));
		secure_strncpy (r.addreq6.ifra_name, ifname, IFNAMSIZ);
		r.addreq6.ifra_addr.sin6_family = AF_INET6;
		r.addreq6.ifra_addr.sin6_len = sizeof (r.addreq6.ifra_addr);
		memcpy (&r.addreq6.ifra_addr.sin6_addr, addr,
			sizeof (r.addreq6.ifra_addr.sin6_addr));

		plen_to_sin6 (prefix_len, &r.addreq6.ifra_prefixmask);

		r.addreq6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
		r.addreq6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

		cmd = SIOCAIFADDR_IN6;
		req = &r.addreq6;
	}
	else
	{
		memset (&r.delreq6, 0, sizeof (r.delreq6));
		secure_strncpy (r.delreq6.ifr_name, ifname, IFNAMSIZ);
		r.delreq6.ifr_addr.sin6_family = AF_INET6;
		r.delreq6.ifr_addr.sin6_len = sizeof (r.delreq6.ifr_addr);
		memcpy (&r.delreq6.ifr_addr.sin6_addr, addr,
			sizeof (r.delreq6.ifr_addr.sin6_addr));

		cmd = SIOCDIFADDR_IN6;
		req = &r.delreq6;
	}
#else
# error FIXME tunnel address setup not implemented
#endif

	return ioctl (reqfd, cmd, req) >= 0 ? 0 : -1;
}


/*
 * Adds or removes a route to the tunnel interface from the kernel routing
 * table.
 */
static int
_iface_route (int reqfd, const char *ifname, bool add,
              const struct in6_addr *addr, unsigned prefix_len,
              int rel_metric)
{
	assert (reqfd != -1);
	assert (ifname != NULL);

	if ((prefix_len > 128) || (addr == NULL))
		return -1;

	int retval = -1;

#if defined (HAVE_LINUX)
	/*
	 * Linux ioctl interface
	 */
	struct in6_rtmsg req6;

	/* Adds/deletes route */
	memset (&req6, 0, sizeof (req6));
	req6.rtmsg_flags = RTF_UP;
	req6.rtmsg_ifindex = if_nametoindex (ifname);
	memcpy (&req6.rtmsg_dst, addr, sizeof (req6.rtmsg_dst));
	req6.rtmsg_dst_len = (unsigned short)prefix_len;
	/* By default, the Linux kernel's metric is 256 for subnets,
	 * and 1024 for gatewayed route. */
	req6.rtmsg_metric = 1024 + rel_metric;
	if (prefix_len == 128)
		req6.rtmsg_flags |= RTF_HOST;
	/* no gateway */

	if (ioctl (reqfd, add ? SIOCADDRT : SIOCDELRT, &req6) == 0)
		retval = 0;
#elif defined (HAVE_BSD)
	/*
	 * BSD routing socket interface
	 * FIXME: metric unimplemented
	 */
	int s = socket (AF_ROUTE, SOCK_RAW, AF_INET6);
	if (s != -1)
	{
		static int rtm_seq = 0;
		struct
		{
			struct rt_msghdr hdr;
			struct sockaddr_in6 dst;
			struct sockaddr_dl gw;
			struct sockaddr_in6 mask;
		} msg;

		shutdown (s, 0);

		memset (&msg, 0, sizeof (msg));
		msg.hdr.rtm_msglen = sizeof (msg);
		msg.hdr.rtm_version = RTM_VERSION;
		msg.hdr.rtm_type = add ? RTM_ADD : RTM_DELETE;
		msg.hdr.rtm_index = if_nametoindex (ifname);
		msg.hdr.rtm_flags = RTF_UP | RTF_STATIC;
		msg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
		if (prefix_len == 128)
			msg.hdr.rtm_flags |= RTF_HOST;
		msg.hdr.rtm_pid = getpid ();

		msg.hdr.rtm_seq = ++rtm_seq;

		msg.dst.sin6_family = AF_INET6;
		msg.dst.sin6_len = sizeof (msg.dst);
		memcpy (&msg.dst.sin6_addr, addr, sizeof (msg.dst.sin6_addr));

		msg.gw.sdl_family = AF_LINK;
		msg.gw.sdl_len = sizeof (msg.gw);
		msg.gw.sdl_index = if_nametoindex (ifname);

		plen_to_sin6 (prefix_len, &msg.mask);

		errno = 0;

		if ((write (s, &msg, sizeof (msg)) == sizeof (msg))
		 && (errno == 0))
			retval = 0;

		close (s);
	}
	else
		syslog (LOG_ERR, _("Error (%s): %s\n", "socket (AF_ROUTE)",
		        strerror (errno));
#else
# error FIXME route setup not implemented
#endif

	return retval;
}


int
tun6_addAddress (tun6 *t, const struct in6_addr *addr, unsigned prefixlen)
{
	assert (t != NULL);

	int res = _iface_addr (t->reqfd, t->name, true, addr, prefixlen);

#if defined (HAVE_LINUX)
	if (res == 0)
	{
		char proc_path[24 + IFNAMSIZ + 16 + 1] = "/proc/sys/net/ipv6/conf/";

		/* Disable Autoconfiguration and ICMPv6 redirects */
		sprintf (proc_path + 24, "%s/accept_ra", t->name);
		proc_write_zero (proc_path);
				
		sprintf (proc_path + 24, "%s/accept_redirects", t->name);
		proc_write_zero (proc_path);
				
		sprintf (proc_path + 24, "%s/autoconf", t->name);
		proc_write_zero (proc_path);
	}
#endif

	return res;
}


int
tun6_delAddress (tun6 *t, const struct in6_addr *addr, unsigned prefixlen)
{
	assert (t != NULL);

	return _iface_addr (t->reqfd, t->name, false, addr, prefixlen);
}


int
tun6_addRoute (tun6 *t, const struct in6_addr *addr, unsigned prefix_len,
               int rel_metric)
{
	assert (t != NULL);

	return _iface_route (t->reqfd, t->name, true, addr, prefix_len,
	                     rel_metric);
}


int
tun6_delRoute (tun6 *t, const struct in6_addr *addr, unsigned prefix_len,
               int rel_metric)
{
	assert (t != NULL);

	return _iface_route (t->reqfd, t->name, false, addr, prefix_len,
	                     rel_metric);
}


/*
 * Defines the tunnel interface Max Transmission Unit (bytes).
 */
int
tun6_setMTU (tun6 *t, unsigned mtu)
{
	struct ifreq req;

	assert (t != NULL);

	if ((mtu < 1280) || (mtu > 65535))
		return -1;

	memset (&req, 0, sizeof (req));
	secure_strncpy (req.ifr_name, t->name, IFNAMSIZ);
	req.ifr_mtu = mtu;

	return ioctl (t->reqfd, SIOCSIFMTU, &req) ? -1 : 0;
}



/*
 * These functions do not require root privileges:
 */

/*
 * Registers the tunnel file descriptor for select().
 * When selects return, you should call ReceivePacket() with the same fd_set.
 */
int
tun6_registerReadSet (const tun6 *t, fd_set *readset)
{
	assert (t != NULL);

	FD_SET (t->fd, readset);
	return t->fd;
}


/*
 * Tries to receive a packet from the kernel networking stack.
 * Fails if fd is not in the readset. Call this function when select()
 * returns.
 */
int
tun6_recv (const tun6 *t, const fd_set *readset, void *buffer, size_t maxlen)
{
	assert (t != NULL);

	int fd = t->fd;
	if (!FD_ISSET (fd, readset))
		return -1;

#if defined (USE_TUNHEAD)
	struct iovec vect[2];
	union
	{
		struct
		{
			uint16_t flags;
			uint16_t proto;
		} tun_linux;
		uint32_t tun_bsd;
	} head;

	vect[0].iov_base = (char *)&head;
	vect[0].iov_len = sizeof (head);
	vect[1].iov_base = (char *)buffer;
	vect[1].iov_len = maxlen;

	int len = readv (fd, vect, 2);
#else /* USE_TUNHEAD */
	int len = read (fd, buffer, maxlen);
#endif /* USE_TUNHEAD */

	if (len == -1)
		return -1;
#if defined (USE_TUNHEAD)
	len -= sizeof (head);

	if (len < 0)
		return -1;
#endif /* USE_TUNHEAD */

#if defined (HAVE_LINUX)
	/* TUNTAP driver */
	if (head.tun_linux.proto != htons (ETH_P_IPV6))
		return -1; /* only accept IPv6 packets */
#elif defined (HAVE_FREEBSD) || defined (HAVE_OPENBSD)
	/* FreeBSD driver */
	if (head.tun_bsd != htonl (AF_INET6))
		return -1;
#endif

	return len;
}


/*
 * Sends a packet from userland to the kernel's networking stack.
 */
int
tun6_send (const tun6 *t, const void *packet, size_t len)
{
#if defined (HAVE_LINUX)
	struct
{
	uint16_t flags;
	uint16_t proto;
} head = { 0, htons (ETH_P_IPV6) };
#elif defined (HAVE_FREEBSD) || defined (HAVE_OPENBSD)
	uint32_t head = htonl (AF_INET6);
#endif

	assert (t != NULL);

	if (len > 65535)
		return -1;

#if defined (USE_TUNHEAD)
	struct iovec vect[2];
	vect[0].iov_base = (char *)&head;
	vect[0].iov_len = sizeof (head);
	vect[1].iov_base = (char *)packet; /* necessary cast to non-const */
	vect[1].iov_len = len;

	int val = writev (t->fd, vect, 2);
#else /* USE_TUNHEAD */
	int val = write (t->fd, packet, len);
#endif /* USE_TUNHEAD */

	if (val == -1)
		return -1;

#if defined (USE_TUNHEAD)
	val -= sizeof (head);

	if (val < 0)
		return -1;
#endif

	return val;
}


int tun6_driver_diagnose (char *errbuf)
{
#if defined (HAVE_LINUX)
	const char *const tundev = "/dev/net/tun";
#else
	const char *const tundev = "/dev/tun0";
#endif

	int fd = open (tundev, O_RDWR);
	if (fd >= 0)
	{
		close (fd);
		snprintf (errbuf, LIBTUN6_ERRBUF_SIZE - 1,
				"%s tunneling driver found.", os_driver);
		errbuf[LIBTUN6_ERRBUF_SIZE - 1] = '\0';
		return 0;
	}

	if (errno == ENOENT)
	{
		const char *specific;

#if defined (HAVE_LINUX)
		specific = N_("You should run these commands to create it:\n"
			"# mkdir -p /dev/net\n"
			"# mknod /dev/net/tun c 10 200\n"
			"(you must be root to do that).\n");
#elif defined (HAVE_DARWIN)
		specific = N_("You can obtain a tunnel driver for the "
			"Darwin kernel (Mac OS X) from:\n"
			"http://chrisp.de/en/projects/tunnel.html\n");
#else
		specific = NULL;
#endif

		snprintf (errbuf, LIBTUN6_ERRBUF_SIZE - 1,
			_("Error: %s character device "
			"not found or unavailable.\n%s"), tundev,
			specific != NULL ? gettext (specific) : "");
		errbuf[LIBTUN6_ERRBUF_SIZE - 1] = '\0';
		return -1;
	}
	else
	/* Linux returns ENODEV instead of ENXIO */
	if ((errno == ENXIO) || (errno == ENODEV))
	{
		const char *specific;

#if defined (HAVE_LINUX)
		specific = N_("Make sure your Linux kernel includes "
			"the \"Universal TUNTAP driver\"\n"
			"(CONFIG_TUN option), possibly as a module.\n");
#elif defined (HAVE_DARWIN)
		specific = N_("You can obtain a tunnel driver for the "
			"Darwin kernel (Mac OS X) from:\n"
			"http://chrisp.de/en/projects/tunnel.html\n");
#else
		specific = NULL;
#endif

		snprintf (errbuf, LIBTUN6_ERRBUF_SIZE - 1,
			_("Error: your operating system does not "
			"seem to provide a network tunnneling\n"
			"device driver, which is required.\n%s"),
			specific != NULL ? gettext (specific) : "");
		errbuf[LIBTUN6_ERRBUF_SIZE - 1] = '\0';
		return -1;
	}

	snprintf (errbuf, LIBTUN6_ERRBUF_SIZE - 1,
		_("Error: cannot open device file %s (%s)\n"
		"IPv6 tunneling will not work.\n"), tundev,
		strerror (errno));
	errbuf[LIBTUN6_ERRBUF_SIZE - 1] = '\0';
	return -1;
}

