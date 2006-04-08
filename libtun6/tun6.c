/*
 * tun6.c - IPv6 tunnel interface definition
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
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
#include <sys/uio.h> // readv() & writev()
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h> // htons(), struct in6_addr

#include <sys/socket.h> // socket(AF_INET6, SOCK_DGRAM, 0)

#include <net/if.h> // struct ifreq, if_nametoindex()

#if defined (__linux__)
/*
 * Linux tunneling driver
 */
static const char *os_driver = "Linux";
# define USE_LINUX 1

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
# include <netinet/if_ether.h> // ETH_P_IPV6

typedef struct
{
	uint16_t flags;
	uint16_t proto;
} tun_head_t;

# define TUN_HEAD_IPV6_INITIALIZER { 0, htons (ETH_P_IPV6) }
# define tun_head_is_ipv6( h ) (h.proto == htons (ETH_P_IPV6))

#elif defined (__FreeBSD__) || defined (__FreeBSD_kernel__) || \
      defined (__NetBSD__)  || defined (__NetBSD_kernel__)  || \
      defined (__OpenBSD__) || defined (__OpenBSD_kernel__) || \
      defined (__DragonFly__) || \
      defined (__APPLE__) /* Darwin */
/*
 * BSD tunneling driver
 * NOTE: the driver is NOT tested on Darwin (Mac OS X).
 */
static const char *os_driver = "BSD";
# define USE_BSD 1

# if defined (HAVE_NET_IF_TUN_H)
#  include <net/if_tun.h> // TUNSIFHEAD, TUNSLMODE
# elif defined (__APPLE__)
#  define TUNSIFHEAD  _IOW('t', 96, int)
# endif
# ifdef HAVE_NET_IF_VAR_H
#  include <net/if_var.h>
# endif

# include <net/if_dl.h> // struct sockaddr_dl
# include <net/route.h> // AF_ROUTE things
# include <netinet6/in6_var.h> // struct in6_aliasreq
# include <netinet6/nd6.h> // ND6_INFINITE_LIFETIME

# include <pthread.h>

typedef uint32_t tun_head_t;

# define TUN_HEAD_IPV6_INITIALIZER htonl (AF_INET6)
# define tun_head_is_ipv6( h ) (h == htonl (AF_INET6))

#else
static const char *os_driver = "Generic";

# warn Unknown host OS. The driver will probably not work.
#endif

#include <libtun6/tun6.h>

#define safe_strcpy( tgt, src ) \
	((strlcpy (tgt, src, sizeof (tgt)) >= sizeof (tgt)) ? -1 : 0)

struct tun6
{
	char name[IFNAMSIZ];
	int  fd, reqfd;
};

/**
 * Tries to allocate a tunnel interface from the kernel.
 *
 * @param req_name may be an interface name for the virtual network device
 * (it might be ignored on some OSes).
 * If NULL, an internal default will be used.
 *
 * @return NULL on error.
 */
tun6 *tun6_create (const char *req_name)
{
	(void)bindtextdomain (PACKAGE_NAME, LOCALEDIR);
	tun6 *t = (tun6 *)malloc (sizeof (*t));
	if (t == NULL)
		return NULL;

	int reqfd = t->reqfd = socket (AF_INET6, SOCK_DGRAM, 0);
	if (reqfd == -1)
	{
		free (t);
		return NULL;
	}

#if defined (USE_LINUX)
	/*
	 * TUNTAP (Linux) tunnel driver initialization
	 */
	static const char tundev[] = "/dev/net/tun";
	struct ifreq req;

	memset (&req, 0, sizeof (req));
	req.ifr_flags = IFF_TUN;
	if ((req_name != NULL) && safe_strcpy (req.ifr_name, req_name))
		return NULL;

	int fd = open (tundev, O_RDWR);
	if (fd == -1)
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %s"), tundev,
		        strerror (errno));
		(void)close (reqfd);
		free (t);
		return NULL;
	}

	// Allocates the tunneling virtual network interface
	if (ioctl (fd, TUNSETIFF, (void *)&req))
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %s"), "TUNSETIFF",
		        strerror (errno));
		goto error;
	}

	if (safe_strcpy (t->name, req.ifr_name))
		goto error;
#elif defined (USE_BSD)
	/*
	 * BSD tunnel driver initialization
	 * (see BSD src/sys/net/if_tun.{c,h})
	 */
	const char *errmsg = NULL;
	int fd = -1, errval = 0;

	for (unsigned i = 0; (i <= 255) && (fd == -1); i++)
	{
		char tundev[12];
		snprintf (tundev, sizeof (tundev), "/dev/tun%u", i);
		tundev[sizeof (tundev) - 1] = '\0';

		int tunfd = open (tundev, O_RDWR);
		if (tunfd == -1)
		{
			if (errno != ENOENT)
				errval = errno;
			continue;
		}

		int value;
# ifdef TUNSIFMODE
		value = IFF_BROADCAST;
		if (ioctl (tunfd, TUNSIFMODE, &value))
		{
			errmsg = "TUNSIFMODE";
			goto next;
		}
# endif
# if defined TUNSIFHEAD
		/* Enables TUNSIFHEAD */
		value = 1;
		if (ioctl (tunfd, TUNSIFHEAD, &value))
		{
			errmsg = "TUNSIFHEAD";
			goto next;
		}
# elif defined TUNSLMODE
		/* Disables TUNSLMODE (deprecated opposite of TUNSIFHEAD) */
		value = 0;
		if (ioctl (tunfd, TUNSLMODE, &value))
		{
			errmsg = "TUNSLMODE";
			goto next;
		}
#endif

# if 0
		/* TODO: have this work on FreeBSD
		 * Overrides the interface name */
		struct ifreq req;
		memset (&req, 0, sizeof (req));
		ifname = strdup (req_name);
		req.ifr_data = ifname;

		if (ioctl (reqfd, SIOCSIFNAME, &req))
		{
			errmsg = "SIOCSIFNAME";
			goto next;
		}
# else /* 0 */
		/* Skips "/dev/" (5 bytes) */
		if (safe_strcpy (t->name, tundev + 5))
			goto next;
# endif /* if 0 */

		fd = tunfd;
		errval = errno;
		break;

	next:
		(void)close (tunfd);
	}

	if (fd == -1)
	{
		if (errmsg == NULL)
			errmsg = "/dev/tun0";
		if (errval == 0)
			errval = ENOENT;
		syslog (LOG_ERR, _("Tunneling driver error (%s): %s"),
		        errmsg, strerror (errval));
		goto error;
	}
#else
# error No tunneling driver implemented on your platform!
#endif /* HAVE_os */

	t->fd = fd;
	return t;

error:
	(void)close (reqfd);
	if (fd != -1)
		(void)close (fd);
	syslog (LOG_ERR, _("%s tunneling interface creation failure"), os_driver);
	free (t);
	return NULL;
}


/**
 * Removes a tunnel from the kernel.
 * BEWARE: if you fork, child processes must call tun6_destroy() too.
 *
 * The kernel will destroy the tunnel interface once all processes called
 * tun6_destroy and/or were terminated.
 */
void tun6_destroy (tun6* t)
{
	assert (t != NULL);
	assert (t->fd != -1);
	assert (t->reqfd != -1);

	(void)close (t->fd);
	(void)close (t->reqfd);
	free (t);
}


/*
 * Unless otherwise stated, all the methods thereafter should return -1 on
 * error, and 0 on success. Similarly, they should require root privileges.
 */

/**
 * @return the name of the tunnel device
 */
const char *tun6_getName (const tun6 *t)
{
	assert (t != NULL);

	return t->name;
}

/**
 * @return the scope id of the tunnel device
 */
int tun6_getId (const tun6 *t)
{
	assert (t != NULL);

	return if_nametoindex (tun6_getName (t));
}


#if defined (USE_LINUX)
static void
proc_write_zero (const char *path)
{
	int fd;

	fd = open (path, O_WRONLY);
	if (fd != -1)
	{
		write (fd, "0", 1);
		(void)close (fd);
	}
}
#endif


/**
 * Brings a tunnel interface up or down.
 *
 * @return 0 on success, -1 on error (see errno).
 */
int
tun6_setState (tun6 *t, bool up)
{
	struct ifreq req;

	assert (t != NULL);

	const char *ifname = t->name;

	/* Sets up the interface */
	memset (&req, 0, sizeof (req));	
	if (safe_strcpy (req.ifr_name, ifname)
	 || ioctl (t->reqfd, SIOCGIFFLAGS, &req))
		return -1;

	/* settings we want/don't want: */
	req.ifr_flags |= IFF_NOARP;
	req.ifr_flags &= ~(IFF_MULTICAST | IFF_BROADCAST);
	if (up)
		req.ifr_flags |= IFF_UP | IFF_RUNNING;
	else
		req.ifr_flags &= ~(IFF_UP | IFF_RUNNING);

	if (safe_strcpy (req.ifr_name, ifname)
	 || ioctl (t->reqfd, SIOCSIFFLAGS, &req))
		return -1;

	return 0;
}


#ifdef USE_BSD
/**
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

#if defined (USE_LINUX)
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
#elif defined (USE_BSD)
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
		if (safe_strcpy (r.addreq6.ifra_name, ifname))
			return -1;
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
		if (safe_strcpy (r.delreq6.ifr_name, ifname))
			return -1;
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

#if defined (USE_LINUX)
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
#elif defined (USE_BSD)
	/*
	 * BSD routing socket interface
	 * FIXME: metric unimplemented
	 */
	int s = socket (AF_ROUTE, SOCK_RAW, AF_INET6);
	if (s != -1)
	{
		static int rtm_seq = 0;
		static pthread_mutex_t rtm_seq_mutex = PTHREAD_MUTEX_INITIALIZER;
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

		pthread_mutex_lock (&rtm_seq_mutex);
		msg.hdr.rtm_seq = ++rtm_seq;
		pthread_mutex_unlock (&rtm_seq_mutex);

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

		(void)close (s);
	}
	else
		syslog (LOG_ERR, _("Error (%s): %s\n"), "socket (AF_ROUTE)",
		        strerror (errno));
#else
# error FIXME route setup not implemented
#endif

	return retval;
}


/**
 * Adds an address with a netmask to a tunnel.
 * Requires CAP_NET_ADMIN or root privileges.
 *
 * @return 0 on success, -1 in case error.
 */
int
tun6_addAddress (tun6 *t, const struct in6_addr *addr, unsigned prefixlen)
{
	assert (t != NULL);

	int res = _iface_addr (t->reqfd, t->name, true, addr, prefixlen);

#if defined (USE_LINUX)
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

/**
 * Deletes an address from a tunnel.
 * Requires CAP_NET_ADMIN or root privileges.
 *
 * @return 0 on success, -1 in case error.
 */
int
tun6_delAddress (tun6 *t, const struct in6_addr *addr, unsigned prefixlen)
{
	assert (t != NULL);

	return _iface_addr (t->reqfd, t->name, false, addr, prefixlen);
}


/**
 * Inserts a route through a tunnel into the IPv6 routing table.
 * Requires CAP_NET_ADMIN or root privileges.
 *
 * @param rel_metric difference between the system's default metric
 * for route with the speficied prefix length (positive = higher priority,
 * negative = lower priority).
 *
 * @return 0 on success, -1 in case error.
 */
int
tun6_addRoute (tun6 *t, const struct in6_addr *addr, unsigned prefix_len,
               int rel_metric)
{
	assert (t != NULL);

	return _iface_route (t->reqfd, t->name, true, addr, prefix_len,
	                     rel_metric);
}


/**
 * Removes a route through a tunnel from the IPv6 routing table.
 * Requires CAP_NET_ADMIN or root privileges.
 *
 * @return 0 on success, -1 in case error.
 */
int
tun6_delRoute (tun6 *t, const struct in6_addr *addr, unsigned prefix_len,
               int rel_metric)
{
	assert (t != NULL);

	return _iface_route (t->reqfd, t->name, false, addr, prefix_len,
	                     rel_metric);
}


/**
 * Defines the tunnel interface Max Transmission Unit (bytes).
 *
 * @return 0 on success, -1 in case of error.
 */
int
tun6_setMTU (tun6 *t, unsigned mtu)
{
	struct ifreq req;

	assert (t != NULL);

	if ((mtu < 1280) || (mtu > 65535))
		return -1;

	memset (&req, 0, sizeof (req));
	req.ifr_mtu = mtu;
	if (safe_strcpy (req.ifr_name, t->name))
		return -1;

	return ioctl (t->reqfd, SIOCSIFMTU, &req) ? -1 : 0;
}


/**
 * Registers file descriptors in an fd_set for use with select().
 *
 * @return the "biggest" file descriptor registered (useful as the
 * first parameter to select()).
 */
int
tun6_registerReadSet (const tun6 *t, fd_set *readset)
{
	assert (t != NULL);

	FD_SET (t->fd, readset);
	return t->fd;
}


/**
 * Checks an fd_set, receives a packet.
 * @param buffer address to store packet
 * @param maxlen buffer length in bytes (should be 65535)
 *
 * This function will block if there is no input.
 *
 * @return the packet length on success, -1 if no packet were to be received.
 */
int
tun6_recv (const tun6 *t, const fd_set *readset, void *buffer, size_t maxlen)
{
	assert (t != NULL);

	int fd = t->fd;
	if (!FD_ISSET (fd, readset))
		return -1;

	struct iovec vect[2];
	tun_head_t head;

	vect[0].iov_base = (char *)&head;
	vect[0].iov_len = sizeof (head);
	vect[1].iov_base = (char *)buffer;
	vect[1].iov_len = maxlen;

	int len = readv (fd, vect, 2);
	if (len == -1)
		return -1;

	len -= sizeof (head);
	if (len < 0)
		return -1;

	if (!tun_head_is_ipv6 (head))
		return -1; /* only accept IPv6 packets */

	return len;
}



/**
 * Sends an IPv6 packet.
 * @param packet pointer to packet
 * @param len packet length (bytes)
 *
 * @return the number of bytes succesfully transmitted on success,
 * -1 on error.
 */
int
tun6_send (const tun6 *t, const void *packet, size_t len)
{
	assert (t != NULL);

	if (len > 65535)
		return -1;

	tun_head_t head = TUN_HEAD_IPV6_INITIALIZER;
	struct iovec vect[2];
	vect[0].iov_base = (char *)&head;
	vect[0].iov_len = sizeof (head);
	vect[1].iov_base = (char *)packet; /* necessary cast to non-const */
	vect[1].iov_len = len;

	int val = writev (t->fd, vect, 2);
	if (val == -1)
		return -1;

	val -= sizeof (head);
	if (val < 0)
		return -1;

	return val;
}

/**
 * Checks if libtun6 should be able to tun on system.
 *
 * @param errbuf a buffer of at least LIBTUN6_ERRBUF_SIZE bytes
 * to hold an error message suitable for the user attention.
 * Also set on success.
 *
 * @return 0 on success, -1 if the system seems inadequate.
 */
int tun6_driver_diagnose (char *errbuf)
{
	(void)bindtextdomain (PACKAGE_NAME, LOCALEDIR);

	int fd = socket (AF_INET6, SOCK_DGRAM, 0);
	if (fd == -1)
	{
		strlcpy (errbuf, "Error: IPv6 stack not available.\n",
		         LIBTUN6_ERRBUF_SIZE - 1);
		errbuf[LIBTUN6_ERRBUF_SIZE - 1] = '\0';
		return -1;
	}
	(void)close (fd);

#if defined (USE_LINUX)
	const char *const tundev = "/dev/net/tun";
#else
	const char *const tundev = "/dev/tun0";
#endif

	fd = open (tundev, O_RDWR);
	if (fd >= 0)
	{
		(void)close (fd);
		snprintf (errbuf, LIBTUN6_ERRBUF_SIZE - 1,
		          "%s tunneling driver found.", os_driver);
		errbuf[LIBTUN6_ERRBUF_SIZE - 1] = '\0';
		return 0;
	}

	if (errno == ENOENT)
	{
		const char *specific;

#if defined (__linux__)
		specific = N_("You should run these commands to create it:\n"
			"# mkdir -p /dev/net\n"
			"# mknod /dev/net/tun c 10 200\n"
			"(you must be root to do that).\n");
#elif defined (__APPLE__)
		specific = N_("You can obtain a tunnel driver for the "
			"Darwin kernel (Mac OS X) from:\n"
			"http://www-user.rhrk.uni-kl.de/~nissler/tuntap/\n");
#else
		specific = NULL;
#endif

		snprintf (errbuf, LIBTUN6_ERRBUF_SIZE - 1,
			_("Error: %s character device "
			"not found or unavailable.\n%s"), tundev,
			specific != NULL ? dgettext (PACKAGE_NAME, specific) : "");
		errbuf[LIBTUN6_ERRBUF_SIZE - 1] = '\0';
		return -1;
	}
	else
	/* Linux returns ENODEV instead of ENXIO */
	if ((errno == ENXIO) || (errno == ENODEV))
	{
		const char *specific;

#if defined (__linux__)
		specific = N_("Make sure your Linux kernel includes "
			"the \"Universal TUNTAP driver\"\n"
			"(CONFIG_TUN option), possibly as a module.\n");
#elif defined (__APPLE__)
		specific = N_("You can obtain a tunnel driver for the "
			"Darwin kernel (Mac OS X) from:\n"
			"http://chrisp.de/en/projects/tunnel.html\n");
#else
		specific = NULL;
#endif

		snprintf (errbuf, LIBTUN6_ERRBUF_SIZE - 1,
			_("Error: your operating system does not "
			"seem to provide a network tunneling\n"
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

