/*
 * tun6.c - IPv6 tunnel interface definition
 */

/***********************************************************************
 *  Copyright © 2004-2009 Rémi Denis-Courmont.                         *
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

#include <gettext.h>

#include <assert.h>

#include <stdio.h> // snprintf() for BSD drivers
#include <string.h>
#include <stdlib.h> // free()
#include <inttypes.h>

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

#include <net/if.h> // struct ifreq, if_nametoindex(), if_indextoname()

#if defined (__linux__)
/*
 * Linux tunneling driver
 */
const char os_driver[] = "Linux";
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
#include <ifaddrs.h>
/*
 * BSD tunneling driver
 * NOTE: the driver is NOT tested on Darwin (Mac OS X).
 */
const char os_driver[] = "BSD";
# define USE_BSD 1

// TUNSIFHEAD or TUNSLMODE
# if defined (HAVE_NET_IF_TUN_H)
#  include <net/if_tun.h>
# elif defined (HAVE_NET_TUN_IF_TUN_H)
#  include <net/tun/if_tun.h>
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
# ifdef __GLIBC__
#  ifdef __FreeBSD_kernel__
#   include <freebsd/stdlib.h> // devname_r()
#  endif
# endif

typedef uint32_t tun_head_t;

# define TUN_HEAD_IPV6_INITIALIZER htonl (AF_INET6)
# define tun_head_is_ipv6( h ) (h == htonl (AF_INET6))

#else
const char os_driver[] = "Generic";

# warning Unknown host OS. The driver will probably not work.
#endif

#include <libtun6/tun6.h>

#define safe_strcpy( tgt, src ) \
	((strlcpy (tgt, src, sizeof (tgt)) >= sizeof (tgt)) ? -1 : 0)

struct tun6
{
	int  id, fd, reqfd;
#if defined (USE_BSD)
	char orig_name[IFNAMSIZ];
#endif
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
	memset (t, 0, sizeof (*t));

	int reqfd = t->reqfd = socket (AF_INET6, SOCK_DGRAM, 0);
	if (reqfd == -1)
	{
		free (t);
		return NULL;
	}

	fcntl (reqfd, F_SETFD, FD_CLOEXEC);

#if defined (USE_LINUX)
	/*
	 * TUNTAP (Linux) tunnel driver initialization
	 */
	static const char tundev[] = "/dev/net/tun";
	struct ifreq req =
	{
		.ifr_flags = IFF_TUN
	};

	if ((req_name != NULL) && safe_strcpy (req.ifr_name, req_name))
	{
		free (t);
		return NULL;
	}

	int fd = open (tundev, O_RDWR);
	if (fd == -1)
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %m"), tundev);
		(void)close (reqfd);
		free (t);
		return NULL;
	}

	// Allocates the tunneling virtual network interface
	if (ioctl (fd, TUNSETIFF, (void *)&req))
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %m"), "TUNSETIFF");
		if (errno == EBUSY)
			syslog (LOG_INFO,
			        _("Please make sure another instance of the program is "
	        	          "not already running."));
		goto error;
	}

	int id = if_nametoindex (req.ifr_name);
	if (id == 0)
		goto error;
#elif defined (USE_BSD)
	/*
	 * BSD tunnel driver initialization
	 * (see BSD src/sys/net/if_tun.{c,h})
	 */
	int fd = open ("/dev/tun", O_RDWR);
	if ((fd == -1) && (errno == ENOENT))
	{
		/*
		 * Some BSD variants or older kernel versions do not support /dev/tun,
		 * so fallback to the old scheme.
		 */
		int saved_errno = 0;
		for (unsigned i = 0; fd == -1; i++)
		{
			char tundev[5 + IFNAMSIZ];
			snprintf (tundev, sizeof (tundev), "/dev/tun%u", i);

			fd = open (tundev, O_RDWR);
			if ((fd == -1) && (errno == ENOENT))
				// If /dev/tun<i> does not exist,
				// /dev/tun<i+1> won't exist either
				break;

			saved_errno = errno;
		}
		errno = saved_errno;
	}

	if (fd == -1)
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %m"), "/dev/tun*");
		goto error;
	}
	else
	{
		struct stat st;
		fstat (fd, &st);
# ifdef HAVE_DEVNAME_R
		devname_r (st.st_rdev, S_IFCHR, t->orig_name, sizeof (t->orig_name));
# else
		const char *name = devname (st.st_rdev, S_IFCHR);
		if (safe_strcpy (t->orig_name, name))
			goto error;
# endif		
	}

	int id = if_nametoindex (t->orig_name);
	if (id == 0)
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %m"),
		        t->orig_name);
		goto error;
	}

# ifdef TUNSIFMODE
	/* Sets sensible tunnel type (broadcast rather than point-to-point) */
	(void)ioctl (fd, TUNSIFMODE, &(int){ IFF_BROADCAST });
# endif

# if defined (TUNSIFHEAD)
	/* Enables TUNSIFHEAD */
	if (ioctl (fd, TUNSIFHEAD, &(int){ 1 }))
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %m"),
		        "TUNSIFHEAD");
#  if defined (__APPLE__)
		if (errno == EINVAL)
			syslog (LOG_NOTICE,
			        "*** Ignoring tun-tap-osx spurious error ***");
		else
#  endif
		goto error;
	}
# elif defined (TUNSLMODE)
	/* Disables TUNSLMODE (deprecated opposite of TUNSIFHEAD) */
	if (ioctl (fd, TUNSLMODE, &(int){ 0 }))
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %m"),
		        "TUNSLMODE");
		goto error;
	}
#endif

	/* Customizes interface name */
	if (req_name != NULL)
	{
		struct ifreq req;
		memset (&req, 0, sizeof (req));

		if (if_indextoname (id, req.ifr_name) == NULL)
		{
			syslog (LOG_ERR, _("Tunneling driver error (%s): %m"),
			        "if_indextoname");
			goto error;
		}
		else
		if (strcmp (req.ifr_name, req_name))
		{
#ifdef SIOCSIFNAME
			char ifname[IFNAMSIZ];
			req.ifr_data = ifname;

			errno = ENAMETOOLONG;
			if (safe_strcpy (ifname, req_name)
			 || ioctl (reqfd, SIOCSIFNAME, &req))
#else
			syslog (LOG_DEBUG,
"Tunnel interface renaming is not supported on your operating system.\n"
"To run miredo properly, you need to remove the InterfaceName directive\n"
"from its configuration file.\n");
			errno = ENOSYS;
#endif
			{
				syslog (LOG_ERR, _("Tunneling driver error (%s): %m"),
				        "SIOCSIFNAME");
				goto error;
			}
		}
	}
#else
# error No tunneling driver implemented on your platform!
#endif /* HAVE_os */

	fcntl (fd, F_SETFD, FD_CLOEXEC);
	/*int val = fcntl (fd, F_GETFL);
	fcntl (fd, F_SETFL, ((val != -1) ? val : 0) | O_NONBLOCK);*/

	t->id = id;
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
	assert (t->id != 0);

	(void)tun6_setState (t, false);

#ifdef USE_BSD
# ifdef SIOCSIFNAME
	/*
	 * SIOCSIFDESTROY doesn't work for tunnels (see FreeBSD PR/73673).
	 * We rename the tunnel to its canonical name to ease the life of other
	 * programs that may re-open the tunnel after us.
	 */
	struct ifreq req;
	memset (&req, 0, sizeof (req));
	if (if_indextoname (t->id, req.ifr_name) != NULL)
	{
		if (ioctl (t->reqfd, SIOCIFDESTROY, &req))
		{
			if ((if_indextoname (t->id, req.ifr_name) != NULL)
			 && strcmp (t->orig_name, req.ifr_name))
			{
				req.ifr_data = t->orig_name;
				(void)ioctl (t->reqfd, SIOCSIFNAME, &req);
			}
		}
	}
# endif
#endif

	(void)close (t->fd);
	(void)close (t->reqfd);
	free (t);
}


/*
 * Unless otherwise stated, all the methods thereafter should return -1 on
 * error, and 0 on success. Similarly, they should require root privileges.
 */

/**
 * @return the scope id of the tunnel device
 */
int tun6_getId (const tun6 *t)
{
	assert (t != NULL);
	assert (t-> id != 0);

	return t->id;
}


#if defined (USE_LINUX)
static int
proc_write_zero (const char *path)
{
	int fd = open (path, O_WRONLY);
	if (fd == -1)
		return -1;

	int retval = 0;

	if (write (fd, "0", 1) != 1)
		retval = -1;
	if (close (fd))
		retval = -1;

	return retval;
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
	assert (t != NULL);
	assert (t-> id != 0);

	struct ifreq req;
	memset (&req, 0, sizeof (req));	
	if ((if_indextoname (t->id, req.ifr_name) == NULL)
	 || ioctl (t->reqfd, SIOCGIFFLAGS, &req))
		return -1;

	/* settings we want/don't want: */
	req.ifr_flags |= IFF_NOARP;
	req.ifr_flags &= ~(IFF_MULTICAST | IFF_BROADCAST);
	if (up)
		req.ifr_flags |= IFF_UP | IFF_RUNNING;
	else
		req.ifr_flags &= ~(IFF_UP | IFF_RUNNING);

	/* Sets up the interface */
	if ((if_indextoname (t->id, req.ifr_name) == NULL)
	 || ioctl (t->reqfd, SIOCSIFFLAGS, &req))
		return -1;

	return 0;
}


#if defined (USE_BSD)
/**
 * Converts a prefix length to a netmask (used for the BSD routing)
 */
static void
plen_to_mask (unsigned plen, struct in6_addr *mask)
{
	assert (plen <= 128);

	div_t d = div (plen, 8);
	int i = 0;

	while (i < d.quot)
		mask->s6_addr[i++] = 0xff;

	if (d.rem)
		mask->s6_addr[i++] = 0xff << (8 - d.rem);

	while (i < 16)
		mask->s6_addr[i++] = 0;
}


static void
plen_to_sin6 (unsigned plen, struct sockaddr_in6 *sin6)
{
	memset (sin6, 0, sizeof (struct sockaddr_in6));

	sin6->sin6_family = AF_INET6;
# ifdef HAVE_SA_LEN
	sin6->sin6_len = sizeof (struct sockaddr_in6);
# endif
	plen_to_mask (plen, &sin6->sin6_addr);
}
#endif /* ifdef SOCAIFADDR_IN6 */


static int
_iface_addr (int reqfd, int id, bool add,
             const struct in6_addr *addr, unsigned prefix_len)
{
	void *req = NULL;
	long cmd = 0;

	assert (reqfd != -1);
	assert (id != 0);

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
	r.req6.ifr6_ifindex = id;
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
		if (if_indextoname (id, r.addreq6.ifra_name) == NULL)
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
		if (if_indextoname (id, r.delreq6.ifr_name) == NULL)
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
_iface_route (int reqfd, int id, bool add, const struct in6_addr *addr,
              unsigned prefix_len, int rel_metric)
{
	assert (reqfd != -1);
	assert (id != 0);

	if ((prefix_len > 128) || (addr == NULL))
		return -1;

	int retval = -1;

#if defined (USE_LINUX)
	/*
	 * Linux ioctl interface
	 */
	struct in6_rtmsg req6 =
	{
		.rtmsg_flags = RTF_UP,
		.rtmsg_ifindex = id,
		.rtmsg_dst_len = (unsigned short)prefix_len,
		/* By default, the Linux kernel's metric is 256 for subnets,
		 * and 1024 for gatewayed route. */
		.rtmsg_metric = 1024 + rel_metric
	};

	/* Adds/deletes route */
	memcpy (&req6.rtmsg_dst, addr, sizeof (req6.rtmsg_dst));
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
	(void)rel_metric;

	int s = socket (AF_ROUTE, SOCK_RAW, AF_INET6);
	if (s == -1)
	{
		syslog (LOG_ERR, _("Error (%s): %m"), "socket (AF_ROUTE)");
		return -1;
	}

	static int rtm_seq = 0;
	static pthread_mutex_t rtm_seq_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct
	{
		struct rt_msghdr hdr;
		struct sockaddr_in6 dst;
		struct sockaddr_storage gw;
		struct sockaddr_storage dummy; /* allocate space for netmask */
	} msg;

	shutdown (s, 0);

	memset (&msg, 0, sizeof (msg));
	msg.hdr.rtm_msglen = sizeof (msg);
	msg.hdr.rtm_version = RTM_VERSION;
	msg.hdr.rtm_type = add ? RTM_ADD : RTM_DELETE;
	msg.hdr.rtm_index = id;
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

	struct ifaddrs *ifap, *ifa;
	struct sockaddr_dl *sdl = NULL;

	if (getifaddrs(&ifap)) {
		syslog (LOG_ERR, "getifaddrs erorr\n");
		return -1;
	}
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		if (id == ((struct sockaddr_dl *)ifa->ifa_addr)->sdl_index)
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	}
	if (sdl == NULL) {
		syslog (LOG_ERR, "no sdl found\n");
		freeifaddrs(ifap);
		return -1;
	}
	memcpy(&msg.gw, sdl, sdl->sdl_len);
	freeifaddrs(ifap);

	struct sockaddr_in6 *mask = (struct sockaddr_in6 *)((u_char *)&msg.gw + sdl->sdl_len);
	plen_to_sin6 (prefix_len, mask);

	errno = 0;

	if ((write (s, &msg, sizeof (msg)) == sizeof (msg))
	 && (errno == 0))
		retval = 0;
    	else if (errno == EEXIST)
		syslog (LOG_NOTICE,
"Miredo could not configure its network tunnel device properly.\n"
"There is probably another tunnel with a conflicting route present\n"
"(see also FreeBSD PR kern/100080).\n"
"Please upgrade to FreeBSD 6.3 or more recent to fix this.\n");
	else syslog (LOG_NOTICE,
"Creating a route erorr: %m");

	(void)close (s);
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

	int res = _iface_addr (t->reqfd, t->id, true, addr, prefixlen);

#if defined (USE_LINUX)
	char ifname[IFNAMSIZ];
	if ((res == 0)
	 && (if_indextoname (t->id, ifname) != NULL))
	{

		char proc_path[24 + IFNAMSIZ + 16 + 1] = "/proc/sys/net/ipv6/conf/";
# if 0
		/* Disable Autoconfiguration */
		snprintf (proc_path + 24, sizeof (proc_path) - 24,
		          "%s/accept_ra", ifname);
		proc_write_zero (proc_path);

		snprintf (proc_path + 24, sizeof (proc_path) - 24,
		          "%s/autoconf", ifname);
		proc_write_zero (proc_path);
#endif
		/* Disable ICMPv6 Redirects. */
		snprintf (proc_path + 24, sizeof (proc_path) - 24,
		          "%s/accept_redirects", ifname);
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

	return _iface_addr (t->reqfd, t->id, false, addr, prefixlen);
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

	return _iface_route (t->reqfd, t->id, true, addr, prefix_len, rel_metric);
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

	return _iface_route (t->reqfd, t->id, false, addr, prefix_len,
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
	assert (t != NULL);

	if ((mtu < 1280) || (mtu > 65535))
		return -1;

	struct ifreq req =
	{
		.ifr_mtu = mtu
	};
	if (if_indextoname (t->id, req.ifr_name) == NULL)
		return -1;

	return ioctl (t->reqfd, SIOCSIFMTU, &req) ? -1 : 0;
}


/**
 * Registers file descriptors in an fd_set for use with select().
 * If any of the file descriptors is out of range (>= FD_SETSIZE), it
 * will not be registered.
 *
 * @param readset a fd_set (with FD_SETSIZE no smaller than the default
 * libc value libtun6 was compiled with).
 *
 * @return the "biggest" file descriptor registered (useful as the
 * first parameter to select()). -1 if any of the file descriptors was
 * bigger than FD_SETSIZE - 1.
 */
int
tun6_registerReadSet (const tun6 *t, fd_set *readset)
{
	assert (t != NULL);

	if (t->fd >= (int)FD_SETSIZE)
		return -1;

	FD_SET (t->fd, readset);
	return t->fd;
}


/**
 * Receives a packet from a tunnel device.
 * @param buffer address to store packet
 * @param maxlen buffer length in bytes (should be 65535)
 *
 * This function will block if there is no input.
 *
 * @return the packet length on success, -1 if no packet were to be received.
 */
static inline int
tun6_recv_inner (int fd, void *buffer, size_t maxlen)
{
	struct iovec vect[2];
	tun_head_t head;

	vect[0].iov_base = (char *)&head;
	vect[0].iov_len = sizeof (head);
	vect[1].iov_base = (char *)buffer;
	vect[1].iov_len = maxlen;

	int len = readv (fd, vect, 2);
	if ((len < (int)sizeof (head))
	 || !tun_head_is_ipv6 (head))
		return -1; /* only accept IPv6 packets */

	return len - sizeof (head);
}


/**
 * Checks an fd_set, and receives a packet if available.
 * @param buffer address to store packet
 * @param maxlen buffer length in bytes (should be 65535)
 *
 * This function will not block if there is no input.
 * Use tun6_wait_recv() if you want to wait until a packet arrives.
 *
 * @return the packet length on success, -1 if no packet were to be received.
 */
int
tun6_recv (tun6 *t, const fd_set *readset, void *buffer, size_t maxlen)
{
	assert (t != NULL);

	int fd = t->fd;
	if ((fd < (int)FD_SETSIZE) && !FD_ISSET (fd, readset))
	{
		errno = EAGAIN;
		return -1;
	}
	return tun6_recv_inner (fd, buffer, maxlen);
}


/**
 * Waits for a packet, and receives it.
 * @param buffer address to store packet
 * @param maxlen buffer length in bytes (should be 65535)
 *
 * This function will block until a packet arrives or an error occurs.
 *
 * @return the packet length on success, -1 if no packet were to be received.
 */
int
tun6_wait_recv (tun6 *t, void *buffer, size_t maxlen)
{
	return tun6_recv_inner (t->fd, buffer, maxlen);
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
tun6_send (tun6 *t, const void *packet, size_t len)
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

