/*
 * maintain.c - Teredo client qualification & maintenance
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright © 2004-2007 Rémi Denis-Courmont.                         *
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gettext.h>

#include <string.h> /* memcmp() */
#include <assert.h>

#include <stdbool.h>
#include <inttypes.h>
#include <time.h> /* clock_gettime() */

#include <sys/types.h>
#include <unistd.h> /* sysconf() */
#include <netinet/in.h> /* struct in6_addr */
#include <netinet/ip6.h> /* struct ip6_hdr */
#include <netdb.h> /* getaddrinfo(), gai_strerror() */
#include <syslog.h>
#include <stdlib.h> /* malloc(), free() */
#include <errno.h> /* EINTR */
#include <pthread.h>
#include <arpa/nameser.h>
#include <resolv.h> /* res_init() */

#include "teredo.h"
#include "teredo-udp.h"
#include "packets.h"

#include "security.h"
#include "maintain.h"
#include "v4global.h" // is_ipv4_global_unicast()
#include "debug.h"

static inline void gettime (struct timespec *now)
{
#if (_POSIX_CLOCK_SELECTION - 0 >= 0) && (_POSIX_MONOTONIC_CLOCK - 0 >= 0)
	if (clock_gettime (CLOCK_MONOTONIC, now) == 0)
		return;
#else
# define pthread_condattr_setclock( a, c ) (((c) != CLOCK_REALTIME) ? EINVAL : 0)
# ifndef CLOCK_MONOTONIC
#  define CLOCK_MONOTONIC CLOCK_REALTIME
# endif
# warning Monotonic clock is needed for proper Teredo maintenance!
#endif
	clock_gettime (CLOCK_REALTIME, now);
}


struct teredo_maintenance
{
	pthread_t thread;
	pthread_mutex_t outer;
	pthread_mutex_t inner;
	pthread_cond_t received;
	pthread_cond_t processed;

	const teredo_packet *incoming;

	int fd;
	struct
	{
		teredo_state state;
		teredo_state_cb cb;
		void *opaque;
	} state;
	char *server;

	unsigned qualification_delay;
	unsigned qualification_retries;
	unsigned refresh_delay;
	unsigned restart_delay;
};


/**
 * Resolves an IPv4 address (thread-safe).
 *
 * @return 0 on success, or an error value as defined for getaddrinfo().
 */
static int getipv4byname (const char *restrict name, uint32_t *restrict ipv4)
{
	struct addrinfo hints =
	{
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM
	}, *res;

	int val = getaddrinfo (name, NULL, &hints, &res);
	if (val)
		return val;

	memcpy (ipv4, &((const struct sockaddr_in *)(res->ai_addr))->sin_addr, 4);
	freeaddrinfo (res);

	return 0;
}


/**
 * Checks and parses a received Router Advertisement.
 *
 * @return 0 if successful.
 */
static int
maintenance_recv (const teredo_packet *restrict packet, uint32_t server_ip,
                  uint8_t *restrict nonce, bool cone, uint16_t *restrict mtu,
                  union teredo_addr *restrict newaddr)
{
	assert (packet->auth_nonce != NULL);

	if (memcmp (packet->auth_nonce, nonce, 8))
		return EPERM;

	/* TODO: fail instead of ignoring the packet? */
	if (packet->auth_conf_byte)
	{
		syslog (LOG_ERR, _("Authentication with server failed."));
		return EACCES;
	}

	if (teredo_parse_ra (packet, newaddr, cone, mtu)
	/* TODO: try to work-around incorrect server IP */
	 || (newaddr->teredo.server_ip != server_ip))
		return EINVAL;

	/* Valid router advertisement received! */
	return 0;
}


/**
 * Waits until the clock reaches deadline or a RS packet is received.
 * @return 0 if a packet was received, ETIMEDOUT if deadline was reached.
 */
static int wait_reply (teredo_maintenance *restrict m,
                       const struct timespec *restrict deadline)
{
	assert (m->incoming == NULL);

	/* Ignore EINTR */
	for (;;)
	{
		int val = pthread_cond_timedwait (&m->received, &m->inner, deadline);

		switch (val)
		{
			case 0:
				if (m->incoming == NULL) // spurious wakeup
					continue;
				/* fall through */
			case ETIMEDOUT:
				return val;
		}
	}
	return 0; // dead code
}


/**
 * Waits until the clock reaches deadline and ignore any RS packet received
 * in the mean time.
 */
static void wait_reply_ignore (teredo_maintenance *restrict m,
                               const struct timespec *restrict deadline)
{
	while (wait_reply (m, deadline) == 0)
	{
		m->incoming = NULL;
		pthread_cond_signal (&m->processed);
	}
}


/**
 * Make sure ts is in the future. If not, set it to the current time.
 * @return false if (*ts) was changed, true otherwise.
 */
static bool
checkTimeDrift (struct timespec *ts)
{
	struct timespec now;
	gettime (&now);

	if ((now.tv_sec > ts->tv_sec)
	 || ((now.tv_sec == ts->tv_sec) && (now.tv_nsec > ts->tv_nsec)))
	{
		/* process stopped, CPU starved, or (ACPI, APM, etc) suspend */
		syslog (LOG_WARNING, _("Too much time drift. Resynchronizing."));
		memcpy (ts, &now, sizeof (*ts));
		return false;
	}
	return true;
}


static void
cleanup_unlock (void *o)
{
	(void)pthread_mutex_unlock ((pthread_mutex_t *)o);
}


/*
 * Implementation notes:
 * - Optional Teredo interval determination procedure was never implemented.
 *   It adds NAT binding maintenance brittleness in addition to implementation
 *   complexity, and is not necessary for RFC4380 compliance.
 *   Also STUN RFC3489bis deprecates this type of behavior.
 * - NAT cone type probing was removed in Miredo version 0.9.5. Since then,
 *   Miredo qualification state machine became explicitly incompliant with
 *   RFC4380. However, this made the startup much faster in many cases (many
 *   NATs are restricted or symmetric), and is in accordance with deprecation
 *   of NAT type determination in STUN RFC3489bis.
 * - NAT symmtric probing was removd in Miredo version 1.1.0, which deepens
 *   the gap between Miredo and RFC4380. Still, this is fairly consistent with
 *   RFC3489bis.
 */

/*
 * Teredo client maintenance procedure
 */
static inline LIBTEREDO_NORETURN
void maintenance_thread (teredo_maintenance *m)
{
	struct timespec deadline = { 0, 0 };
	teredo_state *c_state = &m->state.state;
	uint32_t server_ip = 0;
	unsigned count = 0;
	enum
	{
		TERR_NONE,
		TERR_BLACKHOLE
	} last_error = TERR_NONE;

	pthread_mutex_lock (&m->inner);

	/*
	 * Qualification/maintenance procedure
	 */
	pthread_cleanup_push (cleanup_unlock, &m->inner);
	for (;;)
	{
		/* Resolve server IPv4 addresses */
		for (;;)
		{
			/* FIXME: mutex kept while resolving - very bad */
			int val = getipv4byname (m->server, &server_ip);
			gettime (&deadline);
	
			if (val)
			{
				/* DNS resolution failed */
				syslog (LOG_ERR,
				        _("Cannot resolve Teredo server address \"%s\": %s"),
				        m->server, gai_strerror (val));
			}
			else
			if (!is_ipv4_global_unicast (server_ip))
			{
				syslog (LOG_ERR,
				        _("Teredo server has a non global IPv4 address."));
			}
			else
			{
				/* DNS resolution succeeded */
				/* Tells Teredo client about the new server's IP */
				assert (!c_state->up);
				c_state->addr.teredo.server_ip = server_ip;
				m->state.cb (c_state, m->state.opaque);
				break; /* Done! */
			}

			/* wait some time before next resolution attempt */
			deadline.tv_sec += m->restart_delay;
			wait_reply_ignore (m, &deadline);
		}

		/* SEND ROUTER SOLICATION */
		do
			deadline.tv_sec += m->qualification_delay;
		while (!checkTimeDrift (&deadline));

		uint8_t nonce[8];
		teredo_get_nonce (deadline.tv_sec, server_ip, htons (IPPORT_TEREDO),
		                  nonce);
		teredo_send_rs (m->fd, server_ip, nonce, false);

		int val = 0;
		union teredo_addr newaddr;
		uint16_t mtu = 1280;

		/* RECEIVE ROUTER ADVERTISEMENT */
		do
		{
			val = wait_reply (m, &deadline);
			if (val)
				continue; // time out

			/* check received packet */
			val = maintenance_recv (m->incoming, server_ip,
			                        nonce, false, &mtu, &newaddr);
			m->incoming = NULL;
			pthread_cond_signal (&m->processed);
		}
		while ((val != 0) && (val != ETIMEDOUT));

		unsigned delay = 0;

		/* UPDATE FINITE STATE MACHINE */
		if (val /* == ETIMEDOUT */)
		{
			/* no response */
			count++;

			if (count >= m->qualification_retries)
			{
				count = 0;

				/* No response from server */
				if (last_error != TERR_BLACKHOLE)
				{
					syslog (LOG_INFO, _("No reply from Teredo server"));
					last_error = TERR_BLACKHOLE;
				}

				if (c_state->up)
				{
					syslog (LOG_NOTICE, _("Lost Teredo connectivity"));
					c_state->up = false;
					m->state.cb (c_state, m->state.opaque);
					server_ip = 0;
				}

				/* Wait some time before retrying */
				delay = m->restart_delay;
			}
		}
		else
		/* RA received and parsed succesfully */
		{
			count = 0;

			if ((!c_state->up)
			 || memcmp (&c_state->addr, &newaddr, sizeof (c_state->addr))
			 || (c_state->mtu != mtu))
			{
				memcpy (&c_state->addr, &newaddr, sizeof (c_state->addr));
				c_state->mtu = mtu;
				c_state->up = true;

				syslog (LOG_NOTICE, _("New Teredo address/MTU"));
				m->state.cb (c_state, m->state.opaque);
			}

			/* Success: schedule next NAT binding maintenance */
			last_error = TERR_NONE;
			delay = m->refresh_delay;
		}

		/* WAIT UNTIL NEXT SOLICITATION */
		/* TODO: watch for new interface events
		 * (netlink on Linux, PF_ROUTE on BSD) */
		if (delay)
		{
			deadline.tv_sec -= m->qualification_delay;
			deadline.tv_sec += delay;
			wait_reply_ignore (m, &deadline);
		}
	}
	/* dead code */
	pthread_cleanup_pop (1);
}


static LIBTEREDO_NORETURN void *do_maintenance (void *opaque)
{
	maintenance_thread ((teredo_maintenance *)opaque);
}


static const unsigned QualificationDelay = 4; // seconds
static const unsigned QualificationRetries = 3;

static const unsigned RefreshDelay = 30; // seconds
static const unsigned RestartDelay = 100; // seconds

teredo_maintenance *
teredo_maintenance_start (int fd, teredo_state_cb cb, void *opaque,
                          const char *s1, const char *s2,
                          unsigned q_sec, unsigned q_retries,
                          unsigned refresh_sec, unsigned restart_sec)
{
	teredo_maintenance *m = (teredo_maintenance *)malloc (sizeof (*m));

	if (m == NULL)
		return NULL;

	memset (m, 0, sizeof (*m));
	m->fd = fd;
	m->state.cb = cb;
	m->state.opaque = opaque;

	assert (s1 != NULL);
	m->server = strdup (s1);
	(void)s2;

	m->qualification_delay = q_sec ?: QualificationDelay;
	m->qualification_retries = q_retries ?: QualificationRetries;
	m->refresh_delay = refresh_sec ?: RefreshDelay;
	m->restart_delay = restart_sec ?: RestartDelay;

	if (m->server == NULL)
	{
		free (m);
		return NULL;
	}
	else
	{
		pthread_condattr_t attr;

		pthread_condattr_init (&attr);
		(void)pthread_condattr_setclock (&attr, CLOCK_MONOTONIC);
		/* EINVAL: CLOCK_MONOTONIC unknown */

		pthread_cond_init (&m->received, &attr);
		pthread_condattr_destroy (&attr);
	}

	pthread_cond_init (&m->processed, NULL);
	pthread_mutex_init (&m->outer, NULL);
	pthread_mutex_init (&m->inner, NULL);

	int err = pthread_create (&m->thread, NULL, do_maintenance, m);
	if (err == 0)
		return m;

	syslog (LOG_ALERT, _("Error (%s): %s\n"), "pthread_create",
	        strerror (err));

	pthread_cond_destroy (&m->processed);
	pthread_cond_destroy (&m->received);
	pthread_mutex_destroy (&m->outer);
	pthread_mutex_destroy (&m->inner);

	free (m->server);
	free (m);
	return NULL;
}


void teredo_maintenance_stop (teredo_maintenance *m)
{
	pthread_cancel (m->thread);
	pthread_join (m->thread, NULL);

	pthread_cond_destroy (&m->processed);
	pthread_cond_destroy (&m->received);
	pthread_mutex_destroy (&m->inner);
	pthread_mutex_destroy (&m->outer);

	free (m->server);
	free (m);
}


int teredo_maintenance_process (teredo_maintenance *restrict m,
                                const teredo_packet *restrict packet)
{
	assert (m != NULL);
	assert (packet != NULL);

	/*
	 * We don't accept router advertisement without nonce.
	 * It is far too easy to spoof such packets.
	 */
	if ((packet->source_port != htons (IPPORT_TEREDO))
	    /* TODO: check for primary or secondary server address */
	 || (packet->auth_nonce == NULL)
	 || memcmp (&packet->ip6->ip6_dst, &teredo_restrict, 16))
		return -1;

	pthread_mutex_lock (&m->outer);
	pthread_mutex_lock (&m->inner);

	m->incoming = packet;
	pthread_cond_signal (&m->received);

	/* Waits for maintenance thread to process packet... */
	do
		pthread_cond_wait (&m->processed, &m->inner);
	while (m->incoming != NULL);

	pthread_mutex_unlock (&m->inner);
	pthread_mutex_unlock (&m->outer);

	return 0;
}
