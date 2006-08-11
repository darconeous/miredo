/*
 * security.c - helpers for security-related stuff
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

#include <stdbool.h>
#include <string.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#else
# include <inttypes.h>
#endif
#include <limits.h>
#include <assert.h>

#include <sys/types.h>
#include <fcntl.h> /* open() */
#include <unistd.h> /* read(), close() */
#include <pthread.h>
#include <netinet/in.h> /* struct in6_addr */
#include <errno.h>

#include "security.h"
#include "debug.h"
#include "md5.h"

#if defined (__OpenBSD__) || defined (__OpenBSD_kernel__)
static const char randfile[] = "/dev/srandom";
#else
static const char randfile[] = "/dev/random";
#endif


/* HMAC authentication */
#define LIBTEREDO_KEY_LEN LIBTEREDO_NONCE_LEN
#define HMAC_BLOCK_LEN 64 /* block size in bytes for MD5 (or SHA1) */
#if LIBTEREDO_KEY_LEN > HMAC_BLOCK_LEN
# error HMAC key too long.
#endif

static union
{
	unsigned char key[LIBTEREDO_KEY_LEN];
	unsigned char ipad[HMAC_BLOCK_LEN];
} inner_key;

static union
{
	unsigned char key[LIBTEREDO_KEY_LEN];
	unsigned char opad[HMAC_BLOCK_LEN];
} outer_key;

// PID cannot be zero (otherwise, have fun using fork()!)
static uint16_t hmac_pid = 0;

int teredo_init_HMAC (void)
{
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	int retval = -1;

#define return YOU_DONT_MEAN_return
	pthread_mutex_lock (&mutex);

	if (hmac_pid != htons (getpid ()))
	{
		/* Get a non-predictable random key from the kernel PRNG */
		int fd = open (randfile, O_RDONLY);
		if (fd == -1)
			goto error;

		memset (&inner_key, 0, sizeof (inner_key));

		for (unsigned len = 0; len < LIBTEREDO_KEY_LEN;)
		{
			int val = read (fd, inner_key.key + len, LIBTEREDO_KEY_LEN - len);
			if (val > 0)
				len -= val;
		}
		close (fd);

		/* Precomputes HMAC padding */
		memcpy (&outer_key, &inner_key, sizeof (outer_key));
	
		for (unsigned i = 0; i < sizeof (inner_key); i++)
		{
			inner_key.ipad[i] ^= 0x36;
			outer_key.opad[i] ^= 0x5c;
		}

		hmac_pid = htons (getpid ());
	}
	retval = 0;

error:
	pthread_mutex_unlock (&mutex);
#undef return

	return 0;
}


void teredo_deinit_HMAC (void)
{
}


#define LIBTEREDO_HASH_LEN 16

static void
teredo_hash (const void *src, size_t slen, const void *dst, size_t dlen,
             uint8_t *restrict hash, uint32_t timestamp)
{
	/* compute hash */
	md5_state_t ctx;
	md5_init (&ctx);
	md5_append (&ctx, inner_key.ipad, sizeof (inner_key.ipad));
	md5_append (&ctx, (unsigned char *)src, slen);
	md5_append (&ctx, (unsigned char *)dst, dlen);
	md5_append (&ctx, (unsigned char *)&hmac_pid, sizeof (hmac_pid));
	md5_append (&ctx, (unsigned char *)&timestamp, sizeof (timestamp));
	md5_finish (&ctx, hash);

	md5_init (&ctx);
	md5_append (&ctx, outer_key.opad, sizeof (outer_key.opad));
	md5_append (&ctx, hash, LIBTEREDO_HASH_LEN);
	md5_finish (&ctx, hash);
}


/**
 * Generates a cryptographically strong hash to use a payload for ping
 * packets. That's how we authenticate the last hop of the echo reply
 * (i.e. Teredo relay) before ourselves as being a legitimate first hop
 * toward the echo request's destination.
 *
 * The hash includes a timestamp with a lifetime of 30 units (seconds),
 * source and destination addresses, process ID, and a secret pseudo-random
 * key.
 */
static inline void
teredo_pinghash (const struct in6_addr *src, const struct in6_addr *dst,
                 uint8_t *restrict hash, uint32_t timestamp)
{
	teredo_hash (src, sizeof (*src), dst, sizeof (*dst), hash, timestamp);
}


#if 0
typedef struct teredo_hmac
{
	uint16_t pid;  /* ICMPv6 Echo id */
	uint16_t time; /* ICMPv6 Echo sequence */
	uint16_t epoch;
	unint8_t hash[LIBTEREDO_HASH_LEN]; /* ICMPv6 Echo payload */
} teredo_hmac;
#endif

#if (LIBTEREDO_HASH_LEN + 6) != LIBTEREDO_HMAC_LEN
# error Inconsistent hash and HMAC length
#endif


void
teredo_get_pinghash (uint32_t timestamp, const struct in6_addr *src,
                     const struct in6_addr *dst, uint8_t *restrict hash)
{
	/* save hash-protected data */
	memcpy (hash, &hmac_pid, sizeof (hmac_pid));
	hash += sizeof (hmac_pid);

	timestamp = htonl (timestamp);
	memcpy (hash, ((uint8_t *)&timestamp) + 2, 2);
	hash += 2;
	memcpy (hash, &timestamp, 2);
	hash += 2;

	teredo_pinghash (src, dst, hash, timestamp);
}


int
teredo_verify_pinghash (uint32_t now, const struct in6_addr *src,
                        const struct in6_addr *dst,
                        const uint8_t *restrict hash)
{
	/* Check ICMPv6 ID */
	if (memcmp (hash, &hmac_pid, sizeof (hmac_pid)))
		return -1;
	hash += sizeof (hmac_pid);

	/* Check ICMPv6 sequence */
	uint32_t timestamp;
	memcpy (((uint8_t *)&timestamp) + 2, hash, 2);
	hash += 2;
	memcpy (&timestamp, hash, 2);
	hash += 2;

	if (((now - ntohl (timestamp)) & 0xffffffff) >= 30)
		return -1; /* replay attack */

	unsigned char h1[LIBTEREDO_HASH_LEN];
	teredo_pinghash (src, dst, h1, timestamp);

	/* compare HMAC hash */
	return memcmp (h1, hash, LIBTEREDO_HASH_LEN) ? -1 : 0;
}


#if LIBTEREDO_HASH_LEN < LIBTEREDO_NONCE_LEN
# error Inconsistent hash size
#endif
void
teredo_get_nonce (uint32_t timestamp, uint32_t ipv4, uint16_t port,
                  uint8_t *restrict nonce)
{
	uint8_t buf[LIBTEREDO_HASH_LEN];

	teredo_hash (&ipv4, 4, &port, 2, buf, timestamp);
	memcpy (nonce, buf, LIBTEREDO_NONCE_LEN);
}


int
teredo_verify_nonce (uint32_t timestamp, uint32_t ipv4, uint16_t port,
                     const uint8_t *restrict nonce)
{
	unsigned char buf[LIBTEREDO_HASH_LEN];
	teredo_hash (&ipv4, 4, &port, 2, buf, timestamp);

	/* compare HMAC hash */
	return memcmp (nonce, buf, LIBTEREDO_NONCE_LEN) ? -1 : 0;
}
