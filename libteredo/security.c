/*
 * security.c - helpers for security-related stuff
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004-2005 Rémi Denis-Courmont.                         *
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
#include <time.h> /* time_t */
#include <errno.h>

#include "security.h"
#include "debug.h"
#include "md5.h"

#if defined (__OpenBSD__) || defined (__OpenBSD_kernel__)
static const char randfile[] = "/dev/srandom";
#else
static const char randfile[] = "/dev/random";
#endif


static int devfd = -1;
static pthread_mutex_t nonce_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned refs = 0;

/**
 * Has to be called before any call to teredo_generate_nonce() can succeed.
 * It should additionnaly be called before calling chroot().
 * Thread-safe. Can be called multiple times with no side effect.
 *
 * @return 0 on success, -1 on fatal error.
 */
int
teredo_init_nonce_generator (void)
{
	bool ok = false;
	pthread_mutex_lock (&nonce_mutex);

	if (refs == 0)
	{
		devfd = open (randfile, 0);
		ok = (devfd != -1);
	}
	else
	if (refs < UINT_MAX)
		ok = true;

	if (ok)
		refs++;

	pthread_mutex_unlock (&nonce_mutex);

	return ok ? 0 : -1;
}


/**
 * Should be called after use of GenerateNonce(), as many times as
 * teredo_init_nonce_generator() was called.
 * Thread-safe.
 *
 * Calling teredo_deinit_nonce_generator() more times than
 * teredo_init_nonce_generator is undefined. If debugging is enabled,
 * an assertion will fail, and the program will abort.
 */
void
teredo_deinit_nonce_generator (void)
{
	pthread_mutex_lock (&nonce_mutex);
	assert (refs > 0);

	if (--refs == 0)
	{
		(void)close (devfd);
		devfd = -1;
	}

	pthread_mutex_unlock (&nonce_mutex);
}


/**
 * Generates an unpredictible random nonce value (8 bytes). Thread-safe.
 *
 *
 * @param b pointer to a 8-bytes buffer [OUT]
 *
 * @return -1 on error, 0 on success.
 */
int
teredo_generate_nonce (unsigned char *b)
{
	for (int tot = 0, val; tot < LIBTEREDO_NONCE_LEN; tot += val)
	{
		val = read (devfd, b + tot, LIBTEREDO_NONCE_LEN - tot);
		if (val <= 0)
			return -1;
	}

	return 0;
}


/* HMAC authentication */
#define HMAC_BLOCK_LEN 64 /* block size in bytes for MD5 (or SHA1) */
#define LIBTEREDO_KEY_LEN LIBTEREDO_NONCE_LEN

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

static uint16_t hmac_pid;

static void init_hmac_once (void)
{
	hmac_pid = (uint16_t)getpid ();

	/* Generate HMAC key and precomputes padding */
	memset (&inner_key, 0, sizeof (inner_key));
	teredo_generate_nonce (inner_key.key);
	memcpy (&outer_key, &inner_key, sizeof (outer_key));

	for (unsigned i = 0; i < sizeof (inner_key); i++)
	{
		inner_key.ipad[i] ^= 0x36;
		outer_key.opad[i] ^= 0x5c;
	}
}


int teredo_init_HMAC (void)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;

	pthread_once (&once, init_hmac_once);
	return 0;
}


void teredo_deinit_HMAC (void)
{
}


#define LIBTEREDO_HASH_LEN 16
#if 0
typedef struct teredo_hmac
{
	uint16_t pid;  /* ICMPv6 Echo id */
	uint16_t time; /* ICMPv6 Echo sequence */
	unint8_t hash[LIBTEREDO_HASH_LEN]; /* ICMPv6 Echo payload */
} teredo_hmac;
#endif

#if (LIBTEREDO_HASH_LEN + 4) != LIBTEREDO_HMAC_LEN
# error Inconsistent hash and HMAC length
#endif


static void
teredo_hash (const struct in6_addr *src, const struct in6_addr *dst,
             uint8_t *restrict hash, uint16_t timestamp)
{
	/* compute hash */
	md5_state_t ctx;
	md5_init (&ctx);
	md5_append (&ctx, inner_key.ipad, sizeof (inner_key.ipad));
	md5_append (&ctx, (unsigned char *)src, sizeof (*src));
	md5_append (&ctx, (unsigned char *)dst, sizeof (*dst));
	md5_append (&ctx, (unsigned char *)&hmac_pid, sizeof (hmac_pid));
	md5_append (&ctx, (unsigned char *)&timestamp, sizeof (timestamp));
	md5_finish (&ctx, hash);

	md5_init (&ctx);
	md5_append (&ctx, outer_key.opad, sizeof (outer_key.opad));
	md5_append (&ctx, hash, LIBTEREDO_HASH_LEN);
	md5_finish (&ctx, hash);
}


int
teredo_generate_HMAC (const struct in6_addr *src, const struct in6_addr *dst,
                      uint8_t *restrict hash)
{
	/* save hash-protected data */
	memcpy (hash, &hmac_pid, sizeof (hmac_pid));
	hash += sizeof (hmac_pid);

	uint16_t v16 = time (NULL);
	memcpy (hash, &v16, sizeof (v16));
	hash += sizeof (v16);

	teredo_hash (src, dst, hash, v16);

	return 0;
}


int
teredo_compare_HMAC (const struct in6_addr *src, const struct in6_addr *dst,
                     const uint8_t *hash)
{
	uint16_t v16, t16;
	unsigned char h1[LIBTEREDO_HASH_LEN];

	/* Check ICMPv6 ID */
	memcpy (&v16, hash, 2);
	if (v16 != hmac_pid)
		return -1;
	hash += 2;

	/* Check ICMPv6 sequence */
	memcpy (&t16, hash, 2);
	v16 = (((uint32_t)time (NULL)) & 0xffff) - t16;
	if (v16 >= 30)
		return -1; /* replay attack */
	hash += 2;

	teredo_hash (src, dst, h1, t16);

	/* compare HMAC hash */
	return memcmp (h1, hash, LIBTEREDO_HASH_LEN) ? -1 : 0;
}
