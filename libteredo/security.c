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
#include <syslog.h>
#include <pthread.h>
#include <netinet/in.h> /* struct in6_addr */
#include <time.h> /* time_t */
#include <errno.h>

#include "security.h"
#include "debug.h"
#include "md5.h"

#if defined (__OpenBSD__) || defined (__OpenBSD_kernel__)
static const char *randfile = "/dev/srandom";
#else
static const char *randfile = "/dev/random";
#endif
static const char *urandfile = "/dev/urandom";


static int devfd[2] = { -1, -1 };
static pthread_mutex_t nonce_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned refs = 0;

static int
random_open (bool critical)
{
	int fd = open (critical ? randfile : urandfile, 0);
	if (fd == -1)
		syslog (LOG_ERR, _("Error (%s): %s\n"),
			critical ? randfile : urandfile,
		        strerror (errno));

	return fd;
}


int
teredo_init_nonce_generator (void)
{
	bool ok;

	pthread_mutex_lock (&nonce_mutex);
	if (refs < UINT_MAX)
	{
		refs++;
		if (devfd[0] == -1)
			devfd[0] = random_open (true);
		if (devfd[1] == -1)
			devfd[1] = random_open (false);

		ok = (devfd[0] != -1) && (devfd[1] != -1);
	}
	else
		ok = false;
	pthread_mutex_unlock (&nonce_mutex);

	return ok ? 0 : -1;
}


void
teredo_deinit_nonce_generator (void)
{
	pthread_mutex_lock (&nonce_mutex);
	assert (refs > 0);

	if (--refs == 0)
	{
		if (devfd[0] != -1)
			(void)close (devfd[0]);
		if (devfd[1] != -1)
			(void)close (devfd[1]);
	}

	pthread_mutex_unlock (&nonce_mutex);
}


/*
 * Generates a random nonce value (8 bytes).
 * Thread-safe. Returns true on success, false on error
 */
bool
GenerateNonce (unsigned char *b, bool critical)
{
	int fd = devfd[critical ? 0 : 1];

	memset (b, 0, LIBTEREDO_NONCE_LEN);
	if (fd != -1)
	{
		ssize_t tot = 0, val;

		do
		{
			val = read (fd, b + tot, LIBTEREDO_NONCE_LEN - tot);
			if (val <= 0)
				syslog (LOG_ERR, _("Error (%s): %s\n"),
				        critical ? randfile : urandfile,
			                strerror (errno));
			else
				tot += val;
		}
		while ((tot < LIBTEREDO_NONCE_LEN) && (val > 0));

		return tot == LIBTEREDO_NONCE_LEN;
	}

	return false;
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


static void init_hmac_once (void)
{
	unsigned i;

	/* Generate HMAC key and precomputes padding */
	memset (&inner_key, 0, sizeof (inner_key));
	GenerateNonce (inner_key.key, true);
	memcpy (&outer_key, &inner_key, sizeof (outer_key));

	for (i = 0; i < sizeof (inner_key); i++)
	{
		inner_key.ipad[i] ^= 0x36;
		outer_key.opad[i] ^= 0x5c;
	}
}


bool InitHMAC (void)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;

	pthread_once (&once, init_hmac_once);
	return true;
}


void DeinitHMAC (void)
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

static pid_t hmac_pid = -1;

#include <stdio.h>
bool
GenerateHMAC (const struct in6_addr *src, const struct in6_addr *dst,
              uint8_t *hash)
{
	md5_state_t ctx;
	uint16_t v16;

	/* save hash-protected data */
	if (hmac_pid == -1)
		hmac_pid = getpid ();
	v16 = hmac_pid;
	memcpy (hash, &v16, 2);
	hash += 2;

	v16 = time (NULL);
	memcpy (hash, &v16, 2);
	hash += 2;

	/* compute hash */
	md5_init (&ctx);
	md5_append (&ctx, inner_key.ipad, sizeof (inner_key.ipad));
	md5_append (&ctx, (unsigned char *)src, sizeof (*src));
	md5_append (&ctx, (unsigned char *)dst, sizeof (*dst));
	md5_append (&ctx, (unsigned char *)&hmac_pid, sizeof (hmac_pid));
	md5_append (&ctx, (unsigned char *)&v16, sizeof (v16));
	md5_finish (&ctx, hash);

	md5_init (&ctx);
	md5_append (&ctx, outer_key.opad, sizeof (outer_key.opad));
	md5_append (&ctx, hash, LIBTEREDO_HASH_LEN);
	md5_finish (&ctx, hash);

	return true;
}

bool
CompareHMAC (const struct in6_addr *src, const struct in6_addr *dst,
             const uint8_t *hash)
{
	md5_state_t ctx;
	uint16_t v16, t16;
	unsigned char h1[LIBTEREDO_HASH_LEN];

	/* Check ICMPv6 ID */
	memcpy (&v16, hash, 2);
	if (v16 != (uint16_t)hmac_pid)
		return false;
	hash += 2;

	/* Check ICMPv6 sequence */
	memcpy (&t16, hash, 2);
	v16 = (((uint32_t)time (NULL)) & 0xffff) - t16;
	if (v16 >= 30)
		return false; /* replay attack */
	hash += 2;

	/* compute HMAC hash */
	md5_init (&ctx);
	md5_append (&ctx, inner_key.ipad, sizeof (inner_key.ipad));
	md5_append (&ctx, (unsigned char *)src, sizeof (*src));
	md5_append (&ctx, (unsigned char *)dst, sizeof (*dst));
	md5_append (&ctx, (unsigned char *)&hmac_pid, sizeof (hmac_pid));
	md5_append (&ctx, (unsigned char *)&t16, sizeof (t16));
	md5_finish (&ctx, h1);

	md5_init (&ctx);
	md5_append (&ctx, outer_key.opad, sizeof (outer_key.opad));
	md5_append (&ctx, h1, sizeof (h1));
	md5_finish (&ctx, h1);

	/* compare HMAC hash */
	return !memcmp (h1, hash, LIBTEREDO_HASH_LEN);
}
