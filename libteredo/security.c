/*
 * security.c - helpers for security-related stuff
 * $Id$
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

#include <stdbool.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h> /* open() */
#include <unistd.h> /* read(), close() */
#include <syslog.h>
#include <pthread.h>
#include <netinet/in.h> /* struct in6_addr */
#include <time.h> /* time_t */

#include <stdlib.h> /* malloc() for gcrypt() */
#include <errno.h> /* ENOMEM for gcrypt() */
#include <gcrypt.h>

#include "security.h"

#ifndef HAVE_OPENBSD
static const char *randfile = "/dev/random";
#else
static const char *randfile = "/dev/srandom";
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


bool
InitNonceGenerator (void)
{
	bool res;

	pthread_mutex_lock (&nonce_mutex);

	refs++;
	if (devfd[0] == -1)
		devfd[0] = random_open (true);
	if (devfd[1] == -1)
		devfd[1] = random_open (false);

	res = (devfd[0] != -1) && (devfd[1] != -1);
	pthread_mutex_unlock (&nonce_mutex);

	return res;
}


void
DeinitNonceGenerator (void)
{
	pthread_mutex_lock (&nonce_mutex);

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


/*** libgcrypt (client only) */
static bool has_libgcrypt = false;
#define LIBTEREDO_KEY_LEN LIBTEREDO_NONCE_LEN
static unsigned char key[LIBTEREDO_KEY_LEN];

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static void init_libgcrypt (void)
{
	gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	if (gcry_check_version ("1.2.0") == NULL)
		syslog (LOG_ERR, _("Libgcrypt version mismatch."));
	else
	{
		has_libgcrypt = true;
		gcry_control (GCRYCTL_DISABLE_SECMEM);
		GenerateNonce (key, true);
	}
}


bool InitHMAC (void)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;

	pthread_once (&once, init_libgcrypt);
	return has_libgcrypt;
}


void DeinitHMAC (void)
{
}


#define LIBTEREDO_HASH_LEN 16
#if 0
typedef struct libteredo_hmac
{
	uint16_t pid;  /* ICMPv6 Echo id */
	uint16_t time; /* ICMPv6 Echo sequence */
	unint8_t hash[LIBTEREDO_HASH_LEN]; /* ICMPv6 Echo payload */
} libteredo_hmac;
#endif

#if (LIBTEREDO_HASH_LEN + 4) != LIBTEREDO_HMAC_LEN
# error Inconsistent hash and HMAC length
#endif

static pid_t hmac_pid = -1;

bool
GenerateHMAC (const struct in6_addr *src, const struct in6_addr *dst,
              uint8_t *hash)
{
	gcry_md_hd_t hd;
	uint16_t v16;

	/* create HMAC handle */
	(void)gcry_md_open (&hd, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);
	if ((hd == NULL) || (gcry_md_setkey (hd, key, LIBTEREDO_KEY_LEN)))
		return false;

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
	gcry_md_write (hd, src, sizeof (*src));
	gcry_md_write (hd, dst, sizeof (*dst));
	gcry_md_write (hd, &hmac_pid, sizeof (hmac_pid));
	gcry_md_write (hd, &v16, sizeof (v16));
	gcry_md_final (hd);

	/* write hash */
	memcpy (hash, gcry_md_read (hd, 0), LIBTEREDO_HASH_LEN);
	gcry_md_close (hd);
	return true;
}

bool
CompareHMAC (const struct in6_addr *src, const struct in6_addr *dst,
             const uint8_t *hash)
{
	gcry_md_hd_t hd;
	uint16_t v16, t16;
	bool res;

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

	/* create HMAC */
	(void)gcry_md_open (&hd, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);
	if ((hd == NULL) || (gcry_md_setkey (hd, key, LIBTEREDO_KEY_LEN)))
		return false;

	/* compute HMAC */
	gcry_md_write (hd, src, sizeof (*src));
	gcry_md_write (hd, dst, sizeof (*dst));
	gcry_md_write (hd, &hmac_pid, sizeof (hmac_pid));
	gcry_md_write (hd, &t16, sizeof (t16));
	gcry_md_final (hd);

	/* compare hash */
	res = !memcmp (gcry_md_read (hd, 0), hash, LIBTEREDO_HASH_LEN);
	gcry_md_close (hd);
	return res;
}
