/*
 * diagnose.c - Libtun6 sanity test
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2006 Rémi Denis-Courmont.                              *
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

#include <assert.h>
#include <stdio.h>
#include <syslog.h> /* TODO: do not use syslog within the library */
#include "tun6.h"

static const char *invalid_name =
	"Overly-long-interface-name-that-will-not-work";

int main (void)
{
	char errbuf[LIBTUN6_ERRBUF_SIZE];

	int res = tun6_driver_diagnose (errbuf);
	fprintf (stderr, "%s\n", errbuf);

	openlog ("libtun6-diagnose", LOG_PERROR, LOG_USER);
#ifdef HAVE_LINUX
	assert (tun6_create (invalid_name) == NULL);
#endif
	
	tun6 *t = tun6_create (NULL);
	if ((t == NULL) != (res != 0))
		return 1;

	if (t == NULL)
	{
		puts ("Warning: cannot perform full libtun6 test");
		return 0;
	}
	/* TODO: further testing */
	
	tun6_destroy (t);
	closelog ();
	return 0;
}
