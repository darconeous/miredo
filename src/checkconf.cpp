/*
 * checkconf.cpp - Miredo conf parser unit test
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2005-2006 Rémi Denis-Courmont.                         *
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
#include <locale.h>
#include "binreloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <unistd.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#else
# include <inttypes.h>
#endif
#include <netinet/in.h>
#include "conf.h"

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

class MiredoCheckConf : public MiredoConf
{
	virtual void Log (bool, const char *fmt, va_list ap)
	{
		vfprintf (stderr, fmt, ap);
		fputc ('\n', stderr);
	}
};

/* FIXME: use same more clever code as in main.c */
static const char conffile[] = SYSCONFDIR"/miredo.conf";

static int miredo_checkconf (MiredoConf& conf)
{
	int i;
	if (!ParseSyslogFacility (conf, "SyslogFacility", &i))
		return -1;

	uint32_t u32;
	uint16_t u16;
	if (!ParseIPv4 (conf, "ServerAddress", &u32)
			|| !ParseIPv4 (conf, "ServerAddress2", &u32))
		return -1;

	struct in6_addr ip6;
	if (!ParseIPv6 (conf, "Prefix", &ip6)
			|| !conf.GetInt16 ("InterfaceMTU", &u16))
		return -1;

	bool b;
	if (!ParseIPv4 (conf, "BindAddress", &u32)
			|| !conf.GetInt16 ("BindPort", &u16)
			|| !conf.GetBoolean ("IgnoreConeBit", &b))
		return -1;

	char *str = conf.GetRawValue ("InterfaceName");
	if (str != NULL)
		free (str);

	conf.Clear (0);
	return 0;
}


static int miredo_checkconffile (const char *filename)
{
	MiredoCheckConf conf;

	if (!conf.ReadFile (filename))
		return -1;

	return miredo_checkconf (conf);
}


static int usage (const char *path)
{
	printf ("Usage: %s [CONF_FILE]\n", path);
	return 0;
}

int version (void)
{
	puts (PACKAGE_NAME" v"PACKAGE_VERSION);
	return 0;
}

int main(int argc, char *argv[])
{
	(void)br_init (NULL);
	(void)setlocale (LC_ALL, "");
	char *path = br_find_locale_dir (LOCALEDIR);
	(void)bindtextdomain (PACKAGE_NAME, path);
	free (path);

	static const struct option opts[] =
	{
		{ "help",       no_argument,       NULL, 'h' },
		{ "version",    no_argument,       NULL, 'V' },
		{ NULL,         no_argument,       NULL, '\0'}
	};

	int c;
	while ((c = getopt_long (argc, argv, "hV", opts, NULL)) != -1)
		switch (c)
		{
			case 'h':
				return usage(argv[0]);

			case 'V':
				return version();
		}

	const char *filename = NULL;
	char *str = NULL;

	if (optind < argc)
		filename = argv[optind++];
	else
	{
		/* No parameters provided - attempt in source tree test */
		const char *srcdir = getenv ("srcdir");

		if (srcdir != NULL)
		{

			if (asprintf (&str, "%s/../misc/miredo.conf-dist",
			              srcdir) == -1)
				filename = str = NULL;
			else
				filename = str;
		}
		else
			filename = conffile;
	}

	int res = miredo_checkconffile (filename);

	if (str != NULL)
		free (str);

	return res;
}
