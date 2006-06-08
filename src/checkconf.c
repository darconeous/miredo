/*
 * checkconf.c - Miredo conf parser unit test
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
#include <string.h>
#include <stdbool.h>

#include <unistd.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#else
# include <inttypes.h>
#endif
#include <netinet/in.h>
#include "miredo.h"
#include "conf.h"

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

static void logger (void *fail, bool error, const char *fmt, va_list ap)
{
	*((bool *)fail) = true;
	(void)error;

	vfprintf (stderr, fmt, ap);
	fputc ('\n', stderr);
}

/* FIXME: use same more clever code as in main.c */
static const char conffile[] = SYSCONFDIR"/miredo.conf";

static int miredo_checkconf (miredo_conf *conf)
{
	int i, res = 0;
	if (!miredo_conf_parse_syslog_facility (conf, "SyslogFacility", &i))
		res = -1;

	bool client = true;

	unsigned line;
	char *val = miredo_conf_get (conf, "RelayType", &line);

	if (val != NULL)
	{
		if ((strcasecmp (val, "client") == 0)
		 || (strcasecmp (val, "autoclient") == 0))
			client = true;
		else
		if ((strcasecmp (val, "cone") == 0)
		 || (strcasecmp (val, "restricted") == 0))
			client = false;
		else
		{
			fprintf (stderr, _("Invalid relay type \"%s\" at line %u"),
			         val, line);
			fputc ('\n', stderr);
			res = -1;
		}
		free (val);
	}

	uint32_t u32;
	uint16_t u16;

	if (client)
	{
#ifdef MIREDO_TEREDO_CLIENT
		if (!miredo_conf_parse_IPv4 (conf, "ServerAddress", &u32)
		 || !miredo_conf_parse_IPv4 (conf, "ServerAddress2", &u32))
			res = -1;
#else
		fputs (_("Unsupported Teredo client mode"), stderr);
		fputc ('\n', stderr);
		res = -1;
#endif
	}
	else
	{
		uint32_t pref;
		if (!miredo_conf_parse_teredo_prefix (conf, "Prefix", &pref)
		 || !miredo_conf_get_int16 (conf, "InterfaceMTU", &u16, NULL))
			res = -1;
	}

	bool b;
	if (!miredo_conf_parse_IPv4 (conf, "BindAddress", &u32)
	 || !miredo_conf_get_int16 (conf, "BindPort", &u16, NULL)
	 || !miredo_conf_get_bool (conf, "IgnoreConeBit", &b, NULL))
		res = -1;

	char *str = miredo_conf_get (conf, "InterfaceName", NULL);
	if (str != NULL)
		free (str);

	miredo_conf_clear (conf, 5);
	return res;
}


static int miredo_checkconffile (const char *filename)
{
	bool failed = false;
	miredo_conf *conf = miredo_conf_create (logger, &failed);

	if (conf == NULL)
		return -1;

	if (!miredo_conf_read_file (conf, filename))
		failed = true;
	else
	if (miredo_checkconf (conf))
		failed = true;

	miredo_conf_destroy (conf);
	return failed ? -1 : 0;
}


static int usage (const char *path)
{
	printf ("Usage: %s [CONF_FILE]\n", path);
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
				return miredo_version();
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
				return 1;
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
