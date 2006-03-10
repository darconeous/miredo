/*
 * checkconf.cpp - Miredo conf parser unit test
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2005-2006 Remi Denis-Courmont.                       *
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

class MiredoCheckConf : public MiredoConf
{
	virtual void Log (bool, const char *fmt, va_list ap)
	{
		vfprintf (stderr, fmt, ap);
		fputc ('\n', stderr);
	}
};


static const char conffile[] = SYSCONFDIR"/miredo.conf";


int main(int argc, char *argv[])
{
	(void)setlocale (LC_ALL, "");
	(void)bindtextdomain (PACKAGE_NAME, LOCALEDIR);

	MiredoCheckConf conf;

	const char *filename = NULL;
	char *str = NULL;

	if (argc <= 1)
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
	else
		filename = argv[1];

	if (!conf.ReadFile (filename))
	{
		if (str != NULL)
			free (str);
		return 1;
	}
	if (str != NULL)
		free (str);

	int i;
	if (!ParseSyslogFacility (conf, "SyslogFacility", &i))
		return 1;

	bool b;
	if (!conf.GetBoolean ("DefaultRoute", &b))
		return 1;

	uint32_t u32;
	uint16_t u16;
	if (!ParseIPv4 (conf, "ServerAddress", &u32)
	 || !ParseIPv4 (conf, "ServerAddress2", &u32))
		return 1;

	struct in6_addr ip6;
	if (!ParseIPv6 (conf, "Prefix", &ip6)
	 || !conf.GetInt16 ("InterfaceMTU", &u16))
		return 1;

	if (!ParseIPv4 (conf, "BindAddress", &u32)
	 || !conf.GetInt16 ("BindPort", &u16)
	 || !conf.GetBoolean ("IgnoreConeBit", &b))
		return 1;

	str = conf.GetRawValue ("InterfaceName");
	if (str != NULL)
		free (str);

	conf.Clear (0);
	return 0;
}
