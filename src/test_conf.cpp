/*
 * test_conf.cpp - Miredo conf parser unit test
 * $Id: relay.cpp 659 2005-08-23 15:34:33Z remi $
 */

/***********************************************************************
 *  Copyright (C) 2005 Remi Denis-Courmont.                            *
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

#include <stdlib.h>
#include <unistd.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#else
# include <inttypes.h>
#endif
#include <netinet/in.h>
#include "conf.h"

int main(int argc, char *argv[])
{
	struct in6_addr ip6;
	char *str;
	int i;
	uint32_t u32;
	uint16_t u16;
	bool b;

	if (argc <= 1)
		return 1;

	MiredoConf conf;

	if (!conf.ReadFile (argv[1]))
		return 1;

	if (!ParseSyslogFacility (conf, "SyslogFacility", &i))
		return 1;

	if (!conf.GetBoolean ("DefaultRoute", &b))
		return 1;

	if (!ParseIPv4 (conf, "ServerAddress", &u32)
	 || !ParseIPv4 (conf, "ServerAddress2", &u32))
		return 1;

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
