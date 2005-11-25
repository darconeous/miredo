/*
 * conf.cpp - Configuration text file parsing definition
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
#include <assert.h>

#include <stdio.h>
#include <stdlib.h> // malloc(), free()
#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#include <string.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/socket.h> // AF_INET, SOCK_DGRAM
#include <netinet/in.h>
#include <netdb.h>
#include <libteredo/teredo.h>

#include "conf.h"

MiredoConf::MiredoConf (void) : head (NULL), tail (NULL)
{
}


MiredoConf::~MiredoConf (void)
{
	Clear (0);
}


void
MiredoConf::Clear (unsigned show)
{
	struct setting *ptr = head;

	head = NULL;

	while (ptr != NULL)
	{
		struct setting *buf = ptr->next;
		if (show > 0)
		{
			syslog (LOG_WARNING,
				_("Superfluous directive %s at line %u"),
				ptr->name, ptr->line);
			show--;
		}
		free (ptr->name);
		free (ptr->value);
		free (ptr);
		ptr = buf;
	}
}


bool
MiredoConf::Set (const char *name, const char *value, unsigned line)
{
	struct setting *parm =
		(struct setting *)malloc (sizeof (struct setting));

	if (parm != NULL)
	{
		parm->name = strdup (name);
		if (parm->name != NULL)
		{
			parm->value = strdup (value);
			if (parm->value != NULL)
			{
				parm->line = line;
				parm->next = NULL;

				/* lock here */
				if (head == NULL)
					head = parm;
				else
				{
					assert (tail != NULL);
					tail->next = parm;
				}
				tail = parm;
				/* unlock here */

				return true;
			}
			free (parm->name);
		}
		free (parm);
	}
	syslog (LOG_ALERT, _("Memory problem: %m"));

	return false;
}


bool
MiredoConf::ReadFile (FILE *stream)
{
	char lbuf[1056];
	unsigned line = 0;

	while (fgets (lbuf, sizeof (lbuf), stream) != NULL)
	{
		size_t len = strlen (lbuf) - 1;
		line++;

		if (lbuf[len] != '\n')
		{
			while (fgetc (stream) != '\n')
				if (feof (stream) || ferror (stream))
					break;
			syslog (LOG_WARNING,
				_("Skipped overly long line %u"), line);
			continue;
		}

		lbuf[len] = '\0';
		char nbuf[32], vbuf[1024];

		switch (sscanf (lbuf, " %31s %1023s", nbuf, vbuf))
		{
			case 2:
				if ((*nbuf != '#') // comment
				 && !Set (nbuf, vbuf, line))
					return false;
				break;

			case 1:
				if (*nbuf != '#')
					syslog (LOG_WARNING,
						_("Ignoring line %u: %s"),
						line, nbuf);
				break;
		}
	}

	if (ferror (stream))
	{
		syslog (LOG_ERR, _("Error reading configuration file: %m"));
		return false;
	}
	return true;
}


bool
MiredoConf::ReadFile (const char *path)
{
	FILE *stream = fopen (path, "r");
	if (stream != NULL)
	{
		bool ret = ReadFile (stream);
		fclose (stream);
		return ret;
	}
	syslog (LOG_ERR, _("Error opening configuration file %s: %m"), path);
	return false;
}


char *
MiredoConf::GetRawValue (const char *name, unsigned *line)
{
	struct setting *prev = NULL;

	for (struct setting *p = head; p != NULL; p = p->next)
	{
		if (strcasecmp (p->name, name) == 0)
		{
			char *buf = p->value;

			if (line != NULL)
				*line = p->line;

			if (prev != NULL)
				prev->next = p->next;
			else
				head = p->next;

			free (p->name);
			free (p);
			return buf;
		}
		prev = p;
	}

	return NULL;
}


bool
MiredoConf::GetInt16 (const char *name, uint16_t *value, unsigned *line)
{
	char *val = GetRawValue (name, line);

	if (val == NULL)
		return true;

	char *end;
	unsigned long l;

	l = strtoul (val, &end, 0);
	
	if ((*end) || (l > 65535))
	{
		syslog (LOG_ERR,
			_("Invalid integer value \"%s\" for %s: %m"),
			val, name);
		free (val);
		return false;
	}
	*value = (uint16_t)l;
	free (val);
	return true;
}



static const char *true_strings[] = { "yes", "true", "on", "enabled", NULL };
static const char *false_strings[] =
	{ "no", "false", "off", "disabled", NULL };

bool
MiredoConf::GetBoolean (const char *name, bool *value, unsigned *line)
{
	char *val = GetRawValue (name, line);

	if (val == NULL)
		return true;
	else
	{
		// check if value is a number
		long l;
		char *end;

		l = strtol (val, &end, 0);

		if (*end == '\0') // success
		{
			*value = (l != 0);
			free (val);
			return true;
		}
	}

	for (const char **ptr = true_strings; *ptr != NULL; ptr++)
		if (!strcasecmp (val, *ptr))
		{
			*value = true;
			free (val);
			return true;
		}

	for (const char **ptr = false_strings; *ptr != NULL; ptr++)
		if (!strcasecmp (val, *ptr))
		{
			*value = false;
			free (val);
			return true;
		}

	syslog (LOG_ERR, _("Invalid boolean value \"%s\" for %s"), val, name);
	free (val);
	return false;
}


/*
 * Looks up an IPv4 address (network byte order) associated with hostname.
 */
int GetIPv4ByName (const char *hostname, uint32_t *ipv4)
{
	struct addrinfo help, *res;

	memset (&help, 0, sizeof (help));
	help.ai_family = AF_INET;
	help.ai_socktype = SOCK_DGRAM;
	help.ai_protocol = IPPROTO_UDP;

	int check = getaddrinfo (hostname, NULL, &help, &res);
	if (check)
		return check;

	*ipv4 = ((const struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
	freeaddrinfo (res);
	return 0;
}


bool
ParseIPv4 (MiredoConf& conf, const char *name, uint32_t *ipv4)
{
	unsigned line;
	char *val = conf.GetRawValue (name, &line);

	if (val == NULL)
		return true;

	int check = GetIPv4ByName (val, ipv4);

	if (check)
	{
		syslog (LOG_ERR, _("Invalid hostname \"%s\" at line %u: %s"),
			val, line, gai_strerror (check));
		free (val);
		return false;
	}

	free (val);
	return true;
}


bool
ParseIPv6 (MiredoConf& conf, const char *name, struct in6_addr *value)
{
	unsigned line;
	char *val = conf.GetRawValue (name, &line);

	if (val == NULL)
		return true;

	struct addrinfo help, *res;

	memset (&help, 0, sizeof (help));
	help.ai_family = AF_INET6;
	help.ai_socktype = SOCK_DGRAM;
	help.ai_protocol = IPPROTO_UDP;

	int check = getaddrinfo (val, NULL, &help, &res);

	if (check)
	{
		syslog (LOG_ERR, _("Invalid hostname \"%s\" at line %u: %s"),
			val, line, gai_strerror (check));
		free (val);
		return false;
	}

	memcpy (value,
		&((const struct sockaddr_in6*)(res->ai_addr))->sin6_addr,
		sizeof (struct in6_addr));

	freeaddrinfo (res);
	free (val);
	return true;
}


bool
ParseTeredoPrefix (MiredoConf& conf, const char *name, uint32_t *value)
{
	union teredo_addr addr;

	if (ParseIPv6 (conf, name, &addr.ip6))
	{
		if (!is_valid_teredo_prefix (addr.teredo.prefix))
		{
			syslog (LOG_ALERT,
				_("Invalid Teredo IPv6 prefix: %x::/32"),
				addr.teredo.prefix);
			return false;
		}

		*value = addr.teredo.prefix;
		return true;
	}
	return false;
}


static const struct miredo_conf_syslog_facility
{
	const char *str;
	int facility;
} facilities[] =
{
#ifdef LOG_AUTH
	{ "auth",	LOG_AUTH },
#endif
#ifdef LOG_AUTHPRIV
	{ "authpriv",	LOG_AUTHPRIV },
#endif
#ifdef LOG_CRON
	{ "cron",	LOG_CRON },
#endif
#ifdef LOG_DAEMON
	{ "daemon",	LOG_DAEMON },
#endif
#ifdef LOG_FTP
	{ "ftp",	LOG_FTP },
#endif
#ifdef LOG_KERN
	{ "kern",	LOG_KERN },
#endif
	{ "local0",	LOG_LOCAL0 },
	{ "local1",	LOG_LOCAL1 },
	{ "local2",	LOG_LOCAL2 },
	{ "local3",	LOG_LOCAL3 },
	{ "local4",	LOG_LOCAL4 },
	{ "local5",	LOG_LOCAL5 },
	{ "local6",	LOG_LOCAL6 },
	{ "local7",	LOG_LOCAL7 },
#ifdef LOG_LPR
	{ "lpr",	LOG_LPR },
#endif
#ifdef LOG_MAIL
	{ "mail",	LOG_MAIL },
#endif
#ifdef LOG_NEWS
	{ "news",	LOG_NEWS },
#endif
#ifdef LOG_SYSLOG
	{ "syslog",	LOG_SYSLOG },
#endif
	{ "user",	LOG_USER },
#ifdef LOG_UUCP
	{ "uucp",	LOG_UUCP },
#endif
	{ NULL,		0 }
};
	

bool
ParseSyslogFacility (MiredoConf& conf, const char *name, int *facility)
{
	unsigned line;
	char *str = conf.GetRawValue (name, &line);

	if (str == NULL)
		return true;

	for (const struct miredo_conf_syslog_facility *ptr = facilities;
						ptr->str != NULL; ptr++)
		if (!strcasecmp (str, ptr->str))
		{
			*facility = ptr->facility;
			free (str);
			return true;
		}

	syslog (LOG_ERR, _("Unknown syslog facility \"%s\" at line %u"),
		str, line);
	free (str);
	return false;
}
