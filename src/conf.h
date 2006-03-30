/*
 * conf.h - Configuration text file parsing declaration
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

#ifndef MIREDO_CONF_H
# ifndef __cplusplus
#  error C++ only header
# endif

# include <stdio.h>
# include <stdarg.h>

class MiredoConf
{
	private:
		struct setting
		{
			char *name;
			char *value;
			unsigned line;
			struct setting *next;
		} *head, *tail;

	protected:
		virtual void Log (bool error, const char *fmt, va_list ap);
		
	public:
		MiredoConf (void);
		virtual ~MiredoConf (void);
		MiredoConf (const MiredoConf& src); /* not implemented */
		MiredoConf& operator= (const MiredoConf& src); /* not implemented */

		void Clear (unsigned show = 5);

		/* Adds a setting. Returns false if memory is missing. */
		bool Set (const char *name, const char *value, unsigned line);

		/* Parses a file. Returns false on I/O error. */
		bool ReadFile (FILE *stream);
		bool ReadFile (const char *path);

		/*
		 * Looks up a setting by name. Returns NULL if not found.
		 * Otherwise, return value must be free()d by caller.
		 */
		char *GetRawValue (const char *name, unsigned *line = NULL);

		void LogError (const char *fmt, ...);
		void LogWarning (const char *fmt, ...);

		/*
		 * Looks up an unsigned 16-bits integer. Returns false if the
		 * setting was found but incorrectly formatted.
		 * If the setting was not found value, returns true and leave
		 * *value unchanged.
		 */
		bool GetInt16 (const char *name, uint16_t *value,
						unsigned *line = NULL);

		bool GetBoolean (const char *name, bool *value,
						unsigned *line = NULL);
};


int GetIPv4ByName (const char *hostname, uint32_t *ipv4);
bool ParseIPv4 (MiredoConf& conf, const char *name, uint32_t *value);
bool ParseIPv6 (MiredoConf& conf, const char *name, struct in6_addr *value);
bool ParseTeredoPrefix (MiredoConf& conf, const char *name, uint32_t *value);

bool ParseSyslogFacility (MiredoConf& conf, const char *name, int *fac);

#endif
