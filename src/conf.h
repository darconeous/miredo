/*
 * conf.h - Configuration text file parsing declaration
 * $Id: main.c 340 2004-12-31 13:28:42Z remi $
 */

/***********************************************************************
 *  Copyright (C) 2004 Remi Denis-Courmont.                            *
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

	public:
		MiredoConf (void);
		~MiredoConf (void);

		/* Adds a setting. Returns false if memory is missing. */
		bool Set (const char *name, const char *value, unsigned line);

		/* Parses a file. Returns false on I/O error. */
		bool ReadFile (FILE *stream);
		bool ReadFile (const char *path);

		/* Looks up a setting by name. Returns NULL if not found. */
		const char *GetRawValue (const char *name,
						unsigned *line = NULL);

		/* 
		 * Looks up a setting by name. Returns false on memory error.
		 * If the setting was found, *value will be a dynamically
		 * dynamically allocated copy of the setting (call free() to
		 * release. If it was not found *value will be unchanged.
		 */
		bool GetString (const char *name, char **value,
						unsigned *line = NULL);

		/*
		 * Looks up an unsigned 16-bits integer. Returns false if the
		 * setting was found but incorrectly formatted.
		 * If the setting was not found value, returns true and leave
		 * *value unchanged.
		 */
		bool GetInt16 (const char *name, uint16_t *value,
						unsigned *line = NULL);
};


bool ParseIPv4 (MiredoConf& conf, const char *name, uint32_t *value);
bool ParseIPv6 (MiredoConf& conf, const char *name, struct in6_addr *value);
bool ParseTeredoPrefix (MiredoConf& conf, const char *name, uint32_t *value);
bool ParseRelayType (MiredoConf& conf, const char *name, bool *enabled,
			bool *cone);

#endif
