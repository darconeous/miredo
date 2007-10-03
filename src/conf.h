/*
 * conf.h - Configuration text file parsing declaration
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license, or (at  *
 *  your option) any later version.                                    *
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

# include <stdarg.h>

typedef void (*miredo_conf_logger) (void *, bool, const char *, va_list);
struct in6_addr;

# ifdef __cplusplus
extern "C" {
# endif

miredo_conf *miredo_conf_create (miredo_conf_logger logger, void *opaque);
void miredo_conf_destroy (miredo_conf *conf);

bool miredo_conf_read_file (miredo_conf *conf, const char *path);

void miredo_conf_clear (miredo_conf *conf, int show);
char *miredo_conf_get (miredo_conf *conf, const char *name, unsigned *line);

bool miredo_conf_get_int16 (miredo_conf *conf, const char *name,
                            uint16_t *value, unsigned *line);
bool miredo_conf_get_bool (miredo_conf *conf, const char *name,
                           bool *value, unsigned *line);

int GetIPv4ByName (const char *hostname, uint32_t *ipv4);

bool miredo_conf_parse_IPv4 (miredo_conf *conf, const char *name,
                             uint32_t *value);
bool miredo_conf_parse_IPv6 (miredo_conf *conf, const char *name,
                             struct in6_addr *value);
bool miredo_conf_parse_teredo_prefix (miredo_conf *conf, const char *name,
                                      uint32_t *value);

bool miredo_conf_parse_syslog_facility (miredo_conf *conf, const char *name,
                                        int *facility);

# ifdef __cplusplus
}
# endif

#endif
