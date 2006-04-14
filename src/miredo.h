/*
 * miredo.h - header for miredo.cpp
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
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

#ifndef MIREDO_MIREDO_H
# define MIREDO_MIREDO_H

# ifdef __cplusplus
extern int miredo_run (MiredoConf& conf, const char *server = NULL);

extern "C"
{
# endif

# include <sys/types.h> // uid_t

int miredo (const char *conffile, const char *server_name, int pidfd);
int drop_privileges (void);
int miredo_diagnose (void);
void miredo_setup_fd (int fd);
void miredo_setup_nonblock_fd (int fd);

# ifdef __cplusplus
}
# endif

extern uid_t unpriv_uid;
extern const char *miredo_chrootdir;
extern const char *const miredo_pidfile;
extern const char *const miredo_name;

# ifdef HAVE_LIBCAP
#  include <sys/capability.h>
extern const cap_value_t *miredo_capv;
extern const int miredo_capc;
# endif

#endif /* ifndef MIREDO_CONF_H */

