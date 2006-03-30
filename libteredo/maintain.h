/*
 * maintain.h - Teredo client qualification & maintenance
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2004-2005 Rémi Denis-Courmont.                       *
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

#ifndef MIREDO_LIBTEREDO_MAINTAIN_H
# define MIREDO_LIBTEREDO_MAINTAIN_H

# ifdef __cplusplus
extern "C" {
# endif

typedef struct teredo_maintenance teredo_maintenance;
typedef void (*teredo_state_change) (const struct teredo_state *s, void *);

teredo_maintenance *
libteredo_maintenance_start (int fd, teredo_state_change cb, void *opaque,
                             const char *s1, const char *s2);
void libteredo_maintenance_stop (teredo_maintenance *m);
void libteredo_maintenance_process (teredo_maintenance *m,
                                    const teredo_packet *packet);

# ifdef __cplusplus
}
# endif

#endif
