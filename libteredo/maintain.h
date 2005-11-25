/*
 * maintain.h - Teredo client qualification & maintenance
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

#ifndef MIREDO_LIBTEREDO_MAINTAIN_H
# define MIREDO_LIBTEREDO_MAINTAIN_H

struct teredo_maintenance;

# ifdef __cplusplus
extern "C" {
# endif

int teredo_maintenance_start (struct teredo_maintenance *);
void teredo_maintenance_stop (struct teredo_maintenance *);

# ifdef __cplusplus
}
# endif

#endif
