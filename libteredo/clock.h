/*
 * clock.h - Fast-lookup 1Hz clock declaration
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2006 Rémi Denis-Courmont.                              *
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

#ifndef LIBTEREDO_CLOCK_H
# define LIBTEREDO_CLOCK_H

typedef unsigned long teredo_clock_t;

# ifdef __cplusplus
extern "C" {
# endif

unsigned long teredo_clock (void);
int teredo_clock_create (void);
void teredo_clock_destroy (void);

# ifdef __cplusplus
}
# endif /* ifdef __cplusplus */
#endif /* ifndef LIBTEREDO_CLOCK_H */
