/*
 * addrwatch.h - Watch system IPv6 addresses
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

#ifndef __MIREDO_ADDRWATCH_H
# define __MIREDO_ADDRWATCH_H

typedef struct miredo_addrwatch miredo_addrwatch;

# ifdef __cplusplus
extern "C" {
# endif

miredo_addrwatch *miredo_addrwatch_start (int self_scope);
void miredo_addrwatch_stop (miredo_addrwatch *self);

void miredo_addrwatch_set_callback (miredo_addrwatch *self,
                                    void (*cb) (void *, int), void *opaque);
int miredo_addrwatch_available (miredo_addrwatch *self);

# ifdef __cplusplus
}
# endif

#endif /* __MIREDO_ADDRWATCH_H */
