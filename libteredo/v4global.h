/**
 * @file v4global.h
 * @brief Check whether an IPv4 address is global
 *
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004 Rémi Denis-Courmont.                              *
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

#ifndef MIREDO_V4GLOBAL_H
# define MIREDO_V4GLOBAL_H

#ifdef __cplusplus
extern "C"
#endif

/**
 * Checks that ip is a global unicast IPv4 address
 * (Values shoud maybe not be hardcoded that way).
 */
int is_ipv4_global_unicast (uint32_t ip);

#endif /* ifndef MIREDO_V4GLOBAL_H */

