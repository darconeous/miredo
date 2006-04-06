/*
 * pselect replacement declaration
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


#ifndef __MIREDO_COMPAT_PSELECT_H
# define __MIREDO_COMPAT_PSELECT_H

# ifndef HAVE_PSELECT

#  ifdef __cplusplus
extern "C" {
#  endif

int pselect (int max, fd_set *rfds, fd_set *wfds, fd_set *efds,
             const struct timespec *ts, const sigset_t *mask);

#  ifdef __cplusplus
}
#  endif
# endif /* !HAVE_PSELECT */
#endif /* __MIREDO_COMPAT_PSELECT_H */
