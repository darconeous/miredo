/**
 * @file iothread.h
 * @brief IO thread management
 */

/***********************************************************************
 *  Copyright © 2009 Jérémie Koenig.                                   *
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

#ifndef LIBTEREDO_IOTHREAD_H
# define LIBTEREDO_IOTHREAD_H

# ifdef __cplusplus
extern "C" {
# endif

typedef struct teredo_iothread teredo_iothread;
typedef void *(*teredo_iothread_proc) (void *opaque, int fd);

/**
 * Start a new IO thread.
 *
 * @param proc callback function to be run as the new thread.
 * @param opaque opaque pointer passed to @p proc.
 * @param fd file descriptor for this thread.
 *
 * @return the new IO thread on success, NULL on error.
 */
teredo_iothread *teredo_iothread_start (teredo_iothread_proc proc,
                                               void *opaque, int fd);

/**
 * Stop an IO thread and destroy the teredo_iothread object.
 *
 * @param io the IO thread to stop.
 * @param close whether to close the file descriptor associted with it.
 */
void teredo_iothread_stop (teredo_iothread *io, bool close);

# ifdef __cplusplus
}
# endif /* ifdef __cplusplus */
#endif /* ifndef LIBTEREDO_IOTHREAD_H */

