/* This is file FILE.H */
/*
** Copyright (C) 1991 DJ Delorie, 24 Kirsten Ave, Rochester NH 03867-2954
**
** This file is distributed under the terms listed in the document
** "copying.dj", available from DJ Delorie at the address above.
** A copy of "copying.dj" should accompany this file; if not, a copy
** should be available from where this file was obtained.  This file
** may not be distributed without a verbatim copy of "copying.dj".
**
** This file is distributed WITHOUT ANY WARRANTY; without even the implied
** warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/
/*
 * 2003-11-27  Nicholas Wourms  <nwourms@netscape.net>:
 *
 *   Include sys/cdefs.h. Add function prototype for flock().
 *   Add some comments from BSD's header for further clarity.
 *   (L_SET, L_CURR, L_INCR, L_XTND): Redefine as the macros
 *   SEEK_SET, SEEK_CUR, SEEK_CUR, & SEEK_END respectively.
 *   (LOCK_SH,LOCK_EX,LOCK_NB,LOCK_UN): New macros for flock().
*/
#ifndef _FILE_H_
#define _FILE_H_

#include <sys/cdefs.h>
#include <fcntl.h>

/* Whence values for lseek(); renamed by POSIX 1003.1 */
#define L_SET		SEEK_SET
#define L_CURR		SEEK_CUR
#define L_INCR		SEEK_CUR
#define L_XTND		SEEK_END

/* Operations for flock() function */
#define	LOCK_SH		1	/* Shared lock. */
#define	LOCK_EX		2	/* Exclusive lock. */
#define	LOCK_NB		4	/* Don't block when locking. */
#define	LOCK_UN		8	/* Unlock. */

/* Operations for access function */
#define	F_OK		0	/* does file exist */
#define X_OK		1	/* is it executable or searchable by caller */
#define	W_OK		2	/* is it writable by caller */
#define	R_OK		4	/* is it readable by caller */

/* Apply or remove an advisory lock on the file fd refers to. */
__BEGIN_DECLS

int	_EXFUN(flock, (int, int));

__END_DECLS

#endif
