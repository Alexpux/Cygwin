/*
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *	%W% (UofMD/Berkeley) %G%
 */

/*
 * Information local to this implementation of stdio,
 * in particular, macros and private variables.
 */

#include <_ansi.h>
#include <reent.h>
#include <stdarg.h>
#include <reent.h>
#include <stdlib.h>
#include <unistd.h>

extern int    _EXFUN(__svfscanf_r,(struct _reent *,FILE *, _CONST char *,va_list));
extern int    _EXFUN(__svfiscanf_r,(struct _reent *,FILE *, _CONST char *,va_list));
extern FILE  *_EXFUN(__sfp,(struct _reent *));
extern int    _EXFUN(__sflags,(struct _reent *,_CONST char*, int*));
extern int    _EXFUN(__srefill,(FILE *));
extern _READ_WRITE_RETURN_TYPE _EXFUN(__sread,(_PTR, char *, int));
extern _READ_WRITE_RETURN_TYPE _EXFUN(__swrite,(_PTR, char _CONST *, int));
extern _fpos_t _EXFUN(__sseek,(_PTR, _fpos_t, int));
extern int    _EXFUN(__sclose,(_PTR));
extern int    _EXFUN(__stextmode,(int));
extern _VOID   _EXFUN(__sinit,(struct _reent *));
extern _VOID   _EXFUN(_cleanup_r,(struct _reent *));
extern _VOID   _EXFUN(__smakebuf,(FILE *));
extern int    _EXFUN(_fwalk,(struct _reent *, int (*)(FILE *)));
extern int    _EXFUN(_fwalk_reent,(struct _reent *, int (*)(struct _reent *, FILE *)));
struct _glue * _EXFUN(__sfmoreglue,(struct _reent *,int n));
extern int   _EXFUN(__srefill,(FILE *fp));

/* Called by the main entry point fns to ensure stdio has been initialized.  */

#define CHECK_INIT(ptr) \
  do						\
    {						\
      if ((ptr) && !(ptr)->__sdidinit)		\
	__sinit (ptr);				\
    }						\
  while (0)

/* Return true iff the given FILE cannot be written now.  */

#define	cantwrite(fp) \
  ((((fp)->_flags & __SWR) == 0 || (fp)->_bf._base == NULL) && \
   __swsetup(fp))

/* Test whether the given stdio file has an active ungetc buffer;
   release such a buffer, without restoring ordinary unread data.  */

#define	HASUB(fp) ((fp)->_ub._base != NULL)
#define	FREEUB(fp) { \
	if ((fp)->_ub._base != (fp)->_ubuf) \
		_free_r(_REENT, (char *)(fp)->_ub._base); \
	(fp)->_ub._base = NULL; \
}

/* Test for an fgetline() buffer.  */

#define	HASLB(fp) ((fp)->_lb._base != NULL)
#define	FREELB(fp) { _free_r(_REENT,(char *)(fp)->_lb._base); (fp)->_lb._base = NULL; }

/* WARNING: _dcvt is defined in the stdlib directory, not here!  */

char *_EXFUN(_dcvt,(struct _reent *, char *, double, int, int, char, int));
char *_EXFUN(_sicvt,(char *, short, char));
char *_EXFUN(_icvt,(char *, int, char));
char *_EXFUN(_licvt,(char *, long, char));
#ifdef __GNUC__
char *_EXFUN(_llicvt,(char *, long long, char));
#endif

#define CVT_BUF_SIZE 128

#define	NDYNAMIC 4	/* add four more whenever necessary */

#ifdef __SINGLE_THREAD__
#define __sfp_lock_acquire()
#define __sfp_lock_release()
#define __sinit_lock_acquire()
#define __sinit_lock_release()
#else
_VOID _EXFUN(__sfp_lock_acquire,(_VOID));
_VOID _EXFUN(__sfp_lock_release,(_VOID));
_VOID _EXFUN(__sinit_lock_acquire,(_VOID));
_VOID _EXFUN(__sinit_lock_release,(_VOID));
#endif
