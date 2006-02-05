/* sys/stdio.h

   Copyright 2004, 2005 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _SYS_STDIO_H_
#define _SYS_STDIO_H_

#include <sys/cdefs.h>
#include <sys/lock.h>

#if !defined(__SINGLE_THREAD__)
#  if !defined(_flockfile)
#    define _flockfile(fp) __cygwin_lock_lock ((_LOCK_T *)&(fp)->_lock)
#  endif
#  if !defined(_ftrylockfile)
#    define _ftrylockfile(fp) __cygwin_lock_trylock ((_LOCK_T *)&(fp)->_lock)
#  endif
#  if !defined(_funlockfile)
#    define _funlockfile(fp) __cygwin_lock_unlock ((_LOCK_T *)&(fp)->_lock)
#  endif
#endif

__BEGIN_DECLS

#ifdef _GNU_SOURCE
ssize_t	_EXFUN(getline, (char **, size_t *, FILE *));
ssize_t	_EXFUN(getdelim, (char **, size_t *, int, FILE *));
#endif /* _GNU_SOURCE */

__END_DECLS

#endif
