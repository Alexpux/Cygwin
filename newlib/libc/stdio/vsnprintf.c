/* doc in vfprintf.c */

/* This code created by modifying vsprintf.c so copyright inherited. */

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
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "%W% (Berkeley) %G%";
#endif /* LIBC_SCCS and not lint */

#include <_ansi.h>
#include <reent.h>
#include <stdio.h>
#include <limits.h>
#ifdef _HAVE_STDC
#include <stdarg.h>
#else
#include <varargs.h>
#endif

int
_DEFUN (vsnprintf, (str, size, fmt, ap),
     char *str _AND
     size_t size _AND
     _CONST char *fmt _AND
     va_list ap)
{
  int ret;
  FILE f;

  f._flags = __SWR | __SSTR;
  f._bf._base = f._p = (unsigned char *) str;
  f._bf._size = f._w = (size > 0 ? size - 1 : 0);
  f._data = _REENT;
  ret = vfprintf (&f, fmt, ap);
  if (size > 0)
    *f._p = 0;
  return ret;
}

int
_DEFUN (_vsnprintf_r, (ptr, str, size, fmt, ap),
     struct _reent *ptr _AND
     char *str _AND
     size_t size _AND
     _CONST char *fmt _AND
     va_list ap)
{
  int ret;
  FILE f;

  f._flags = __SWR | __SSTR;
  f._bf._base = f._p = (unsigned char *) str;
  f._bf._size = f._w = (size > 0 ? size - 1 : 0);
  f._data = ptr;
  ret = _vfprintf_r (ptr, &f, fmt, ap);
  if (size > 0)
    *f._p = 0;
  return ret;
}
