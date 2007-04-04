/* Copyright 2005, 2007 Shaun Jackman
 * Permission to use, copy, modify, and distribute this software
 * is freely granted, provided that this notice is preserved.
 */

#include <_ansi.h>
#include <reent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

int
_DEFUN(_vdiprintf_r, (ptr, fd, format, ap),
       struct _reent *ptr _AND
       int fd _AND
       const char *format _AND
       va_list ap)
{
  char *p;
  int n;

  _REENT_SMALL_CHECK_INIT (ptr);
  n = _vasiprintf_r (ptr, &p, format, ap);
  if (n == -1) return -1;
  n = _write_r (ptr, fd, p, n);
  _free_r (ptr, p);
  return n;
}

#ifndef _REENT_ONLY

int
_DEFUN(vdiprintf, (fd, format, ap),
       int fd _AND
       const char *format _AND
       va_list ap)
{
  return _vdiprintf_r (_REENT, fd, format, ap);
}

#endif /* ! _REENT_ONLY */
