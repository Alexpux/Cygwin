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

/*
FUNCTION
<<iprintf>>---write formatted output (integer only)

INDEX
	iprintf

ANSI_SYNOPSIS
        #include <stdio.h>

        int iprintf(const char *<[format]>, ...);

TRAD_SYNOPSIS
	#include <stdio.h>

	int iprintf(<[format]> [, <[arg]>, ...])
	char *<[format]>;

DESCRIPTION
<<iprintf>> is a restricted version of <<printf>>: it has the same
arguments and behavior, save that it cannot perform any floating-point
formatting: the <<f>>, <<g>>, <<G>>, <<e>>, and <<F>> type specifiers
are not recognized.

RETURNS
        <<iprintf>> returns the number of bytes in the output string,
        save that the concluding <<NULL>> is not counted.
        <<iprintf>> returns when the end of the format string is
        encountered.  If an error occurs, <<iprintf>>
        returns <<EOF>>.

PORTABILITY
<<iprintf>> is not required by ANSI C.

Supporting OS subroutines required: <<close>>, <<fstat>>, <<isatty>>,
<<lseek>>, <<read>>, <<sbrk>>, <<write>>.
*/

#include <_ansi.h>
#include <reent.h>
#include <stdio.h>
#ifdef _HAVE_STDC
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include "local.h"

#ifndef _REENT_ONLY

#ifdef _HAVE_STDC
int
iprintf(_CONST char *fmt,...)
#else
int
iprintf(fmt, va_alist)
        char *fmt;
        va_dcl
#endif
{
  int ret;
  va_list ap;

  _REENT_SMALL_CHECK_INIT (_stdout_r (_REENT));
#ifdef _HAVE_STDC
  va_start (ap, fmt);
#else
  va_start (ap);
#endif
  ret = vfiprintf (stdout, fmt, ap);
  va_end (ap);
  return ret;
}

#endif /* ! _REENT_ONLY */

#ifdef _HAVE_STDC
int
_iprintf_r(struct _reent *ptr, _CONST char *fmt, ...)
#else
int
_iprintf_r(data, fmt, va_alist)
           char *data;
           char *fmt;
           va_dcl
#endif
{
  int ret;
  va_list ap;

  _REENT_SMALL_CHECK_INIT (_stdout_r (ptr));
#ifdef _HAVE_STDC
  va_start (ap, fmt);
#else
  va_start (ap);
#endif
  ret = vfiprintf (_stdout_r (ptr), fmt, ap);
  va_end (ap);
  return ret;
}
