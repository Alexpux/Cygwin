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
<<fiprintf>>---format output to file (integer only)

INDEX
	fiprintf

ANSI_SYNOPSIS
        #include <stdio.h>

        int fiprintf(FILE *<[fd]>, const char *<[format]>, ...);

TRAD_SYNOPSIS
	#include <stdio.h>

	int fiprintf(<[fd]>, <[format]> [, <[arg]>, ...]);
	FILE *<[fd]>;
	char *<[format]>;

DESCRIPTION
<<fiprintf>> is a restricted version of <<fprintf>>: it has the same
arguments and behavior, save that it cannot perform any floating-point
formatting---the <<f>>, <<g>>, <<G>>, <<e>>, and <<F>> type specifiers
are not recognized.

RETURNS
        <<fiprintf>> returns the number of bytes in the output string,
        save that the concluding <<NULL>> is not counted.
        <<fiprintf>> returns when the end of the format string is
        encountered.  If an error occurs, <<fiprintf>>
        returns <<EOF>>.

PORTABILITY
<<fiprintf>> is not required by ANSI C.

Supporting OS subroutines required: <<close>>, <<fstat>>, <<isatty>>,
<<lseek>>, <<read>>, <<sbrk>>, <<write>>.
*/

#include <_ansi.h>
#include <stdio.h>
#ifdef _HAVE_STDC
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#ifdef _HAVE_STDC
int
fiprintf(FILE * fp, _CONST char *fmt,...)
#else
int
fiprintf(fp, fmt, va_alist)
         FILE *fp;
         char *fmt;
         va_dcl
#endif
{
  int ret;
  va_list ap;

#ifdef _HAVE_STDC
  va_start (ap, fmt);
#else
  va_start (ap);
#endif
  ret = vfiprintf (fp, fmt, ap);
  va_end (ap);
  return ret;
}
