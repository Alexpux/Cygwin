/* crt0.c

   Copyright 2001, 2003, 2004, 2005, 2010, 2011 Red Hat, Inc.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

/* In the following ifdef'd i386 code, the FPU precision is set to 80 bits
   and all FPU exceptions are masked.  The former is needed to make long
   doubles work correctly.  The latter causes the FPU to generate NaNs and
   Infinities instead of signals for certain operations.  */

#include "winlean.h"
#include <sys/cygwin.h>

extern int main (int argc, char **argv);

void cygwin_crt0 (int (*main) (int, char **));

void
mainCRTStartup ()
{
#ifdef __i386__
  (void)__builtin_return_address(1);
  asm volatile ("andl $-16,%%esp" ::: "%esp");
#endif

  cygwin_crt0 (main);

  /* These are never actually called.  They are just here to force the inclusion
     of things like -lbinmode.  */

  cygwin_premain0 (0, NULL, NULL);
  cygwin_premain1 (0, NULL, NULL);
  cygwin_premain2 (0, NULL, NULL);
  cygwin_premain3 (0, NULL, NULL);
}

void WinMainCRTStartup(void) __attribute__ ((alias("mainCRTStartup")));
