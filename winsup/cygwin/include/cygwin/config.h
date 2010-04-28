/* cygwin/config.h header file for Cygwin.

   This wraps Cygwin configuration setting which were in newlib's
   sys/config.h before.  This way we can manaage our configuration
   setting without bothering newlib.

   Copyright 2003, 2007, 2008, 2009, 2010 Red Hat, Inc.
   Written by C. Vinschen.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _CYGWIN_CONFIG_H
#ifdef __cplusplus
extern "C" {
#endif
#define _CYGWIN_CONFIG_H

#define __DYNAMIC_REENT__

/* The following provides an inline version of __getreent() for newlib,
   which will be used throughout the library whereever there is a _r
   version of a function that takes _REENT.  This saves the overhead
   of a function call for what amounts to a simple computation.

   The definition below is essentially equivalent to the one in cygtls.h
   (&_my_tls.local_clib) however it uses a fixed precomputed
   offset rather than dereferencing a field of a structure.

   Including tlsoffets.h here in order to get this constant offset
   tls_local_clib is a bit of a hack, but the alternative would require
   dragging the entire definition of struct _cygtls (a large and complex
   Cygwin internal data structure) into newlib.  The machinery to
   compute these offsets already exists for the sake of gendef so
   we might as well just use it here.  */

#ifdef _COMPILING_NEWLIB
#include "../tlsoffsets.h"
extern char *_tlsbase __asm__ ("%fs:4");
#define __getreent() (struct _reent *)(_tlsbase + tls_local_clib)
#endif  /* _COMPILING_NEWLIB */

#define __FILENAME_MAX__ 4096	/* Keep in sync with PATH_MAX in limits.h. */

/* The following block of macros is required to build newlib correctly for
   Cygwin.  Changing them in applications has no or not the desired effect.
   Just leave them alone. */
#define _READ_WRITE_RETURN_TYPE _ssize_t
#define __LARGE64_FILES 1
#define __USE_INTERNAL_STAT64 1
#define __LINUX_ERRNO_EXTENSIONS__ 1
#define _MB_EXTENDED_CHARSETS_ALL 1
#define __HAVE_LOCALE_INFO__ 1
#define __HAVE_LOCALE_INFO_EXTENDED__ 1
#define _WANT_C99_TIME_FORMATS 1
#if defined(__INSIDE_CYGWIN__) || defined(_COMPILING_NEWLIB)
#define __EXPORT __declspec(dllexport)
#define __IMPORT
#else
#define __EXPORT
#define __IMPORT __declspec(dllimport)
#endif

#ifndef __WCHAR_MAX__
#define __WCHAR_MAX__ 0xffffu
#endif

#define DEFAULT_LOCALE "C.UTF-8"

#ifdef __cplusplus
}
#endif
#endif /* _CYGWIN_CONFIG_H */
