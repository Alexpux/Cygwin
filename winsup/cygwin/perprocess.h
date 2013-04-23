/* per_process.h: main Cygwin header file.

   Copyright 2000, 2001, 2013 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include <sys/cygwin.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Pointer into application's static data */
extern struct per_process __cygwin_user_data;
#define user_data (&__cygwin_user_data)

/* We use the following to test that sizeof hasn't changed.  When adding
   or deleting members, insert fillers or use the reserved entries.
   Do not change this value. */
#ifdef __x86_64__
#define SIZEOF_PER_PROCESS (41 * 8)
#else
#define SIZEOF_PER_PROCESS (42 * 4)
#endif

#ifdef __cplusplus
}
#endif
