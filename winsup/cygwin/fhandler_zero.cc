/* fhandler_dev_zero.cc: code to access /dev/zero

   Copyright 2000, 2001, 2002, 2003, 2004 Red Hat, Inc.

   Written by DJ Delorie (dj@cygnus.com)

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <errno.h>
#include "security.h"
#include "path.h"
#include "fhandler.h"

fhandler_dev_zero::fhandler_dev_zero ()
  : fhandler_base ()
{
}

int
fhandler_dev_zero::open (int flags, mode_t)
{
  set_flags ((flags & ~O_TEXT) | O_BINARY);
  nohandle (true);
  set_open_status ();
  return 1;
}

int
fhandler_dev_zero::write (const void *, size_t len)
{
  return len;
}

void __stdcall
fhandler_dev_zero::read (void *ptr, size_t& len)
{
  memset (ptr, 0, len);
  return;
}

_off64_t
fhandler_dev_zero::lseek (_off64_t, int)
{
  return 0;
}

void
fhandler_dev_zero::dump ()
{
  paranoid_printf ("here, fhandler_dev_zero");
}
