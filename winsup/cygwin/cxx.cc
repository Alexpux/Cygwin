/* cxx.cc

   Copyright 2002, 2003 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#if (__GNUC__ >= 3)

#include "winsup.h"
#include <stdlib.h>

void *
operator new (size_t s)
{
  void *p = calloc (1, s);
  return p;
}

void
operator delete (void *p)
{
  free (p);
}

void *
operator new[] (size_t s)
{
  return ::operator new (s);
}

void
operator delete[] (void *p)
{
  ::operator delete (p);
}

extern "C" void
__cxa_pure_virtual (void)
{
  api_fatal ("pure virtual method called");
}

extern "C" void
__cxa_guard_acquire ()
{
}

extern "C" void
__cxa_guard_release ()
{
}
#endif
