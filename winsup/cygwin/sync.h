/* sync.h: Header file for cygwin synchronization primitives.

   Copyright 1999, 2000, 2001, 2002, 2003, 2004 Red Hat, Inc.

   Written by Christopher Faylor <cgf@cygnus.com>

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _SYNC_H
#define _SYNC_H
/* FIXME: Note that currently this class cannot be allocated via `new' since
   there are issues with malloc and fork. */
class muto
{
  static DWORD exiting_thread;
  LONG sync;	/* Used to serialize access to this class. */
  LONG visits;	/* Count of number of times a thread has called acquire. */
  LONG waiters;	/* Number of threads waiting for lock. */
  HANDLE bruteforce; /* event handle used to control waiting for lock. */
  DWORD tid;	/* Thread Id of lock owner. */
public:
  // class muto *next;
  const char *name;

  /* The real constructor. */
  muto *init(const char *name) __attribute__ ((regparm (3)));

#if 0	/* FIXME: See comment in sync.cc */
  ~muto ()
#endif
  int acquire (DWORD ms = INFINITE) __attribute__ ((regparm (2))); /* Acquire the lock. */
  int release () __attribute__ ((regparm (1)));		     /* Release the lock. */

  /* Return true if caller thread owns the lock. */
  int ismine () {return tid == GetCurrentThreadId ();}
  DWORD owner () {return tid;}
  int unstable () {return !tid && (sync || waiters >= 0);}
  void reset () __attribute__ ((regparm (1)));
  bool acquired ();
  static void set_exiting_thread () {exiting_thread = GetCurrentThreadId ();}
};

extern muto muto_start;

/* Use a statically allocated buffer as the storage for a muto */
#define new_muto(__name) \
({ \
  static muto __name##_storage __attribute__((nocommon)) __attribute__((section(".data_cygwin_nocopy1"))); \
  __name = __name##_storage.init (#__name); \
})

/* Use a statically allocated buffer as the storage for a muto */
#define new_muto1(__name, __storage) \
({ \
  static muto __storage __attribute__((nocommon)) __attribute__((section(".data_cygwin_nocopy1"))); \
  __name = __storage.init (#__name); \
})
#endif /*_SYNC_H*/
