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
public:
  const char *name;
private:
  static DWORD exiting_thread;
  LONG sync;	/* Used to serialize access to this class. */
  LONG waiters;	/* Number of threads waiting for lock. */
  HANDLE bruteforce; /* event handle used to control waiting for lock. */
public:
  LONG visits;	/* Count of number of times a thread has called acquire. */
  void *tls;	/* Tls of lock owner. */
  // class muto *next;

  /* The real constructor. */
  muto *init (const char *) __attribute__ ((regparm (2)));

#if 0	/* FIXME: See comment in sync.cc */
  ~muto ()
#endif
  int acquire (DWORD ms = INFINITE) __attribute__ ((regparm (2))); /* Acquire the lock. */
  int release () __attribute__ ((regparm (1)));		     /* Release the lock. */

  bool acquired () __attribute__ ((regparm (1)));
  void upforgrabs () {tls = this;}  // just set to an invalid address
  void grab () __attribute__ ((regparm (1)));
  operator int () const {return !!name;}
  static void set_exiting_thread () {exiting_thread = GetCurrentThreadId ();}
};

#endif /*_SYNC_H*/
