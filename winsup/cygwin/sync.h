/* sync.h: Header file for cygwin synchronization primitives.

   Copyright 1999, 2000, 2001 Red Hat, Inc.

   Written by Christopher Faylor <cgf@cygnus.com>

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

/* FIXME: Note that currently this class cannot be allocated via `new' since
   there are issues with malloc and fork. */
class muto
{
  LONG sync;	/* Used to serialize access to this class. */
  LONG visits;	/* Count of number of times a thread has called acquire. */
  LONG waiters;	/* Number of threads waiting for lock. */
  HANDLE bruteforce; /* event handle used to control waiting for lock. */
  DWORD tid;	/* Thread Id of lock owner. */
public:
  class muto *next;
  const char *name;
  void *operator new (size_t, void *p) {return p;}
  void *operator new (size_t) {return ::new muto; }
  void operator delete (void *) {;} /* can't handle allocated mutos
					currently */

  muto() {}
  /* The real constructor. */
  muto(int inh, const char *name);
  ~muto ();
  int acquire (DWORD ms = INFINITE) __attribute__ ((regparm(1))); /* Acquire the lock. */
  int release ();		     /* Release the lock. */

  /* Return true if caller thread owns the lock. */
  int ismine () {return tid == GetCurrentThreadId ();}
  DWORD owner () {return tid;}
  int unstable () {return !tid && (sync || waiters >= 0);}
  void reset ();
};

extern muto muto_start;

/* Use a statically allocated buffer as the storage for a muto */
#define new_muto(__inh, __name) \
({ \
  static __attribute__((section(".data_cygwin_nocopy"))) muto __mbuf; \
  (void) new ((char *) &__mbuf) muto (__inh, __name); \
  __mbuf.next = muto_start.next; \
  muto_start.next = &__mbuf; \
  &__mbuf; \
})
