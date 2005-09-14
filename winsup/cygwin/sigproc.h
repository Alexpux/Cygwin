/* sigproc.h

   Copyright 1997, 1998, 2000, 2001, 2002, 2003, 2004, 2005 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _SIGPROC_H
#define _SIGPROC_H
#include <signal.h>

#ifdef NSIG
enum
{
  __SIGFLUSH	    = -(NSIG + 1),
  __SIGSTRACE	    = -(NSIG + 2),
  __SIGCOMMUNE	    = -(NSIG + 3),
  __SIGPENDING	    = -(NSIG + 4),
  __SIGDELETE	    = -(NSIG + 5),
  __SIGFLUSHFAST    = -(NSIG + 6),
  __SIGHOLD	    = -(NSIG + 7),
  __SIGNOHOLD	    = -(NSIG + 8),
  __SIGEXIT	    = -(NSIG + 9)
};
#endif

#define SIG_BAD_MASK (1 << (SIGKILL - 1))

enum procstuff
{
  PROC_ADDCHILD		  = 1,	// add a new subprocess to list
  PROC_DETACHED_CHILD	  = 2,	// set up a detached child
  PROC_CLEARWAIT	  = 3,	// clear all waits - signal arrived
  PROC_WAIT		  = 4,	// setup for wait() for subproc
  PROC_NOTHING		  = 5	// nothing, really
};

struct sigpacket
{
  siginfo_t si;
  pid_t pid;
  class _cygtls *tls;
  sigset_t *mask;
  union
  {
    HANDLE wakeup;
    struct sigpacket *next;
  };
  int __stdcall process () __attribute__ ((regparm (1)));
};

extern HANDLE signal_arrived;
extern HANDLE sigCONT;

void __stdcall sig_dispatch_pending (bool fast = false);
#ifdef _PINFO_H
extern "C" void __stdcall set_signal_mask (sigset_t newmask, sigset_t&);
#endif
int __stdcall handle_sigprocmask (int sig, const sigset_t *set,
				  sigset_t *oldset, sigset_t& opmask)
  __attribute__ ((regparm (3)));

extern "C" void __stdcall reset_signal_arrived ();
void __stdcall sig_clear (int) __attribute__ ((regparm (1)));
void __stdcall sig_set_pending (int) __attribute__ ((regparm (1)));
int __stdcall handle_sigsuspend (sigset_t);

int __stdcall proc_subproc (DWORD, DWORD) __attribute__ ((regparm (2)));

class _pinfo;
void __stdcall proc_terminate ();
void __stdcall sigproc_init ();
void __stdcall sigproc_terminate (enum exit_states);
bool __stdcall pid_exists (pid_t) __attribute__ ((regparm(1)));
int __stdcall sig_send (_pinfo *, siginfo_t&, class _cygtls *tls = NULL) __attribute__ ((regparm (3)));
int __stdcall sig_send (_pinfo *, int) __attribute__ ((regparm (2)));
void __stdcall signal_fixup_after_exec ();
void __stdcall wait_for_sigthread ();
void __stdcall sigalloc ();
void __stdcall create_signal_arrived ();

int kill_pgrp (pid_t, siginfo_t&);
int killsys (pid_t, int);

extern char myself_nowait_dummy[];

extern struct sigaction *global_sigs;

#define WAIT_SIG_PRIORITY THREAD_PRIORITY_NORMAL

#define myself_nowait ((_pinfo *)myself_nowait_dummy)
#endif /*_SIGPROC_H*/
