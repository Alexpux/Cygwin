/* sigproc.h

   Copyright 1997, 1998, 2000, 2001 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include <signal.h>

#define EXIT_SIGNAL	 0x010000
#define EXIT_REPARENTING 0x020000
#define EXIT_NOCLOSEALL  0x040000

enum procstuff
{
  PROC_ADDCHILD		= 1,	// add a new subprocess to list
  PROC_CHILDSTOPPED	= 2,	// a child stopped
  PROC_CHILDTERMINATED	= 3,	// a child died
  PROC_CLEARWAIT	= 4,	// clear all waits - signal arrived
  PROC_WAIT		= 5,	// setup for wait() for subproc
  PROC_NOTHING		= 6	// nothing, really
};

typedef struct struct_waitq
{
  int pid;
  int options;
  int status;
  HANDLE ev;
  void *rusage;			/* pointer to potential rusage */
  struct struct_waitq *next;
  HANDLE thread_ev;
} waitq;

struct sigthread
{
  DWORD id;
  DWORD frame;
  CRITICAL_SECTION lock;
  void init (const char *s);
};

class sigframe
{
private:
  sigthread *st;

public:
  void set (sigthread &t, DWORD ebp)
  {
    st = &t;
    t.frame = ebp;
  }

  sigframe () {st = NULL;}
  sigframe (sigthread &t, DWORD ebp = (DWORD) __builtin_frame_address (0))
  {
    if (!t.frame && t.id == GetCurrentThreadId ())
      set (t, ebp);
    else
      st = NULL;
  }
  ~sigframe ()
  {
    if (st)
      {
	EnterCriticalSection (&st->lock);
	st->frame = 0;
	LeaveCriticalSection (&st->lock);
	st = NULL;
      }
  }
};

extern sigthread mainthread;
extern HANDLE signal_arrived;

BOOL __stdcall my_parent_is_alive ();
extern "C" int __stdcall sig_dispatch_pending (int force = FALSE);
extern "C" void __stdcall set_process_mask (sigset_t newmask);
int __stdcall sig_handle (int);
void __stdcall sig_clear (int);
void __stdcall sig_set_pending (int);
int __stdcall handle_sigsuspend (sigset_t);

int __stdcall proc_subproc (DWORD, DWORD);

class _pinfo;
void __stdcall proc_terminate ();
void __stdcall sigproc_init ();
void __stdcall subproc_init ();
void __stdcall sigproc_terminate ();
BOOL __stdcall proc_exists (_pinfo *) __attribute__ ((regparm(1)));
BOOL __stdcall pid_exists (pid_t) __attribute__ ((regparm(1)));
int __stdcall sig_send (_pinfo *, int, DWORD ebp = (DWORD) __builtin_frame_address (0))  __attribute__ ((regparm(3)));
void __stdcall signal_fixup_after_fork ();
void __stdcall signal_fixup_after_exec (bool);
extern "C" int __stdcall call_signal_handler ();

extern char myself_nowait_dummy[];
extern char myself_nowait_nonmain_dummy[];

#define WAIT_SIG_EXITING (WAIT_OBJECT_0 + 1)

#define myself_nowait ((_pinfo *)myself_nowait_dummy)
#define myself_nowait_nonmain ((_pinfo *)myself_nowait_nonmain_dummy)
