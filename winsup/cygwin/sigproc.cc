/* sigproc.cc: inter/intra signal and sub process handler

   Copyright 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005 Red Hat, Inc.

   Written by Christopher Faylor

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <stdlib.h>
#include <time.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/cygwin.h>
#include <assert.h>
#include <sys/signal.h>
#include "cygerrno.h"
#include "sync.h"
#include "pinfo.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "child_info_magic.h"
#include "shared_info.h"
#include "cygtls.h"
#include "sigproc.h"
#include "exceptions.h"

/*
 * Convenience defines
 */
#define WSSC		  60000	// Wait for signal completion
#define WPSP		  40000	// Wait for proc_subproc mutex

#define no_signals_available() (!hwait_sig || (myself->sendsig == INVALID_HANDLE_VALUE) || exit_state)

#define NPROCS	256

/*
 * Global variables
 */
struct sigaction *global_sigs;

const char *__sp_fn ;
int __sp_ln;

char NO_COPY myself_nowait_dummy[1] = {'0'};// Flag to sig_send that signal goes to
					//  current process but no wait is required
HANDLE NO_COPY signal_arrived;		// Event signaled when a signal has
					//  resulted in a user-specified
					//  function call

#define Static static NO_COPY

HANDLE NO_COPY sigCONT;			// Used to "STOP" a process
Static cygthread *hwait_sig;		// Handle of wait_sig thread

Static HANDLE wait_sig_inited;		// Control synchronization of
					//  message queue startup

Static int nprocs;			// Number of deceased children
Static char cprocs[(NPROCS + 1) * sizeof (pinfo)];// All my children info
#define procs ((pinfo *) cprocs)	// All this just to avoid expensive
					// constructor operation  at DLL startup
Static waitq waitq_head = {0, 0, 0, 0, 0, 0, 0};// Start of queue for wait'ing threads

muto NO_COPY sync_proc_subproc;		// Control access to subproc stuff

DWORD NO_COPY sigtid = 0;		// ID of the signal thread

/* Function declarations */
static int __stdcall checkstate (waitq *) __attribute__ ((regparm (1)));
static __inline__ bool get_proc_lock (DWORD, DWORD);
static bool __stdcall remove_proc (int);
static bool __stdcall stopped_or_terminated (waitq *, _pinfo *);
static DWORD WINAPI wait_sig (VOID *arg);

extern HANDLE hExeced;

/* wait_sig bookkeeping */

class pending_signals
{
  sigpacket sigs[NSIG + 1];
  sigpacket start;
  sigpacket *end;
  sigpacket *prev;
  sigpacket *curr;
public:
  void reset () {curr = &start; prev = &start;}
  void add (sigpacket&);
  void del ();
  sigpacket *next ();
  sigpacket *save () const {return curr;}
  void restore (sigpacket *saved) {curr = saved;}
  friend void __stdcall sig_dispatch_pending (bool);
  friend DWORD WINAPI wait_sig (VOID *arg);
};

static pending_signals sigq;

/* Functions */
void __stdcall
sigalloc ()
{
  cygheap->sigs = global_sigs =
    (struct sigaction *) ccalloc (HEAP_SIGS, NSIG, sizeof (struct sigaction));
}

void __stdcall
signal_fixup_after_exec ()
{
  global_sigs = cygheap->sigs;
  /* Set up child's signal handlers */
  for (int i = 0; i < NSIG; i++)
    {
      global_sigs[i].sa_mask = 0;
      if (global_sigs[i].sa_handler != SIG_IGN)
	global_sigs[i].sa_handler = SIG_DFL;
    }
}

void __stdcall
wait_for_sigthread ()
{
  sigproc_printf ("wait_sig_inited %p", wait_sig_inited);
  HANDLE hsig_inited = wait_sig_inited;
  (void) WaitForSingleObject (hsig_inited, INFINITE);
  wait_sig_inited = NULL;
  (void) ForceCloseHandle1 (hsig_inited, wait_sig_inited);
}

/* Get the sync_proc_subproc muto to control access to
 * children, proc arrays.
 * Attempt to handle case where process is exiting as we try to grab
 * the mutex.
 */
static bool
get_proc_lock (DWORD what, DWORD val)
{
  Static int lastwhat = -1;
  if (!sync_proc_subproc)
    {
      sigproc_printf ("sync_proc_subproc is NULL (1)");
      return false;
    }
  if (sync_proc_subproc.acquire (WPSP))
    {
      lastwhat = what;
      return true;
    }
  if (!sync_proc_subproc)
    {
      sigproc_printf ("sync_proc_subproc is NULL (2)");
      return false;
    }
  system_printf ("Couldn't aquire sync_proc_subproc for(%d,%d), last %d, %E",
		  what, val, lastwhat);
  return true;
}

static bool __stdcall
proc_can_be_signalled (_pinfo *p)
{
  if (p->sendsig != INVALID_HANDLE_VALUE)
    {
      if (p == myself_nowait || p == myself)
	if (hwait_sig)
	  return true;
	else
	  {
	    set_errno (EAGAIN);
	    return hwait_sig;
	  }

      if (ISSTATE (p, PID_INITIALIZING) ||
	  (((p)->process_state & (PID_ACTIVE | PID_IN_USE)) ==
	   (PID_ACTIVE | PID_IN_USE)))
	return true;
    }

  set_errno (ESRCH);
  return false;
}

bool __stdcall
pid_exists (pid_t pid)
{
  return pinfo (pid)->exists ();
}

/* Return true if this is one of our children, false otherwise.  */
static inline bool __stdcall
mychild (int pid)
{
  for (int i = 0; i < nprocs; i++)
    if (procs[i]->pid == pid)
      return true;
  return false;
}

/* Handle all subprocess requests
 */
int __stdcall
proc_subproc (DWORD what, DWORD val)
{
  int rc = 1;
  int potential_match;
  _pinfo *child;
  int clearing;
  waitq *w;

#define wval	 ((waitq *) val)
#define vchild (*((pinfo *) val))

  sigproc_printf ("args: %x, %d", what, val);

  if (!get_proc_lock (what, val))	// Serialize access to this function
    {
      system_printf ("couldn't get proc lock. what %d, val %d", what, val);
      goto out1;
    }

  switch (what)
    {
    /* Add a new subprocess to the children arrays.
     * (usually called from the main thread)
     */
    case PROC_ADDCHILD:
      /* Filled up process table? */
      if (nprocs >= NPROCS)
	{
	  sigproc_printf ("proc table overflow: hit %d processes, pid %d\n",
			  nprocs, vchild->pid);
	  rc = 0;
	  set_errno (EAGAIN);
	  break;
	}
      /* fall through intentionally */

    case PROC_DETACHED_CHILD:
      if (vchild != myself)
	{
	  vchild->ppid = what == PROC_DETACHED_CHILD ? 1 : myself->pid;
	  vchild->uid = myself->uid;
	  vchild->gid = myself->gid;
	  vchild->pgid = myself->pgid;
	  vchild->sid = myself->sid;
	  vchild->ctty = myself->ctty;
	  vchild->cygstarted = true;
	  vchild->process_state |= PID_INITIALIZING | (myself->process_state & PID_USETTY);
	}
      if (what == PROC_DETACHED_CHILD)
	break;
      procs[nprocs] = vchild;
      rc = procs[nprocs].wait ();
      if (rc)
	{
	  sigproc_printf ("added pid %d to proc table, slot %d", vchild->pid,
			  nprocs);
	  nprocs++;
	}
      break;

    /* Handle a wait4() operation.  Allocates an event for the calling
     * thread which is signaled when the appropriate pid exits or stops.
     * (usually called from the main thread)
     */
    case PROC_WAIT:
      wval->ev = NULL;		// Don't know event flag yet

      if (wval->pid == -1)
	child = NULL;		// Not looking for a specific pid
      else if (!mychild (wval->pid))
	goto out;		// invalid pid.  flag no such child

      wval->status = 0;		// Don't know status yet
      sigproc_printf ("wval->pid %d, wval->options %d", wval->pid, wval->options);

      /* If the first time for this thread, create a new event, otherwise
       * reset the event.
       */
      if ((wval->ev = wval->thread_ev) == NULL)
	{
	  wval->ev = wval->thread_ev = CreateEvent (&sec_none_nih, TRUE, FALSE,
						    NULL);
	  ProtectHandle1 (wval->ev, wq_ev);
	}

      ResetEvent (wval->ev);
      w = waitq_head.next;
      waitq_head.next = wval;	/* Add at the beginning. */
      wval->next = w;		/* Link in rest of the list. */
      clearing = 0;
      goto scan_wait;

    /* Clear all waiting threads.  Called from exceptions.cc prior to
       the main thread's dispatch to a signal handler function.
       (called from wait_sig thread) */
    case PROC_CLEARWAIT:
      /* Clear all "wait"ing threads. */
      if (val)
	sigproc_printf ("clear waiting threads");
      else
	sigproc_printf ("looking for processes to reap");
      clearing = val;

    scan_wait:
      /* Scan the linked list of wait()ing threads.  If a wait's parameters
	 match this pid, then activate it.  */
      for (w = &waitq_head; w->next != NULL; w = w->next)
	{
	  if ((potential_match = checkstate (w)) > 0)
	    sigproc_printf ("released waiting thread");
	  else if (!clearing && !(w->next->options & WNOHANG) && potential_match < 0)
	    sigproc_printf ("only found non-terminated children");
	  else if (potential_match <= 0)		// nothing matched
	    {
	      sigproc_printf ("waiting thread found no children");
	      HANDLE oldw = w->next->ev;
	      w->next->pid = 0;
	      if (clearing)
		w->next->status = -1;		/* flag that a signal was received */
	      else if (!potential_match || !(w->next->options & WNOHANG))
		w->next->ev = NULL;
	      if (!SetEvent (oldw))
		system_printf ("couldn't wake up wait event %p, %E", oldw);
	      w->next = w->next->next;
	    }
	  if (w->next == NULL)
	    break;
	}

      if (!clearing)
	sigproc_printf ("finished processing terminated/stopped child");
      else
	{
	  waitq_head.next = NULL;
	  sigproc_printf ("finished clearing");
	}

      if (global_sigs[SIGCHLD].sa_handler == (void *) SIG_IGN)
	for (int i = 0; i < nprocs; i += remove_proc (i))
	  continue;
  }

out:
  sync_proc_subproc.release ();	// Release the lock
out1:
  sigproc_printf ("returning %d", rc);
  return rc;
#undef wval
#undef vchild
}

// FIXME: This is inelegant
void
_cygtls::remove_wq (DWORD wait)
{
  if (sync_proc_subproc && sync_proc_subproc.acquire (wait))
    {
      for (waitq *w = &waitq_head; w->next != NULL; w = w->next)
	if (w->next == &wq)
	  {
	    ForceCloseHandle1 (wq.thread_ev, wq_ev);
	    w->next = wq.next;
	    break;
	  }
      sync_proc_subproc.release ();
    }
}

/* Terminate the wait_subproc thread.
 * Called on process exit.
 * Also called by spawn_guts to disassociate any subprocesses from this
 * process.  Subprocesses will then know to clean up after themselves and
 * will not become procs.
 */
void __stdcall
proc_terminate (void)
{
  sigproc_printf ("nprocs %d", nprocs);
  /* Signal processing is assumed to be blocked in this routine. */
  if (nprocs)
    {
      sync_proc_subproc.acquire (WPSP);

      (void) proc_subproc (PROC_CLEARWAIT, 1);

      /* Clean out proc processes from the pid list. */
      int i;
      for (i = 0; i < nprocs; i++)
	{
	  procs[i]->ppid = 1;
	  if (procs[i].wait_thread)
	    {
	      // CloseHandle (procs[i].rd_proc_pipe);
	      procs[i].wait_thread->terminate_thread ();
	    }
	  procs[i].release ();
	}
      nprocs = 0;
      sync_proc_subproc.release ();
    }
  sigproc_printf ("leaving");
}

/* Clear pending signal */
void __stdcall
sig_clear (int target_sig)
{
  if (GetCurrentThreadId () != sigtid)
    sig_send (myself, -target_sig);
  else
    {
      sigpacket *q;
      sigpacket *save = sigq.save ();
      sigq.reset ();
      while ((q = sigq.next ()))
	if (q->si.si_signo == target_sig)
	  {
	    q->si.si_signo = __SIGDELETE;
	    break;
	  }
      sigq.restore (save);
    }
  return;
}

extern "C" int
sigpending (sigset_t *mask)
{
  sigset_t outset = (sigset_t) sig_send (myself, __SIGPENDING);
  if (outset == SIG_BAD_MASK)
    return -1;
  *mask = outset;
  return 0;
}

/* Force the wait_sig thread to wake up and scan for pending signals */
void __stdcall
sig_dispatch_pending (bool fast)
{
  if (exit_state || GetCurrentThreadId () == sigtid || !sigq.start.next)
    {
#ifdef DEBUGGING
      sigproc_printf ("exit_state %d, cur thread id %p, sigtid %p, sigq.start.next %p",
		      exit_state, GetCurrentThreadId (), sigtid, sigq.start.next);
#endif
      return;
    }

#ifdef DEBUGGING
  sigproc_printf ("flushing");
#endif
  (void) sig_send (myself, fast ? __SIGFLUSHFAST : __SIGFLUSH);
}

void __stdcall
create_signal_arrived ()
{
  if (signal_arrived)
    return;
  /* local event signaled when main thread has been dispatched
     to a signal handler function. */
  signal_arrived = CreateEvent (&sec_none_nih, TRUE, FALSE, NULL);
  ProtectHandle (signal_arrived);
}

/* Message initialization.  Called from dll_crt0_1
  
   This routine starts the signal handling thread.  The wait_sig_inited
   event is used to signal that the thread is ready to handle signals.
   We don't wait for this during initialization but instead detect it
   in sig_send to gain a little concurrency.  */
void __stdcall
sigproc_init ()
{
  wait_sig_inited = CreateEvent (&sec_none_nih, TRUE, FALSE, NULL);
  ProtectHandle (wait_sig_inited);

  /* sync_proc_subproc is used by proc_subproc.  It serialises
   * access to the children and proc arrays.
   */
  sync_proc_subproc.init ("sync_proc_subproc");

  create_signal_arrived ();

  hwait_sig = new cygthread (wait_sig, cygself, "sig");
  hwait_sig->zap_h ();

  global_sigs[SIGSTOP].sa_flags = SA_RESTART | SA_NODEFER;
  sigproc_printf ("process/signal handling enabled(%x)", myself->process_state);
  return;
}

/* Called on process termination to terminate signal and process threads.
 */
void __stdcall
sigproc_terminate (void)
{
  hwait_sig = NULL;

  if (myself->sendsig == INVALID_HANDLE_VALUE)
    sigproc_printf ("sigproc handling not active");
  else
    {
      sigproc_printf ("entering");
      if (!hExeced)
	{
	  HANDLE sendsig = myself->sendsig;
	  myself->sendsig = INVALID_HANDLE_VALUE;
	  CloseHandle (sendsig);
	}
    }
  proc_terminate ();		// clean up process stuff

  return;
}

int __stdcall
sig_send (_pinfo *p, int sig)
{
  siginfo_t si;
  si.si_signo = sig;
  si.si_code = SI_KERNEL;
  si.si_pid = si.si_uid = si.si_errno = 0;
  return sig_send (p, si);
}

/* Send a signal to another process by raising its signal semaphore.
   If pinfo *p == NULL, send to the current process.
   If sending to this process, wait for notification that a signal has
   completed before returning.  */
int __stdcall
sig_send (_pinfo *p, siginfo_t& si, _cygtls *tls)
{
  int rc = 1;
  bool its_me;
  HANDLE sendsig;
  sigpacket pack;

  pack.wakeup = NULL;
  bool wait_for_completion;
  if (!(its_me = (p == NULL || p == myself || p == myself_nowait)))
    wait_for_completion = false;
  else
    {
      if (no_signals_available ())
	{
	  sigproc_printf ("hwait_sig %p, myself->sendsig %p, exit_state %d",
			  hwait_sig, myself->sendsig, exit_state);
	  set_errno (EAGAIN);
	  goto out;		// Either exiting or not yet initializing
	}
      if (wait_sig_inited)
	wait_for_sigthread ();
      wait_for_completion = p != myself_nowait && _my_tls.isinitialized ();
      p = myself;
    }

  /* It is possible that the process is not yet ready to receive messages
   * or that it has exited.  Detect this.
   */
  if (!proc_can_be_signalled (p))	/* Is the process accepting messages? */
    {
      sigproc_printf ("invalid pid %d(%x), signal %d",
		  p->pid, p->process_state, si.si_signo);
      goto out;
    }

  if (its_me)
    sendsig = myself->sendsig;
  else
    {
      HANDLE dupsig;
      DWORD dwProcessId;
      for (int i = 0; !p->sendsig && i < 10000; i++)
	low_priority_sleep (0);
      if (p->sendsig)
	{
	  dupsig = p->sendsig;
	  dwProcessId = p->dwProcessId;
	}
      else
	{
	  dupsig = p->exec_sendsig;
	  dwProcessId = p->exec_dwProcessId;
	}
      if (!dupsig)
	{
	  set_errno (EAGAIN);
	  sigproc_printf ("sendsig handle never materialized");
	  goto out;
	}
      HANDLE hp = OpenProcess (PROCESS_DUP_HANDLE, false, dwProcessId);
      if (!hp)
	{
	  __seterrno ();
	  sigproc_printf ("OpenProcess failed, %E");
	  goto out;
	}
      VerifyHandle (hp);
      if (!DuplicateHandle (hp, dupsig, hMainProc, &sendsig, false, 0,
			    DUPLICATE_SAME_ACCESS) || !sendsig)
	{
	  __seterrno ();
	  sigproc_printf ("DuplicateHandle failed, %E");
	  CloseHandle (hp);
	  goto out;
	}
      CloseHandle (hp);
      VerifyHandle (sendsig);
    }

  sigproc_printf ("sendsig %p, pid %d, signal %d, its_me %d", sendsig, p->pid, si.si_signo, its_me);

  sigset_t pending;
  if (!its_me)
    pack.mask = NULL;
  else if (si.si_signo == __SIGPENDING)
    pack.mask = &pending;
  else if (si.si_signo == __SIGFLUSH || si.si_signo > 0)
    pack.mask = &myself->getsigmask ();
  else
    pack.mask = NULL;

  pack.si = si;
  if (!pack.si.si_pid)
    pack.si.si_pid = myself->pid;
  if (!pack.si.si_uid)
    pack.si.si_uid = myself->uid;
  pack.pid = myself->pid;
  pack.tls = (_cygtls *) tls;
  if (wait_for_completion)
    {
      pack.wakeup = CreateEvent (&sec_none_nih, FALSE, FALSE, NULL);
      sigproc_printf ("wakeup %p", pack.wakeup);
      ProtectHandle (pack.wakeup);
    }

  DWORD nb;
  if (!WriteFile (sendsig, &pack, sizeof (pack), &nb, NULL) || nb != sizeof (pack))
    {
      /* Couldn't send to the pipe.  This probably means that the
	 process is exiting.  */
      if (!its_me)
	{
	  __seterrno ();
	  sigproc_printf ("WriteFile for pipe %p failed, %E", sendsig);
	  ForceCloseHandle (sendsig);
	}
      else
	{
	  if (no_signals_available ())
	    sigproc_printf ("I'm going away now");
	  else if (!p->exec_sendsig)
	    system_printf ("error sending signal %d to pid %d, pipe handle %p, %E",
			   si.si_signo, p->pid, sendsig);
	  set_errno (EACCES);
	}
      goto out;
    }


  /* No need to wait for signal completion unless this was a signal to
     this process.

     If it was a signal to this process, wait for a dispatched signal.
     Otherwise just wait for the wait_sig to signal that it has finished
     processing the signal.  */
  if (wait_for_completion)
    {
      sigproc_printf ("Waiting for pack.wakeup %p", pack.wakeup);
      rc = WaitForSingleObject (pack.wakeup, WSSC);
    }
  else
    {
      rc = WAIT_OBJECT_0;
      sigproc_printf ("Not waiting for sigcomplete.  its_me %d signal %d",
		      its_me, si.si_signo);
      if (!its_me)
	ForceCloseHandle (sendsig);
    }

  if (pack.wakeup)
    {
      ForceCloseHandle (pack.wakeup);
      pack.wakeup = NULL;
    }

  if (rc == WAIT_OBJECT_0)
    rc = 0;		// Successful exit
  else
    {
      if (!no_signals_available ())
	system_printf ("wait for sig_complete event failed, signal %d, rc %d, %E",
		       si.si_signo, rc);
      set_errno (ENOSYS);
      rc = -1;
    }

  if (wait_for_completion && si.si_signo != __SIGFLUSHFAST)
    _my_tls.call_signal_handler ();

out:
  if (pack.wakeup)
    ForceCloseHandle (pack.wakeup);
  if (si.si_signo != __SIGPENDING)
    /* nothing */;
  else if (!rc)
    rc = (int) pending;
  else
    rc = SIG_BAD_MASK;
  sigproc_printf ("returning %p from sending signal %d", rc, si.si_signo);
  return rc;
}

/* Initialize some of the memory block passed to child processes
   by fork/spawn/exec. */

child_info::child_info (unsigned in_cb, child_info_types chtype)
{
  memset (this, 0, in_cb);
  cb = in_cb;
  intro = PROC_MAGIC_GENERIC;
  magic = CHILD_INFO_MAGIC;
  type = chtype;
  fhandler_union_cb = sizeof (fhandler_union);
  user_h = cygwin_user_h;
  if (chtype != PROC_SPAWN)
    subproc_ready = CreateEvent (&sec_all, FALSE, FALSE, NULL);
  sigproc_printf ("subproc_ready %p", subproc_ready);
}

child_info::~child_info ()
{
  if (subproc_ready)
    CloseHandle (subproc_ready);
}

child_info_fork::child_info_fork () :
  child_info (sizeof *this, _PROC_FORK)
{
}

child_info_spawn::child_info_spawn (child_info_types chtype) :
  child_info (sizeof *this, chtype)
{
}

void
child_info::ready (bool execed)
{
  if (!subproc_ready)
    {
      sigproc_printf ("subproc_ready not set");
      return;
    }

  if (!SetEvent (subproc_ready))
    api_fatal ("SetEvent failed");
  else
    sigproc_printf ("signalled %p that I was ready", subproc_ready);

  if (execed)
    {
      CloseHandle (subproc_ready);
      subproc_ready = NULL;
    }
}

bool
child_info::sync (pinfo& vchild, DWORD howlong)
{
  if (!subproc_ready)
    {
      sigproc_printf ("not waiting.  subproc_ready is NULL");
      return false;
    }

  HANDLE w4[2];
  w4[0] = subproc_ready;
  w4[1] = vchild.hProcess;

  bool res;
  sigproc_printf ("waiting for subproc_ready(%p) and child process(%p)", w4[0], w4[1]);
  switch (WaitForMultipleObjects (2, w4, FALSE, howlong))
    {
    case WAIT_OBJECT_0:
      sigproc_printf ("got subproc_ready for pid %d", vchild->pid);
      res = true;
      break;
    case WAIT_OBJECT_0 + 1:
      sigproc_printf ("process exited before subproc_ready");
      if (WaitForSingleObject (subproc_ready, 0) == WAIT_OBJECT_0)
	sigproc_printf ("should never happen.  noticed subproc_ready after process exit");
      res = false;
      break;
    default:
      system_printf ("wait failed, pid %d, %E", vchild->pid);
      res = false;
      break;
    }
  return res;
}

/* Check the state of all of our children to see if any are stopped or
 * terminated.
 */
static int __stdcall
checkstate (waitq *parent_w)
{
  int potential_match = 0;

  sigproc_printf ("nprocs %d", nprocs);

  /* Check already dead processes first to see if they match the criteria
   * given in w->next.  */
  int res;
  for (int i = 0; i < nprocs; i++)
    if ((res = stopped_or_terminated (parent_w, procs[i])))
      {
	remove_proc (i);
	potential_match = 1;
	goto out;
      }

  sigproc_printf ("no matching terminated children found");
  potential_match = -!!nprocs;

out:
  sigproc_printf ("returning %d", potential_match);
  return potential_match;
}

/* Remove a proc from procs by swapping it with the last child in the list.
   Also releases shared memory of exited processes.  */
static bool __stdcall
remove_proc (int ci)
{
  if (procs[ci]->exists ())
    return true;

  sigproc_printf ("removing procs[%d], pid %d, nprocs %d", ci, procs[ci]->pid,
		  nprocs);
  if (procs[ci] != myself)
    {
      procs[ci].release ();
      if (procs[ci].hProcess)
	ForceCloseHandle1 (procs[ci].hProcess, childhProc);
    }
  if (ci < --nprocs)
    {
      /* Wait for proc_waiter thread to make a copy of this element before
	 moving it or it may become confused.  The chances are very high that
	 the proc_waiter thread has already done this by the time we
	 get here.  */
      while (!procs[nprocs].waiter_ready)
	low_priority_sleep (0);
      procs[ci] = procs[nprocs];
    }
  return 0;
}

/* Check status of child process vs. waitq member.

   parent_w is the pointer to the parent of the waitq member in question.
   child is the subprocess being considered.

   Returns non-zero if waiting thread released.  */
static bool __stdcall
stopped_or_terminated (waitq *parent_w, _pinfo *child)
{
  int might_match;
  waitq *w = parent_w->next;

  sigproc_printf ("considering pid %d", child->pid);
  if (w->pid == -1)
    might_match = 1;
  else if (w->pid == 0)
    might_match = child->pgid == myself->pgid;
  else if (w->pid < 0)
    might_match = child->pgid == -w->pid;
  else
    might_match = (w->pid == child->pid);

  if (!might_match)
    return 0;

  int terminated;

  if (!((terminated = (child->process_state == PID_EXITED)) ||
      ((w->options & WUNTRACED) && child->stopsig)))
    return 0;

  parent_w->next = w->next;	/* successful wait.  remove from wait queue */
  w->pid = child->pid;

  if (!terminated)
    {
      sigproc_printf ("stopped child");
      w->status = (child->stopsig << 8) | 0x7f;
      child->stopsig = 0;
    }
  else
    {
      w->status = (__uint16_t) child->exitcode;

      add_rusage (&myself->rusage_children, &child->rusage_children);
      add_rusage (&myself->rusage_children, &child->rusage_self);

      if (w->rusage)
	{
	  add_rusage ((struct rusage *) w->rusage, &child->rusage_children);
	  add_rusage ((struct rusage *) w->rusage, &child->rusage_self);
	}
    }

  if (!SetEvent (w->ev))	/* wake up wait4 () immediately */
    system_printf ("couldn't wake up wait event %p, %E", w->ev);
  return true;
}

static void
talktome ()
{
  winpids pids ((DWORD) PID_MAP_RW);
  for (unsigned i = 0; i < pids.npids; i++)
    if (pids[i]->hello_pid == myself->pid)
      if (!IsBadWritePtr (pids[i], sizeof (_pinfo)))
	pids[i]->commune_recv ();
}

void
pending_signals::add (sigpacket& pack)
{
  sigpacket *se;
  if (sigs[pack.si.si_signo].si.si_signo)
    return;
  se = sigs + pack.si.si_signo;
  *se = pack;
  se->mask = &myself->getsigmask ();
  se->next = NULL;
  if (end)
    end->next = se;
  end = se;
  if (!start.next)
    start.next = se;
}

void
pending_signals::del ()
{
  sigpacket *next = curr->next;
  prev->next = next;
  curr->si.si_signo = 0;
#ifdef DEBUGGING
  curr->next = NULL;
#endif
  if (end == curr)
    end = prev;
  curr = next;
}

sigpacket *
pending_signals::next ()
{
  sigpacket *res;
  prev = curr;
  if (!curr || !(curr = curr->next))
    res = NULL;
  else
    res = curr;
  return res;
}

/* Process signals by waiting for signal data to arrive in a pipe.
   Set a completion event if one was specified. */
static DWORD WINAPI
wait_sig (VOID *self)
{
  HANDLE readsig;
  char sa_buf[1024];
  Static bool holding_signals;

  /* Initialization */
  (void) SetThreadPriority (GetCurrentThread (), WAIT_SIG_PRIORITY);

  if (!CreatePipe (&readsig, &myself->sendsig, sec_user_nih (sa_buf), 0))
    api_fatal ("couldn't create signal pipe, %E");
  sigCONT = CreateEvent (&sec_none_nih, FALSE, FALSE, NULL);

  /* Setting dwProcessId flags that this process is now capable of receiving
     signals.  Prior to this, dwProcessId was set to the windows pid of
     of the original windows process which spawned us unless this was a
     "toplevel" process.  */
  myself->process_state |= PID_ACTIVE;
  myself->process_state &= ~PID_INITIALIZING;

  sigproc_printf ("myself->dwProcessId %u", myself->dwProcessId);
  SetEvent (wait_sig_inited);
  sigtid = GetCurrentThreadId ();

  exception_list el;
  _my_tls.init_threadlist_exceptions (&el);
  debug_printf ("entering ReadFile loop, readsig %p, myself->sendsig %p",
		readsig, myself->sendsig);

  for (;;)
    {
      DWORD nb;
      sigpacket pack;
      if (!ReadFile (readsig, &pack, sizeof (pack), &nb, NULL))
	break;
      if (myself->sendsig == INVALID_HANDLE_VALUE)
	break;

      if (nb != sizeof (pack))
	{
	  system_printf ("short read from signal pipe: %d != %d", nb,
			 sizeof (pack));
	  continue;
	}

      if (!pack.si.si_signo)
	{
#ifdef DEBUGGING
	  system_printf ("zero signal?");
#endif
	  continue;
	}

      sigset_t dummy_mask;
      if (!pack.mask)
	{
	  dummy_mask = myself->getsigmask ();
	  pack.mask = &dummy_mask;
	}

      sigpacket *q;
      bool clearwait = false;
      switch (pack.si.si_signo)
	{
	case __SIGCOMMUNE:
	  talktome ();
	  break;
	case __SIGSTRACE:
	  strace.hello ();
	  break;
	case __SIGPENDING:
	  *pack.mask = 0;
	  unsigned bit;
	  sigq.reset ();
	  while ((q = sigq.next ()))
	    if (myself->getsigmask () & (bit = SIGTOMASK (q->si.si_signo)))
	      *pack.mask |= bit;
	  break;
	case __SIGHOLD:
	  holding_signals = 1;
	  break;
	case __SIGNOHOLD:
	  holding_signals = 0;
	  /* fall through, intentionally */
	case __SIGFLUSH:
	case __SIGFLUSHFAST:
	  sigq.reset ();
	  while ((q = sigq.next ()))
	    {
	      int sig = q->si.si_signo;
	      if (sig == __SIGDELETE || q->process () > 0)
		sigq.del ();
	      if (sig == __SIGNOHOLD && q->si.si_signo == SIGCHLD)
		clearwait = true;
	    }
	  break;
	default:
	  if (pack.si.si_signo < 0)
	    sig_clear (-pack.si.si_signo);
	  else if (holding_signals)
	    sigq.add (pack);
	  else
	    {
	      int sig = pack.si.si_signo;
	      // FIXME: Not quite right when taking threads into consideration.
	      // Do we need a per-thread queue?
	      if (sigq.sigs[sig].si.si_signo)
		sigproc_printf ("sig %d already queued", pack.si.si_signo);
	      else
		{
		  int sigres = pack.process ();
		  if (sigres <= 0)
		    {
#ifdef DEBUGGING2
		      if (!sigres)
			system_printf ("Failed to arm signal %d from pid %d", pack.sig, pack.pid);
#endif
		      sigq.add (pack);	// FIXME: Shouldn't add this in !sh condition
		    }
		}
	      if (sig == SIGCHLD)
		clearwait = true;
	    }
	  break;
	}
      if (clearwait)
	proc_subproc (PROC_CLEARWAIT, 0);
      if (pack.wakeup)
	{
	  SetEvent (pack.wakeup);
	  sigproc_printf ("signalled %p", pack.wakeup);
	}
    }

  sigproc_printf ("done");
  ExitThread (0);
}
