/* cygtls.cc

   Copyright 2003, 2004 Red Hat, Inc.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include "thread.h"
#include "cygtls.h"
#include "assert.h"
#include <syslog.h>
#include <signal.h>
#include "exceptions.h"
#include "sync.h"
#include "cygerrno.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "pinfo.h"
#include "sigproc.h"

class sentry
{
  static muto *lock;
  int destroy;
public:
  void init ();
  bool acquired () {return lock->acquired ();}
  sentry () {destroy = 0;}
  sentry (DWORD wait) {destroy = lock->acquire (wait);}
  ~sentry () {if (destroy) lock->release ();}
  friend void _cygtls::init ();
};

muto NO_COPY *sentry::lock;

static size_t NO_COPY nthreads;

#define THREADLIST_CHUNK 256

void
_cygtls::init ()
{
  if (cygheap->threadlist)
    memset (cygheap->threadlist, 0, cygheap->sthreads * sizeof (cygheap->threadlist[0]));
  else
    {
      cygheap->sthreads = THREADLIST_CHUNK;
      cygheap->threadlist = (_cygtls **) ccalloc (HEAP_TLS, cygheap->sthreads,
						     sizeof (cygheap->threadlist[0]));
    }
  new_muto1 (sentry::lock, sentry_lock);
}

void
_cygtls::set_state (bool is_exception)
{
  initialized = CYGTLS_INITIALIZED + is_exception;
}

void
_cygtls::reset_exception ()
{
  if (initialized == CYGTLS_EXCEPTION)
    {
#ifdef DEBUGGING
      debug_printf ("resetting stack after an exception stack %p, stackptr %p", stack, stackptr);
#endif
      set_state (false);
    }
}

/* Two calls to get the stack right... */
void
_cygtls::call (DWORD (*func) (void *, void *), void *arg)
{
  char buf[CYGTLS_PADSIZE];
  call2 (func, arg, buf);
}

void
_cygtls::call2 (DWORD (*func) (void *, void *), void *arg, void *buf)
{
  exception_list except_entry;
  /* Initialize this thread's ability to respond to things like
     SIGSEGV or SIGFPE. */
  init_exceptions (&except_entry);
  _my_tls.init_thread (buf, func);
  DWORD res = func (arg, buf);
  _my_tls.remove (INFINITE);
  // FIXME: Need some sort of atthreadexit function to allow things like
  // select to control this themselves
  if (_my_tls.locals.exitsock != INVALID_SOCKET)
    closesocket (_my_tls.locals.exitsock);
  ExitThread (res);
}

void
_cygtls::init_thread (void *x, DWORD (*func) (void *, void *))
{
  if (x)
    {
      memset (this, 0, CYGTLS_PADSIZE);
      stackptr = stack;
      if (_GLOBAL_REENT)
	{
	  local_clib._stdin = _GLOBAL_REENT->_stdin;
	  local_clib._stdout = _GLOBAL_REENT->_stdout;
	  local_clib._stderr = _GLOBAL_REENT->_stderr;
	  local_clib.__sdidinit = _GLOBAL_REENT->__sdidinit ? -1 : 0;
	  local_clib.__cleanup = _GLOBAL_REENT->__cleanup;
	  local_clib.__sglue._niobs = 3;
	  local_clib.__sglue._iobs = &_GLOBAL_REENT->__sf[0];
	}
      local_clib._current_locale = "C";
      locals.process_logmask = LOG_UPTO (LOG_DEBUG);
      locals.exitsock = INVALID_SOCKET;
    }

  set_state (false);
  errno_addr = &(local_clib._errno);

  if ((void *) func == (void *) cygthread::stub
      || (void *) func == (void *) cygthread::simplestub)
    return;

  sentry here (INFINITE);
  if (nthreads >= cygheap->sthreads)
    {
      cygheap->threadlist = (_cygtls **)
	crealloc (cygheap->threadlist, (cygheap->sthreads += THREADLIST_CHUNK)
		 * sizeof (cygheap->threadlist[0]));
      memset (cygheap->threadlist + nthreads, 0, THREADLIST_CHUNK * sizeof (cygheap->threadlist[0]));
    }

  cygheap->threadlist[nthreads++] = this;
}

void
_cygtls::fixup_after_fork ()
{
  if (sig)
    {
      pop ();
      sig = 0;
    }
  stacklock = 0;
  locals.exitsock = INVALID_SOCKET;
  wq.thread_ev = NULL;
}

void
_cygtls::remove (DWORD wait)
{
  debug_printf ("wait %p\n", wait);
  do
    {
      sentry here (wait);
      if (here.acquired ())
	{
	  for (size_t i = 0; i < nthreads; i++)
	    if (this == cygheap->threadlist[i])
	      {
		if (i < --nthreads)
		  cygheap->threadlist[i] = cygheap->threadlist[nthreads];
		debug_printf ("removed %p element %d", this, i);
		break;
	      }
	}
    } while (0);
  remove_wq (wait);
}

void
_cygtls::push (__stack_t addr, bool exception)
{
  if (exception)
    lock ();
  *stackptr++ = (__stack_t) addr;
  if (exception)
    unlock ();
  set_state (exception);
}

#define BAD_IX ((size_t) -1)
static size_t NO_COPY threadlist_ix = BAD_IX;

_cygtls *
_cygtls::find_tls (int sig)
{
  debug_printf ("sig %d\n", sig);
  sentry here (INFINITE);
  __asm__ volatile (".equ _threadlist_exception_return,.");
  _cygtls *res = NULL;
  for (threadlist_ix = 0; threadlist_ix < nthreads; threadlist_ix++)
    if (sigismember (&(cygheap->threadlist[threadlist_ix]->sigwait_mask), sig))
      {
	res = cygheap->threadlist[threadlist_ix];
	break;
      }
  threadlist_ix = BAD_IX;
  return res;
}

void
_cygtls::set_siginfo (sigpacket *pack)
{
  infodata = pack->si;
}

extern "C" DWORD __stdcall RtlUnwind (void *, void *, void *, DWORD);
static int
handle_threadlist_exception (EXCEPTION_RECORD *e, void *frame, CONTEXT *, void *)
{
  if (e->ExceptionCode != STATUS_ACCESS_VIOLATION)
    {
      system_printf ("handle_threadlist_exception called with exception code %d\n",
		     e->ExceptionCode);
      return 1;
    }

  sentry here;
  if (threadlist_ix == BAD_IX)
    {
      system_printf ("handle_threadlist_exception called with threadlist_ix %d\n",
		     BAD_IX);
      return 1;
    }

  if (!here.acquired ())
    {
      system_printf ("handle_threadlist_exception couldn't aquire muto\n");
      return 1;
    }

  extern void *threadlist_exception_return;
  cygheap->threadlist[threadlist_ix]->remove (INFINITE);
  threadlist_ix = 0;
  RtlUnwind (frame, threadlist_exception_return, e, 0);
  return 0;
}

void
_cygtls::init_threadlist_exceptions (exception_list *el)
{
  extern void init_exception_handler (exception_list *, exception_handler *);
  init_exception_handler (el, handle_threadlist_exception);
}
