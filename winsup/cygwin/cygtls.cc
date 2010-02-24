/* cygtls.cc

   Copyright 2003, 2004, 2005, 2006, 2007, 2008, 2009 Red Hat, Inc.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#define USE_SYS_TYPES_FD_SET
#include "cygtls.h"
#include <syslog.h>
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "sigproc.h"

class sentry
{
  static muto lock;
  int destroy;
public:
  void init ();
  bool acquired () {return lock.acquired ();}
  sentry () {destroy = 0;}
  sentry (DWORD wait) {destroy = lock.acquire (wait);}
  ~sentry () {if (destroy) lock.release ();}
  friend void _cygtls::init ();
};

muto NO_COPY sentry::lock;

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
      cygheap->threadlist = (_cygtls **) ccalloc_abort (HEAP_TLS, cygheap->sthreads,
							sizeof (cygheap->threadlist[0]));
    }
  sentry::lock.init ("sentry_lock");
}

/* Two calls to get the stack right... */
void
_cygtls::call (DWORD (*func) (void *, void *), void *arg)
{
  char buf[CYGTLS_PADSIZE];
  _my_tls.call2 (func, arg, buf);
}

void
_cygtls::call2 (DWORD (*func) (void *, void *), void *arg, void *buf)
{
  init_thread (buf, func);
  DWORD res = func (arg, buf);
  remove (INFINITE);
  /* Don't call ExitThread on the main thread since we may have been
     dynamically loaded.  */
  if ((void *) func != (void *) dll_crt0_1
      && (void *) func != (void *) dll_dllcrt0_1)
    ExitThread (res);
}

void
_cygtls::init_thread (void *x, DWORD (*func) (void *, void *))
{
  if (x)
    {
      memset (this, 0, sizeof (*this));
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
      /* Initialize this thread's ability to respond to things like
	 SIGSEGV or SIGFPE. */
      init_exception_handler (handle_exceptions);
    }

  thread_id = GetCurrentThreadId ();
  initialized = CYGTLS_INITIALIZED;
  errno_addr = &(local_clib._errno);

  if ((void *) func == (void *) cygthread::stub
      || (void *) func == (void *) cygthread::simplestub)
    return;

  cygheap->user.reimpersonate ();

  sentry here (INFINITE);
  if (nthreads >= cygheap->sthreads)
    {
      cygheap->threadlist = (_cygtls **)
	crealloc_abort (cygheap->threadlist, (cygheap->sthreads += THREADLIST_CHUNK)
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
  stacklock = spinning = 0;
  locals.select.sockevt = NULL;
  wq.thread_ev = NULL;
}

#define free_local(x) \
  if (locals.x) \
    { \
      free (locals.x); \
      locals.x = NULL; \
    }

void
_cygtls::remove (DWORD wait)
{
  initialized = 0;
  if (exit_state >= ES_FINAL)
    return;

  debug_printf ("wait %p", wait);
  if (wait)
    {
      /* FIXME: Need some sort of atthreadexit function to allow things like
	 select to control this themselves. */
      if (locals.select.sockevt)
	{
	  CloseHandle (locals.select.sockevt);
	  locals.select.sockevt = NULL;
	  free_local (select.ser_num);
	  free_local (select.w4);
	}
      free_local (process_ident);
      free_local (ntoa_buf);
      free_local (protoent_buf);
      free_local (servent_buf);
      free_local (hostent_buf);
    }

  /* Free temporary TLS path buffers. */
  locals.pathbufs.destroy ();

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
_cygtls::push (__stack_t addr)
{
  *stackptr++ = (__stack_t) addr;
}


_cygtls *
_cygtls::find_tls (int sig)
{
  static int NO_COPY threadlist_ix;

  debug_printf ("sig %d\n", sig);
  sentry here (INFINITE);

  _cygtls *res = NULL;
  threadlist_ix = -1;

  myfault efault;
  if (efault.faulted ())
    cygheap->threadlist[threadlist_ix]->remove (INFINITE);

  while (++threadlist_ix < (int) nthreads)
    if (sigismember (&(cygheap->threadlist[threadlist_ix]->sigwait_mask), sig))
      {
	res = cygheap->threadlist[threadlist_ix];
	break;
      }
  return res;
}

void
_cygtls::set_siginfo (sigpacket *pack)
{
  infodata = pack->si;
}

/* Set up the exception handler for the current thread.  The x86 uses segment
   register fs, offset 0 to point to the current exception handler. */

extern exception_list *_except_list asm ("%fs:0");

void
_cygtls::init_exception_handler (exception_handler *eh)
{
  /* Here in the distant past of 17-Jul-2009, we had an issue where Windows
     2008 became YA perplexed because the cygwin exception handler was added
     at the start of the SEH while still being in the list further on.  This
     was because we added a loop by setting el.prev to _except_list here.
     Since el is reused in this thread, and this function can be called
     more than once when a dll is loaded, this is not a good thing.

     So, for now, until the next required tweak, we will just avoid adding the
     cygwin exception handler if it is already on this list.  This could present
     a problem if some previous exception handler tries to do things that are
     better left to Cygwin.  I await the cygwin mailing list notification of
     this event with bated breath.
     (cgf 2009-07-17)

     A change in plans:  In the not-so-distant past of 2010-02-23 it was
     discovered that something was moving in ahead of cygwin's exception
     handler so just detecting that the exception handler was loaded wasn't
     good enough.  I sort of anticipated this.  So, the next step is to remove
     the old exception handler from the list and add it to the beginning.

     The next step will probably be to call this function at various points
     in cygwin (like from _cygtls::setup_fault maybe) to absoltely ensure that
     we have control.  For now, however, this seems good enough.
     (cgf 2010-02-23) 
    */
  exception_list *e = _except_list;
  if (e == &el)
    return;
  while (e && e  != (exception_list *) -1)
    if (e->prev != &el)
      e = e->prev;
    else
      {
	e->prev = el.prev;
	break;
      }
  /* Apparently Windows stores some information about an exception and tries
     to figure out if the SEH which returned 0 last time actually solved the
     problem, or if the problem still persists (e.g. same exception at same
     address).  In this case Windows seems to decide that it can't trust
     that SEH and calls the next handler in the chain instead.

     At one point this was a loop (el.prev = &el;).  This outsmarted the
     above behaviour.  Unfortunately this trick doesn't work anymore with
     Windows 2008, which irremediably gets into an endless loop, taking 100%
     CPU.  That's why we reverted to a normal SEH chain and changed the way
     the exception handler returns to the application. */
  el.handler = eh;
  el.prev = _except_list;
  _except_list = &el;
}
