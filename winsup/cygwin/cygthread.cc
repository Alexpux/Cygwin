/* cygthread.cc

   Copyright 1998, 1999, 2000, 2001, 2002 Red Hat, Inc.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <windows.h>
#include "exceptions.h"
#include "security.h"
#include "cygthread.h"

#undef CloseHandle

static cygthread NO_COPY threads[8];
#define NTHREADS (sizeof (threads) / sizeof (threads[0]))

static HANDLE NO_COPY hthreads[NTHREADS];

DWORD NO_COPY cygthread::main_thread_id;

/* Initial stub called by cygthread constructor. Performs initial
   per-thread initialization and loops waiting for new thread functions
   to execute.  */
DWORD WINAPI
cygthread::stub (VOID *arg)
{
  DECLARE_TLS_STORAGE;
  exception_list except_entry;

  /* Initialize this thread's ability to respond to things like
     SIGSEGV or SIGFPE. */
  init_exceptions (&except_entry);

  cygthread *info = (cygthread *) arg;
  info->ev = CreateEvent (&sec_none_nih, TRUE, FALSE, NULL);
  while (1)
    {
      if (!info->func)
	ExitThread (0);

      /* Cygwin threads should not call ExitThread directly */
      info->func (info->arg == cygself ? info : info->arg);
      /* ...so the above should always return */

#ifdef DEBUGGING
      info->func = NULL;	// catch erroneous activation
#endif
      SetEvent (info->ev);
      info->__name = NULL;
      SuspendThread (info->h);
    }
}

/* This function runs in a secondary thread and starts up a bunch of
   other suspended threads for use in the cygthread pool. */
DWORD WINAPI
cygthread::runner (VOID *arg)
{
  for (unsigned i = 0; i < NTHREADS; i++)
    hthreads[i] = threads[i].h =
      CreateThread (&sec_none_nih, 0, cygthread::stub, &threads[i],
		    CREATE_SUSPENDED, &threads[i].avail);
  return 0;
}

/* Start things going.  Called from dll_crt0_1. */
void
cygthread::init ()
{
  DWORD tid;
  HANDLE h = CreateThread (&sec_none_nih, 0, cygthread::runner, NULL, 0, &tid);
  if (!h)
    api_fatal ("can't start thread_runner, %E");
  CloseHandle (h);
  main_thread_id = GetCurrentThreadId ();
}

bool
cygthread::is ()
{
  DWORD tid = GetCurrentThreadId ();

  for (DWORD i = 0; i < NTHREADS; i++)
    if (threads[i].id == tid)
      return 1;

  return 0;
}

void * cygthread::operator
new (size_t)
{
  DWORD id;
  cygthread *info;

  for (;;)
    {
      /* Search the threads array for an empty slot to use */
      for (info = threads; info < threads + NTHREADS; info++)
	if ((id = (DWORD) InterlockedExchange ((LPLONG) &info->avail, 0)))
	  {
	    info->id = id;
#ifdef DEBUGGING
	    if (info->__name)
	      api_fatal ("name not NULL? id %p, i %d", id, info - threads);
#endif
	    return info;
	  }

      /* thread_runner may not be finished yet. */
      Sleep (0);
    }
}

cygthread::cygthread (LPTHREAD_START_ROUTINE start, LPVOID param,
		      const char *name): func (start), arg (param)
{
#ifdef DEBUGGGING
  if (!__name)
    api_fatal ("name should never be NULL");
#endif
  thread_printf ("name %s, id %p", name, id);
  while (!h || ResumeThread (h) != 1)
#ifndef DEBUGGING
    Sleep (0);
#else
    {
      thread_printf ("waiting for %s<%p> to become active", __name, h);
      Sleep (0);
    }
#endif
  __name = name;	/* Need to set after thread has woken up to
			   ensure that it won't be cleared by exiting
			   thread. */
}

/* Return the symbolic name of the current thread for debugging.
 */
const char *
cygthread::name (DWORD tid)
{
  const char *res = NULL;
  if (!tid)
    tid = GetCurrentThreadId ();

  if (tid == main_thread_id)
    return "main";

  for (DWORD i = 0; i < NTHREADS; i++)
    if (threads[i].id == tid)
      {
	res = threads[i].__name ?: "exiting thread";
	break;
      }

  if (!res)
    {
      static char buf[30] NO_COPY = {0};
      __small_sprintf (buf, "unknown (%p)", tid);
      res = buf;
    }

  return res;
}

cygthread::operator
HANDLE ()
{
  while (!ev)
    Sleep (0);
  return ev;
}

/* Should only be called when the process is exiting since it
   leaves an open thread slot. */
void
cygthread::exit_thread ()
{
  SetEvent (*this);
  ExitThread (0);
}

/* Detach the cygthread from the current thread.  Note that the
   theory is that cygthread's are only associated with one thread.
   So, there should be no problems with multiple threads doing waits
   on the one cygthread. */
void
cygthread::detach ()
{
  if (avail)
    system_printf ("called detach on available thread %d?", avail);
  else
    {
      DWORD avail = id;
      /* Checking for __name here is just a minor optimization to avoid
	 an OS call. */
      if (!__name)
	thread_printf ("thread id %p returned.  No need to wait.", id);
      else
	{
	  DWORD res = WaitForSingleObject (*this, INFINITE);
	  thread_printf ("WFSO returns %d, id %p", res, id);
	}
      ResetEvent (*this);
      id = 0;
      __name = NULL;
      /* Mark the thread as available by setting avail to non-zero */
      (void) InterlockedExchange ((LPLONG) &this->avail, avail);
    }
}
