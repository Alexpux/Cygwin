/* wait.cc: Posix wait routines.

   Copyright 1996, 1997, 1998, 1999, 2000, 2001 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include "cygerrno.h"
#include "sync.h"
#include "sigproc.h"
#include "perthread.h"

/* This is called _wait and not wait because the real wait is defined
   in libc/syscalls/syswait.c.  It calls us.  */

extern "C"
pid_t
_wait (int *status)
{
  return wait4 (-1, status, 0, NULL);
}

pid_t
waitpid (pid_t intpid, int *status, int options)
{
  return wait4 (intpid, status, options, NULL);
}

pid_t
wait3 (int *status, int options, struct rusage *r)
{
  return wait4 (-1, status, options, r);
}

/* Wait for any child to complete.
 * Note: this is not thread safe.  Use of wait in multiple threads will
 * not work correctly.
 */

pid_t
wait4 (int intpid, int *status, int options, struct rusage *r)
{
  int res;
  waitq *w;
  HANDLE waitfor;
  bool sawsig;

  while (1)
    {
      sigframe thisframe (mainthread);
      sawsig = 0;
      if (options & ~(WNOHANG | WUNTRACED))
	{
	  set_errno (EINVAL);
	  return -1;
	}

      if (r)
	memset (r, 0, sizeof (*r));

      if ((w = (waitq *) waitq_storage.get ()) == NULL)
	w = (waitq *) waitq_storage.create ();

      w->pid = intpid;
      w->options = options;
      w->rusage = r;
      sigproc_printf ("calling proc_subproc, pid %d, options %d",
		     w->pid, w->options);
      if (!proc_subproc (PROC_WAIT, (DWORD)w))
	{
	  set_errno (ENOSYS);
	  paranoid_printf ("proc_subproc returned 0");
	  res = -1;
	  goto done;
	}

      if ((waitfor = w->ev) == NULL)
	goto nochildren;

      res = WaitForSingleObject (waitfor, INFINITE);

      sigproc_printf ("%d = WaitForSingleObject (...)", res);

      if (w->ev == NULL)
	{
	nochildren:
	  /* found no children */
	  set_errno (ECHILD);
	  res = -1;
	  goto done;
	}

      if (w->status == -1)
	{
	  set_sig_errno (EINTR);
	  sawsig = 1;
	  res = -1;
	}
      else if (res != WAIT_OBJECT_0)
	{
	  /* We shouldn't set errno to any random value if we can help it.
	     See the Posix manual for a list of valid values for `errno'.  */
	  set_errno (EINVAL);
	  res = -1;
	}
      else if ((res = w->pid) != 0 && status)
	*status = w->status;

    done:
      if (!sawsig || !thisframe.call_signal_handler ())
	break;
    }

  sigproc_printf ("intpid %d, status %p, w->status %d, options %d, res %d",
		  intpid, status, w->status, options, res);
  w->status = -1;
  if (res < 0)
    sigproc_printf ("*** errno = %d", get_errno ());
  return res;
}
