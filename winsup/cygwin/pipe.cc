/* pipe.cc: pipe for Cygwin.

   Copyright 1996, 1998, 1999, 2000, 2001, 2002, 2003 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

/* FIXME: Should this really be fhandler_pipe.cc? */

#include "winsup.h"
#include <unistd.h>
#include <sys/socket.h>
#include "cygerrno.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "thread.h"
#include "pinfo.h"
#include "cygthread.h"

static unsigned pipecount;
static const NO_COPY char pipeid_fmt[] = "stupid_pipe.%u.%u";

fhandler_pipe::fhandler_pipe ()
  : fhandler_base (), guard (NULL), broken_pipe (false), writepipe_exists(0),
    orig_pid (0), id (0)
{
}

_off64_t
fhandler_pipe::lseek (_off64_t offset, int whence)
{
  debug_printf ("(%d, %d)", offset, whence);
  set_errno (ESPIPE);
  return -1;
}

void
fhandler_pipe::set_close_on_exec (int val)
{
  fhandler_base::set_close_on_exec (val);
  if (guard)
    set_no_inheritance (guard, val);
  if (writepipe_exists)
    set_no_inheritance (writepipe_exists, val);
}

struct pipeargs
{
  fhandler_base *fh;
  void *ptr;
  size_t *len;
};

static DWORD WINAPI
read_pipe (void *arg)
{
  pipeargs *pi = (pipeargs *) arg;
  pi->fh->fhandler_base::read (pi->ptr, *pi->len);
  return 0;
}

void __stdcall
fhandler_pipe::read (void *in_ptr, size_t& in_len)
{
  if (broken_pipe)
    in_len = 0;
  else
    {
      pipeargs pi = {dynamic_cast<fhandler_base *>(this), in_ptr, &in_len};
      ResetEvent (read_state);
      cygthread *th = new cygthread (read_pipe, &pi, "read_pipe");
      if (th->detach (read_state) && !in_len)
	in_len = (size_t) -1;	/* received a signal */
    }
  (void) ReleaseMutex (guard);
  return;
}

int
fhandler_pipe::close ()
{
  if (guard)
    CloseHandle (guard);
  if (writepipe_exists)
    CloseHandle (writepipe_exists);
#ifndef NEWVFORK
  if (read_state)
#else
  // FIXME is this vfork_cleanup test right?  Is it responsible for some of
  // the strange pipe behavior that has been reported in the cygwin mailing
  // list?
  if (read_state && !cygheap->fdtab.in_vfork_cleanup ())
#endif
    ForceCloseHandle (read_state);
  if (get_handle ())
    {
      CloseHandle (get_handle ());
      set_io_handle (NULL);
    }
  return 0;
}

bool
fhandler_pipe::hit_eof ()
{
  char buf[80];
  HANDLE ev;
  if (broken_pipe)
    return 1;
  if (!orig_pid)
    return false;
  __small_sprintf (buf, pipeid_fmt, orig_pid, id);
  if ((ev = OpenEvent (EVENT_ALL_ACCESS, FALSE, buf)))
    CloseHandle (ev);
  debug_printf ("%s %p", buf, ev);
  return ev == NULL;
}

void
fhandler_pipe::fixup_after_exec (HANDLE parent)
{
  if (read_state)
    {
      read_state = CreateEvent (&sec_none_nih, FALSE, FALSE, NULL);
      ProtectHandle (read_state);
    }
}

void
fhandler_pipe::fixup_after_fork (HANDLE parent)
{
  fhandler_base::fixup_after_fork (parent);
  if (guard)
    fork_fixup (parent, guard, "guard");
  if (writepipe_exists)
    fork_fixup (parent, writepipe_exists, "guard");
  fixup_after_exec (parent);
}

int
fhandler_pipe::dup (fhandler_base *child)
{
  int res = -1;
  fhandler_pipe *ftp = (fhandler_pipe *) child;
  ftp->guard = ftp->writepipe_exists = ftp->read_state = NULL;

  if (get_handle ())
    {
      res = fhandler_base::dup (child);
      if (res)
	goto err;
    }

  /* FIXME: This leaks handles in the failing condition */
  if (guard == NULL)
    ftp->guard = NULL;
  else if (!DuplicateHandle (hMainProc, guard, hMainProc, &ftp->guard, 0, 1,
			     DUPLICATE_SAME_ACCESS))
    {
      debug_printf ("couldn't duplicate guard %p, %E", guard);
      goto err;
    }

  if (writepipe_exists == NULL)
    ftp->writepipe_exists = NULL;
  else if (!DuplicateHandle (hMainProc, writepipe_exists, hMainProc,
			     &ftp->writepipe_exists, 0, 1,
			     DUPLICATE_SAME_ACCESS))
    {
      debug_printf ("couldn't duplicate writepipe_exists %p, %E", writepipe_exists);
      goto err;
    }

  if (read_state == NULL)
    ftp->read_state = NULL;
  else if (!DuplicateHandle (hMainProc, read_state, hMainProc,
			     &ftp->read_state, 0, 1,
			     DUPLICATE_SAME_ACCESS))
    {
      debug_printf ("couldn't duplicate read_state %p, %E", writepipe_exists);
      goto err;
    }

  res = 0;
  goto out;

err:
  if (!ftp->guard)
    CloseHandle (ftp->guard);
  if (!ftp->writepipe_exists)
    CloseHandle (ftp->writepipe_exists);
  if (!ftp->read_state)
    CloseHandle (ftp->read_state);
  goto leave;

out:
  ftp->id = id;
  ftp->orig_pid = orig_pid;
  VerifyHandle (ftp->guard);
  VerifyHandle (ftp->writepipe_exists);
  VerifyHandle (ftp->read_state);

leave:
  debug_printf ("res %d", res);
  return res;
}

int
fhandler_pipe::create (fhandler_pipe *fhs[2], unsigned psize, int mode, bool fifo)
{
  HANDLE r, w;
  SECURITY_ATTRIBUTES *sa = (mode & O_NOINHERIT) ?  &sec_none_nih : &sec_none;
  int res = -1;

  if (!CreatePipe (&r, &w, sa, psize))
    __seterrno ();
  else
    {
      fhs[0] = (fhandler_pipe *) build_fh_dev (*piper_dev);
      fhs[1] = (fhandler_pipe *) build_fh_dev (*pipew_dev);

      int binmode = mode & O_TEXT ?: O_BINARY;
      fhs[0]->init (r, GENERIC_READ, binmode);
      fhs[1]->init (w, GENERIC_WRITE, binmode);
      if (mode & O_NOINHERIT)
       {
	 fhs[0]->set_close_on_exec_flag (1);
	 fhs[1]->set_close_on_exec_flag (1);
       }

      fhs[0]->read_state = CreateEvent (&sec_none_nih, FALSE, FALSE, NULL);
      fhs[0]->set_need_fork_fixup ();
      ProtectHandle1 (fhs[0]->read_state, read_state);

      res = 0;
      fhs[0]->create_guard (sa);
      if (wincap.has_unreliable_pipes ())
	{
	  char buf[80];
	  int count = pipecount++;	/* FIXME: Should this be InterlockedIncrement? */
	  __small_sprintf (buf, pipeid_fmt, myself->pid, count);
	  fhs[1]->writepipe_exists = CreateEvent (sa, TRUE, FALSE, buf);
	  fhs[0]->orig_pid = myself->pid;
	  fhs[0]->id = count;
	}
    }

  syscall_printf ("%d = ([%p, %p], %d, %p)", res, fhs[0], fhs[1], psize, mode);
  return res;
}

int
fhandler_pipe::ioctl (unsigned int cmd, void *p)
{
  int n;

  switch (cmd)
    {
    case FIONREAD:
      if (get_device () == FH_PIPEW)
	{
	  set_errno (EINVAL);
	  return -1;
	}
      if (!PeekNamedPipe (get_handle (), NULL, 0, NULL, (DWORD *) &n, NULL))
	{
	  __seterrno ();
	  return -1;
	}
      break;
    default:
      return fhandler_base::ioctl (cmd, p);
      break;
    }
  *(int *) p = n;
  return 0;
}

extern "C" int
pipe (int filedes[2])
{
  extern DWORD binmode;
  fhandler_pipe *fhs[2];
  int res = fhandler_pipe::create (fhs, 16384, (!binmode || binmode == O_BINARY)
					       ? O_BINARY : O_TEXT);
  if (res == 0)
    {
      cygheap_fdnew fdin;
      cygheap_fdnew fdout (fdin, false);
      fdin = fhs[0];
      fdout = fhs[1];
      filedes[0] = fdin;
      filedes[1] = fdout;
    }

  return res;
}

extern "C" int
_pipe (int filedes[2], unsigned int psize, int mode)
{
  fhandler_pipe *fhs[2];
  int res = fhandler_pipe::create (fhs, psize, mode);
  /* This type of pipe is not interruptible so set the appropriate flag. */
  if (!res)
    {
      cygheap_fdnew fdin;
      cygheap_fdnew fdout (fdin, false);
      fhs[0]->set_r_no_interrupt (1);
      fdin = fhs[0];
      fdout = fhs[1];
      filedes[0] = fdin;
      filedes[1] = fdout;
    }

  return res;
}
