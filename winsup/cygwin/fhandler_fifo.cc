/* fhandler_fifo.cc - See fhandler.h for a description of the fhandler classes.

   Copyright 2002, 2003, 2004, 2005 Red Hat, Inc.

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

#include "winsup.h"
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include "cygerrno.h"
#include "perprocess.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "pinfo.h"

fhandler_fifo::fhandler_fifo ()
  : fhandler_pipe (), output_handle (NULL),
    read_use (0), write_use (0)
{
}

void
fhandler_fifo::set_use (int incr)
{
  long oread_use = read_use;

  if (get_flags () & (O_WRONLY | O_APPEND))
    write_use += incr;
  else if (get_flags () & O_RDWR)
    {
      write_use += incr;
      read_use += incr;
    }
  else
    read_use += incr;

  if (incr >= 0)
    return;
  if (read_use <= 0 && oread_use != read_use)
    {
      HANDLE h = get_handle ();
      if (h)
	{
	  set_io_handle (NULL);
	  CloseHandle (h);
	}
    }
}

int
fhandler_fifo::close ()
{
  fhandler_pipe::close ();
  if (get_output_handle ())
    CloseHandle (get_output_handle ());
  if (!hExeced)
    set_use (-1);
  return 0;
}

#define DUMMY_O_RDONLY 4

void
fhandler_fifo::close_one_end ()
{
  int testflags = (get_flags () & (O_RDWR | O_WRONLY | O_APPEND)) ?: DUMMY_O_RDONLY;
  static int flagtypes[] = {DUMMY_O_RDONLY | O_RDWR, O_WRONLY | O_APPEND | O_RDWR};
  HANDLE *handles[2] = {&(get_handle ()), &(get_output_handle ())};
  for (int i = 0; i < 2; i++)
    if (!(testflags & flagtypes[i]))
      {
	CloseHandle (*handles[i]);
	*handles[i] = NULL;
      }
    else if (i == 0 && !read_state)
      {
	create_read_state (2);
	need_fork_fixup (true);
      }
}
int
fhandler_fifo::open_not_mine (int flags)
{
  winpids pids ((DWORD) 0);
  int res = 0;

  for (unsigned i = 0; i < pids.npids; i++)
    {
      _pinfo *p = pids[i];
      commune_result r;
      if (p->pid != myself->pid)
	{
	  r = p->commune_send (PICOM_FIFO, get_win32_name ());
	  if (r.handles[0] == NULL)
	    continue;		// process doesn't own fifo
	  debug_printf ("pid %d, handles[0] %p, handles[1] %p", p->pid,
			r.handles[0], r.handles[1]);
	}
      else
	{
	  /* FIXME: racy? */
	  fhandler_fifo *fh = cygheap->fdtab.find_fifo (get_win32_name ());
	  if (!fh)
	    continue;
	  if (!DuplicateHandle (hMainProc, fh->get_handle (), hMainProc,
				&r.handles[0], 0, false, DUPLICATE_SAME_ACCESS))
	    {
	      __seterrno ();
	      goto out;
	    }
	  if (!DuplicateHandle (hMainProc, fh->get_output_handle (), hMainProc,
				&r.handles[1], 0, false, DUPLICATE_SAME_ACCESS))
	    {
	      CloseHandle (r.handles[0]);
	      __seterrno ();
	      goto out;
	    }
	}

      set_io_handle (r.handles[0]);
      set_output_handle (r.handles[1]);
      set_flags (flags);
      close_one_end ();
      res = 1;
      goto out;
    }

  set_errno (EAGAIN);

out:
  debug_printf ("res %d", res);
  return res;
}

int
fhandler_fifo::open (int flags, mode_t)
{
  int res = 1;

  set_io_handle (NULL);
  set_output_handle (NULL);
  if (open_not_mine (flags))
    goto out;

  fhandler_pipe *fhs[2];
  if (create (fhs, 1, flags, true))
    {
      __seterrno ();
      res = 0;
    }
  else
    {
      set_flags (flags);
      set_io_handle (fhs[0]->get_handle ());
      set_output_handle (fhs[1]->get_handle ());
      guard = fhs[0]->guard;
      read_state = fhs[0]->read_state;
      writepipe_exists = fhs[1]->writepipe_exists;
      orig_pid = fhs[0]->orig_pid;
      id = fhs[0]->id;
      delete (fhs[0]);
      delete (fhs[1]);
      set_use (1);
      need_fork_fixup (true);
    }

out:
  debug_printf ("returning %d, errno %d", res, get_errno ());
  return res;
}

int
fhandler_fifo::dup (fhandler_base *child, HANDLE from_proc)
{
  int res = fhandler_pipe::dup (child, from_proc);
  if (!res)
    {
      fhandler_fifo *ff = (fhandler_fifo *) child;
      if (get_output_handle ()
	  && !DuplicateHandle (from_proc, get_output_handle (), hMainProc,
			       &ff->get_output_handle (), false, true,
			       DUPLICATE_SAME_ACCESS))
	{
	  __seterrno ();
	  child->close ();
	  res = -1;
	}
    }
  return res;
}
