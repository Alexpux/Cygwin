/* dtable.cc: file descriptor support.

   Copyright 1996, 1997, 1998, 1999, 2000, 2001 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#define  __INSIDE_CYGWIN_NET__

#include "winsup.h"
#include <errno.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/cygwin.h>

#define USE_SYS_TYPES_FD_SET
#include <winsock.h>
#include "sync.h"
#include "sigproc.h"
#include "pinfo.h"
#include "cygerrno.h"
#include "perprocess.h"
#include "security.h"
#include "fhandler.h"
#include "path.h"
#include "dtable.h"
#include "cygheap.h"

static const NO_COPY DWORD std_consts[] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
			     STD_ERROR_HANDLE};

/* Set aside space for the table of fds */
void
dtable_init (void)
{
  if (!cygheap->fdtab.size)
    cygheap->fdtab.extend (NOFILE_INCR);
}

void __stdcall
set_std_handle (int fd)
{
  if (fd == 0)
    SetStdHandle (std_consts[fd], cygheap->fdtab[fd]->get_handle ());
  else if (fd <= 2)
    SetStdHandle (std_consts[fd], cygheap->fdtab[fd]->get_output_handle ());
}

void
dtable::dec_console_fds ()
{
  if (console_fds > 0 && !--console_fds && myself->ctty != TTY_CONSOLE)
    FreeConsole ();
}

int
dtable::extend (int howmuch)
{
  int new_size = size + howmuch;
  fhandler_base **newfds;

  if (howmuch <= 0)
    return 0;

  /* Try to allocate more space for fd table. We can't call realloc ()
     here to preserve old table if memory allocation fails */

  if (!(newfds = (fhandler_base **) ccalloc (HEAP_ARGV, new_size, sizeof newfds[0])))
    {
      debug_printf ("calloc failed");
      return 0;
    }
  if (fds)
    {
      memcpy (newfds, fds, size * sizeof (fds[0]));
      cfree (fds);
    }

  size = new_size;
  fds = newfds;
  debug_printf ("size %d, fds %p", size, fds);
  return 1;
}

/* Initialize the file descriptor/handle mapping table.
   We only initialize the parent table here.  The child table is
   initialized at each fork () call.  */

void
stdio_init (void)
{
  extern void set_console_ctty ();
  /* Set these before trying to output anything from strace.
     Also, always set them even if we're to pick up our parent's fds
     in case they're missed.  */

  if (!myself->ppid_handle && NOTSTATE (myself, PID_CYGPARENT))
    {
      HANDLE in = GetStdHandle (STD_INPUT_HANDLE);
      HANDLE out = GetStdHandle (STD_OUTPUT_HANDLE);
      HANDLE err = GetStdHandle (STD_ERROR_HANDLE);

      cygheap->fdtab.init_std_file_from_handle (0, in, GENERIC_READ, "{stdin}");

      /* STD_ERROR_HANDLE has been observed to be the same as
	 STD_OUTPUT_HANDLE.  We need separate handles (e.g. using pipes
	 to pass data from child to parent).  */
      if (out == err)
	{
	  /* Since this code is not invoked for forked tasks, we don't have
	     to worry about the close-on-exec flag here.  */
	  if (!DuplicateHandle (hMainProc, out, hMainProc, &err, 0,
				 1, DUPLICATE_SAME_ACCESS))
	    {
	      /* If that fails, do this as a fall back.  */
	      err = out;
	      system_printf ("couldn't make stderr distinct from stdout");
	    }
	}

      cygheap->fdtab.init_std_file_from_handle (1, out, GENERIC_WRITE, "{stdout}");
      cygheap->fdtab.init_std_file_from_handle (2, err, GENERIC_WRITE, "{stderr}");
      /* Assign the console as the controlling tty for this process if we actually
	 have a console and no other controlling tty has been assigned. */
      if (myself->ctty < 0 && GetConsoleCP () > 0)
	set_console_ctty ();
    }
}

int
dtable::find_unused_handle (int start)
{
  AssertResourceOwner (LOCK_FD_LIST, READ_LOCK);

  do
    {
      for (int i = start; i < (int) size; i++)
	/* See if open -- no need for overhead of not_open */
	if (fds[i] == NULL)
	  return i;
    }
  while (extend (NOFILE_INCR));
  return -1;
}

void
dtable::release (int fd)
{
  if (!not_open (fd))
    {
      switch (fds[fd]->get_device ())
	{
	case FH_SOCKET:
	  dec_need_fixup_before ();
	  break;
	case FH_CONSOLE:
	  dec_console_fds ();
	  break;
	}
      delete fds[fd];
      fds[fd] = NULL;
    }
}

void
dtable::init_std_file_from_handle (int fd, HANDLE handle,
				  DWORD myaccess, const char *name)
{
  int bin;

  if (__fmode)
    bin = __fmode;
  else
    bin = binmode ?: 0;

  /* Check to see if we're being redirected - if not then
     we open then as consoles */
  if (fd == 0 || fd == 1 || fd == 2)
    {
      first_fd_for_open = 0;
      /* See if we can consoleify it  - if it is a console,
       don't open it in binary.  That will screw up our crlfs*/
      CONSOLE_SCREEN_BUFFER_INFO buf;
      if (GetConsoleScreenBufferInfo (handle, &buf))
	{
	  bin = 0;
	  if (ISSTATE (myself, PID_USETTY))
	    name = "/dev/tty";
	  else
	    name = "/dev/conout";
	}
      else if (FlushConsoleInputBuffer (handle))
	{
	  bin = 0;
	  if (ISSTATE (myself, PID_USETTY))
	    name = "/dev/tty";
	  else
	    name = "/dev/conin";
	}
      else if (GetFileType (handle) == FILE_TYPE_PIPE)
	{
	  if (bin == 0)
	    bin = O_BINARY;
	}
    }

  build_fhandler (fd, name, handle)->init (handle, myaccess, bin);
  set_std_handle (fd);
  paranoid_printf ("fd %d, handle %p", fd, handle);
}

extern "C"
int
cygwin_attach_handle_to_fd (char *name, int fd, HANDLE handle, mode_t bin,
			      DWORD myaccess)
{
  if (fd == -1)
    fd = cygheap->fdtab.find_unused_handle ();
  fhandler_base *res = cygheap->fdtab.build_fhandler (fd, name, handle);
  res->init (handle, myaccess, bin);
  return fd;
}

fhandler_base *
dtable::build_fhandler (int fd, const char *name, HANDLE handle)
{
  int unit;
  DWORD devn;

  if ((devn = get_device_number (name, unit)) == FH_BAD)
    {
      struct sockaddr sa;
      int sal = sizeof (sa);
      CONSOLE_SCREEN_BUFFER_INFO cinfo;
      DCB dcb;

      if (handle == NULL)
	devn = FH_DISK;
      else if (GetNumberOfConsoleInputEvents (handle, (DWORD *) &cinfo))
	devn = FH_CONIN;
      else if (GetConsoleScreenBufferInfo (handle, &cinfo))
	devn= FH_CONOUT;
      else if (wsock_started && getpeername ((SOCKET) handle, &sa, &sal) == 0)
	devn = FH_SOCKET;
      else if (GetFileType (handle) == FILE_TYPE_PIPE)
	devn = FH_PIPE;
      else if (GetCommState (handle, &dcb))
	devn = FH_SERIAL;
      else
	devn = FH_DISK;
    }

  return build_fhandler (fd, devn, name, unit);
}

fhandler_base *
dtable::build_fhandler (int fd, DWORD dev, const char *name, int unit)
{
  fhandler_base *fh;
  void *buf = ccalloc (HEAP_FHANDLER, 1, sizeof (fhandler_union) + 100);

  dev &= FH_DEVMASK;
  switch (dev)
    {
      case FH_TTYM:
	fh = new (buf) fhandler_tty_master (name, unit);
	break;
      case FH_CONSOLE:
      case FH_CONIN:
      case FH_CONOUT:
	fh = new (buf) fhandler_console (name);
	inc_console_fds ();
	break;
      case FH_PTYM:
	fh = new (buf) fhandler_pty_master (name);
	break;
      case FH_TTYS:
	if (unit < 0)
	  fh = new (buf) fhandler_tty_slave (name);
	else
	  fh = new (buf) fhandler_tty_slave (unit, name);
	break;
      case FH_WINDOWS:
	fh = new (buf) fhandler_windows (name);
	break;
      case FH_SERIAL:
	fh = new (buf) fhandler_serial (name, dev, unit);
	break;
      case FH_PIPE:
      case FH_PIPER:
      case FH_PIPEW:
	fh = new (buf) fhandler_pipe (name, dev);
	break;
      case FH_SOCKET:
	fh = new (buf) fhandler_socket (name);
	break;
      case FH_DISK:
	fh = new (buf) fhandler_disk_file (NULL);
	break;
      case FH_FLOPPY:
	fh = new (buf) fhandler_dev_floppy (name, unit);
	break;
      case FH_TAPE:
	fh = new (buf) fhandler_dev_tape (name, unit);
	break;
      case FH_NULL:
	fh = new (buf) fhandler_dev_null (name);
	break;
      case FH_ZERO:
	fh = new (buf) fhandler_dev_zero (name);
	break;
      case FH_RANDOM:
	fh = new (buf) fhandler_dev_random (name, unit);
	break;
      case FH_MEM:
	fh = new (buf) fhandler_dev_mem (name, unit);
	break;
      case FH_CLIPBOARD:
	fh = new (buf) fhandler_dev_clipboard (name);
	break;
      case FH_OSS_DSP:
	fh = new (buf) fhandler_dev_dsp (name);
	break;
      default:
	/* FIXME - this could recurse forever */
	return build_fhandler (fd, name, NULL);
    }

  debug_printf ("%s - cb %d, fd %d, fh %p", fh->get_name () ?: "", fh->cb,
		fd, fh);
  return fd >= 0 ? (fds[fd] = fh) : fh;
}

fhandler_base *
dtable::dup_worker (fhandler_base *oldfh)
{
  fhandler_base *newfh = build_fhandler (-1, oldfh->get_device (), NULL);
  *newfh = *oldfh;
  newfh->set_io_handle (NULL);
  if (oldfh->dup (newfh))
    {
      cfree (newfh);
      newfh = NULL;
      return NULL;
    }

  newfh->set_close_on_exec_flag (0);
  MALLOC_CHECK;
  debug_printf ("duped '%s' old %p, new %p", oldfh->get_name (), oldfh->get_io_handle (), newfh->get_io_handle ());
  return newfh;
}

int
dtable::dup2 (int oldfd, int newfd)
{
  int res = -1;
  fhandler_base *newfh = NULL;	// = NULL to avoid an incorrect warning

  MALLOC_CHECK;
  debug_printf ("dup2 (%d, %d)", oldfd, newfd);

  if (not_open (oldfd))
    {
      syscall_printf ("fd %d not open", oldfd);
      set_errno (EBADF);
      goto done;
    }

  if (newfd == oldfd)
    {
      res = 0;
      goto done;
    }

  if ((newfh = dup_worker (fds[oldfd])) == NULL)
    {
      res = -1;
      goto done;
    }

  SetResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "dup");

  if (newfd < 0)
    {
      syscall_printf ("new fd out of bounds: %d", newfd);
      set_errno (EBADF);
      goto done;
    }

  if ((size_t) newfd >= cygheap->fdtab.size)
   {
     int inc_size = NOFILE_INCR * ((newfd + NOFILE_INCR - 1) / NOFILE_INCR) -
		    cygheap->fdtab.size;
     cygheap->fdtab.extend (inc_size);
   }

  if (!not_open (newfd))
    _close (newfd);
  fds[newfd] = newfh;

  /* Count sockets. */
  if ((fds[newfd]->get_device () & FH_DEVMASK) == FH_SOCKET)
    inc_need_fixup_before ();

  ReleaseResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "dup");
  MALLOC_CHECK;

  if ((res = newfd) <= 2)
    set_std_handle (res);

  MALLOC_CHECK;
done:
  syscall_printf ("%d = dup2 (%d, %d)", res, oldfd, newfd);

  return res;
}

select_record *
dtable::select_read (int fd, select_record *s)
{
  if (not_open (fd))
    {
      set_errno (EBADF);
      return NULL;
    }
  fhandler_base *fh = fds[fd];
  s = fh->select_read (s);
  s->fd = fd;
  s->fh = fh;
  s->saw_error = 0;
  debug_printf ("%s fd %d", fh->get_name (), fd);
  return s;
}

select_record *
dtable::select_write (int fd, select_record *s)
{
  if (not_open (fd))
    {
      set_errno (EBADF);
      return NULL;
    }
  fhandler_base *fh = fds[fd];
  s = fh->select_write (s);
  s->fd = fd;
  s->fh = fh;
  s->saw_error = 0;
  debug_printf ("%s fd %d", fh->get_name (), fd);
  return s;
}

select_record *
dtable::select_except (int fd, select_record *s)
{
  if (not_open (fd))
    {
      set_errno (EBADF);
      return NULL;
    }
  fhandler_base *fh = fds[fd];
  s = fh->select_except (s);
  s->fd = fd;
  s->fh = fh;
  s->saw_error = 0;
  debug_printf ("%s fd %d", fh->get_name (), fd);
  return s;
}

/* Function to walk the fd table after an exec and perform
   per-fhandler type fixups. */
void
dtable::fixup_before_fork (DWORD target_proc_id)
{
  SetResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "fixup_before_fork");
  fhandler_base *fh;
  for (size_t i = 0; i < size; i++)
    if ((fh = fds[i]) != NULL)
      {
	debug_printf ("fd %d (%s)", i, fh->get_name ());
	fh->fixup_before_fork_exec (target_proc_id);
      }
  ReleaseResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "fixup_before_fork");
}

void
dtable::fixup_before_exec (DWORD target_proc_id)
{
  SetResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "fixup_before_exec");
  fhandler_base *fh;
  for (size_t i = 0; i < size; i++)
    if ((fh = fds[i]) != NULL && !fh->get_close_on_exec ())
      {
	debug_printf ("fd %d (%s)", i, fh->get_name ());
	fh->fixup_before_fork_exec (target_proc_id);
      }
  ReleaseResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "fixup_before_exec");
}

void
dtable::fixup_after_exec (HANDLE parent)
{
  first_fd_for_open = 0;
  fhandler_base *fh;
  for (size_t i = 0; i < size; i++)
    if ((fh = fds[i]) != NULL)
      {
	fh->clear_readahead ();
	if (fh->get_close_on_exec ())
	  release (i);
	else
	  {
	    fh->fixup_after_exec (parent);
	    if (i == 0)
	      SetStdHandle (std_consts[i], fh->get_io_handle ());
	    else if (i <= 2)
	      SetStdHandle (std_consts[i], fh->get_output_handle ());
	  }
      }
}

void
dtable::fixup_after_fork (HANDLE parent)
{
  fhandler_base *fh;
  for (size_t i = 0; i < size; i++)
    if ((fh = fds[i]) != NULL)
      {
	if (fh->get_close_on_exec () || fh->get_need_fork_fixup ())
	  {
	    debug_printf ("fd %d (%s)", i, fh->get_name ());
	    fh->fixup_after_fork (parent);
	  }
	if (i == 0)
	  SetStdHandle (std_consts[i], fh->get_io_handle ());
	else if (i <= 2)
	  SetStdHandle (std_consts[i], fh->get_output_handle ());
      }
}

int
dtable::vfork_child_dup ()
{
  fhandler_base **newtable;
  SetResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "dup");
  newtable = (fhandler_base **) ccalloc (HEAP_ARGV, size, sizeof (fds[0]));
  int res = 1;

  for (size_t i = 0; i < size; i++)
    if (not_open (i))
      continue;
    else if ((newtable[i] = dup_worker (fds[i])) != NULL)
      newtable[i]->set_close_on_exec (fds[i]->get_close_on_exec ());
    else
      {
	res = 0;
	set_errno (EBADF);
	goto out;
      }

  fds_on_hold = fds;
  fds = newtable;

out:
  ReleaseResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "dup");
  return 1;
}

void
dtable::vfork_parent_restore ()
{
  SetResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "restore");

  close_all_files ();
  fhandler_base **deleteme = fds;
  fds = fds_on_hold;
  fds_on_hold = NULL;
  cfree (deleteme);

  ReleaseResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "restore");
  return;
}

void
dtable::vfork_child_fixup ()
{
  if (!fds_on_hold)
    return;
  debug_printf ("here");
  fhandler_base **saveme = fds;
  fds = fds_on_hold;

  fhandler_base *fh;
  for (int i = 0; i < (int) cygheap->fdtab.size; i++)
    if ((fh = cygheap->fdtab[i]) != NULL)
      {
	fh->clear_readahead ();
	if (fh->get_close_on_exec ())
	  release (i);
	else
	  {
	    fh->close ();
	    cygheap->fdtab.release (i);
	  }
      }

  fds = saveme;
  cfree (fds_on_hold);
  fds_on_hold = NULL;

  return;
}
