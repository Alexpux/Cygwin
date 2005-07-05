/* fhandler_tty.cc

   Copyright 1997, 1998, 2000, 2001, 2002, 2003, 2004 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <wingdi.h>
#include <winuser.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include "cygerrno.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "sigproc.h"
#include "pinfo.h"
#include "cygheap.h"
#include "shared_info.h"
#include "cygserver.h"
#include "cygthread.h"

/* Tty master stuff */

fhandler_tty_master NO_COPY *tty_master;

static DWORD WINAPI process_input (void *);		// Input queue thread
static DWORD WINAPI process_output (void *);		// Output queue thread
static DWORD WINAPI process_ioctl (void *);		// Ioctl requests thread

fhandler_tty_master::fhandler_tty_master ()
  : fhandler_pty_master (), console (NULL)
{
}

int
fhandler_tty_slave::get_unit ()
{
  return dev () == FH_TTY ? myself->ctty : dev ().minor;
}

void
fhandler_tty_master::set_winsize (bool sendSIGWINCH)
{
  winsize w;
  console->ioctl (TIOCGWINSZ, &w);
  get_ttyp ()->winsize = w;
  if (sendSIGWINCH)
    tc->kill_pgrp (SIGWINCH);
}

int
fhandler_tty_master::init ()
{
  slave = dev ();
  termios_printf ("Creating master for tty%d", get_unit ());

  if (init_console ())
    {
      termios_printf ("can't create fhandler");
      return -1;
    }

  termios ti;
  memset (&ti, 0, sizeof (ti));
  console->tcsetattr (0, &ti);

  cygwin_shared->tty[get_unit ()]->common_init (this);

  set_winsize (false);

  inuse = get_ttyp ()->create_inuse (TTY_MASTER_ALIVE);
  set_close_on_exec (true);

  cygthread *h;
  h = new cygthread (process_input, cygself, "ttyin");
  h->SetThreadPriority (THREAD_PRIORITY_HIGHEST);
  h->zap_h ();

  h = new cygthread (process_ioctl, cygself, "ttyioctl");
  h->SetThreadPriority (THREAD_PRIORITY_HIGHEST);
  h->zap_h ();

  h = new cygthread (process_output, cygself, "ttyout");
  h->SetThreadPriority (THREAD_PRIORITY_HIGHEST);
  h->zap_h ();

  return 0;
}

#ifdef DEBUGGING
static class mutex_stack
{
public:
  const char *fn;
  int ln;
  const char *tname;
} ostack[100];

static int osi;
#endif /*DEBUGGING*/

DWORD
fhandler_tty_common::__acquire_output_mutex (const char *fn, int ln,
					   DWORD ms)
{
  if (strace.active)
    strace.prntf (_STRACE_TERMIOS, fn, "(%d): tty output_mutex: waiting %d ms", ln, ms);
  DWORD res = WaitForSingleObject (output_mutex, ms);
  if (res == WAIT_OBJECT_0)
    {
#ifndef DEBUGGING
      if (strace.active)
	strace.prntf (_STRACE_TERMIOS, fn, "(%d): tty output_mutex: acquired", ln, res);
#else
      ostack[osi].fn = fn;
      ostack[osi].ln = ln;
      ostack[osi].tname = cygthread::name ();
      termios_printf ("acquired for %s:%d, osi %d", fn, ln, osi);
      osi++;
#endif
    }
  return res;
}

void
fhandler_tty_common::__release_output_mutex (const char *fn, int ln)
{
  if (ReleaseMutex (output_mutex))
    {
#ifndef DEBUGGING
      if (strace.active)
	strace.prntf (_STRACE_TERMIOS, fn, "(%d): tty output_mutex released", ln);
#else
      if (osi > 0)
	osi--;
      termios_printf ("released at %s:%d, osi %d", fn, ln, osi);
      termios_printf ("  for %s:%d (%s)", ostack[osi].fn, ostack[osi].ln, ostack[osi].tname);
      ostack[osi].ln = -ln;
#endif
    }
}

/* Process tty input. */

void
fhandler_pty_master::doecho (const void *str, DWORD len)
{
  acquire_output_mutex (INFINITE);
  if (!WriteFile (get_ttyp ()->to_master, str, len, &len, NULL))
    termios_printf ("Write to %p failed, %E", get_ttyp ()->to_master);
//  WaitForSingleObject (output_done_event, INFINITE);
  release_output_mutex ();
}

int
fhandler_pty_master::accept_input ()
{
  DWORD bytes_left;
  int ret = 1;

  (void) WaitForSingleObject (input_mutex, INFINITE);

  bytes_left = eat_readahead (-1);

  if (!bytes_left)
    {
      termios_printf ("sending EOF to slave");
      get_ttyp ()->read_retval = 0;
    }
  else
    {
      char *p = rabuf;
      DWORD rc;
      DWORD written = 0;

      termios_printf ("about to write %d chars to slave", bytes_left);
      rc = WriteFile (get_output_handle (), p, bytes_left, &written, NULL);
      if (!rc)
	{
	  debug_printf ("error writing to pipe %E");
	  get_ttyp ()->read_retval = -1;
	  ret = -1;
	}
      else
	{
	  get_ttyp ()->read_retval = 1;
	  p += written;
	  bytes_left -= written;
	  if (bytes_left > 0)
	    {
	      debug_printf ("to_slave pipe is full");
	      puts_readahead (p, bytes_left);
	      ret = 0;
	    }
	}
    }

  SetEvent (input_available_event);
  ReleaseMutex (input_mutex);
  return ret;
}

static DWORD WINAPI
process_input (void *)
{
  char rawbuf[INP_BUFFER_SIZE];

  while (1)
    {
      size_t nraw = INP_BUFFER_SIZE;
      tty_master->console->read ((void *) rawbuf, nraw);
      if (tty_master->line_edit (rawbuf, nraw, tty_master->get_ttyp ()->ti)
	  == line_edit_signalled)
	tty_master->console->eat_readahead (-1);
    }
}

bool
fhandler_pty_master::hit_eof ()
{
  if (get_ttyp ()->was_opened && !get_ttyp ()->slave_alive ())
    {
      /* We have the only remaining open handle to this pty, and
	 the slave pty has been opened at least once.  We treat
	 this as EOF.  */
      termios_printf ("all other handles closed");
      return 1;
    }
  return 0;
}

/* Process tty output requests */

int
fhandler_pty_master::process_slave_output (char *buf, size_t len, int pktmode_on)
{
  size_t rlen;
  char outbuf[OUT_BUFFER_SIZE + 1];
  DWORD n;
  int column = 0;
  int rc = 0;

  if (len == 0)
    goto out;

  if (need_nl)
    {
      /* We need to return a left over \n character, resulting from
	 \r\n conversion.  Note that we already checked for FLUSHO and
	 output_stopped at the time that we read the character, so we
	 don't check again here.  */
      if (buf)
	buf[0] = '\n';
      need_nl = 0;
      rc = 1;
      goto out;
    }


  for (;;)
    {
      /* Set RLEN to the number of bytes to read from the pipe.  */
      rlen = len;
      if (get_ttyp ()->ti.c_oflag & OPOST && get_ttyp ()->ti.c_oflag & ONLCR)
	{
	  /* We are going to expand \n to \r\n, so don't read more than
	     half of the number of bytes requested.  */
	  rlen /= 2;
	  if (rlen == 0)
	    rlen = 1;
	}
      if (rlen > sizeof outbuf)
	rlen = sizeof outbuf;

      HANDLE handle = get_io_handle ();

      n = 0; // get_readahead_into_buffer (outbuf, len);
      if (!n)
	{
	  /* Doing a busy wait like this is quite inefficient, but nothing
	     else seems to work completely.  Windows should provide some sort
	     of overlapped I/O for pipes, or something, but it doesn't.  */
	  while (1)
	    {
	      if (!PeekNamedPipe (handle, NULL, 0, NULL, &n, NULL))
		goto err;
	      if (n > 0)
		break;
	      if (hit_eof ())
		goto out;
	      /* DISCARD (FLUSHO) and tcflush can finish here. */
	      if (n == 0 && (get_ttyp ()->ti.c_lflag & FLUSHO || !buf))
		goto out;
	      if (n == 0 && is_nonblocking ())
		{
		  set_errno (EAGAIN);
		  rc = -1;
		  break;
		}

	      Sleep (10);
	    }

	  if (ReadFile (handle, outbuf, rlen, &n, NULL) == FALSE)
	    goto err;
	}

      termios_printf ("bytes read %u", n);
      get_ttyp ()->write_error = 0;
      if (output_done_event != NULL)
	SetEvent (output_done_event);

      if (get_ttyp ()->ti.c_lflag & FLUSHO || !buf)
	continue;

      char *optr;
      optr = buf;
      if (pktmode_on)
	*optr++ = TIOCPKT_DATA;

      if (!(get_ttyp ()->ti.c_oflag & OPOST))	// post-process output
	{
	  memcpy (optr, outbuf, n);
	  optr += n;
	}
      else					// raw output mode
	{
	  char *iptr = outbuf;

	  while (n--)
	    {
	      switch (*iptr)
		{
		case '\r':
		  if ((get_ttyp ()->ti.c_oflag & ONOCR) && column == 0)
		    {
		      iptr++;
		      continue;
		    }
		  if (get_ttyp ()->ti.c_oflag & OCRNL)
		    *iptr = '\n';
		  else
		    column = 0;
		  break;
		case '\n':
		  if (get_ttyp ()->ti.c_oflag & ONLCR)
		    {
		      *optr++ = '\r';
		      column = 0;
		    }
		  if (get_ttyp ()->ti.c_oflag & ONLRET)
		    column = 0;
		  break;
		default:
		  column++;
		  break;
		}

	      /* Don't store data past the end of the user's buffer.  This
		 can happen if the user requests a read of 1 byte when
		 doing \r\n expansion.  */
	      if (optr - buf >= (int) len)
		{
		  if (*iptr != '\n' || n != 0)
		    system_printf ("internal error: %d unexpected characters", n);
		  need_nl = 1;
		  break;
		}

	      *optr++ = *iptr++;
	    }
	}
      rc = optr - buf;
      break;

    err:
      if (GetLastError () == ERROR_BROKEN_PIPE)
	rc = 0;
      else
	{
	  __seterrno ();
	  rc = -1;
	}
      break;
    }

out:
  termios_printf ("returning %d", rc);
  return rc;
}

static DWORD WINAPI
process_output (void *)
{
  char buf[OUT_BUFFER_SIZE * 2];

  for (;;)
    {
      int n = tty_master->process_slave_output (buf, OUT_BUFFER_SIZE, 0);
      if (n <= 0)
	{
	  if (n < 0)
	    termios_printf ("ReadFile %E");
	  ExitThread (0);
	}
      n = tty_master->console->write ((void *) buf, (size_t) n);
      tty_master->get_ttyp ()->write_error = n == -1 ? get_errno () : 0;
    }
}


/* Process tty ioctl requests */

static DWORD WINAPI
process_ioctl (void *)
{
  while (1)
    {
      WaitForSingleObject (tty_master->ioctl_request_event, INFINITE);
      termios_printf ("ioctl() request");
      tty_master->get_ttyp ()->ioctl_retval =
      tty_master->console->ioctl (tty_master->get_ttyp ()->cmd,
			     (void *) &tty_master->get_ttyp ()->arg);
      SetEvent (tty_master->ioctl_done_event);
    }
}

/**********************************************************************/
/* Tty slave stuff */

fhandler_tty_slave::fhandler_tty_slave ()
  : fhandler_tty_common ()
{
  uninterruptible_io (true);
}

/* FIXME: This function needs to close handles when it has
   a failing condition. */
int
fhandler_tty_slave::open (int flags, mode_t)
{
  if (get_device () == FH_TTY)
    pc.dev.tty_to_real_device ();
  fhandler_tty_slave *arch = (fhandler_tty_slave *)
    cygheap->fdtab.find_archetype (pc.dev);
  if (arch)
    {
      *this = *(fhandler_tty_slave *) arch;
      termios_printf ("copied tty fhandler archetype");
      set_flags ((flags & ~O_TEXT) | O_BINARY);
      cygheap->open_fhs++;
      goto out;
    }

  tcinit (cygwin_shared->tty[get_unit ()]);

  attach_tty (get_unit ());

  set_flags ((flags & ~O_TEXT) | O_BINARY);
  /* Create synchronisation events */
  char buf[CYG_MAX_PATH];

  /* output_done_event may or may not exist.  It will exist if the tty
     was opened by fhandler_tty_master::init, normally called at
     startup if use_tty is non-zero.  It will not exist if this is a
     pty opened by fhandler_pty_master::open.  In the former case, tty
     output is handled by a separate thread which controls output.  */
  shared_name (buf, OUTPUT_DONE_EVENT, get_unit ());
  output_done_event = OpenEvent (EVENT_ALL_ACCESS, TRUE, buf);

  if (!(output_mutex = get_ttyp ()->open_output_mutex ()))
    {
      termios_printf ("open output mutex failed, %E");
      __seterrno ();
      return 0;
    }
  if (!(input_mutex = get_ttyp ()->open_input_mutex ()))
    {
      termios_printf ("open input mutex failed, %E");
      __seterrno ();
      return 0;
    }
  shared_name (buf, INPUT_AVAILABLE_EVENT, get_unit ());
  if (!(input_available_event = OpenEvent (EVENT_ALL_ACCESS, TRUE, buf)))
    {
      termios_printf ("open input event failed, %E");
      __seterrno ();
      return 0;
    }

  /* The ioctl events may or may not exist.  See output_done_event,
     above.  */
  shared_name (buf, IOCTL_REQUEST_EVENT, get_unit ());
  ioctl_request_event = OpenEvent (EVENT_ALL_ACCESS, TRUE, buf);
  shared_name (buf, IOCTL_DONE_EVENT, get_unit ());
  ioctl_done_event = OpenEvent (EVENT_ALL_ACCESS, TRUE, buf);

  /* FIXME: Needs a method to eliminate tty races */
  {
    acquire_output_mutex (500);
    inuse = get_ttyp ()->create_inuse (TTY_SLAVE_ALIVE);
    get_ttyp ()->was_opened = true;
    release_output_mutex ();
  }

  /* Duplicate tty handles.  */

  if (!get_ttyp ()->from_slave || !get_ttyp ()->to_slave)
    {
      termios_printf ("tty handles have been closed");
      set_errno (EACCES);
      return 0;
    }

  HANDLE from_master_local;
  HANDLE to_master_local;
  from_master_local = to_master_local = NULL;

#ifdef USE_SERVER
  if (!wincap.has_security ()
      || cygserver_running == CYGSERVER_UNAVAIL
      || !cygserver_attach_tty (&from_master_local, &to_master_local))
#endif
    {
#ifdef USE_SERVER
      termios_printf ("cannot dup handles via server. using old method.");
#endif
      HANDLE tty_owner = OpenProcess (PROCESS_DUP_HANDLE, FALSE,
				      get_ttyp ()->master_pid);
      termios_printf ("tty own handle %p",tty_owner);
      if (tty_owner == NULL)
	{
	  termios_printf ("can't open tty (%d) handle process %d",
			  get_unit (), get_ttyp ()->master_pid);
	  __seterrno ();
	  return 0;
	}

      if (!DuplicateHandle (tty_owner, get_ttyp ()->from_master,
			    hMainProc, &from_master_local, 0, TRUE,
			    DUPLICATE_SAME_ACCESS))
	{
	  termios_printf ("can't duplicate input, %E");
	  __seterrno ();
	  return 0;
	}

      VerifyHandle (from_master_local);
      if (!DuplicateHandle (tty_owner, get_ttyp ()->to_master,
			  hMainProc, &to_master_local, 0, TRUE,
			  DUPLICATE_SAME_ACCESS))
	{
	  termios_printf ("can't duplicate output, %E");
	  __seterrno ();
	  return 0;
	}
      VerifyHandle (to_master_local);
      CloseHandle (tty_owner);
    }

  termios_printf ("duplicated from_master %p->%p from tty_owner",
      get_ttyp ()->from_master, from_master_local);
  termios_printf ("duplicated to_master %p->%p from tty_owner",
      get_ttyp ()->to_master, to_master_local);

  set_io_handle (from_master_local);
  set_output_handle (to_master_local);

  set_open_status ();
  if (cygheap->open_fhs++ == 0 && !GetConsoleCP () && !output_done_event
      && wincap.pty_needs_alloc_console () && !GetProcessWindowStation ())
    {
      BOOL b;
      HWINSTA h = CreateWindowStation (NULL, 0, GENERIC_READ | GENERIC_WRITE, &sec_none_nih);
      termios_printf ("CreateWindowStation %p, %E", h);
      if (h)
	{
	  b = SetProcessWindowStation (h);
	  termios_printf ("SetProcessWindowStation %d, %E", b);
	}
      b = AllocConsole ();	// will cause flashing if workstation
				// stuff fails
      termios_printf ("%d = AllocConsole (), %E", b);
      if (b)
	init_console_handler (TRUE);
    }

  // FIXME: Do this better someday
  arch = (fhandler_tty_slave *) cmalloc (HEAP_ARCHETYPES, sizeof (*this));
  *((fhandler_tty_slave **) cygheap->fdtab.add_archetype ()) = arch;
  archetype = arch;
  *arch = *this;

out:
  usecount = 0;
  archetype->usecount++;
  report_tty_counts (this, "opened", "incremented ", "");
  myself->set_ctty (get_ttyp (), flags, arch);

  return 1;
}

int
fhandler_tty_slave::close ()
{
  if (!hExeced)
    {
      if (!--cygheap->open_fhs && myself->ctty == -1)
	FreeConsole ();

      archetype->usecount--;
      report_tty_counts (this, "closed", "decremented ", "");

      if (archetype->usecount)
	{
#ifdef DEBUGGING
	  if (archetype->usecount < 0)
	    system_printf ("error: usecount %d", archetype->usecount);
#endif
	  termios_printf ("just returning because archetype usecount is != 0");
	  return 0;
	}
    }

  termios_printf ("closing last open %s handle", ttyname ());
  return fhandler_tty_common::close ();
}

int
fhandler_tty_slave::cygserver_attach_tty (LPHANDLE from_master_ptr,
					  LPHANDLE to_master_ptr)
{
#ifndef USE_SERVER
  return 0;
#else
  if (!from_master_ptr || !to_master_ptr)
    return 0;

  client_request_attach_tty req ((DWORD) get_ttyp ()->master_pid,
				 (HANDLE) get_ttyp ()->from_master,
				 (HANDLE) get_ttyp ()->to_master);

  if (req.make_request () == -1 || req.error_code ())
    return 0;

  *from_master_ptr = req.from_master ();
  *to_master_ptr = req.to_master ();

  return 1;
#endif
}

void
fhandler_tty_slave::init (HANDLE, DWORD a, mode_t)
{
  int flags = 0;

  a &= GENERIC_READ | GENERIC_WRITE;
  if (a == GENERIC_READ)
    flags = O_RDONLY;
  if (a == GENERIC_WRITE)
    flags = O_WRONLY;
  if (a == (GENERIC_READ | GENERIC_WRITE))
    flags = O_RDWR;

  open (flags);
}

int
fhandler_tty_slave::write (const void *ptr, size_t len)
{
  DWORD n, towrite = len;

  termios_printf ("tty%d, write(%x, %d)", get_unit (), ptr, len);

  acquire_output_mutex (INFINITE);

  while (len)
    {
      n = min (OUT_BUFFER_SIZE, len);
      char *buf = (char *)ptr;
      ptr = (char *) ptr + n;
      len -= n;

      /* Previous write may have set write_error to != 0.  Check it here.
	 This is less than optimal, but the alternative slows down tty
	 writes enormously. */
      if (get_ttyp ()->write_error)
	{
	  set_errno (get_ttyp ()->write_error);
	  towrite = (DWORD) -1;
	  break;
	}

      if (WriteFile (get_output_handle (), buf, n, &n, NULL) == FALSE)
	{
	  DWORD err = GetLastError ();
	  termios_printf ("WriteFile failed, %E");
	  switch (err)
	    {
	    case ERROR_NO_DATA:
	      err = ERROR_IO_DEVICE;
	    default:
	      __seterrno_from_win_error (err);
	    }
	  raise (SIGHUP);		/* FIXME: Should this be SIGTTOU? */
	  towrite = (DWORD) -1;
	  break;
	}

      if (output_done_event != NULL)
	{
	  DWORD rc;
	  DWORD x = n * 1000;
	  rc = WaitForSingleObject (output_done_event, x);
	  termios_printf ("waited %d ms for output_done_event, WFSO %d", x, rc);
	}
    }
  release_output_mutex ();
  return towrite;
}

void __stdcall
fhandler_tty_slave::read (void *ptr, size_t& len)
{
  int totalread = 0;
  int vmin = 0;
  int vtime = 0;	/* Initialized to prevent -Wuninitialized warning */
  size_t readlen;
  DWORD bytes_in_pipe;
  char buf[INP_BUFFER_SIZE];
  char peek_buf[INP_BUFFER_SIZE];
  DWORD time_to_wait;
  DWORD rc;
  HANDLE w4[2];

  termios_printf ("read(%x, %d) handle %p", ptr, len, get_handle ());

  if (!ptr) /* Indicating tcflush(). */
    time_to_wait = 0;
  else if ((get_ttyp ()->ti.c_lflag & ICANON))
    time_to_wait = INFINITE;
  else
    {
      vmin = get_ttyp ()->ti.c_cc[VMIN];
      if (vmin > INP_BUFFER_SIZE)
	vmin = INP_BUFFER_SIZE;
      vtime = get_ttyp ()->ti.c_cc[VTIME];
      if (vmin < 0)
	vmin = 0;
      if (vtime < 0)
	vtime = 0;
      if (!vmin && !vtime)
	time_to_wait = 0;
      else
	time_to_wait = !vtime ? INFINITE : 100 * vtime;
    }

  w4[0] = signal_arrived;
  w4[1] = input_available_event;

  DWORD waiter = time_to_wait;
  while (len)
    {
      rc = WaitForMultipleObjects (2, w4, FALSE, waiter);

      if (rc == WAIT_TIMEOUT)
	{
	  termios_printf ("wait timed out, waiter %u", waiter);
	  break;
	}

      if (rc == WAIT_FAILED)
	{
	  termios_printf ("wait for input event failed, %E");
	  break;
	}

      if (rc == WAIT_OBJECT_0)
	{
	  /* if we've received signal after successfully reading some data,
	     just return all data successfully read */
	  if (totalread > 0)
	    break;
	  set_sig_errno (EINTR);
	  len = (size_t) -1;
	  return;
	}

      rc = WaitForSingleObject (input_mutex, 1000);
      if (rc == WAIT_FAILED)
	{
	  termios_printf ("wait for input mutex failed, %E");
	  break;
	}
      else if (rc == WAIT_TIMEOUT)
	{
	  termios_printf ("failed to acquire input mutex after input event arrived");
	  break;
	}
      if (!PeekNamedPipe (get_handle (), peek_buf, sizeof (peek_buf), &bytes_in_pipe, NULL, NULL))
	{
	  termios_printf ("PeekNamedPipe failed, %E");
	  raise (SIGHUP);
	  bytes_in_pipe = 0;
	}

      /* On first peek determine no. of bytes to flush. */
      if (!ptr && len == UINT_MAX)
	len = (size_t) bytes_in_pipe;

      if (ptr && !bytes_in_pipe && !vmin && !time_to_wait)
	{
	  ReleaseMutex (input_mutex);
	  len = (size_t) bytes_in_pipe;
	  return;
	}

      readlen = min (bytes_in_pipe, min (len, sizeof (buf)));

      if (ptr && vmin && readlen > (unsigned) vmin)
	readlen = vmin;

      DWORD n = 0;
      if (readlen)
	{
	  termios_printf ("reading %d bytes (vtime %d)", readlen, vtime);
	  if (ReadFile (get_handle (), buf, readlen, &n, NULL) == FALSE)
	    {
	      termios_printf ("read failed, %E");
	      raise (SIGHUP);
	    }
	  /* MSDN states that 5th prameter can be used to determine total
	     number of bytes in pipe, but for some reason this number doesn't
	     change after successful read. So we have to peek into the pipe
	     again to see if input is still available */
	  if (!PeekNamedPipe (get_handle (), peek_buf, 1, &bytes_in_pipe, NULL, NULL))
	    {
	      termios_printf ("PeekNamedPipe failed, %E");
	      raise (SIGHUP);
	      bytes_in_pipe = 0;
	    }
	  if (n)
	    {
	      len -= n;
	      totalread += n;
	      if (ptr)
		{
		  memcpy (ptr, buf, n);
		  ptr = (char *) ptr + n;
		}
	    }
	}

      if (!bytes_in_pipe)
	ResetEvent (input_available_event);

      ReleaseMutex (input_mutex);

      if (!ptr)
	{
	  if (!bytes_in_pipe)
	    break;
	  continue;
	}

      if (get_ttyp ()->read_retval < 0)	// read error
	{
	  set_errno (-get_ttyp ()->read_retval);
	  totalread = -1;
	  break;
	}
      if (get_ttyp ()->read_retval == 0)	//EOF
	{
	  termios_printf ("saw EOF");
	  break;
	}
      if (get_ttyp ()->ti.c_lflag & ICANON || is_nonblocking ())
	break;
      if (vmin && totalread >= vmin)
	break;

      /* vmin == 0 && vtime == 0:
       *   we've already read all input, if any, so return immediately
       * vmin == 0 && vtime > 0:
       *   we've waited for input 10*vtime ms in WFSO(input_available_event),
       *   no matter whether any input arrived, we shouldn't wait any longer,
       *   so return immediately
       * vmin > 0 && vtime == 0:
       *   here, totalread < vmin, so continue waiting until more data
       *   arrive
       * vmin > 0 && vtime > 0:
       *   similar to the previous here, totalread < vmin, and timer
       *   hadn't expired -- WFSO(input_available_event) != WAIT_TIMEOUT,
       *   so "restart timer" and wait until more data arrive
       */

      if (vmin == 0)
	break;

      if (n)
	waiter = time_to_wait;
    }
  termios_printf ("%d=read(%x, %d)", totalread, ptr, len);
  len = (size_t) totalread;
  return;
}

int
fhandler_tty_slave::dup (fhandler_base *child)
{
  fhandler_tty_slave *arch = (fhandler_tty_slave *) archetype;
  *(fhandler_tty_slave *) child = *arch;
  child->usecount = 0;
  arch->usecount++;
  cygheap->open_fhs++;
  report_tty_counts (child, "duped", "incremented ", "");
  myself->set_ctty (get_ttyp (), openflags, arch);
  return 0;
}

int
fhandler_tty_common::dup (fhandler_base *child)
{
  fhandler_tty_slave *fts = (fhandler_tty_slave *) child;
  int errind;

  fts->tcinit (get_ttyp ());

  attach_tty (get_unit ());

  HANDLE nh;

  if (output_done_event == NULL)
    fts->output_done_event = NULL;
  else if (!DuplicateHandle (hMainProc, output_done_event, hMainProc,
			     &fts->output_done_event, 0, 1,
			     DUPLICATE_SAME_ACCESS))
    {
      errind = 1;
      goto err;
    }
  if (ioctl_request_event == NULL)
    fts->ioctl_request_event = NULL;
  else if (!DuplicateHandle (hMainProc, ioctl_request_event, hMainProc,
			     &fts->ioctl_request_event, 0, 1,
			     DUPLICATE_SAME_ACCESS))
    {
      errind = 2;
      goto err;
    }
  if (ioctl_done_event == NULL)
    fts->ioctl_done_event = NULL;
  else if (!DuplicateHandle (hMainProc, ioctl_done_event, hMainProc,
			     &fts->ioctl_done_event, 0, 1,
			     DUPLICATE_SAME_ACCESS))
    {
      errind = 3;
      goto err;
    }
  if (!DuplicateHandle (hMainProc, input_available_event, hMainProc,
			&fts->input_available_event, 0, 1,
			DUPLICATE_SAME_ACCESS))
    {
      errind = 4;
      goto err;
    }
  if (!DuplicateHandle (hMainProc, output_mutex, hMainProc,
			&fts->output_mutex, 0, 1,
			DUPLICATE_SAME_ACCESS))
    {
      errind = 5;
      goto err;
    }
  if (!DuplicateHandle (hMainProc, input_mutex, hMainProc,
			&fts->input_mutex, 0, 1,
			DUPLICATE_SAME_ACCESS))
    {
      errind = 6;
      goto err;
    }
  if (!DuplicateHandle (hMainProc, get_handle (), hMainProc,
			&nh, 0, 1,
			DUPLICATE_SAME_ACCESS))
    {
      errind = 7;
      goto err;
    }
  fts->set_io_handle (nh);

  if (!DuplicateHandle (hMainProc, get_output_handle (), hMainProc,
			&nh, 0, 1,
			DUPLICATE_SAME_ACCESS))
    {
      errind = 8;
      goto err;
    }
  fts->set_output_handle (nh);

  if (inuse == NULL)
    fts->inuse = NULL;
  else if (!DuplicateHandle (hMainProc, inuse, hMainProc,
			     &fts->inuse, 0, 1,
			     DUPLICATE_SAME_ACCESS))
    {
      errind = 9;
      goto err;
    }

  return 0;

err:
  __seterrno ();
  termios_printf ("dup %d failed in DuplicateHandle, %E", errind);
  return -1;
}

int
fhandler_tty_slave::tcgetattr (struct termios *t)
{
  *t = get_ttyp ()->ti;
  return 0;
}

int
fhandler_tty_slave::tcsetattr (int, const struct termios *t)
{
  acquire_output_mutex (INFINITE);
  get_ttyp ()->ti = *t;
  release_output_mutex ();
  return 0;
}

int
fhandler_tty_slave::tcflush (int queue)
{
  int ret = 0;

  termios_printf ("tcflush(%d) handle %p", queue, get_handle ());

  if (queue == TCIFLUSH || queue == TCIOFLUSH)
    {
      size_t len = UINT_MAX;
      read (NULL, len);
      ret = ((int) len) >= 0;
    }
  if (queue == TCOFLUSH || queue == TCIOFLUSH)
    {
      /* do nothing for now. */
    }

  termios_printf ("%d=tcflush(%d)", ret, queue);
  return ret;
}

int
fhandler_tty_slave::ioctl (unsigned int cmd, void *arg)
{
  termios_printf ("ioctl (%x)", cmd);

  if (myself->pgid && get_ttyp ()->getpgid () != myself->pgid
      && myself->ctty == get_unit () && (get_ttyp ()->ti.c_lflag & TOSTOP))
    {
      /* background process */
      termios_printf ("bg ioctl pgid %d, tpgid %d, ctty %d",
		      myself->pgid, get_ttyp ()->getpgid (), myself->ctty);
      raise (SIGTTOU);
    }

  int retval;
  switch (cmd)
    {
    case TIOCGWINSZ:
    case TIOCSWINSZ:
    case TIOCLINUX:
      break;
    case FIONBIO:
      set_nonblocking (*(int *) arg);
      retval = 0;
      goto out;
    default:
      set_errno (EINVAL);
      return -1;
    }

  acquire_output_mutex (INFINITE);

  get_ttyp ()->cmd = cmd;
  get_ttyp ()->ioctl_retval = 0;
  switch (cmd)
    {
    case TIOCGWINSZ:
      get_ttyp ()->arg.winsize = get_ttyp ()->winsize;
      if (ioctl_request_event)
	SetEvent (ioctl_request_event);
      *(struct winsize *) arg = get_ttyp ()->arg.winsize;
      if (ioctl_done_event)
	WaitForSingleObject (ioctl_done_event, INFINITE);
      get_ttyp ()->winsize = get_ttyp ()->arg.winsize;
      break;
    case TIOCSWINSZ:
      if (get_ttyp ()->winsize.ws_row != ((struct winsize *) arg)->ws_row
	  || get_ttyp ()->winsize.ws_col != ((struct winsize *) arg)->ws_col)
	{
	  get_ttyp ()->arg.winsize = *(struct winsize *) arg;
	  if (ioctl_request_event)
	    {
	      get_ttyp ()->ioctl_retval = -EINVAL;
	      SetEvent (ioctl_request_event);
	    }
	  else
	    {
	      get_ttyp ()->winsize = *(struct winsize *) arg;
	      killsys (-get_ttyp ()->getpgid (), SIGWINCH);
	    }
	  if (ioctl_done_event)
	    WaitForSingleObject (ioctl_done_event, INFINITE);
	}
      break;
    case TIOCLINUX:
      int val = *(unsigned char *) arg;
      if (val != 6 || !ioctl_request_event || !ioctl_done_event)
	  get_ttyp ()->ioctl_retval = -EINVAL;
      else
	{
	  get_ttyp ()->arg.value = val;
	  SetEvent (ioctl_request_event);
	  WaitForSingleObject (ioctl_done_event, INFINITE);
	  *(unsigned char *) arg = get_ttyp ()->arg.value & 0xFF;
	}
      break;
    }

  release_output_mutex ();
  retval = get_ttyp ()->ioctl_retval;
  if (retval < 0)
    {
      set_errno (-retval);
      retval = -1;
    }

out:
  termios_printf ("%d = ioctl (%x)", retval, cmd);
  return retval;
}

/*******************************************************
 fhandler_pty_master
*/
fhandler_pty_master::fhandler_pty_master ()
  : fhandler_tty_common ()
{
}

int
fhandler_pty_master::open (int flags, mode_t)
{
  int ntty = cygwin_shared->tty.allocate_tty (false);
  if (ntty < 0)
    return 0;

  slave = *ttys_dev;
  slave.setunit (ntty);
  cygwin_shared->tty[ntty]->common_init (this);
  ReleaseMutex (tty_mutex);	// lock was set in allocate_tty
  inuse = get_ttyp ()->create_inuse (TTY_MASTER_ALIVE);
  set_flags ((flags & ~O_TEXT) | O_BINARY);
  set_open_status ();

  termios_printf ("opened pty master tty%d", get_unit ());
  return 1;
}

int
fhandler_tty_common::close ()
{
  termios_printf ("tty%d <%p,%p> closing", get_unit (), get_handle (), get_output_handle ());
  if (output_done_event && !CloseHandle (output_done_event))
    termios_printf ("CloseHandle (output_done_event), %E");
  if (ioctl_done_event && !CloseHandle (ioctl_done_event))
    termios_printf ("CloseHandle (ioctl_done_event), %E");
  if (ioctl_request_event && !CloseHandle (ioctl_request_event))
    termios_printf ("CloseHandle (ioctl_request_event), %E");
  if (inuse && !CloseHandle (inuse))
    termios_printf ("CloseHandle (inuse), %E");
  if (!ForceCloseHandle (input_mutex))
    termios_printf ("CloseHandle (input_mutex<%p>), %E", input_mutex);
  if (!ForceCloseHandle (output_mutex))
    termios_printf ("CloseHandle (output_mutex<%p>), %E", output_mutex);

  /* Send EOF to slaves if master side is closed */
  if (!get_ttyp ()->master_alive ())
    {
      termios_printf ("no more masters left. sending EOF");
      SetEvent (input_available_event);
    }

  if (!ForceCloseHandle (input_available_event))
    termios_printf ("CloseHandle (input_available_event<%p>), %E", input_available_event);
  if (!ForceCloseHandle1 (get_handle (), from_pty))
    termios_printf ("CloseHandle (get_handle ()<%p>), %E", get_handle ());
  if (!ForceCloseHandle1 (get_output_handle (), to_pty))
    termios_printf ("CloseHandle (get_output_handle ()<%p>), %E", get_output_handle ());

  if (!hExeced)
    {
      inuse = NULL;
      set_io_handle (NULL);
    }
  return 0;
}

int
fhandler_pty_master::close ()
{
#if 0
  while (accept_input () > 0)
    continue;
#endif
  fhandler_tty_common::close ();

  if (!get_ttyp ()->master_alive ())
    {
      termios_printf ("freeing tty%d (%d)", get_unit (), get_ttyp ()->ntty);
#if 0
      if (get_ttyp ()->to_slave)
	ForceCloseHandle1 (get_ttyp ()->to_slave, to_slave);
      if (get_ttyp ()->from_slave)
	ForceCloseHandle1 (get_ttyp ()->from_slave, from_slave);
#endif
      if (get_ttyp ()->from_master)
	CloseHandle (get_ttyp ()->from_master);
      if (get_ttyp ()->to_master)
	CloseHandle (get_ttyp ()->to_master);
      if (!hExeced)
	get_ttyp ()->init ();
    }

  return 0;
}

int
fhandler_pty_master::write (const void *ptr, size_t len)
{
  int i;
  char *p = (char *) ptr;
  termios ti = tc->ti;

  for (i = 0; i < (int) len; i++)
    {
      line_edit_status status = line_edit (p++, 1, ti);
      if (status > line_edit_signalled)
	{
	  if (status != line_edit_pipe_full)
	    i = -1;
	  break;
	}
    }
  return i;
}

void __stdcall
fhandler_pty_master::read (void *ptr, size_t& len)
{
  len = (size_t) process_slave_output ((char *) ptr, len, pktmode);
  return;
}

int
fhandler_pty_master::tcgetattr (struct termios *t)
{
  *t = cygwin_shared->tty[get_unit ()]->ti;
  return 0;
}

int
fhandler_pty_master::tcsetattr (int, const struct termios *t)
{
  cygwin_shared->tty[get_unit ()]->ti = *t;
  return 0;
}

int
fhandler_pty_master::tcflush (int queue)
{
  int ret = 0;

  termios_printf ("tcflush(%d) handle %p", queue, get_handle ());

  if (queue == TCIFLUSH || queue == TCIOFLUSH)
    ret = process_slave_output (NULL, OUT_BUFFER_SIZE, 0);
  else if (queue == TCIFLUSH || queue == TCIOFLUSH)
    {
      /* do nothing for now. */
    }

  termios_printf ("%d=tcflush(%d)", ret, queue);
  return ret;
}

int
fhandler_pty_master::ioctl (unsigned int cmd, void *arg)
{
  switch (cmd)
    {
      case TIOCPKT:
	pktmode = *(int *) arg;
	break;
      case TIOCGWINSZ:
	*(struct winsize *) arg = get_ttyp ()->winsize;
	break;
      case TIOCSWINSZ:
	if (get_ttyp ()->winsize.ws_row != ((struct winsize *) arg)->ws_row
	    || get_ttyp ()->winsize.ws_col != ((struct winsize *) arg)->ws_col)
	  {
	    get_ttyp ()->winsize = *(struct winsize *) arg;
	    killsys (-get_ttyp ()->getpgid (), SIGWINCH);
	  }
	break;
      case FIONBIO:
	set_nonblocking (*(int *) arg);
	break;
      default:
	set_errno (EINVAL);
	return -1;
    }
  return 0;
}

char *
fhandler_pty_master::ptsname ()
{
  static char buf[32];

  __small_sprintf (buf, "/dev/tty%d", get_unit ());
  return buf;
}

void
fhandler_tty_common::set_close_on_exec (bool val)
{
  if (archetype)
    close_on_exec (val);
  else
    {
      if (output_done_event)
	set_no_inheritance (output_done_event, val);
      if (ioctl_request_event)
	set_no_inheritance (ioctl_request_event, val);
      if (ioctl_done_event)
	set_no_inheritance (ioctl_done_event, val);
      if (inuse)
	set_no_inheritance (inuse, val);
      set_no_inheritance (output_mutex, val);
      set_no_inheritance (input_mutex, val);
      set_no_inheritance (input_available_event, val);
      set_no_inheritance (output_handle, val);
#ifndef DEBUGGING
      fhandler_base::set_close_on_exec (val);
#else
      /* FIXME: This is a duplication from fhandler_base::set_close_on_exec.
	 It is here because we need to specify the "from_pty" stuff here or
	 we'll get warnings from ForceCloseHandle when debugging. */
      set_no_inheritance (get_io_handle (), val);
      close_on_exec (val);
#endif
    }
}

void
fhandler_tty_slave::fixup_after_fork (HANDLE parent)
{
  // fhandler_tty_common::fixup_after_fork (parent);
  report_tty_counts (this, "inherited", "", "");
}

void
fhandler_tty_common::fixup_after_fork (HANDLE parent)
{
  fhandler_termios::fixup_after_fork (parent);
  if (output_done_event)
    fork_fixup (parent, output_done_event, "output_done_event");
  if (ioctl_request_event)
    fork_fixup (parent, ioctl_request_event, "ioctl_request_event");
  if (ioctl_done_event)
    fork_fixup (parent, ioctl_done_event, "ioctl_done_event");
  if (output_mutex)
    fork_fixup (parent, output_mutex, "output_mutex");
  if (input_mutex)
    fork_fixup (parent, input_mutex, "input_mutex");
  if (input_available_event)
    fork_fixup (parent, input_available_event, "input_available_event");
  fork_fixup (parent, inuse, "inuse");
}

void
fhandler_pty_master::set_close_on_exec (bool val)
{
  fhandler_tty_common::set_close_on_exec (val);

  /* FIXME: There is a console handle leak here. */
  if (get_ttyp ()->master_pid == GetCurrentProcessId ())
    {
      get_ttyp ()->from_slave = get_handle ();
      get_ttyp ()->to_slave = get_output_handle ();
      termios_printf ("from_slave %p, to_slave %p", get_handle (),
		      get_output_handle ());
    }
}

int
fhandler_tty_master::init_console ()
{
  console = (fhandler_console *) build_fh_dev (*console_dev, "/dev/ttym");
  if (console == NULL)
    return -1;

  console->init (INVALID_HANDLE_VALUE, GENERIC_READ | GENERIC_WRITE, O_BINARY);
  cygheap->open_fhs--;		/* handled when individual fds are opened */
  console->uninterruptible_io (true);
  return 0;
}
