/* fhandler_tty.cc

   Copyright 1997, 1998, 2000, 2001 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include "cygerrno.h"
#include "security.h"
#include "fhandler.h"
#include "dtable.h"
#include "sync.h"
#include "sigproc.h"
#include "pinfo.h"
#include "cygheap.h"
#include "shared_info.h"

/* Tty master stuff */

fhandler_tty_master NO_COPY *tty_master;

static DWORD WINAPI process_input (void *);		// Input queue thread
static DWORD WINAPI process_output (void *);		// Output queue thread
static DWORD WINAPI process_ioctl (void *);		// Ioctl requests thread

fhandler_tty_master::fhandler_tty_master (const char *name, int unit) :
	fhandler_pty_master (name, FH_TTYM, unit)
{
  set_cb (sizeof *this);
  console = NULL;
  hThread = NULL;
}

int
fhandler_tty_master::init (int ntty)
{
  HANDLE h;
  termios_printf ("Creating master for tty%d", ntty);

  if (init_console ())
    {
      termios_printf ("can't create fhandler");
      return -1;
    }

  termios ti;
  memset (&ti, 0, sizeof (ti));
  console->tcsetattr (0, &ti);

  ttynum = ntty;

  cygwin_shared->tty[ttynum]->common_init (this);

  inuse = get_ttyp ()->create_inuse (TTY_MASTER_ALIVE);

  h = makethread (process_input, NULL, 0, "ttyin");
  if (h == NULL)
    {
      termios_printf ("can't create input thread");
      return -1;
    }
  else
    {
      SetThreadPriority (h, THREAD_PRIORITY_HIGHEST);
      CloseHandle (h);
    }

  h = makethread (process_ioctl, NULL, 0, "ttyioctl");
  if (h == NULL)
    {
      termios_printf ("can't create ioctl thread");
      return -1;
    }
  else
    {
      SetThreadPriority (h, THREAD_PRIORITY_HIGHEST);
      CloseHandle (h);
    }

  hThread = makethread (process_output, NULL, 0, "ttyout");
  if (hThread != NULL)
    SetThreadPriority (hThread, THREAD_PRIORITY_HIGHEST);
  else
    {
      termios_printf ("can't create output thread");
      return -1;
    }

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
      ostack[osi].tname = threadname (0, 0);
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
  DWORD bytes_left, written;
  DWORD n;
  DWORD rc;
  char* p;

  rc = WaitForSingleObject (input_mutex, INFINITE);

  bytes_left = n = eat_readahead (-1);
  get_ttyp ()->read_retval = 0;
  p = rabuf;

  if (n != 0)
    {
      while (bytes_left > 0)
	{
	  termios_printf ("about to write %d chars to slave", bytes_left);
	  rc = WriteFile (get_output_handle (), p, bytes_left, &written, NULL);
	  if (!rc)
	    {
	      debug_printf ("error writing to pipe %E");
	      break;
	    }
	  get_ttyp ()->read_retval += written;
	  p += written;
	  bytes_left -= written;
	  if (bytes_left > 0)
	    {
	      debug_printf ("to_slave pipe is full");
	      SetEvent (input_available_event);
	      ReleaseMutex (input_mutex);
	      Sleep (10);
	      rc = WaitForSingleObject (input_mutex, INFINITE);
	    }
	}
    }
  else
    termios_printf ("sending EOF to slave");
  SetEvent (input_available_event);
  ReleaseMutex (input_mutex);
  return get_ttyp ()->read_retval;
}

static DWORD WINAPI
process_input (void *)
{
  char rawbuf[INP_BUFFER_SIZE];

  while (1)
    {
      int nraw = tty_master->console->read ((void *) rawbuf,
				      (size_t) INP_BUFFER_SIZE);
      (void) tty_master->line_edit (rawbuf, nraw);
    }
}

BOOL
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

      if (get_ttyp ()->ti.c_lflag & FLUSHO)
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
  char buf[OUT_BUFFER_SIZE*2];

  for (;;)
    {
      int n = tty_master->process_slave_output (buf, OUT_BUFFER_SIZE, 0);
      if (n < 0)
	{
	  termios_printf ("ReadFile %E");
	  ExitThread (0);
	}
      if (n == 0)
	{
	  /* End of file.  */
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

fhandler_tty_slave::fhandler_tty_slave (int num, const char *name) :
	fhandler_tty_common (FH_TTYS, name, num)
{
  set_cb (sizeof *this);
  ttynum = num;
  /* FIXME: This is wasteful.  We should rewrite the set_name path to eliminate the
     need for double allocates. */
  unix_path_name = (char *) crealloc (unix_path_name, strlen (win32_path_name) + 1);
  strcpy (unix_path_name, win32_path_name);
  unix_path_name[0] = unix_path_name[4] = '/';
  debug_printf ("unix '%s', win32 '%s'", unix_path_name, win32_path_name);
  inuse = NULL;
}

fhandler_tty_slave::fhandler_tty_slave (const char *name) :
	fhandler_tty_common (FH_TTYS, name, 0)
{
  set_cb (sizeof *this);
  inuse = NULL;
}

/* FIXME: This function needs to close handles when it has
   a failing condition. */
int
fhandler_tty_slave::open (const char *, int flags, mode_t)
{
  tcinit (cygwin_shared->tty[ttynum]);

  attach_tty (ttynum);
  tc->set_ctty (ttynum, flags);

  set_flags (flags);
  /* Create synchronisation events */
  char buf[40];

  /* output_done_event may or may not exist.  It will exist if the tty
     was opened by fhandler_tty_master::init, normally called at
     startup if use_tty is non-zero.  It will not exist if this is a
     pty opened by fhandler_pty_master::open.  In the former case, tty
     output is handled by a separate thread which controls output.  */
  __small_sprintf (buf, OUTPUT_DONE_EVENT, ttynum);
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
  __small_sprintf (buf, INPUT_AVAILABLE_EVENT, ttynum);
  if (!(input_available_event = OpenEvent (EVENT_ALL_ACCESS, TRUE, buf)))
    {
      termios_printf ("open input event failed, %E");
      __seterrno ();
      return 0;
    }

  /* The ioctl events may or may not exist.  See output_done_event,
     above.  */
  __small_sprintf (buf, IOCTL_REQUEST_EVENT, ttynum);
  ioctl_request_event = OpenEvent (EVENT_ALL_ACCESS, TRUE, buf);
  __small_sprintf (buf, IOCTL_DONE_EVENT, ttynum);
  ioctl_done_event = OpenEvent (EVENT_ALL_ACCESS, TRUE, buf);

  /* FIXME: Needs a method to eliminate tty races */
  {
    acquire_output_mutex (500);
    inuse = get_ttyp ()->create_inuse (TTY_SLAVE_ALIVE);
    get_ttyp ()->was_opened = TRUE;
    release_output_mutex ();
  }

  /* Duplicate tty handles.  */

  if (!get_ttyp ()->from_slave || !get_ttyp ()->to_slave)
    {
      termios_printf ("tty handles have been closed");
      set_errno (EACCES);
      return 0;
    }

  HANDLE tty_owner = OpenProcess (PROCESS_DUP_HANDLE, FALSE,
				     get_ttyp ()->master_pid);
  if (tty_owner == NULL)
    {
      termios_printf ("can't open tty (%d) handle process %d",
		      ttynum, get_ttyp ()->master_pid);
      __seterrno ();
      return 0;
    }

  HANDLE nh;
  if (!DuplicateHandle (tty_owner, get_ttyp ()->from_master, hMainProc, &nh, 0, TRUE,
			DUPLICATE_SAME_ACCESS))
    {
      termios_printf ("can't duplicate input, %E");
      __seterrno ();
      return 0;
    }
  set_io_handle (nh);
  ProtectHandle1 (nh, from_pty);
  termios_printf ("duplicated from_master %p->%p from tty_owner %p",
		  get_ttyp ()->from_master, nh, tty_owner);
  if (!DuplicateHandle (tty_owner, get_ttyp ()->to_master, hMainProc, &nh, 0, TRUE,
			DUPLICATE_SAME_ACCESS))
    {
      termios_printf ("can't duplicate output, %E");
      __seterrno ();
      return 0;
    }
  set_output_handle (nh);
  ProtectHandle1 (nh, to_pty);
  CloseHandle (tty_owner);

  set_open_status ();
  termios_printf ("tty%d opened", ttynum);

  return 1;
}

void
fhandler_tty_slave::init (HANDLE, DWORD a, mode_t)
{
  int mode = 0;

  a &= GENERIC_READ | GENERIC_WRITE;
  if (a == GENERIC_READ)
    mode = O_RDONLY;
  if (a == GENERIC_WRITE)
    mode = O_WRONLY;
  if (a == (GENERIC_READ | GENERIC_WRITE))
    mode = O_RDWR;

  open (0, mode);
}

int
fhandler_tty_slave::write (const void *ptr, size_t len)
{
  DWORD n, towrite = len;

  termios_printf ("tty%d, write(%x, %d)", ttynum, ptr, len);

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
	  _raise (SIGHUP);		/* FIXME: Should this be SIGTTOU? */
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

int
fhandler_tty_slave::read (void *ptr, size_t len)
{
  DWORD n;
  int totalread = 0;
  int vmin = INT_MAX;
  int vtime = 0;	/* Initialized to prevent -Wuninitialized warning */
  size_t readlen;
  DWORD bytes_in_pipe;
  char buf[INP_BUFFER_SIZE];
  char peek_buf[INP_BUFFER_SIZE];
  DWORD time_to_wait;
  DWORD rc;
  HANDLE w4[2];

  termios_printf ("read(%x, %d) handle %d", ptr, len, get_handle ());

  if (!(get_ttyp ()->ti.c_lflag & ICANON))
    {
      vmin = min (INP_BUFFER_SIZE, get_ttyp ()->ti.c_cc[VMIN]);
      vtime = get_ttyp ()->ti.c_cc[VTIME];
      if (vmin < 0) vmin = 0;
      if (vtime < 0) vtime = 0;
      if (vmin == 0)
	time_to_wait = INFINITE;
      else
	time_to_wait = (vtime == 0 ? INFINITE : 100 * vtime);
    }
  else
    time_to_wait = INFINITE;

  w4[0] = signal_arrived;
  w4[1] = input_available_event;

  while (len)
    {
      rc = WaitForMultipleObjects (2, w4, FALSE, time_to_wait);
      if (rc == WAIT_OBJECT_0)
	{
	  /* if we've received signal after successfully reading some data,
	     just return all data successfully read */
	  if (totalread > 0)
	    break;
	  set_sig_errno (EINTR);
	  return -1;
	}
      else if (rc == WAIT_FAILED)
	{
	  termios_printf ("wait for input event failed, %E");
	  break;
	}
      else if (rc == WAIT_TIMEOUT)
	break;
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
      if (!PeekNamedPipe (get_handle (), peek_buf, sizeof(peek_buf), &bytes_in_pipe, NULL, NULL))
	{
	  termios_printf ("PeekNamedPipe failed, %E");
	  _raise (SIGHUP);
	  bytes_in_pipe = 0;
	}
      readlen = min (bytes_in_pipe, min (len, sizeof (buf)));
      if (readlen)
	{
	  termios_printf ("reading %d bytes (vtime %d)", readlen, vtime);
	  if (ReadFile (get_handle (), buf, readlen, &n, NULL) == FALSE)
	    {
	      termios_printf ("read failed, %E");
	      _raise (SIGHUP);
	    }
	  /* MSDN states that 5th prameter can be used to determine total
	     number of bytes in pipe, but for some reason this number doesn't
	     change after successful read. So we have to peek into the pipe
	     again to see if input is still available */
	  if (!PeekNamedPipe (get_handle (), peek_buf, 1, &bytes_in_pipe, NULL, NULL))
	    {
	      termios_printf ("PeekNamedPipe failed, %E");
	      _raise (SIGHUP);
	      bytes_in_pipe = 0;
	    }
	  if (n)
	    {
	      len -= n;
	      totalread += n;
	      memcpy (ptr, buf, n);
	      ptr = (char *) ptr + n;
	    }
	}

      if (!bytes_in_pipe)
	ResetEvent (input_available_event);

      ReleaseMutex (input_mutex);

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
      if (totalread >= vmin && (vmin > 0 || totalread > 0))
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
    }
  termios_printf ("%d=read(%x, %d)", totalread, ptr, len);
  return totalread;
}

int
fhandler_tty_common::dup (fhandler_base *child)
{
  fhandler_tty_slave *fts = (fhandler_tty_slave *) child;
  int errind;

  fts->ttynum = ttynum;
  fts->tcinit (get_ttyp ());

  attach_tty (ttynum);
  tc->set_ctty (ttynum, openflags);

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
fhandler_tty_slave::tcflush (int)
{
  return 0;
}

int
fhandler_tty_slave::ioctl (unsigned int cmd, void *arg)
{
  termios_printf ("ioctl (%x)", cmd);

  if (myself->pgid && get_ttyp ()->getpgid () != myself->pgid &&
	 myself->ctty == ttynum && (get_ttyp ()->ti.c_lflag & TOSTOP))
    {
      /* background process */
      termios_printf ("bg ioctl pgid %d, tpgid %d, ctty %d",
		      myself->pgid, get_ttyp ()->getpgid (), myself->ctty);
      _raise (SIGTTOU);
    }

  switch (cmd)
    {
    case TIOCGWINSZ:
    case TIOCSWINSZ:
      break;
    case FIONBIO:
      set_nonblocking (*(int *) arg);
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
      * (struct winsize *) arg = get_ttyp ()->arg.winsize;
      if (ioctl_done_event)
	WaitForSingleObject (ioctl_done_event, INFINITE);
      get_ttyp ()->winsize = get_ttyp ()->arg.winsize;
      break;
    case TIOCSWINSZ:
      get_ttyp ()->ioctl_retval = -1;
      get_ttyp ()->arg.winsize = * (struct winsize *) arg;
      if (ioctl_request_event)
	SetEvent (ioctl_request_event);
      if (ioctl_done_event)
	WaitForSingleObject (ioctl_done_event, INFINITE);
      break;
    }

  release_output_mutex ();

out:
  termios_printf ("%d = ioctl (%x)", get_ttyp ()->ioctl_retval, cmd);
  return get_ttyp ()->ioctl_retval;
}

/*******************************************************
 fhandler_pty_master
*/
fhandler_pty_master::fhandler_pty_master (const char *name, DWORD devtype, int unit) :
	fhandler_tty_common (devtype, name, unit)
{
  set_cb (sizeof *this);
  ioctl_request_event = NULL;
  ioctl_done_event = NULL;
  pktmode = need_nl = 0;
  inuse = NULL;
}

int
fhandler_pty_master::open (const char *, int flags, mode_t)
{
  ttynum = cygwin_shared->tty.allocate_tty (0);
  if (ttynum < 0)
    return 0;

  cygwin_shared->tty[ttynum]->common_init (this);
  inuse = get_ttyp ()->create_inuse (TTY_MASTER_ALIVE);
  set_flags (flags);
  set_open_status ();

  termios_printf ("opened pty master tty%d<%p>", ttynum, this);
  return 1;
}

int
fhandler_tty_common::close ()
{
  if (output_done_event && !CloseHandle (output_done_event))
    termios_printf ("CloseHandle (output_done_event), %E");
  if (ioctl_done_event && !CloseHandle (ioctl_done_event))
    termios_printf ("CloseHandle (ioctl_done_event), %E");
  if (ioctl_request_event && !CloseHandle (ioctl_request_event))
    termios_printf ("CloseHandle (ioctl_request_event), %E");
  if (inuse && !CloseHandle (inuse))
    termios_printf ("CloseHandle (inuse), %E");
  if (!ForceCloseHandle (output_mutex))
    termios_printf ("CloseHandle (output_mutex<%p>), %E", output_mutex);
  if (!ForceCloseHandle (input_mutex))
    termios_printf ("CloseHandle (input_mutex<%p>), %E", input_mutex);

  /* Send EOF to slaves if master side is closed */
  if (!get_ttyp ()->master_alive ())
    {
      termios_printf ("no more masters left. sending EOF" );
      SetEvent (input_available_event);
    }

  if (!ForceCloseHandle (input_available_event))
    termios_printf ("CloseHandle (input_available_event<%p>), %E", input_available_event);
  if (!ForceCloseHandle1 (get_handle (), from_pty))
    termios_printf ("CloseHandle (get_handle ()<%p>), %E", get_handle ());
  if (!ForceCloseHandle1 (get_output_handle (), to_pty))
    termios_printf ("CloseHandle (get_output_handle ()<%p>), %E", get_output_handle ());

  inuse = NULL;
  termios_printf ("tty%d <%p,%p> closed", ttynum, get_handle (), get_output_handle ());
  return 0;
}

int
fhandler_pty_master::close ()
{
#if 0
  while (accept_input () > 0)
    continue;
#endif
  this->fhandler_tty_common::close ();

  if (!get_ttyp ()->master_alive ())
    {
      termios_printf ("freeing tty%d (%d)", ttynum, get_ttyp ()->ntty);
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
      get_ttyp ()->init ();
    }

  return 0;
}

int
fhandler_pty_master::write (const void *ptr, size_t len)
{
  (void) line_edit ((char *) ptr, len);
  return len;
}

int
fhandler_pty_master::read (void *ptr, size_t len)
{
  return process_slave_output ((char *) ptr, len, pktmode);
}

int
fhandler_pty_master::tcgetattr (struct termios *t)
{
  *t = cygwin_shared->tty[ttynum]->ti;
  return 0;
}

int
fhandler_pty_master::tcsetattr (int, const struct termios *t)
{
  cygwin_shared->tty[ttynum]->ti = *t;
  return 0;
}

int
fhandler_pty_master::tcflush (int)
{
  return 0;
}

int
fhandler_pty_master::ioctl (unsigned int cmd, void *arg)
{
  switch (cmd)
    {
      case TIOCPKT:
	pktmode = * (int *) arg;
	break;
      case TIOCGWINSZ:
	* (struct winsize *) arg = get_ttyp ()->winsize;
	break;
      case TIOCSWINSZ:
	get_ttyp ()->winsize = * (struct winsize *) arg;
	_kill (-get_ttyp ()->getpgid (), SIGWINCH);
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
fhandler_pty_master::ptsname (void)
{
  static char buf[32];

  __small_sprintf (buf, "/dev/tty%d", ttynum);
  return buf;
}

void
fhandler_tty_common::set_close_on_exec (int val)
{
#ifndef DEBUGGING
  this->fhandler_base::set_close_on_exec (val);
#else
  /* FIXME: This is a duplication from fhandler_base::set_close_on_exec.
     It is here because we need to specify the "from_pty" stuff here or
     we'll get warnings from ForceCloseHandle when debugging. */
  set_inheritance (get_io_handle (), val, "from_pty");
  set_close_on_exec_flag (val);
#endif
  if (output_done_event)
    set_inheritance (output_done_event, val);
  if (ioctl_request_event)
    set_inheritance (ioctl_request_event, val);
  if (ioctl_done_event)
    set_inheritance (ioctl_done_event, val);
  if (inuse)
    set_inheritance (inuse, val);
  set_inheritance (output_mutex, val, "output_mutex");
  set_inheritance (input_mutex, val, "input_mutex");
  set_inheritance (input_available_event, val);
  set_inheritance (output_handle, val, "to_pty");
}

void
fhandler_tty_common::fixup_after_fork (HANDLE parent)
{
  this->fhandler_termios::fixup_after_fork (parent);
  if (output_done_event)
    fork_fixup (parent, output_done_event, "output_done_event");
  if (ioctl_request_event)
    fork_fixup (parent, ioctl_request_event, "ioctl_request_event");
  if (ioctl_done_event)
    fork_fixup (parent, ioctl_done_event, "ioctl_done_event");
  if (output_mutex)
    {
      fork_fixup (parent, output_mutex, "output_mutex");
      ProtectHandle (output_mutex);
    }
  if (input_mutex)
    {
      fork_fixup (parent, input_mutex, "input_mutex");
      ProtectHandle (input_mutex);
    }
  if (input_available_event)
    fork_fixup (parent, input_available_event, "input_available_event");
  fork_fixup (parent, inuse, "inuse");
}

void
fhandler_pty_master::set_close_on_exec (int val)
{
  this->fhandler_tty_common::set_close_on_exec (val);

  /* FIXME: There is a console handle leak here. */
  if (get_ttyp ()->master_pid == GetCurrentProcessId ())
    {
      get_ttyp ()->from_slave = get_handle ();
      get_ttyp ()->to_slave = get_output_handle ();
      termios_printf ("from_slave %p, to_slave %p", get_handle (),
		      get_output_handle ());
    }
}

void
fhandler_tty_master::fixup_after_fork (HANDLE child)
{
  this->fhandler_pty_master::fixup_after_fork (child);
  console->fixup_after_fork (child);
}

void
fhandler_tty_master::fixup_after_exec (HANDLE)
{
  console->close ();
  init_console ();
  return;
}

int
fhandler_tty_master::init_console ()
{
  console = (fhandler_console *) cygheap->fdtab.build_fhandler (-1, FH_CONSOLE, "/dev/ttym");
  if (console == NULL)
    return -1;

  console->init (INVALID_HANDLE_VALUE, GENERIC_READ | GENERIC_WRITE, O_BINARY);
  console->set_r_no_interrupt (1);
  return 0;
}
