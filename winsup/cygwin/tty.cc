/* tty.cc

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include "miscfuncs.h"
#include <unistd.h>
#include <utmp.h>
#include <sys/cygwin.h>
#include "cygerrno.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "pinfo.h"
#include "shared_info.h"

HANDLE NO_COPY tty_list::mutex = NULL;

extern "C" int
getpt (void)
{
  return open ("/dev/ptmx", O_RDWR | O_NOCTTY);
}

extern "C" int
posix_openpt (int oflags)
{
  return open ("/dev/ptmx", oflags);
}

extern "C" int
grantpt (int fd)
{
  cygheap_fdget cfd (fd);
  return cfd < 0 ? -1 : 0;
}

extern "C" int
unlockpt (int fd)
{
  cygheap_fdget cfd (fd);
  return cfd < 0 ? -1 : 0;
}

extern "C" int
revoke (char *ttyname)
{
  set_errno (ENOSYS);
  return -1;
}

extern "C" int
ttyslot (void)
{
  if (myself->ctty <= 0 || iscons_dev (myself->ctty))
    return -1;
  return device::minor (myself->ctty);
}

void __stdcall
tty_list::init_session ()
{
  char mutex_name[MAX_PATH];
  char *name = shared_name (mutex_name, "tty_list::mutex", 0);

  /* tty_list::mutex is used while searching for a tty slot */
  if (!(mutex = CreateMutex (&sec_all_nih, FALSE, name)))
    api_fatal ("can't create tty_list::mutex '%s', %E", name);
  ProtectHandle (mutex);
}

void __stdcall
tty::init_session ()
{
  if (!myself->cygstarted && NOTSTATE (myself, PID_CYGPARENT))
    cygheap->fdtab.get_debugger_info ();
}

int __reg2
tty_list::attach (int n)
{
  int res;
  if (iscons_dev (n))
    res = -1;
  else if (n != -1)
    res = connect (device::minor (n));
  else
    res = -1;
  return res;
}

int
tty_list::connect (int ttynum)
{
  if (ttynum < 0 || ttynum >= NTTYS)
    {
      termios_printf ("ttynum (%d) out of range", ttynum);
      return -1;
    }
  if (!ttys[ttynum].exists ())
    {
      termios_printf ("pty %d was not allocated", ttynum);
      set_errno (ENXIO);
      return -1;
    }

  return ttynum;
}

void
tty_list::init ()
{
  for (int i = 0; i < NTTYS; i++)
    {
      ttys[i].init ();
      ttys[i].setntty (DEV_PTYS_MAJOR, i);
    }
}

/* Search for a free tty and allocate it.
   Return tty number or -1 if error.
 */
int
tty_list::allocate (HANDLE& r, HANDLE& w)
{
  lock_ttys here;
  int freetty = -1;

  tty *t = NULL;
  for (int i = 0; i < NTTYS; i++)
    if (ttys[i].not_allocated (r, w))
      {
	t = ttys + i;
	t->init ();
	t->setsid (0);
	freetty = i;
	break;
      }

  if (freetty >= 0)
    termios_printf ("pty%d allocated", freetty);
  else
    {
      system_printf ("No pty allocated");
      r = w = NULL;
    }

  return freetty;
}

bool
tty::not_allocated (HANDLE& r, HANDLE& w)
{
  /* Attempt to open the from-master side of the tty.  If it is accessible
     then it exists although we may not have privileges to actually use it. */
  char pipename[sizeof("ptyNNNN-from-master")];
  __small_sprintf (pipename, "pty%d-from-master", get_minor ());
  /* fhandler_pipe::create returns 0 when creation succeeds */
  return fhandler_pipe::create (&sec_none, &r, &w,
				fhandler_pty_common::pipesize, pipename,
				0) == 0;
}

bool
tty::exists ()
{
  HANDLE r, w;
  bool res;
  if (!not_allocated (r, w))
    res = true;

  else
    {
      /* Handles are left open when not_allocated finds a non-open "tty" */
      CloseHandle (r);
      CloseHandle (w);
      res = false;
    }
  debug_printf ("exists %d", res);
  return res;
}

bool
tty::slave_alive ()
{
  HANDLE ev;
  if ((ev = open_inuse (READ_CONTROL)))
    CloseHandle (ev);
  return ev != NULL;
}

HANDLE
tty::open_mutex (const char *mutex, ACCESS_MASK access)
{
  char buf[MAX_PATH];
  shared_name (buf, mutex, get_minor ());
  return OpenMutex (access, TRUE, buf);
}

HANDLE
tty::open_inuse (ACCESS_MASK access)
{
  char buf[MAX_PATH];
  shared_name (buf, TTY_SLAVE_ALIVE, get_minor ());
  return OpenEvent (access, FALSE, buf);
}

HANDLE
tty::create_inuse (PSECURITY_ATTRIBUTES sa)
{
  HANDLE h;
  char buf[MAX_PATH];

  shared_name (buf, TTY_SLAVE_ALIVE, get_minor ());
  h = CreateEvent (sa, TRUE, FALSE, buf);
  termios_printf ("%s %p", buf, h);
  if (!h)
    termios_printf ("couldn't open inuse event %s, %E", buf);
  return h;
}

void
tty::init ()
{
  output_stopped = 0;
  setsid (0);
  pgid = 0;
  was_opened = false;
  master_pid = 0;
  is_console = false;
  column = 0;
  pcon_activated = false;
  switch_to_pcon_in = false;
  pcon_pid = 0;
  term_code_page = 0;
  pcon_last_time = 0;
  pcon_start = false;
  pcon_start_pid = 0;
  pcon_cap_checked = false;
  has_csi6n = false;
  need_invisible_console = false;
  invisible_console_pid = 0;
  previous_code_page = 0;
  previous_output_code_page = 0;
  master_is_running_as_service = false;
  req_xfer_input = false;
  pcon_input_state = to_cyg;
  last_sig = 0;
  mask_flusho = false;
  discard_input = false;
}

HANDLE
tty::get_event (const char *fmt, PSECURITY_ATTRIBUTES sa, BOOL manual_reset)
{
  HANDLE hev;
  char buf[MAX_PATH];

  shared_name (buf, fmt, get_minor ());
  if (!sa)
    sa = &sec_all;
  if (!(hev = CreateEvent (sa, manual_reset, FALSE, buf)))
    {
      termios_printf ("couldn't create %s", buf);
      set_errno (ENOENT);	/* FIXME this can't be the right errno */
      return NULL;
    }

  termios_printf ("created event %s", buf);
  return hev;
}

lock_ttys::lock_ttys (DWORD howlong): release_me (true)
{
  if (WaitForSingleObject (tty_list::mutex, howlong) == WAIT_FAILED)
    {
      termios_printf ("WFSO for mutex %p failed, %E", tty_list::mutex);
      release_me = false;
    }
}

void
lock_ttys::release ()
{
  ReleaseMutex (tty_list::mutex);
}

const char *
tty_min::ttyname ()
{
  device d;
  d.parse (ntty);
  return d.name ();
}

void
tty_min::setpgid (int pid)
{
  fhandler_pty_slave *ptys = NULL;
  cygheap_fdenum cfd (false);
  while (cfd.next () >= 0 && ptys == NULL)
    if (cfd->get_device () == getntty ())
      ptys = (fhandler_pty_slave *) (fhandler_base *) cfd;

  if (ptys)
    {
      tty *ttyp = ptys->get_ttyp ();
      WaitForSingleObject (ptys->pcon_mutex, INFINITE);
      bool was_pcon_fg = ttyp->pcon_fg (pgid);
      bool pcon_fg = ttyp->pcon_fg (pid);
      if (!was_pcon_fg && pcon_fg && ttyp->switch_to_pcon_in
	  && ttyp->pcon_input_state_eq (tty::to_cyg))
	{
	WaitForSingleObject (ptys->input_mutex, INFINITE);
	fhandler_pty_slave::transfer_input (tty::to_nat,
					    ptys->get_handle (), ttyp,
					    ptys->get_input_available_event ());
	ReleaseMutex (ptys->input_mutex);
	}
      else if (was_pcon_fg && !pcon_fg && ttyp->switch_to_pcon_in
	       && ttyp->pcon_input_state_eq (tty::to_nat))
	{
	  bool attach_restore = false;
	  HANDLE from = ptys->get_handle_nat ();
	  if (ttyp->pcon_activated && ttyp->pcon_pid
	      && !ptys->get_console_process_id (ttyp->pcon_pid, true))
	    {
	      HANDLE pcon_owner =
		OpenProcess (PROCESS_DUP_HANDLE, FALSE, ttyp->pcon_pid);
	      DuplicateHandle (pcon_owner, ttyp->h_pcon_in,
			       GetCurrentProcess (), &from,
			       0, TRUE, DUPLICATE_SAME_ACCESS);
	      CloseHandle (pcon_owner);
	      FreeConsole ();
	      AttachConsole (ttyp->pcon_pid);
	      attach_restore = true;
	    }
	  WaitForSingleObject (ptys->input_mutex, INFINITE);
	  fhandler_pty_slave::transfer_input (tty::to_cyg, from, ttyp,
				  ptys->get_input_available_event ());
	  ReleaseMutex (ptys->input_mutex);
	  if (attach_restore)
	    {
	      FreeConsole ();
	      pinfo p (myself->ppid);
	      if (p)
		{
		  if (!AttachConsole (p->dwProcessId))
		    AttachConsole (ATTACH_PARENT_PROCESS);
		}
	      else
		AttachConsole (ATTACH_PARENT_PROCESS);
	    }
	}
      ReleaseMutex (ptys->pcon_mutex);
    }
  pgid = pid;
}

void
tty::wait_pcon_fwd (bool init)
{
  /* The forwarding in pseudo console sometimes stops for
     16-32 msec even if it already has data to transfer.
     If the time without transfer exceeds 32 msec, the
     forwarding is supposed to be finished. pcon_last_time
     is reset to GetTickCount() in pty master forwarding
     thread when the last data is transfered. */
  const int sleep_in_pcon = 16;
  const int time_to_wait = sleep_in_pcon * 2 + 1/* margine */;
  if (init)
    pcon_last_time = GetTickCount ();
  while (GetTickCount () - pcon_last_time < time_to_wait)
    {
      int tw = time_to_wait - (GetTickCount () - pcon_last_time);
      cygwait (tw);
    }
}

bool
tty::pcon_fg (pid_t pgid)
{
  /* Check if the terminal pgid matches with the pgid of the
     non-cygwin process. */
  winpids pids ((DWORD) 0);
  for (unsigned i = 0; i < pids.npids; i++)
    {
      _pinfo *p = pids[i];
      if (p->ctty == ntty && p->pgid == pgid && p->exec_dwProcessId)
	return true;
    }
  if (pgid > MAX_PID)
    return true;
  return false;
}
