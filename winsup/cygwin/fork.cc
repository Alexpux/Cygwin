/* fork.cc

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2004 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygerrno.h"
#include "sigproc.h"
#include "pinfo.h"
#include "cygheap.h"
#include "child_info.h"
#define NEED_VFORK
#include "perthread.h"
#include "perprocess.h"
#include "dll_init.h"
#include "sync.h"
#include "shared_info.h"
#include "cygmalloc.h"
#include "cygthread.h"

#ifdef DEBUGGING
static int npid;
static int npid_max;
static pid_t fork_pids[100];
#endif

/* Timeout to wait for child to start, parent to init child, etc.  */
/* FIXME: Once things stabilize, bump up to a few minutes.  */
#define FORK_WAIT_TIMEOUT (300 * 1000)     /* 300 seconds */

#define dll_data_start &_data_start__
#define dll_data_end &_data_end__
#define dll_bss_start &_bss_start__
#define dll_bss_end &_bss_end__

void
per_thread::set (void *s)
{
  if (s == PER_THREAD_FORK_CLEAR)
    {
      tls = TlsAlloc ();
      s = NULL;
    }
  TlsSetValue (get_tls (), s);
}

static void
stack_base (child_info_fork &ch)
{
  MEMORY_BASIC_INFORMATION m;
  memset (&m, 0, sizeof m);
  if (!VirtualQuery ((LPCVOID) &m, &m, sizeof m))
    system_printf ("couldn't get memory info, %E");

  ch.stacktop = m.AllocationBase;
  ch.stackbottom = (LPBYTE) m.BaseAddress + m.RegionSize;
  ch.stacksize = (DWORD) ch.stackbottom - (DWORD) &m;
  debug_printf ("bottom %p, top %p, stack %p, size %d, reserve %d",
		ch.stackbottom, ch.stacktop, &m, ch.stacksize,
		(DWORD) ch.stackbottom - (DWORD) ch.stacktop);
}

/* Copy memory from parent to child.
   The result is a boolean indicating success.  */

static int
fork_copy (PROCESS_INFORMATION &pi, const char *what, ...)
{
  va_list args;
  char *low;
  int pass = 0;

  va_start (args, what);

  while ((low = va_arg (args, char *)))
    {
      char *high = va_arg (args, char *);
      DWORD todo = wincap.chunksize () ?: high - low;
      char *here;

      for (here = low; here < high; here += todo)
	{
	  DWORD done = 0;
	  if (here + todo > high)
	    todo = high - here;
	  int res = WriteProcessMemory (pi.hProcess, here, here, todo, &done);
	  debug_printf ("child handle %p, low %p, high %p, res %d", pi.hProcess,
			low, high, res);
	  if (!res || todo != done)
	    {
	      if (!res)
		__seterrno ();
	      /* If this happens then there is a bug in our fork
		 implementation somewhere. */
	      system_printf ("%s pass %d failed, %p..%p, done %d, windows pid %u, %E",
			    what, pass, low, high, done, pi.dwProcessId);
	      goto err;
	    }
	}

      pass++;
    }

  debug_printf ("done");
  return 1;

 err:
  TerminateProcess (pi.hProcess, 1);
  set_errno (EAGAIN);
  return 0;
}

/* Wait for child to finish what it's doing and signal us.
   We don't want to wait forever here.If there's a problem somewhere
   it'll hang the entire system (since all forks are mutex'd). If we
   time out, set errno = EAGAIN and hope the app tries again.  */
static int
sync_with_child (PROCESS_INFORMATION &pi, HANDLE subproc_ready,
		 bool hang_child, const char *s)
{
  /* We also add the child process handle to the wait. If the child fails
     to initialize (eg. because of a missing dll). Then this
     handle will become signalled. This stops a *looong* timeout wait.
  */
  HANDLE w4[2];

  debug_printf ("waiting for child.  reason: %s, hang_child %d", s,
		hang_child);
  w4[1] = pi.hProcess;
  w4[0] = subproc_ready;
  DWORD rc = WaitForMultipleObjects (2, w4, FALSE, FORK_WAIT_TIMEOUT);

  if (rc == WAIT_OBJECT_0 ||
      WaitForSingleObject (subproc_ready, 0) == WAIT_OBJECT_0)
    /* That's ok */;
  else if (rc == WAIT_FAILED || rc == WAIT_TIMEOUT)
    {
      if (rc != WAIT_FAILED)
	system_printf ("WaitForMultipleObjects timed out");
      else
	system_printf ("WaitForMultipleObjects failed, %E");
      set_errno (EAGAIN);
      syscall_printf ("-1 = fork(), WaitForMultipleObjects failed");
      TerminateProcess (pi.hProcess, 1);
      return 0;
    }
  else
    {
      /* Child died. Clean up and exit. */
      DWORD errcode;
      GetExitCodeProcess (pi.hProcess, &errcode);
      /* Fix me.  This is not enough.  The fork should not be considered
       * to have failed if the process was essentially killed by a signal.
       */
      if (errcode != STATUS_CONTROL_C_EXIT)
	{
	  system_printf ("child %u(%p) died before initialization with status code %p",
			 cygwin_pid (pi.dwProcessId), pi.hProcess, errcode);
	  system_printf ("*** child state %s", s);
#ifdef DEBUGGING
	  try_to_debug ();
#endif
	}
      set_errno (EAGAIN);
      syscall_printf ("Child died before subproc_ready signalled");
      return 0;
    }

  debug_printf ("child signalled me");
  return 1;
}

static int
resume_child (PROCESS_INFORMATION &pi, HANDLE forker_finished)
{
  SetEvent (forker_finished);
  debug_printf ("signalled child");
  return 1;
}

/* Notify parent that it is time for the next step.
   Note that this has to be a macro since the parent may be messing with
   our stack. */
static void __stdcall
sync_with_parent (const char *s, bool hang_self)
{
  debug_printf ("signalling parent: %s", s);
  /* Tell our parent we're waiting. */
  if (!SetEvent (fork_info->subproc_ready))
    api_fatal ("fork child - SetEvent for %s failed, %E", s);
  if (hang_self)
    {
      HANDLE h = fork_info->forker_finished;
      /* Wait for the parent to fill in our stack and heap.
	 Don't wait forever here.  If our parent dies we don't want to clog
	 the system.  If the wait fails, we really can't continue so exit.  */
      DWORD psync_rc = WaitForSingleObject (h, FORK_WAIT_TIMEOUT);
      debug_printf ("awake");
      switch (psync_rc)
	{
	case WAIT_TIMEOUT:
	  api_fatal ("WFSO timed out %s", s);
	  break;
	case WAIT_FAILED:
	  if (GetLastError () == ERROR_INVALID_HANDLE &&
	      WaitForSingleObject (fork_info->forker_finished, 1) != WAIT_FAILED)
	    break;
	  api_fatal ("WFSO failed %s, fork_finished %p, %E", s,
		     fork_info->forker_finished);
	  break;
	default:
	  debug_printf ("no problems");
	  break;
	}
    }
}

static int __stdcall
fork_child (HANDLE& hParent, dll *&first_dll, bool& load_dlls)
{
  extern void fixup_timers_after_fork ();
  debug_printf ("child is running.  pid %d, ppid %d, stack here %p",
		myself->pid, myself->ppid, __builtin_frame_address (0));

  /* Restore the inheritance state as in parent
     Don't call setuid here! The flags are already set. */
  cygheap->user.reimpersonate ();

  sync_with_parent ("after longjmp", true);
  sigproc_printf ("hParent %p, child 1 first_dll %p, load_dlls %d", hParent,
		  first_dll, load_dlls);

  /* If we've played with the stack, stacksize != 0.  That means that
     fork() was invoked from other than the main thread.  Make sure that
     the threadinfo information is properly set up.  */
  if (!fork_info->stacksize)
    {
      _main_tls = &_my_tls;
      _main_tls->init_thread (NULL, NULL);
      _main_tls->local_clib = *_impure_ptr;
      _impure_ptr = &_main_tls->local_clib;
    }

#ifdef DEBUGGING
  char c;
  if (GetEnvironmentVariable ("FORKDEBUG", &c, 1))
    try_to_debug ();
  char buf[80];
  /* This is useful for debugging fork problems.  Use gdb to attach to
     the pid reported here. */
  if (GetEnvironmentVariable ("CYGWIN_FORK_SLEEP", buf, sizeof (buf)))
    {
      small_printf ("Sleeping %d after fork, pid %u\n", atoi (buf), GetCurrentProcessId ());
      Sleep (atoi (buf));
    }
#endif

  set_file_api_mode (current_codepage);

  MALLOC_CHECK;

  if (fixup_mmaps_after_fork (hParent))
    api_fatal ("recreate_mmaps_after_fork_failed");


  MALLOC_CHECK;

  /* If we haven't dynamically loaded any dlls, just signal
     the parent.  Otherwise, load all the dlls, tell the parent
      that we're done, and wait for the parent to fill in the.
      loaded dlls' data/bss. */
  if (!load_dlls)
    {
      cygheap->fdtab.fixup_after_fork (hParent);
      ProtectHandleINH (hParent);
      sync_with_parent ("performed fork fixup", false);
    }
  else
    {
      dlls.load_after_fork (hParent, first_dll);
      cygheap->fdtab.fixup_after_fork (hParent);
      ProtectHandleINH (hParent);
      sync_with_parent ("loaded dlls", true);
    }

  ForceCloseHandle (hParent);
  (void) ForceCloseHandle1 (fork_info->subproc_ready, subproc_ready);
  (void) ForceCloseHandle1 (fork_info->forker_finished, forker_finished);

#ifdef USE_SERVER
  if (fixup_shms_after_fork ())
    api_fatal ("recreate_shm areas after fork failed");
#endif

  pinfo_fixup_after_fork ();
  _my_tls.fixup_after_fork ();
  sigproc_init ();

  /* Set thread local stuff to zero.  Under Windows 95/98 this is sometimes
     non-zero, for some reason.
     FIXME:  There is a memory leak here after a fork. */
  for (per_thread **t = threadstuff; *t; t++)
    if ((*t)->clear_on_fork ())
      (*t)->set ();

  pthread::atforkchild ();
  fixup_timers_after_fork ();
  wait_for_sigthread ();
  cygbench ("fork-child");
  cygwin_finished_initializing = true;
  return 0;
}

#ifndef NO_SLOW_PID_REUSE
static void
slow_pid_reuse (HANDLE h)
{
  static NO_COPY HANDLE last_fork_procs[4] = {0};
  static NO_COPY unsigned nfork_procs = 0;

  if (nfork_procs >= (sizeof (last_fork_procs) / sizeof (last_fork_procs [0])))
    nfork_procs = 0;
  /* Keep a list of handles to forked processes sitting around to prevent
     Windows from reusing the same pid n times in a row.  Having the same pids
     close in succesion confuses bash.  Keeping a handle open will stop
     windows from reusing the same pid.  */
  if (last_fork_procs[nfork_procs])
    ForceCloseHandle1 (last_fork_procs[nfork_procs], fork_stupidity);
  if (DuplicateHandle (hMainProc, h, hMainProc, &last_fork_procs[nfork_procs],
			0, FALSE, DUPLICATE_SAME_ACCESS))
    ProtectHandle1 (last_fork_procs[nfork_procs], fork_stupidity);
  else
    {
      last_fork_procs[nfork_procs] = NULL;
      system_printf ("couldn't create last_fork_proc, %E");
    }
  nfork_procs++;
}
#endif

static int __stdcall
fork_parent (HANDLE& hParent, dll *&first_dll,
	     bool& load_dlls, void *stack_here, child_info_fork &ch)
{
  HANDLE subproc_ready, forker_finished;
  DWORD rc;
  PROCESS_INFORMATION pi = {0, NULL, 0, 0};

  pthread::atforkprepare ();

  subproc_init ();

  int c_flags = GetPriorityClass (hMainProc) /*|
		CREATE_NEW_PROCESS_GROUP*/;
  STARTUPINFO si = {0, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL};

  /* If we don't have a console, then don't create a console for the
     child either.  */
  HANDLE console_handle = CreateFile ("CONOUT$", GENERIC_WRITE,
				      FILE_SHARE_WRITE, &sec_none_nih,
				      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
				      NULL);

  if (console_handle != INVALID_HANDLE_VALUE)
    CloseHandle (console_handle);
  else
    c_flags |= DETACHED_PROCESS;

  /* Some file types (currently only sockets) need extra effort in the
     parent after CreateProcess and before copying the datastructures
     to the child. So we have to start the child in suspend state,
     unfortunately, to avoid a race condition. */
  if (cygheap->fdtab.need_fixup_before ())
    c_flags |= CREATE_SUSPENDED;

  /* Create an inheritable handle to pass to the child process.  This will
     allow the child to duplicate handles from the parent to itself. */
  hParent = NULL;
  if (!DuplicateHandle (hMainProc, hMainProc, hMainProc, &hParent, 0, 1,
			DUPLICATE_SAME_ACCESS))
    {
      system_printf ("couldn't create handle to myself for child, %E");
      return -1;
    }

  /* Remember the address of the first loaded dll and decide
     if we need to load dlls.  We do this here so that this
     information will be available in the parent and, when
     the stack is copied, in the child. */
  first_dll = dlls.start.next;
  load_dlls = dlls.reload_on_fork && dlls.loaded_dlls;

  /* This will help some of the confusion.  */
  fflush (stdout);

  subproc_ready = CreateEvent (&sec_all, FALSE, FALSE, NULL);
  if (subproc_ready == NULL)
    {
      CloseHandle (hParent);
      system_printf ("unable to allocate subproc_ready event, %E");
      return -1;
    }
  forker_finished = CreateEvent (&sec_all, FALSE, FALSE, NULL);
  if (forker_finished == NULL)
    {
      CloseHandle (hParent);
      CloseHandle (subproc_ready);
      system_printf ("unable to allocate forker_finished event, %E");
      return -1;
    }

  ProtectHandleINH (subproc_ready);
  ProtectHandleINH (forker_finished);

  init_child_info (PROC_FORK, &ch, 1, subproc_ready);

  ch.forker_finished = forker_finished;

  stack_base (ch);

  si.cb = sizeof (STARTUPINFO);
  si.lpReserved2 = (LPBYTE)&ch;
  si.cbReserved2 = sizeof (ch);

  /* Remove impersonation */
  cygheap->user.deimpersonate ();

  ch.parent = hParent;
#ifdef DEBUGGING
  if (npid_max)
    {
      for (int pass = 0; pass < 2; pass++)
	{
	  pid_t pid;
	  while ((pid = fork_pids[npid++]))
	    if (!pinfo (pid))
	      {
		ch.cygpid = pid;
		goto out;
	      }
	  npid = 0;
	}
    }
 out:
#endif

  syscall_printf ("CreateProcess (%s, %s, 0, 0, 1, %x, 0, 0, %p, %p)",
		  myself->progname, myself->progname, c_flags, &si, &pi);
  bool locked = __malloc_lock ();
  void *newheap;
  newheap = cygheap_setup_for_child (&ch, cygheap->fdtab.need_fixup_before ());
  rc = CreateProcess (myself->progname, /* image to run */
		      myself->progname, /* what we send in arg0 */
		      &sec_none_nih,
		      &sec_none_nih,
		      TRUE,	  /* inherit handles from parent */
		      c_flags,
		      NULL,	  /* environment filled in later */
		      0,	  /* use current drive/directory */
		      &si,
		      &pi);

  CloseHandle (hParent);

  if (!rc)
    {
      __seterrno ();
      syscall_printf ("CreateProcessA failed, %E");
      ForceCloseHandle (subproc_ready);
      ForceCloseHandle (forker_finished);
      /* Restore impersonation */
      cygheap->user.reimpersonate ();
      cygheap_setup_for_child_cleanup (newheap, &ch, 0);
      __malloc_unlock ();
      return -1;
    }

  /* Fixup the parent datastructure if needed and resume the child's
     main thread. */
  if (!cygheap->fdtab.need_fixup_before ())
    cygheap_setup_for_child_cleanup (newheap, &ch, 0);
  else
    {
      cygheap->fdtab.fixup_before_fork (pi.dwProcessId);
      cygheap_setup_for_child_cleanup (newheap, &ch, 1);
      ResumeThread (pi.hThread);
    }

#ifdef DEBUGGING
  pinfo forked ((ch.cygpid != 1 ? ch.cygpid : cygwin_pid (pi.dwProcessId)), 1);
#else
  pinfo forked (cygwin_pid (pi.dwProcessId), 1);
#endif
  if (!forked)
    {
      syscall_printf ("pinfo failed");
      if (get_errno () != ENOMEM)
	set_errno (EAGAIN);
      goto cleanup;
    }

  /* Initialize things that are done later in dll_crt0_1 that aren't done
     for the forkee.  */
  strcpy (forked->progname, myself->progname);

  /* Restore impersonation */
  cygheap->user.reimpersonate ();

  ProtectHandle (pi.hThread);
  /* Protect the handle but name it similarly to the way it will
     be called in subproc handling. */
  ProtectHandle1 (pi.hProcess, childhProc);

  /* Fill in fields in the child's process table entry.  */
  forked->hProcess = pi.hProcess;
  forked->dwProcessId = pi.dwProcessId;

  /* Hopefully, this will succeed.  The alternative to doing things this
     way is to reserve space prior to calling CreateProcess and then fill
     it in afterwards.  This requires more bookkeeping than I like, though,
     so we'll just do it the easy way.  So, terminate any child process if
     we can't actually record the pid in the internal table. */
  if (!forked.remember ())
    {
      TerminateProcess (pi.hProcess, 1);
      set_errno (EAGAIN);
      goto cleanup;
    }

#ifndef NO_SLOW_PID_REUSE
  slow_pid_reuse (pi.hProcess);
#endif

  /* Wait for subproc to initialize itself. */
  if (!sync_with_child (pi, subproc_ready, true, "waiting for longjmp"))
    goto cleanup;

  /* CHILD IS STOPPED */
  debug_printf ("child is alive (but stopped)");

  /* Initialize, in order: data, bss, heap, stack, dll data, dll bss
     Note: variables marked as NO_COPY will not be copied
     since they are placed in a protected segment. */


  MALLOC_CHECK;
  void *impure_beg;
  void *impure_end;
  if (&_my_tls == _main_tls)
    impure_beg = impure_end = NULL;
  else
    {
      impure_beg = _impure_ptr;
      impure_end = _impure_ptr + 1;
    }
  rc = fork_copy (pi, "user/cygwin data",
		  user_data->data_start, user_data->data_end,
		  user_data->bss_start, user_data->bss_end,
		  cygheap->user_heap.base, cygheap->user_heap.ptr,
		  stack_here, ch.stackbottom,
		  dll_data_start, dll_data_end,
		  dll_bss_start, dll_bss_end, impure_beg, impure_end, NULL);

  __malloc_unlock ();
  locked = false;
  MALLOC_CHECK;
  if (!rc)
    goto cleanup;

  /* Now fill data/bss of any DLLs that were linked into the program. */
  for (dll *d = dlls.istart (DLL_LINK); d; d = dlls.inext ())
    {
      debug_printf ("copying data/bss of a linked dll");
      if (!fork_copy (pi, "linked dll data/bss", d->p.data_start, d->p.data_end,
						 d->p.bss_start, d->p.bss_end,
						 NULL))
	goto cleanup;
    }

  /* Start thread, and wait for it to reload dlls.  */
  if (!resume_child (pi, forker_finished) ||
      !sync_with_child (pi, subproc_ready, load_dlls, "child loading dlls"))
    goto cleanup;

  /* If DLLs were loaded in the parent, then the child has reloaded all
     of them and is now waiting to have all of the individual data and
     bss sections filled in. */
  if (load_dlls)
    {
      /* CHILD IS STOPPED */
      /* write memory of reloaded dlls */
      for (dll *d = dlls.istart (DLL_LOAD); d; d = dlls.inext ())
	{
	  debug_printf ("copying data/bss for a loaded dll");
	  if (!fork_copy (pi, "loaded dll data/bss", d->p.data_start, d->p.data_end,
						     d->p.bss_start, d->p.bss_end,
						     NULL))
	    goto cleanup;
	}
      /* Start the child up again. */
      (void) resume_child (pi, forker_finished);
    }

  ForceCloseHandle (subproc_ready);
  ForceCloseHandle (pi.hThread);
  ForceCloseHandle (forker_finished);
  forker_finished = NULL;
  pi.hThread = NULL;
  pthread::atforkparent ();

  return forked->pid;

/* Common cleanup code for failure cases */
 cleanup:
  if (locked)
    __malloc_unlock ();

  /* Remember to de-allocate the fd table. */
  if (pi.hProcess)
    ForceCloseHandle1 (pi.hProcess, childhProc);
  if (pi.hThread)
    ForceCloseHandle (pi.hThread);
  if (subproc_ready)
    ForceCloseHandle (subproc_ready);
  if (forker_finished)
    ForceCloseHandle (forker_finished);
  return -1;
}

extern "C" int
fork ()
{
  struct
  {
    HANDLE hParent;
    dll *first_dll;
    bool load_dlls;
  } grouped;

  MALLOC_CHECK;

  debug_printf ("entering");
  grouped.hParent = grouped.first_dll = NULL;
  grouped.load_dlls = 0;

  void *esp;
  __asm__ volatile ("movl %%esp,%0": "=r" (esp));

  myself->set_has_pgid_children ();

  child_info_fork ch;

  int res = setjmp (ch.jmp);
  if (res)
    res = fork_child (grouped.hParent, grouped.first_dll, grouped.load_dlls);
  else
    res = fork_parent (grouped.hParent, grouped.first_dll, grouped.load_dlls, esp, ch);

  MALLOC_CHECK;
  syscall_printf ("%d = fork()", res);
  return res;
}
#ifdef DEBUGGING
void
fork_init ()
{
  char buf[1024];
  if (!GetEnvironmentVariable ("CYGWIN_FORK_PIDS", buf, 1024))
    return;
  pid_t pid;
  char *p, *pe;
  for (p = buf; (pid = strtol (p, &pe, 10)); p = pe)
    fork_pids[npid_max++] = pid;
}
#endif /*DEBUGGING*/

#ifdef NEWVFORK
/* Dummy function to force second assignment below to actually be
   carried out */
static vfork_save *
get_vfork_val ()
{
  return vfork_storage.val ();
}
#endif

extern "C" int
vfork ()
{
#ifndef NEWVFORK
  debug_printf ("stub called");
  return fork ();
#else
  vfork_save *vf = get_vfork_val ();
  char **esp, **pp;

  if (vf == NULL)
    vf = vfork_storage.create ();
  else if (vf->pid)
    return fork ();

  // FIXME the tls stuff could introduce a signal race if a child process
  // exits quickly.
  if (!setjmp (vf->j))
    {
      vf->pid = -1;
      __asm__ volatile ("movl %%esp,%0": "=r" (vf->vfork_esp):);
      __asm__ volatile ("movl %%ebp,%0": "=r" (vf->vfork_ebp):);
      for (pp = (char **) vf->frame, esp = vf->vfork_esp;
	   esp <= vf->vfork_ebp + 2; pp++, esp++)
	*pp = *esp;
      vf->ctty = myself->ctty;
      vf->sid = myself->sid;
      vf->pgid = myself->pgid;
      cygheap->ctty_on_hold = cygheap->ctty;
      vf->open_fhs = cygheap->open_fhs;
      debug_printf ("cygheap->ctty_on_hold %p, cygheap->open_fhs %d", cygheap->ctty_on_hold, cygheap->open_fhs);
      int res = cygheap->fdtab.vfork_child_dup () ? 0 : -1;
      debug_printf ("%d = vfork()", res);
      _my_tls.call_signal_handler ();	// FIXME: racy
      vf->tls = _my_tls;
      return res;
    }

  vf = get_vfork_val ();

  for (pp = (char **) vf->frame, esp = vf->vfork_esp;
       esp <= vf->vfork_ebp + 2; pp++, esp++)
    *esp = *pp;

  cygheap->fdtab.vfork_parent_restore ();

  myself->ctty = vf->ctty;
  myself->sid = vf->sid;
  myself->pgid = vf->pgid;
  termios_printf ("cygheap->ctty %p, cygheap->ctty_on_hold %p", cygheap->ctty, cygheap->ctty_on_hold);
  cygheap->open_fhs = vf->open_fhs;

  if (vf->pid < 0)
    {
      int exitval = vf->exitval;
      vf->pid = 0;
      if ((vf->pid = fork ()) == 0)
	exit (exitval);
    }

  int pid = vf->pid;
  vf->pid = 0;
  debug_printf ("exiting vfork, pid %d", pid);
  sig_dispatch_pending ();

  _my_tls.call_signal_handler ();	// FIXME: racy
  _my_tls = vf->tls;
  return pid;
#endif
}
