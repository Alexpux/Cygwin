/* exceptions.cc

   Copyright 1996, 1997, 1998, 1999, 2000, 2001 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <imagehlp.h>
#include <errno.h>

#include "exceptions.h"
#include "sync.h"
#include "sigproc.h"
#include "pinfo.h"
#include "cygerrno.h"
#include "perthread.h"
#include "shared_info.h"
#include "perprocess.h"
#include "security.h"

#define CALL_HANDLER_RETRY 20

char debugger_command[2 * MAX_PATH + 20];

extern "C" {
static int handle_exceptions (EXCEPTION_RECORD *, void *, CONTEXT *, void *);
extern void sigreturn ();
extern void sigdelayed ();
extern void sigdelayed0 ();
extern void siglast ();
extern DWORD __no_sig_start, __no_sig_end;
};

extern DWORD sigtid;

static BOOL WINAPI ctrl_c_handler (DWORD);
static void signal_exit (int) __attribute__ ((noreturn));
static char windows_system_directory[1024];
static size_t windows_system_directory_length;

/* This is set to indicate that we have already exited.  */

static NO_COPY int exit_already = 0;
static NO_COPY muto *mask_sync = NULL;

HMODULE NO_COPY cygwin_hmodule;

static const struct
{
  unsigned int code;
  const char *name;
} status_info[] NO_COPY =
{
#define X(s) s, #s
  { X (STATUS_ABANDONED_WAIT_0) },
  { X (STATUS_ACCESS_VIOLATION) },
  { X (STATUS_ARRAY_BOUNDS_EXCEEDED) },
  { X (STATUS_BREAKPOINT) },
  { X (STATUS_CONTROL_C_EXIT) },
  { X (STATUS_DATATYPE_MISALIGNMENT) },
  { X (STATUS_FLOAT_DENORMAL_OPERAND) },
  { X (STATUS_FLOAT_DIVIDE_BY_ZERO) },
  { X (STATUS_FLOAT_INEXACT_RESULT) },
  { X (STATUS_FLOAT_INVALID_OPERATION) },
  { X (STATUS_FLOAT_OVERFLOW) },
  { X (STATUS_FLOAT_STACK_CHECK) },
  { X (STATUS_FLOAT_UNDERFLOW) },
  { X (STATUS_GUARD_PAGE_VIOLATION) },
  { X (STATUS_ILLEGAL_INSTRUCTION) },
  { X (STATUS_INTEGER_DIVIDE_BY_ZERO) },
  { X (STATUS_INTEGER_OVERFLOW) },
  { X (STATUS_INVALID_DISPOSITION) },
  { X (STATUS_IN_PAGE_ERROR) },
  { X (STATUS_NONCONTINUABLE_EXCEPTION) },
  { X (STATUS_NO_MEMORY) },
  { X (STATUS_PENDING) },
  { X (STATUS_PRIVILEGED_INSTRUCTION) },
  { X (STATUS_SINGLE_STEP) },
  { X (STATUS_STACK_OVERFLOW) },
  { X (STATUS_TIMEOUT) },
  { X (STATUS_USER_APC) },
  { X (STATUS_WAIT_0) },
  { 0, 0 }
#undef X
};

/* Initialization code.  */

#ifdef __i386__

// Set up the exception handler for the current thread.  The PowerPC & Mips
// use compiler generated tables to set up the exception handlers for each
// region of code, and the kernel walks the call list until it finds a region
// of code that handles exceptions.  The x86 on the other hand uses segment
// register fs, offset 0 to point to the current exception handler.

asm (".equ __except_list,0");

extern exception_list *_except_list asm ("%fs:__except_list");

static void
init_exception_handler (exception_list *el)
{
  el->handler = handle_exceptions;
  el->prev = _except_list;
  _except_list = el;
}
#endif

void
set_console_handler ()
{
  /* Initialize global security attribute stuff */

  sec_none.nLength = sec_none_nih.nLength =
  sec_all.nLength = sec_all_nih.nLength = sizeof (SECURITY_ATTRIBUTES);
  sec_none.bInheritHandle = sec_all.bInheritHandle = TRUE;
  sec_none_nih.bInheritHandle = sec_all_nih.bInheritHandle = FALSE;
  sec_none.lpSecurityDescriptor = sec_none_nih.lpSecurityDescriptor = NULL;
  sec_all.lpSecurityDescriptor = sec_all_nih.lpSecurityDescriptor =
    get_null_sd ();

  (void) SetConsoleCtrlHandler (ctrl_c_handler, FALSE);
  if (!SetConsoleCtrlHandler (ctrl_c_handler, TRUE))
    system_printf ("SetConsoleCtrlHandler failed, %E");
}

extern "C" void
init_exceptions (exception_list *el)
{
  init_exception_handler (el);
}

extern "C" void
error_start_init (const char *buf)
{
  if (!buf || !*buf)
    {
      debugger_command[0] = '\0';
      return;
    }

  char myself_posix_name[MAX_PATH];

  /* FIXME: gdb cannot use win32 paths, but what if debugger isn't gdb? */
  cygwin_conv_to_posix_path (myself->progname, myself_posix_name);
  __small_sprintf (debugger_command, "%s %s", buf, myself_posix_name);
}

static void
open_stackdumpfile ()
{
  if (myself->progname[0])
    {
      const char *p;
      /* write to progname.stackdump if possible */
      if (!myself->progname[0])
	p = "unknown";
      else if ((p = strrchr (myself->progname, '\\')))
	p++;
      else
	p = myself->progname;
      char corefile[strlen (p) + sizeof (".stackdump")];
      __small_sprintf (corefile, "%s.stackdump", p);
      HANDLE h = CreateFile (corefile, GENERIC_WRITE, 0, &sec_none_nih,
			     CREATE_ALWAYS, 0, 0);
      if (h != INVALID_HANDLE_VALUE)
	{
	  system_printf ("Dumping stack trace to %s", corefile);
	  SetStdHandle (STD_ERROR_HANDLE, h);
	}
    }
}

/* Utilities for dumping the stack, etc.  */

static void
exception (EXCEPTION_RECORD *e,  CONTEXT *in)
{
  const char *exception_name = NULL;

  if (e)
    {
      for (int i = 0; status_info[i].name; i++)
	{
	  if (status_info[i].code == e->ExceptionCode)
	    {
	      exception_name = status_info[i].name;
	      break;
	    }
	}
    }

#ifdef __i386__
#define HAVE_STATUS
  if (exception_name)
    small_printf ("Exception: %s at eip=%08x\r\n", exception_name, in->Eip);
  else
    small_printf ("Exception %d at eip=%08x\r\n", e->ExceptionCode, in->Eip);
  small_printf ("eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\r\n",
	      in->Eax, in->Ebx, in->Ecx, in->Edx, in->Esi, in->Edi);
  small_printf ("ebp=%08x esp=%08x program=%s\r\n",
	      in->Ebp, in->Esp, myself->progname);
  small_printf ("cs=%04x ds=%04x es=%04x fs=%04x gs=%04x ss=%04x\r\n",
	      in->SegCs, in->SegDs, in->SegEs, in->SegFs, in->SegGs, in->SegSs);
#endif

#ifndef HAVE_STATUS
  system_printf ("Had an exception");
#endif
}

#ifdef __i386__
/* Print a stack backtrace. */

#define HAVE_STACK_TRACE

/* A class for manipulating the stack. */
class stack_info
{
  int walk ();			/* Uses the "old" method */
  char *next_offset () {return *((char **) sf.AddrFrame.Offset);}
  bool needargs;
  DWORD dummy_frame;
public:
  STACKFRAME sf;		 /* For storing the stack information */
  void init (DWORD, bool, bool); /* Called the first time that stack info is needed */

  /* Postfix ++ iterates over the stack, returning zero when nothing is left. */
  int operator ++(int) { return this->walk (); }
};

/* The number of parameters used in STACKFRAME */
#define NPARAMS (sizeof (thestack.sf.Params) / sizeof (thestack.sf.Params[0]))

/* This is the main stack frame info for this process. */
static NO_COPY stack_info thestack;
static signal_dispatch sigsave;

/* Initialize everything needed to start iterating. */
void
stack_info::init (DWORD ebp, bool wantargs, bool goodframe)
{
# define debp ((DWORD *) ebp)
  memset (&sf, 0, sizeof (sf));
  if (!goodframe)
    sf.AddrFrame.Offset = ebp;
  else
    {
      dummy_frame = ebp;
      sf.AddrFrame.Offset = (DWORD) &dummy_frame;
    }
  sf.AddrReturn.Offset = debp[1];
  sf.AddrFrame.Mode = AddrModeFlat;
  needargs = wantargs;
# undef debp
}

/* Walk the stack by looking at successive stored 'bp' frames.
   This is not foolproof. */
int
stack_info::walk ()
{
  char **ebp;
  if ((ebp = (char **) next_offset ()) == NULL)
    return 0;

  sf.AddrFrame.Offset = (DWORD) ebp;
  sf.AddrPC.Offset = sf.AddrReturn.Offset;

  if (!sf.AddrPC.Offset)
    return 0;		/* stack frames are exhausted */

  /* The return address always follows the stack pointer */
  sf.AddrReturn.Offset = (DWORD) *++ebp;

  if (needargs)
    /* The arguments follow the return address */
    for (unsigned i = 0; i < NPARAMS; i++)
      sf.Params[i] = (DWORD) *++ebp;

  return 1;
}

static void
stackdump (DWORD ebp, int open_file, bool isexception)
{
  extern unsigned long rlim_core;

  if (rlim_core == 0UL)
    return;

  if (open_file)
    open_stackdumpfile ();

  int i;

  thestack.init (ebp, 1, !isexception);	/* Initialize from the input CONTEXT */
  small_printf ("Stack trace:\r\nFrame     Function  Args\r\n");
  for (i = 0; i < 16 && thestack++; i++)
    {
      small_printf ("%08x  %08x ", thestack.sf.AddrFrame.Offset,
		    thestack.sf.AddrPC.Offset);
      for (unsigned j = 0; j < NPARAMS; j++)
	small_printf ("%s%08x", j == 0 ? " (" : ", ", thestack.sf.Params[j]);
      small_printf (")\r\n");
    }
  small_printf ("End of stack trace%s",
	      i == 16 ? " (more stack frames may be present)" : "");
}

/* Temporary (?) function for external callers to get a stack dump */
extern "C" void
cygwin_stackdump ()
{
  CONTEXT c;
  c.ContextFlags = CONTEXT_FULL;
  GetThreadContext (GetCurrentThread (), &c);
  stackdump (c.Ebp, 0, 0);
}

#define TIME_TO_WAIT_FOR_DEBUGGER 10000

extern "C" int
try_to_debug (bool waitloop)
{
  debug_printf ("debugger_command '%s'", debugger_command);
  if (*debugger_command == '\0')
    return 0;

  __small_sprintf (strchr (debugger_command, '\0'), " %u", GetCurrentProcessId ());

  BOOL dbg;

  SetThreadPriority (hMainThread, THREAD_PRIORITY_HIGHEST);
  PROCESS_INFORMATION pi = {NULL, 0, 0, 0};

  STARTUPINFO si = {0, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL};
  si.lpReserved = NULL;
  si.lpDesktop = NULL;
  si.dwFlags = 0;
  si.cb = sizeof (si);

  /* FIXME: need to know handles of all running threads to
     suspend_all_threads_except (current_thread_id);
  */

  /* if any of these mutexes is owned, we will fail to start any cygwin app
     until trapped app exits */

  ReleaseMutex (title_mutex);

  /* prevent recursive exception handling */
  char* rawenv = GetEnvironmentStrings () ;
  for (char* p = rawenv; *p != '\0'; p = strchr (p, '\0') + 1)
    {
      if (strncmp (p, "CYGWIN=", sizeof ("CYGWIN=") - 1) == 0)
	{
	  char* q = strstr (p, "error_start") ;
	  /* replace 'error_start=...' with '_rror_start=...' */
	  if (q) *q = '_' ;
	  SetEnvironmentVariable ("CYGWIN", p + sizeof ("CYGWIN=")) ;
	  break ;
	}
    }

  dbg = CreateProcess (NULL,
		       debugger_command,
		       NULL,
		       NULL,
		       FALSE,
		       CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
		       NULL,
		       NULL,
		       &si,
		       &pi);

  static int NO_COPY keep_looping = 0;

  if (dbg)
    {
      if (!waitloop)
	return 1;
      SetThreadPriority (hMainThread, THREAD_PRIORITY_IDLE);
      while (keep_looping)
	/* spin */;
    }


  system_printf ("Failed to start debugger: %E");
  /* FIXME: need to know handles of all running threads to
    resume_all_threads_except (current_thread_id);
  */
  return 0;
}

/* Main exception handler. */

static int
handle_exceptions (EXCEPTION_RECORD *e, void *, CONTEXT *in, void *)
{
  int sig;
  static int NO_COPY debugging = 0;
  static int NO_COPY recursed = 0;

  if (debugging && ++debugging < 500000)
    {
      SetThreadPriority (hMainThread, THREAD_PRIORITY_NORMAL);
      return 0;
    }

  /* If we've already exited, don't do anything here.  Returning 1
     tells Windows to keep looking for an exception handler.  */
  if (exit_already)
    return 1;

  /* Coerce win32 value to posix value.  */
  switch (e->ExceptionCode)
    {
    case STATUS_FLOAT_DENORMAL_OPERAND:
    case STATUS_FLOAT_DIVIDE_BY_ZERO:
    case STATUS_FLOAT_INEXACT_RESULT:
    case STATUS_FLOAT_INVALID_OPERATION:
    case STATUS_FLOAT_OVERFLOW:
    case STATUS_FLOAT_STACK_CHECK:
    case STATUS_FLOAT_UNDERFLOW:
    case STATUS_INTEGER_DIVIDE_BY_ZERO:
    case STATUS_INTEGER_OVERFLOW:
      sig = SIGFPE;
      break;

    case STATUS_ILLEGAL_INSTRUCTION:
    case STATUS_PRIVILEGED_INSTRUCTION:
    case STATUS_NONCONTINUABLE_EXCEPTION:
      sig = SIGILL;
      break;

    case STATUS_TIMEOUT:
      sig = SIGALRM;
      break;

    case STATUS_ACCESS_VIOLATION:
    case STATUS_DATATYPE_MISALIGNMENT:
    case STATUS_ARRAY_BOUNDS_EXCEEDED:
    case STATUS_GUARD_PAGE_VIOLATION:
    case STATUS_IN_PAGE_ERROR:
    case STATUS_NO_MEMORY:
    case STATUS_INVALID_DISPOSITION:
    case STATUS_STACK_OVERFLOW:
      sig = SIGSEGV;
      break;

    case STATUS_CONTROL_C_EXIT:
      sig = SIGINT;
      break;

    case STATUS_INVALID_HANDLE:
      /* CloseHandle will throw this exception if it is given an
	 invalid handle.  We don't care about the exception; we just
	 want CloseHandle to return an error.  This can be revisited
	 if gcc ever supports Windows style structured exception
	 handling.  */
      return 0;

    default:
      /* If we don't recognize the exception, we have to assume that
	 we are doing structured exception handling, and we let
	 something else handle it.  */
      return 1;
    }

  debug_printf ("In cygwin_except_handler exc %p at %p sp %p", e->ExceptionCode, in->Eip, in->Esp);
  debug_printf ("In cygwin_except_handler sig = %d at %p", sig, in->Eip);

  if (myself->getsig (sig).sa_mask & SIGTOMASK (sig))
    syscall_printf ("signal %d, masked %p", sig, myself->getsig (sig).sa_mask);

  debug_printf ("In cygwin_except_handler calling %p",
		 myself->getsig (sig).sa_handler);

  DWORD *ebp = (DWORD *)in->Esp;
  for (DWORD *bpend = (DWORD *) __builtin_frame_address (0); ebp > bpend; ebp--)
    if (*ebp == in->SegCs && ebp[-1] == in->Eip)
      {
	ebp -= 2;
	break;
      }

  if (!myself->progname[0]
      || GetCurrentThreadId () == sigtid
      || (void *) myself->getsig (sig).sa_handler == (void *) SIG_DFL
      || (void *) myself->getsig (sig).sa_handler == (void *) SIG_IGN
      || (void *) myself->getsig (sig).sa_handler == (void *) SIG_ERR)
    {
      /* Print the exception to the console */
      if (e)
	{
	  for (int i = 0; status_info[i].name; i++)
	    {
	      if (status_info[i].code == e->ExceptionCode)
		{
		  if (!myself->ppid_handle)
		    system_printf ("Exception: %s", status_info[i].name);
		  break;
		}
	    }
	}

      /* Another exception could happen while tracing or while exiting.
	 Only do this once.  */
      if (recursed++)
	system_printf ("Error while dumping state (probably corrupted stack)");
      else
	{
	  if (try_to_debug (0))
	    {
	      debugging = 1;
	      return 0;
	    }

	  open_stackdumpfile ();
	  exception (e, in);
	  stackdump ((DWORD) ebp, 0, 1);
	}

      signal_exit (0x80 | sig);	// Flag signal + core dump
    }

  sig_send (NULL, sig, (DWORD) ebp, 1);		// Signal myself
  return 0;
}
#endif /* __i386__ */

#ifndef HAVE_STACK_TRACE
void
stack (void)
{
  system_printf ("Stack trace not yet supported on this machine.");
}
#endif

/* Utilities to call a user supplied exception handler.  */

#define SIG_NONMASKABLE	(SIGTOMASK (SIGKILL) | SIGTOMASK (SIGSTOP))

#ifdef __i386__
#define HAVE_CALL_HANDLER

/* Non-raceable sigsuspend
 * Note: This implementation is based on the Single UNIX Specification
 * man page.  This indicates that sigsuspend always returns -1 and that
 * attempts to block unblockable signals will be silently ignored.
 * This is counter to what appears to be documented in some UNIX
 * man pages, e.g. Linux.
 */
int __stdcall
handle_sigsuspend (sigset_t tempmask)
{
  sigframe thisframe (mainthread);
  sigset_t oldmask = myself->getsigmask ();	// Remember for restoration

  set_process_mask (tempmask & ~SIG_NONMASKABLE);// Let signals we're
				//  interested in through.
  sigproc_printf ("old mask %x, new mask %x", oldmask, tempmask);

  WaitForSingleObject (signal_arrived, INFINITE);

  set_sig_errno (EINTR);	// Per POSIX

  /* A signal dispatch function will have been added to our stack and will
     be hit eventually.  Set the old mask to be restored when the signal
     handler returns. */

  sigsave.oldmask = oldmask;	// Will be restored by signal handler
  return -1;
}

extern DWORD exec_exit;		// Possible exit value for exec
extern int pending_signals;

extern "C" {
static void
sig_handle_tty_stop (int sig)
{
  /* Silently ignore attempts to suspend if there is no accomodating
     cygwin parent to deal with this behavior. */
  if (!myself->ppid_handle)
    {
      myself->process_state &= ~PID_STOPPED;
      return;
    }
  myself->stopsig = sig;
  /* See if we have a living parent.  If so, send it a special signal.
   * It will figure out exactly which pid has stopped by scanning
   * its list of subprocesses.
   */
  if (my_parent_is_alive ())
    {
      pinfo parent (myself->ppid);
      sig_send (parent, SIGCHLD);
    }
  sigproc_printf ("process %d stopped by signal %d, myself->ppid_handle %p",
		  myself->pid, sig, myself->ppid_handle);
  SuspendThread (hMainThread);
  return;
}
}

int
interruptible (DWORD pc, int testvalid = 0)
{
  int res;
  MEMORY_BASIC_INFORMATION m;

  memset (&m, 0, sizeof m);
  if (!VirtualQuery ((LPCVOID) pc, &m, sizeof m))
    sigproc_printf ("couldn't get memory info, pc %p, %E", pc);

  char *checkdir = (char *) alloca (windows_system_directory_length + 4);
  memset (checkdir, 0, sizeof (checkdir));

# define h ((HMODULE) m.AllocationBase)
  /* Apparently Windows 95 can sometimes return bogus addresses from
     GetThreadContext.  These resolve to an allocation base == 0.
     These should *never* be treated as interruptible. */
  if (!h || m.State != MEM_COMMIT)
    res = 0;
  else if (testvalid)
    res = 1;	/* All we wanted to know was if this was a valid module. */
  else if (h == user_data->hmodule)
    res = 1;
  else if (h == cygwin_hmodule)
    res = 0;
  else if (!GetModuleFileName (h, checkdir, windows_system_directory_length + 2))
    res = 0;
  else
    res = !strncasematch (windows_system_directory, checkdir,
			  windows_system_directory_length);
  sigproc_printf ("pc %p, h %p, interruptible %d, testvalid %d", pc, h, res, testvalid);
# undef h
  return res;
}

bool
sigthread::get_winapi_lock (int test)
{
  if (test)
    return !InterlockedExchange (&winapi_lock, 1);

  /* Need to do a busy loop because we can't block or a potential SuspendThread
     will hang. */
  while (InterlockedExchange (&winapi_lock, 1))
    Sleep (1);
  return 1;
}

void
sigthread::release_winapi_lock ()
{
  /* Assumes that we have the lock. */
  InterlockedExchange (&winapi_lock, 0);
}

static void __stdcall interrupt_setup (int sig, void *handler, DWORD retaddr,
				       DWORD *retaddr_on_stack,
				       struct sigaction& siga)
		      __attribute__((regparm(3)));
static void __stdcall
interrupt_setup (int sig, void *handler, DWORD retaddr, DWORD *retaddr_on_stack,
		 struct sigaction& siga)
{
  sigsave.retaddr = retaddr;
  sigsave.retaddr_on_stack = retaddr_on_stack;
  /* FIXME: Not multi-thread aware */
  sigsave.newmask = myself->getsigmask () | siga.sa_mask | SIGTOMASK (sig);
  sigsave.sa_flags = siga.sa_flags;
  sigsave.func = (void (*)(int)) handler;
  sigsave.sig = sig;
  sigsave.saved_errno = -1;		// Flag: no errno to save
  if (handler == sig_handle_tty_stop)
    {
      myself->stopsig = 0;
      myself->process_state |= PID_STOPPED;
    }
  /* Clear any waiting threads prior to dispatching to handler function */
  proc_subproc (PROC_CLEARWAIT, 1);
  int res = SetEvent (signal_arrived);	// For an EINTR case
  sigproc_printf ("armed signal_arrived %p, res %d", signal_arrived, res);
}

static bool interrupt_now (CONTEXT *, int, void *, struct sigaction&) __attribute__((regparm(3)));
static bool
interrupt_now (CONTEXT *ctx, int sig, void *handler, struct sigaction& siga)
{
  interrupt_setup (sig, handler, ctx->Eip, 0, siga);
  ctx->Eip = (DWORD) sigdelayed;
  SetThreadContext (myself->getthread2signal (), ctx); /* Restart the thread in a new location */
  return 1;
}

void __stdcall
signal_fixup_after_fork ()
{
  if (!sigsave.sig)
    return;

  sigsave.sig = 0;
  if (sigsave.retaddr_on_stack)
    {
      *sigsave.retaddr_on_stack = sigsave.retaddr;
      set_process_mask (sigsave.oldmask);
    }
}

void __stdcall
signal_fixup_after_exec (bool isspawn)
{
  /* Set up child's signal handlers */
  for (int i = 0; i < NSIG; i++)
    {
      myself->getsig(i).sa_mask = 0;
      if (myself->getsig(i).sa_handler != SIG_IGN || isspawn)
	myself->getsig(i).sa_handler = SIG_DFL;
    }
}

static int interrupt_on_return (sigthread *, int, void *, struct sigaction&) __attribute__((regparm(3)));
static int
interrupt_on_return (sigthread *th, int sig, void *handler, struct sigaction& siga)
{
  int i;
  DWORD ebp = th->frame;

  if (!ebp)
    return 0;

  thestack.init (ebp, 0, 1);  /* Initialize from the input CONTEXT */
  for (i = 0; i < 32 && thestack++ ; i++)
    if (th->exception || interruptible (thestack.sf.AddrReturn.Offset))
      {
	DWORD *addr_retaddr = ((DWORD *)thestack.sf.AddrFrame.Offset) + 1;
	if (*addr_retaddr  == thestack.sf.AddrReturn.Offset)
	  {
	    interrupt_setup (sig, handler, *addr_retaddr, addr_retaddr, siga);
	    *addr_retaddr = (DWORD) sigdelayed;
	  }
	return 1;
      }

  sigproc_printf ("couldn't find a stack frame, i %d\n", i);
  return 0;
}

extern "C" void __stdcall
set_sig_errno (int e)
{
  set_errno (e);
  sigsave.saved_errno = e;
  // sigproc_printf ("errno %d", e);
}

static int setup_handler (int, void *, struct sigaction&) __attribute__((regparm(3)));
static int
setup_handler (int sig, void *handler, struct sigaction& siga)
{
  CONTEXT cx;
  bool interrupted = 0;
  HANDLE hth = NULL;
  int res;
  sigthread *th = NULL;		// Initialization needed to shut up gcc

  if (sigsave.sig)
    goto set_pending;

  for (int i = 0; !interrupted && i < CALL_HANDLER_RETRY; i++)
    {
      EnterCriticalSection (&mainthread.lock);
      if (mainthread.frame)
	th = &mainthread;
      else
	{
	  LeaveCriticalSection (&mainthread.lock);

	  th = NULL;

	  hth = myself->getthread2signal ();

	  /* Suspend the thread which will receive the signal.  But first ensure that
	     this thread doesn't have any mutos.  (FIXME: Someday we should just grab
	     all of the mutos rather than checking for them)
	     For Windows 95, we also have to ensure that the addresses returned by GetThreadContext
	     are valid.
	     If one of these conditions is not true we loop for a fixed number of times
	     since we don't want to stall the signal handler.  FIXME: Will this result in
	     noticeable delays?
	     If the thread is already suspended (which can occur when a program is stopped) then
	     just queue the signal. */

	  if (!mainthread.get_winapi_lock (1))
	    continue;
	  sigproc_printf ("suspending mainthread");
	  res = SuspendThread (hth);
	  mainthread.release_winapi_lock ();
	  if (mainthread.frame)
	    goto resume_thread;	/* In case the main thread *just* set the frame */

	  /* Just set pending if thread is already suspended */
	  if (res)
	    goto set_pending;

	  muto *m;
	  /* FIXME: Make multi-thread aware */
	  for (m = muto_start.next;  m != NULL; m = m->next)
	    if (m->unstable () || m->owner () == mainthread.id)
	      {
		sigproc_printf ("suspended thread owns a muto (%s)", m->name);
		goto resume_thread;
	      }

	  EnterCriticalSection (&mainthread.lock);
	  if (mainthread.frame)
	    {
	      th = &mainthread;
	      goto try_to_interrupt;
	    }

	  LeaveCriticalSection (&mainthread.lock);

	  cx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	  if (!GetThreadContext (hth, &cx))
	    system_printf ("couldn't get context of main thread, %E");
	  else if (!interruptible (cx.Eip, 1))
	    sigproc_printf ("suspended thread in a strange state pc %p, sp %p",
			    cx.Eip, cx.Esp);
	  else
	    goto try_to_interrupt;

	resume_thread:
	  ResumeThread (hth);
	  Sleep (0);
	  continue;
	}

    try_to_interrupt:
      if (th)
	{
	  interrupted = interrupt_on_return (th, sig, handler, siga);
	  if (!interrupted)
	    LeaveCriticalSection (&th->lock);
	}
      else if (interruptible (cx.Eip))
	interrupted = interrupt_now (&cx, sig, handler, siga);
      else
	break;
    }

 set_pending:
  if (interrupted)
    res = 1;
  else
    {
      pending_signals = 1;	/* FIXME: Probably need to be more tricky here */
      sig_set_pending (sig);
      sig_dispatch_pending (1);
      Sleep (0);		/* Hopefully, other process will be waking up soon. */
      sigproc_printf ("couldn't send signal %d", sig);
    }

  if (th)
    LeaveCriticalSection (&th->lock);

  if (!hth)
    sigproc_printf ("good.  Didn't suspend main thread, th %p", th);
  else
    {
      res = ResumeThread (hth);
      sigproc_printf ("ResumeThread returned %d", res);
    }

  sigproc_printf ("returning %d", interrupted);
  return interrupted;
}
#endif /* i386 */

#ifndef HAVE_CALL_HANDLER
#error "Need to supply machine dependent setup_handler"
#endif

/* CGF Keyboard interrupt handler.  */
static BOOL WINAPI
ctrl_c_handler (DWORD type)
{
  if (type == CTRL_LOGOFF_EVENT)
    return TRUE;

  /* Return FALSE to prevent an "End task" dialog box from appearing
     for each Cygwin process window that's open when the computer
     is shut down or console window is closed. */
  if (type == CTRL_SHUTDOWN_EVENT)
    {
      sig_send (NULL, SIGTERM);
      return FALSE;
    }
  if (type == CTRL_CLOSE_EVENT)
    {
      sig_send (NULL, SIGHUP);
      return FALSE;
    }

  tty_min *t = cygwin_shared->tty.get_tty (myself->ctty);
  /* Ignore this if we're not the process group lead since it should be handled
     *by* the process group leader. */
  if (myself->ctty != -1 && t->getpgid () == myself->pid &&
       (GetTickCount () - t->last_ctrl_c) >= MIN_CTRL_C_SLOP)
    /* Otherwise we just send a SIGINT to the process group and return TRUE (to indicate
       that we have handled the signal).  At this point, type should be
       a CTRL_C_EVENT or CTRL_BREAK_EVENT. */
    {
      t->last_ctrl_c = GetTickCount ();
      kill (-myself->pid, SIGINT);
      t->last_ctrl_c = GetTickCount ();
      return TRUE;
    }
  return TRUE;
}

/* Set the signal mask for this process.
   Note that some signals are unmaskable, as in UNIX.  */
extern "C" void __stdcall
set_process_mask (sigset_t newmask)
{
  sigframe thisframe (mainthread);
  mask_sync->acquire (INFINITE);
  sigset_t oldmask = myself->getsigmask ();
  newmask &= ~SIG_NONMASKABLE;
  sigproc_printf ("old mask = %x, new mask = %x", myself->getsigmask (), newmask);
  myself->setsigmask (newmask);	// Set a new mask
  mask_sync->release ();
  if (oldmask != newmask && GetCurrentThreadId () != sigtid)
    sig_dispatch_pending ();
  else
    sigproc_printf ("not calling sig_dispatch_pending.  sigtid %p current %p",
		    sigtid, GetCurrentThreadId ());
  return;
}

int __stdcall
sig_handle (int sig)
{
  int rc = 0;

  sigproc_printf ("signal %d", sig);

  struct sigaction thissig = myself->getsig (sig);
  void *handler = (void *) thissig.sa_handler;

  myself->rusage_self.ru_nsignals++;

  /* Clear pending SIGCONT on stop signals */
  if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU)
    sig_clear (SIGCONT);

  if (sig == SIGKILL)
    goto exit_sig;

  if (sig == SIGSTOP)
    goto stop;

  /* FIXME: Should we still do this if SIGCONT has a handler? */
  if (sig == SIGCONT)
    {
      myself->stopsig = 0;
      myself->process_state &= ~PID_STOPPED;
      /* Clear pending stop signals */
      sig_clear (SIGSTOP);
      sig_clear (SIGTSTP);
      sig_clear (SIGTTIN);
      sig_clear (SIGTTOU);
      /* Windows 95 hangs on resuming non-suspended thread */
      SuspendThread (hMainThread);
      while (ResumeThread (hMainThread) > 1)
	;
      /* process pending signals */
      sig_dispatch_pending (1);
    }

#if 0
  char sigmsg[24];
  __small_sprintf (sigmsg, "cygwin: signal %d\n", sig);
  OutputDebugString (sigmsg);
#endif

  if (handler == (void *) SIG_DFL)
    {
      if (sig == SIGCHLD || sig == SIGIO || sig == SIGCONT || sig == SIGWINCH)
	{
	  sigproc_printf ("default signal %d ignored", sig);
	  goto done;
	}

      if (sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU)
	goto stop;

      goto exit_sig;
    }

  if (handler == (void *) SIG_IGN)
    {
      sigproc_printf ("signal %d ignored", sig);
      goto done;
    }

  if (handler == (void *) SIG_ERR)
    goto exit_sig;

  if ((sig == SIGCHLD) && (thissig.sa_flags & SA_NOCLDSTOP))
    goto done;

  goto dosig;

 stop:
  /* Eat multiple attempts to STOP */
  if (ISSTATE (myself, PID_STOPPED))
    goto done;
  handler = (void *) sig_handle_tty_stop;
  thissig = myself->getsig (SIGSTOP);

 dosig:
  /* Dispatch to the appropriate function. */
  sigproc_printf ("signal %d, about to call %p", sig, handler);
  rc = setup_handler (sig, handler, thissig);

 done:
  sigproc_printf ("returning %d", rc);
  return rc;

 exit_sig:
  if (sig == SIGQUIT || sig == SIGABRT)
    {
      CONTEXT c;
      c.ContextFlags = CONTEXT_FULL;
      GetThreadContext (hMainThread, &c);
      if (!try_to_debug ())
	stackdump (c.Ebp, 1, 1);
      sig |= 0x80;
    }
  sigproc_printf ("signal %d, about to call do_exit", sig);
  signal_exit (sig);
  /* Never returns */
}

/* Cover function to `do_exit' to handle exiting even in presence of more
   exceptions.  We used to call exit, but a SIGSEGV shouldn't cause atexit
   routines to run.  */
static void
signal_exit (int rc)
{
  extern HANDLE hExeced;

  rc = EXIT_SIGNAL | (rc << 8);
  if (exit_already++)
    myself->exit (rc);

  /* We'd like to stop the main thread from executing but when we do that it
     causes random, inexplicable hangs.  So, instead, we set up the priority
     of this thread really high so that it should do its thing and then exit. */
  (void) SetThreadPriority (GetCurrentThread (), THREAD_PRIORITY_TIME_CRITICAL);

  /* Unlock any main thread mutos since we're executing with prejudice. */
  muto *m;
  for (m = muto_start.next;  m != NULL; m = m->next)
    if (m->unstable () || m->owner () == mainthread.id)
      m->reset ();

  user_data->resourcelocks->Delete ();
  user_data->resourcelocks->Init ();

  if (hExeced)
    TerminateProcess (hExeced, rc);

  sigproc_printf ("about to call do_exit (%x)", rc);
  do_exit (rc);
}

HANDLE NO_COPY title_mutex = NULL;

void
events_init (void)
{
  /* title_mutex protects modification of console title. It's neccessary
     while finding console window handle */

  if (!(title_mutex = CreateMutex (&sec_all_nih, FALSE,
				   shared_name ("title_mutex", 0))))
    api_fatal ("can't create title mutex, %E");

  ProtectHandle (title_mutex);
  mask_sync = new_muto (FALSE, "mask_sync");
  windows_system_directory[0] = '\0';
  (void) GetSystemDirectory (windows_system_directory, sizeof (windows_system_directory) - 2);
  char *end = strchr (windows_system_directory, '\0');
  if (end == windows_system_directory)
    api_fatal ("can't find windows system directory");
  if (end[-1] != '\\')
    {
      *end++ = '\\';
      *end = '\0';
    }
  windows_system_directory_length = end - windows_system_directory;
  debug_printf ("windows_system_directory '%s', windows_system_directory_length %d",
		windows_system_directory, windows_system_directory_length);
  debug_printf ("cygwin_hmodule %p", cygwin_hmodule);
}

void
events_terminate (void)
{
  ForceCloseHandle (title_mutex);
  exit_already = 1;
}

extern "C" {
static int __stdcall
call_signal_handler_now ()
{
  if (!sigsave.sig)
    {
      sigproc_printf ("call_signal_handler_now called when no signal active");
      return 0;
    }

  int sa_flags = sigsave.sa_flags;
  sigproc_printf ("sa_flags %p", sa_flags);
  *sigsave.retaddr_on_stack = sigsave.retaddr;
  sigdelayed0 ();
  return sa_flags & SA_RESTART;
}
/* This kludge seems to keep a copy of call_signal_handler_now around
   even when compiling with -finline-functions. */
static int __stdcall call_signal_handler_now_dummy ()
  __attribute__((alias ("call_signal_handler_now")));
};

int
sigframe::call_signal_handler ()
{
  return unregister () ? call_signal_handler_now () : 0;

}

#define pid_offset (unsigned)(((_pinfo *)NULL)->pid)
extern "C" {
void __stdcall
reset_signal_arrived ()
{
  (void) ResetEvent (signal_arrived);
  sigproc_printf ("reset signal_arrived");
}

void unused_sig_wrapper ()
{
/* Signal cleanup stuff.  Cleans up stack (too bad that we didn't
   prototype signal handlers as __stdcall), calls _set_process_mask
   to restore any mask, restores any potentially clobbered registers
   and returns to original caller. */
__asm__ volatile ("\n\
	.text								\n\
_sigreturn:								\n\
	addl	$4,%%esp	# Remove argument			\n\
	movl	%%esp,%%ebp						\n\
	addl	$36,%%ebp						\n\
	call	_set_process_mask@4					\n\
									\n\
	cmpl	$0,%4		# Did a signal come in?			\n\
	jz	1f		# No, if zero				\n\
	call	_call_signal_handler_now@0 # yes handle the signal	\n\
									\n\
1:	popl	%%eax		# saved errno				\n\
	testl	%%eax,%%eax	# Is it < 0				\n\
	jl	2f		# yup.  ignore it			\n\
	movl	%1,%%ebx						\n\
	movl	%%eax,(%%ebx)						\n\
2:	popl	%%eax							\n\
	popl	%%ebx							\n\
	popl	%%ecx							\n\
	popl	%%edx							\n\
	popl	%%edi							\n\
	popl	%%esi							\n\
	popf								\n\
	popl	%%ebp							\n\
	ret								\n\
									\n\
__no_sig_start:								\n\
_sigdelayed:								\n\
	pushl	%2			# original return address	\n\
_sigdelayed0:								\n\
	pushl	%%ebp							\n\
	movl	%%esp,%%ebp						\n\
	pushf								\n\
	pushl	%%esi							\n\
	pushl	%%edi							\n\
	pushl	%%edx							\n\
	pushl	%%ecx							\n\
	pushl	%%ebx							\n\
	pushl	%%eax							\n\
	pushl	%7			# saved errno			\n\
	pushl	%3			# oldmask			\n\
	pushl	%4			# signal argument		\n\
	pushl	$_sigreturn						\n\
									\n\
	call	_reset_signal_arrived@0					\n\
	pushl	%5			# signal number			\n\
	pushl	%8			# newmask			\n\
	movl	$0,%0			# zero the signal number as a	\n\
					# flag to the signal handler thread\n\
					# that it is ok to set up sigsave\n\
									\n\
	call	_set_process_mask@4					\n\
	popl	%%eax							\n\
	jmp	*%%eax							\n\
__no_sig_end:								\n\
" : "=m" (sigsave.sig) : "m" (&_impure_ptr->_errno),
  "g" (sigsave.retaddr), "g" (sigsave.oldmask), "g" (sigsave.sig),
    "g" (sigsave.func), "o" (pid_offset), "g" (sigsave.saved_errno), "g" (sigsave.newmask)
);
}
}
