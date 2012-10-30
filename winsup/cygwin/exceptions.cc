/* exceptions.cc

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004,
   2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#define CYGTLS_HANDLE
#include "winsup.h"
#include "miscfuncs.h"
#include <wingdi.h>
#include <winuser.h>
#include <imagehlp.h>
#include <stdlib.h>
#include <syslog.h>
#include <wchar.h>

#include "cygtls.h"
#include "pinfo.h"
#include "sigproc.h"
#include "shared_info.h"
#include "perprocess.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "child_info.h"
#include "ntdll.h"
#include "exception.h"

/* Definitions for code simplification */
#ifdef __x86_64__
# define _GR(reg)	R ## reg
# define _AFMT		"%016X"
# define _ADDR		DWORD64
#else
# define _GR(reg)	E ## reg
# define _AFMT		"%08x"
# define _ADDR		DWORD
#endif

#define CALL_HANDLER_RETRY_OUTER 10
#define CALL_HANDLER_RETRY_INNER 10

char debugger_command[2 * NT_MAX_PATH + 20];

static BOOL WINAPI ctrl_c_handler (DWORD);

/* This is set to indicate that we have already exited.  */

static NO_COPY int exit_already = 0;

NO_COPY static struct
{
  NTSTATUS code;
  const char *name;
} status_info[] =
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

void
init_console_handler (bool install_handler)
{
  BOOL res;

  SetConsoleCtrlHandler (ctrl_c_handler, FALSE);
  SetConsoleCtrlHandler (NULL, FALSE);
  if (install_handler)
    res = SetConsoleCtrlHandler (ctrl_c_handler, TRUE);
  else
    res = SetConsoleCtrlHandler (NULL, TRUE);
  if (!res)
    system_printf ("SetConsoleCtrlHandler failed, %E");
}

extern "C" void
error_start_init (const char *buf)
{
  if (!buf || !*buf)
    {
      debugger_command[0] = '\0';
      return;
    }

  char pgm[NT_MAX_PATH];
  if (!GetModuleFileName (NULL, pgm, NT_MAX_PATH))
    strcpy (pgm, "cygwin1.dll");
  for (char *p = strchr (pgm, '\\'); p; p = strchr (p, '\\'))
    *p = '/';

  __small_sprintf (debugger_command, "%s \"%s\"", buf, pgm);
}

static void
open_stackdumpfile ()
{
  /* If we have no executable name, or if the CWD handle is NULL,
     which means, the CWD is a virtual path, don't even try to open
     a stackdump file. */
  if (myself->progname[0] && cygheap->cwd.get_handle ())
    {
      const WCHAR *p;
      /* write to progname.stackdump if possible */
      if (!myself->progname[0])
	p = L"unknown";
      else if ((p = wcsrchr (myself->progname, L'\\')))
	p++;
      else
	p = myself->progname;

      WCHAR corefile[wcslen (p) + sizeof (".stackdump")];
      wcpcpy (wcpcpy(corefile, p), L".stackdump");
      UNICODE_STRING ucore;
      OBJECT_ATTRIBUTES attr;
      /* Create the UNICODE variation of <progname>.stackdump. */
      RtlInitUnicodeString (&ucore, corefile);
      /* Create an object attribute which refers to <progname>.stackdump
	 in Cygwin's cwd.  Stick to caseinsensitivity. */
      InitializeObjectAttributes (&attr, &ucore, OBJ_CASE_INSENSITIVE,
				  cygheap->cwd.get_handle (), NULL);
      HANDLE h;
      IO_STATUS_BLOCK io;
      NTSTATUS status;
      /* Try to open it to dump the stack in it. */
      status = NtCreateFile (&h, GENERIC_WRITE | SYNCHRONIZE, &attr, &io,
			     NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
			     FILE_SYNCHRONOUS_IO_NONALERT
			     | FILE_OPEN_FOR_BACKUP_INTENT, NULL, 0);
      if (NT_SUCCESS (status))
	{
	  if (!myself->cygstarted)
	    system_printf ("Dumping stack trace to %S", &ucore);
	  else
	    debug_printf ("Dumping stack trace to %S", &ucore);
	  SetStdHandle (STD_ERROR_HANDLE, h);
	}
    }
}

/* Utilities for dumping the stack, etc.  */

static void
dump_exception (EXCEPTION_RECORD *e,  CONTEXT *in)
{
  const char *exception_name = NULL;

  if (e)
    {
      for (int i = 0; status_info[i].name; i++)
	{
	  if (status_info[i].code == (NTSTATUS) e->ExceptionCode)
	    {
	      exception_name = status_info[i].name;
	      break;
	    }
	}
    }

#ifdef __x86_64__
  if (exception_name)
    small_printf ("Exception: %s at rip=%016X\r\n", exception_name, in->Rip);
  else
    small_printf ("Signal %d at rip=%016X\r\n", e->ExceptionCode, in->Rip);
  small_printf ("rax=%16X rbx=%16X rcx=%16X\r\n", in->Rax, in->Rbx, in->Rcx);
  small_printf ("rdx=%16X rsi=%16X rdi=%16X\r\n", in->Rdx, in->Rsi, in->Rdi);
  small_printf ("r8 =%16X r9 =%16X r10=%16X\r\n", in->R8, in->R9, in->R10);
  small_printf ("r11=%16X r12=%16X r13=%16X\r\n", in->R11, in->R12, in->R13);
  small_printf ("r14=%16X r15=%16X\r\n", in->R14, in->R15);
  small_printf ("rbp=%16X rsp=%16X program=%W, pid %u, thread %s\r\n",
		in->Rbp, in->Rsp, myself->progname, myself->pid,
		cygthread::name ());
#else
  if (exception_name)
    small_printf ("Exception: %s at eip=%08x\r\n", exception_name, in->Eip);
  else
    small_printf ("Signal %d at eip=%08x\r\n", e->ExceptionCode, in->Eip);
  small_printf ("eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\r\n",
		in->Eax, in->Ebx, in->Ecx, in->Edx, in->Esi, in->Edi);
  small_printf ("ebp=%08x esp=%08x program=%W, pid %u, thread %s\r\n",
		in->Ebp, in->Esp, myself->progname, myself->pid,
		cygthread::name ());
#endif
  small_printf ("cs=%04x ds=%04x es=%04x fs=%04x gs=%04x ss=%04x\r\n",
		in->SegCs, in->SegDs, in->SegEs, in->SegFs, in->SegGs, in->SegSs);
}

/* A class for manipulating the stack. */
class stack_info
{
  int walk ();			/* Uses the "old" method */
  char *next_offset () {return *((char **) sf.AddrFrame.Offset);}
  bool needargs;
  PUINT_PTR dummy_frame;
public:
  STACKFRAME sf;		 /* For storing the stack information */
  void init (PUINT_PTR, bool, bool); /* Called the first time that stack info is needed */

  /* Postfix ++ iterates over the stack, returning zero when nothing is left. */
  int operator ++(int) { return walk (); }
};

/* The number of parameters used in STACKFRAME */
#define NPARAMS (sizeof (thestack.sf.Params) / sizeof (thestack.sf.Params[0]))

/* This is the main stack frame info for this process. */
static NO_COPY stack_info thestack;

/* Initialize everything needed to start iterating. */
void
stack_info::init (PUINT_PTR framep, bool wantargs, bool goodframe)
{
  memset (&sf, 0, sizeof (sf));
  if (!goodframe)
    sf.AddrFrame.Offset = (UINT_PTR) framep;
  else
    {
      dummy_frame = framep;
      sf.AddrFrame.Offset = (UINT_PTR) &dummy_frame;
    }
  sf.AddrReturn.Offset = framep[1];
  sf.AddrFrame.Mode = AddrModeFlat;
  needargs = wantargs;
}

extern "C" void _cygwin_exit_return ();

/* Walk the stack by looking at successive stored 'bp' frames.
   This is not foolproof. */
int
stack_info::walk ()
{
  char **framep;

  if ((void (*) ()) sf.AddrPC.Offset == _cygwin_exit_return)
    return 0;		/* stack frames are exhausted */

  if (((framep = (char **) next_offset ()) == NULL)
      || (framep >= (char **) cygwin_hmodule))
    return 0;

  sf.AddrFrame.Offset = (_ADDR) framep;
  sf.AddrPC.Offset = sf.AddrReturn.Offset;

  /* The return address always follows the stack pointer */
  sf.AddrReturn.Offset = (_ADDR) *++framep;

  if (needargs)
    {
      unsigned nparams = NPARAMS;

      /* The arguments follow the return address */
      sf.Params[0] = (_ADDR) *++framep;
#ifndef __x86_64__
      /* Hack for XP/2K3 WOW64.  If the first stack param points to the
	 application entry point, we can only fetch one additional
	 parameter.  Accessing anything beyond this address results in
	 a SEGV.  This is fixed in Vista/2K8 WOW64. */
      if (wincap.has_restricted_stack_args () && sf.Params[0] == 0x401000)
	nparams = 2;
#endif
      for (unsigned i = 1; i < nparams; i++)
	sf.Params[i] = (_ADDR) *++framep;
    }
  return 1;
}

void
stackdump (PUINT_PTR framep, PCONTEXT in, EXCEPTION_RECORD *e)
{
  static bool already_dumped;

  if (already_dumped || cygheap->rlim_core == 0Ul)
    return;
  already_dumped = true;
  open_stackdumpfile ();

  if (e)
    dump_exception (e, in);

  int i;

  thestack.init (framep, 1, !in);	/* Initialize from the input CONTEXT */
  small_printf ("Stack trace:\r\nFrame     Function  Args\r\n");
  for (i = 0; i < 16 && thestack++; i++)
    {
      small_printf (_AFMT "  " _AFMT, thestack.sf.AddrFrame.Offset,
		    thestack.sf.AddrPC.Offset);
      for (unsigned j = 0; j < NPARAMS; j++)
	small_printf ("%s" _AFMT, j == 0 ? " (" : ", ", thestack.sf.Params[j]);
      small_printf (")\r\n");
    }
  small_printf ("End of stack trace%s\n",
	      i == 16 ? " (more stack frames may be present)" : "");
}

bool
_cygtls::inside_kernel (CONTEXT *cx)
{
  int res;
  MEMORY_BASIC_INFORMATION m;

  if (!isinitialized ())
    return true;

  memset (&m, 0, sizeof m);
  if (!VirtualQuery ((LPCVOID) cx->_GR(ip), &m, sizeof m))
    sigproc_printf ("couldn't get memory info, pc %p, %E", cx->_GR(ip));

  size_t size = (windows_system_directory_length + 6) * sizeof (WCHAR);
  PWCHAR checkdir = (PWCHAR) alloca (size);
  memset (checkdir, 0, size);

# define h ((HMODULE) m.AllocationBase)
  if (!h || m.State != MEM_COMMIT)	/* Be defensive */
    res = true;
  else if (h == user_data->hmodule)
    res = false;
  else if (!GetModuleFileNameW (h, checkdir, windows_system_directory_length + 6))
    res = false;
  else
    {
      /* Skip potential long path prefix. */
      if (!wcsncmp (checkdir, L"\\\\?\\", 4))
	checkdir += 4;
      res = wcsncasecmp (windows_system_directory, checkdir,
			 windows_system_directory_length) == 0;
#ifndef __x86_64__
      if (!res && system_wow64_directory_length)
	res = wcsncasecmp (system_wow64_directory, checkdir,
			   system_wow64_directory_length) == 0;

#endif
    }
  sigproc_printf ("pc %p, h %p, inside_kernel %d", cx->_GR(ip), h, res);
# undef h
  return res;
}

/* Temporary (?) function for external callers to get a stack dump */
extern "C" void
cygwin_stackdump ()
{
  CONTEXT c;
  c.ContextFlags = CONTEXT_FULL;
  GetThreadContext (GetCurrentThread (), &c);
  stackdump ((PUINT_PTR) c._GR(bp));
}

#define TIME_TO_WAIT_FOR_DEBUGGER 10000

extern "C" int
try_to_debug (bool waitloop)
{
  debug_printf ("debugger_command '%s'", debugger_command);
  if (*debugger_command == '\0')
    return 0;
  if (being_debugged ())
    {
      extern void break_here ();
      break_here ();
      return 0;
    }

  __small_sprintf (strchr (debugger_command, '\0'), " %u", GetCurrentProcessId ());

  LONG prio = GetThreadPriority (GetCurrentThread ());
  SetThreadPriority (GetCurrentThread (), THREAD_PRIORITY_HIGHEST);
  PROCESS_INFORMATION pi = {NULL, 0, 0, 0};

  STARTUPINFOW si = {0, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL};
  si.lpReserved = NULL;
  si.lpDesktop = NULL;
  si.dwFlags = 0;
  si.cb = sizeof (si);

  /* FIXME: need to know handles of all running threads to
     suspend_all_threads_except (current_thread_id);
  */

  /* If the tty mutex is owned, we will fail to start any cygwin app
     until the trapped app exits.  However, this will only release any
     the mutex if it is owned by this thread so that may be problematic. */

  lock_ttys::release ();

  /* prevent recursive exception handling */
  PWCHAR rawenv = GetEnvironmentStringsW () ;
  for (PWCHAR p = rawenv; *p != L'\0'; p = wcschr (p, L'\0') + 1)
    {
      if (wcsncmp (p, L"CYGWIN=", wcslen (L"CYGWIN=")) == 0)
	{
	  PWCHAR q = wcsstr (p, L"error_start") ;
	  /* replace 'error_start=...' with '_rror_start=...' */
	  if (q)
	    {
	      *q = L'_' ;
	      SetEnvironmentVariableW (L"CYGWIN", p + wcslen (L"CYGWIN=")) ;
	    }
	  break ;
	}
    }

  console_printf ("*** starting debugger for pid %u, tid %u\n",
		  cygwin_pid (GetCurrentProcessId ()), GetCurrentThreadId ());
  BOOL dbg;
  WCHAR dbg_cmd[strlen(debugger_command)];
  sys_mbstowcs (dbg_cmd, strlen(debugger_command) + 1, debugger_command);
  dbg = CreateProcessW (NULL,
			dbg_cmd,
			NULL,
			NULL,
			FALSE,
			CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
			NULL,
			NULL,
			&si,
			&pi);

  if (!dbg)
    system_printf ("Failed to start debugger, %E");
  else
    {
      if (!waitloop)
	return dbg;
      SetThreadPriority (GetCurrentThread (), THREAD_PRIORITY_IDLE);
      while (!being_debugged ())
	yield ();
      Sleep (2000);
    }

  console_printf ("*** continuing pid %u from debugger call (%d)\n",
		  cygwin_pid (GetCurrentProcessId ()), dbg);

  SetThreadPriority (GetCurrentThread (), prio);
  return dbg;
}

#ifdef __x86_64__
static void __stdcall rtl_unwind (exception_list *, PEXCEPTION_RECORD) __attribute__ ((noinline));
void __stdcall
rtl_unwind (exception_list *frame, PEXCEPTION_RECORD e)
{
  RtlUnwind (frame, __builtin_return_address (0), e, 0);
}
#else
static void __stdcall rtl_unwind (exception_list *, PEXCEPTION_RECORD) __attribute__ ((noinline, regparm (3)));
void __stdcall
rtl_unwind (exception_list *frame, PEXCEPTION_RECORD e)
{
  __asm__ ("\n\
  pushl		%%ebx					\n\
  pushl		%%edi					\n\
  pushl		%%esi					\n\
  pushl		$0					\n\
  pushl		%1					\n\
  pushl		$1f					\n\
  pushl		%0					\n\
  call		_RtlUnwind@16				\n\
1:							\n\
  popl		%%esi					\n\
  popl		%%edi					\n\
  popl		%%ebx					\n\
": : "r" (frame), "r" (e));
}
#endif

/* Main exception handler. */

int
exception::handle (EXCEPTION_RECORD *e, exception_list *frame, CONTEXT *in, void *)
{
  static bool NO_COPY debugging;
  static int NO_COPY recursed;
  _cygtls& me = _my_tls;

  if (debugging && ++debugging < 500000)
    {
      SetThreadPriority (hMainThread, THREAD_PRIORITY_NORMAL);
      return 0;
    }

  /* If we've already exited, don't do anything here.  Returning 1
     tells Windows to keep looking for an exception handler.  */
  if (exit_already || e->ExceptionFlags)
    return 1;

  siginfo_t si = {0};
  si.si_code = SI_KERNEL;
  /* Coerce win32 value to posix value.  */
  switch (e->ExceptionCode)
    {
    case STATUS_FLOAT_DENORMAL_OPERAND:
    case STATUS_FLOAT_DIVIDE_BY_ZERO:
    case STATUS_FLOAT_INVALID_OPERATION:
    case STATUS_FLOAT_STACK_CHECK:
      si.si_signo = SIGFPE;
      si.si_code = FPE_FLTSUB;
      break;
    case STATUS_FLOAT_INEXACT_RESULT:
      si.si_signo = SIGFPE;
      si.si_code = FPE_FLTRES;
      break;
    case STATUS_FLOAT_OVERFLOW:
      si.si_signo = SIGFPE;
      si.si_code = FPE_FLTOVF;
      break;
    case STATUS_FLOAT_UNDERFLOW:
      si.si_signo = SIGFPE;
      si.si_code = FPE_FLTUND;
      break;
    case STATUS_INTEGER_DIVIDE_BY_ZERO:
      si.si_signo = SIGFPE;
      si.si_code = FPE_INTDIV;
      break;
    case STATUS_INTEGER_OVERFLOW:
      si.si_signo = SIGFPE;
      si.si_code = FPE_INTOVF;
      break;

    case STATUS_ILLEGAL_INSTRUCTION:
      si.si_signo = SIGILL;
      si.si_code = ILL_ILLOPC;
      break;

    case STATUS_PRIVILEGED_INSTRUCTION:
      si.si_signo = SIGILL;
      si.si_code = ILL_PRVOPC;
      break;

    case STATUS_NONCONTINUABLE_EXCEPTION:
      si.si_signo = SIGILL;
      si.si_code = ILL_ILLADR;
      break;

    case STATUS_TIMEOUT:
      si.si_signo = SIGALRM;
      break;

    case STATUS_GUARD_PAGE_VIOLATION:
      si.si_signo = SIGBUS;
      si.si_code = BUS_OBJERR;
      break;

    case STATUS_DATATYPE_MISALIGNMENT:
      si.si_signo = SIGBUS;
      si.si_code = BUS_ADRALN;
      break;

    case STATUS_ACCESS_VIOLATION:
      switch (mmap_is_attached_or_noreserve ((void *)e->ExceptionInformation[1],
					     1))
	{
	case MMAP_NORESERVE_COMMITED:
	  return 0;
	case MMAP_RAISE_SIGBUS:	/* MAP_NORESERVE page, commit failed, or
				   access to mmap page beyond EOF. */
	  si.si_signo = SIGBUS;
	  si.si_code = BUS_OBJERR;
	  break;
	default:
	  MEMORY_BASIC_INFORMATION m;
	  VirtualQuery ((PVOID) e->ExceptionInformation[1], &m, sizeof m);
	  si.si_signo = SIGSEGV;
	  si.si_code = m.State == MEM_FREE ? SEGV_MAPERR : SEGV_ACCERR;
	  break;
	}
      break;

    case STATUS_ARRAY_BOUNDS_EXCEEDED:
    case STATUS_IN_PAGE_ERROR:
    case STATUS_NO_MEMORY:
    case STATUS_INVALID_DISPOSITION:
    case STATUS_STACK_OVERFLOW:
      si.si_signo = SIGSEGV;
      si.si_code = SEGV_MAPERR;
      break;

    case STATUS_CONTROL_C_EXIT:
      si.si_signo = SIGINT;
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

  debug_printf ("In cygwin_except_handler exception %y at %p sp %p", e->ExceptionCode, in->_GR(ip), in->_GR(sp));
  debug_printf ("In cygwin_except_handler signal %d at %p", si.si_signo, in->_GR(ip));

  bool masked = !!(me.sigmask & SIGTOMASK (si.si_signo));
  if (masked)
    syscall_printf ("signal %d, masked 0x%lx", si.si_signo,
		    global_sigs[si.si_signo].sa_mask);

  debug_printf ("In cygwin_except_handler calling %p",
		 global_sigs[si.si_signo].sa_handler);

  PUINT_PTR framep = (PUINT_PTR) in->_GR(sp);
  for (PUINT_PTR bpend = (PUINT_PTR) __builtin_frame_address (0); framep > bpend; framep--)
    if (*framep == in->SegCs && framep[-1] == in->_GR(ip))
      {
	framep -= 2;
	break;
      }

  if (me.andreas)
    me.andreas->leave ();	/* Return from a "san" caught fault */

  me.copy_context (in);

  /* Temporarily replace windows top level SEH with our own handler.
     We don't want any Windows magic kicking in.  This top level frame
     will be removed automatically after our exception handler returns. */
  _except_list->handler = handle;

  if (masked
      || &me == _sig_tls
      || !cygwin_finished_initializing
      || (void *) global_sigs[si.si_signo].sa_handler == (void *) SIG_DFL
      || (void *) global_sigs[si.si_signo].sa_handler == (void *) SIG_IGN
      || (void *) global_sigs[si.si_signo].sa_handler == (void *) SIG_ERR)
    {
      /* Print the exception to the console */
      if (!myself->cygstarted)
	for (int i = 0; status_info[i].name; i++)
	  if (status_info[i].code == (NTSTATUS) e->ExceptionCode)
	    {
	      system_printf ("Exception: %s", status_info[i].name);
	      break;
	    }

      /* Another exception could happen while tracing or while exiting.
	 Only do this once.  */
      if (recursed++)
	system_printf ("Error while dumping state (probably corrupted stack)");
      else
	{
	  if (try_to_debug (0))
	    {
	      debugging = true;
	      return 0;
	    }

	  rtl_unwind (frame, e);
	  if (cygheap->rlim_core > 0UL)
	    stackdump (framep, in, e);
	}

      if ((NTSTATUS) e->ExceptionCode == STATUS_ACCESS_VIOLATION)
	{
	  int error_code = 0;
	  if (si.si_code == SEGV_ACCERR)	/* Address present */
	    error_code |= 1;
	  if (e->ExceptionInformation[0])	/* Write access */
	    error_code |= 2;
	  if (!me.inside_kernel (in))		/* User space */
	    error_code |= 4;
	  klog (LOG_INFO, "%s[%d]: segfault at " _AFMT " rip " _AFMT " rsp " _AFMT " error %d",
			  __progname, myself->pid,
			  e->ExceptionInformation[1], in->_GR(ip), in->_GR(sp),
			  error_code);
	}

      /* Flag signal + core dump */
      me.signal_exit ((cygheap->rlim_core > 0UL ? 0x80 : 0) | si.si_signo);
    }

  si.si_addr =  (si.si_signo == SIGSEGV || si.si_signo == SIGBUS
		 ? (void *) e->ExceptionInformation[1]
		 : (void *) in->_GR(ip));
  si.si_errno = si.si_pid = si.si_uid = 0;
  me.incyg++;
  sig_send (NULL, si, &me);	// Signal myself
  me.incyg--;
  e->ExceptionFlags = 0;
  return 0;
}

/* Utilities to call a user supplied exception handler.  */

#define SIG_NONMASKABLE	(SIGTOMASK (SIGKILL) | SIGTOMASK (SIGSTOP))

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
  sigset_t oldmask = _my_tls.sigmask;	// Remember for restoration

  set_signal_mask (_my_tls.sigmask, tempmask);
  sigproc_printf ("oldmask 0x%lx, newmask 0x%lx", oldmask, tempmask);

  pthread_testcancel ();
  cygwait (NULL, cw_infinite, cw_cancel | cw_cancel_self | cw_sig_eintr);

  set_sig_errno (EINTR);	// Per POSIX

  /* A signal dispatch function will have been added to our stack and will
     be hit eventually.  Set the old mask to be restored when the signal
     handler returns and indicate its presence by modifying deltamask. */

  _my_tls.deltamask |= SIG_NONMASKABLE;
  _my_tls.oldmask = oldmask;	// Will be restored by signal handler
  return -1;
}

extern DWORD exec_exit;		// Possible exit value for exec

extern "C" {
static void
sig_handle_tty_stop (int sig)
{
  _my_tls.incyg = 1;
  /* Silently ignore attempts to suspend if there is no accommodating
     cygwin parent to deal with this behavior. */
  if (!myself->cygstarted)
    myself->process_state &= ~PID_STOPPED;
  else
    {
      myself->stopsig = sig;
      myself->alert_parent (sig);
      sigproc_printf ("process %d stopped by signal %d", myself->pid, sig);
      /* FIXME! This does nothing to suspend anything other than the main
	 thread. */
      DWORD res = cygwait (NULL, cw_infinite, cw_sig_eintr);
      switch (res)
	{
	case WAIT_SIGNALED:
	  _my_tls.sig = 0;
	  myself->stopsig = SIGCONT;
	  myself->alert_parent (SIGCONT);
	  break;
	default:
	  api_fatal ("WaitSingleObject returned %d", res);
	  break;
	}
    }
  _my_tls.incyg = 0;
}
} /* end extern "C" */

bool
_cygtls::interrupt_now (CONTEXT *cx, siginfo_t& si, void *handler,
			struct sigaction& siga)
{
  bool interrupted;

  /* Delay the interrupt if we are
     1) somehow inside the DLL
     2) in _sigfe (spinning is true) and about to enter cygwin DLL
     3) in a Windows DLL.  */
  if (incyg || spinning || inside_kernel (cx))
    interrupted = false;
  else
    {
      _ADDR &ip = cx->_GR(ip);
      push (ip);
      interrupt_setup (si, handler, siga);
      ip = pop ();
      SetThreadContext (*this, cx); /* Restart the thread in a new location */
      interrupted = true;
    }
  return interrupted;
}

void __stdcall
_cygtls::interrupt_setup (siginfo_t& si, void *handler, struct sigaction& siga)
{
  push ((__stack_t) sigdelayed);
  deltamask = siga.sa_mask & ~SIG_NONMASKABLE;
  sa_flags = siga.sa_flags;
  func = (void (*) (int)) handler;
  if (siga.sa_flags & SA_RESETHAND)
    siga.sa_handler = SIG_DFL;
  saved_errno = -1;		// Flag: no errno to save
  if (handler == sig_handle_tty_stop)
    {
      myself->stopsig = 0;
      myself->process_state |= PID_STOPPED;
    }

  infodata = si;
  this->sig = si.si_signo;		// Should always be last thing set to avoid a race

  if (incyg)
    {
      if (!signal_arrived)
	create_signal_arrived ();
      SetEvent (signal_arrived);
    }

  proc_subproc (PROC_CLEARWAIT, 1);
  sigproc_printf ("armed signal_arrived %p, signal %d", signal_arrived, si.si_signo);
}

extern "C" void __stdcall
set_sig_errno (int e)
{
  *_my_tls.errno_addr = e;
  _my_tls.saved_errno = e;
}

int
sigpacket::setup_handler (void *handler, struct sigaction& siga, _cygtls *tls)
{
  CONTEXT cx;
  bool interrupted = false;

  if (tls->sig)
    {
      sigproc_printf ("trying to send signal %d but signal %d already armed",
		      si.si_signo, tls->sig);
      goto out;
    }

  for (int n = 0; n < CALL_HANDLER_RETRY_OUTER; n++)
    {
      for (int i = 0; i < CALL_HANDLER_RETRY_INNER; i++)
	{
	  tls->lock ();
	  if (tls->incyg)
	    {
	      sigproc_printf ("controlled interrupt. stackptr %p, stack %p, stackptr[-1] %p",
			      tls->stackptr, tls->stack, tls->stackptr[-1]);
	      tls->interrupt_setup (si, handler, siga);
	      interrupted = true;
	      tls->unlock ();
	      goto out;
	    }

	  DWORD res;
	  HANDLE hth = (HANDLE) *tls;
	  if (!hth)
	    sigproc_printf ("thread handle NULL, not set up yet?");
	  else
	    {
	      /* Suspend the thread which will receive the signal.
		 If one of these conditions is not true we loop.
		 If the thread is already suspended (which can occur when a program
		 has called SuspendThread on itself) then just queue the signal. */

	      sigproc_printf ("suspending thread, tls %p, _main_tls %p", tls, _main_tls);
	      res = SuspendThread (hth);
	      /* Just set pending if thread is already suspended */
	      if (res)
		{
		  ResumeThread (hth);
		  goto out;
		}
	      cx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	      if (!GetThreadContext (hth, &cx))
		sigproc_printf ("couldn't get context of thread, %E");
	      else
		interrupted = tls->interrupt_now (&cx, si, handler, siga);

	      tls->unlock ();
	      ResumeThread (hth);
	      if (interrupted)
		goto out;
	    }

	  sigproc_printf ("couldn't interrupt.  trying again.");
	  yield ();
	}
      /* Hit here if we couldn't deliver the signal.  Take a more drastic
	 action before trying again. */
      Sleep (1);
    }

out:
  sigproc_printf ("signal %d %sdelivered", si.si_signo, interrupted ? "" : "not ");
  return interrupted;
}

static inline bool
has_visible_window_station ()
{
  HWINSTA station_hdl;
  USEROBJECTFLAGS uof;
  DWORD len;

  /* Check if the process is associated with a visible window station.
     These are processes running on the local desktop as well as processes
     running in terminal server sessions.
     Processes running in a service session not explicitely associated
     with the desktop (using the "Allow service to interact with desktop"
     property) are running in an invisible window station. */
  if ((station_hdl = GetProcessWindowStation ())
      && GetUserObjectInformationW (station_hdl, UOI_FLAGS, &uof,
				    sizeof uof, &len)
      && (uof.dwFlags & WSF_VISIBLE))
    return true;
  return false;
}

/* Keyboard interrupt handler.  */
static BOOL WINAPI
ctrl_c_handler (DWORD type)
{
  static bool saw_close;

  if (!cygwin_finished_initializing)
    {
      if (myself->cygstarted)	/* Was this process created by a cygwin process? */
	return TRUE;		/* Yes.  Let the parent eventually handle CTRL-C issues. */
      debug_printf ("exiting with status 0x%08x", STATUS_CONTROL_C_EXIT);
      ExitProcess (STATUS_CONTROL_C_EXIT);
    }

  /* Remove early or we could overthrow the threadlist in cygheap.
     Deleting this line causes ash to SEGV if CTRL-C is hit repeatedly.
     I am not exactly sure why that is.  Maybe it's just because this
     adds some early serialization to ctrl_c_handler which prevents
     multiple simultaneous calls? */
  _my_tls.remove (INFINITE);

#if 0
  if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT)
    proc_subproc (PROC_KILLFORKED, 0);
#endif

  /* Return FALSE to prevent an "End task" dialog box from appearing
     for each Cygwin process window that's open when the computer
     is shut down or console window is closed. */

  if (type == CTRL_SHUTDOWN_EVENT)
    {
#if 0
      /* Don't send a signal.  Only NT service applications and their child
	 processes will receive this event and the services typically already
	 handle the shutdown action when getting the SERVICE_CONTROL_SHUTDOWN
	 control message. */
      sig_send (NULL, SIGTERM);
#endif
      return FALSE;
    }

  if (myself->ctty != -1)
    {
      if (type == CTRL_CLOSE_EVENT)
	{
	  sig_send (NULL, SIGHUP);
	  saw_close = true;
	  return FALSE;
	}
      if (!saw_close && type == CTRL_LOGOFF_EVENT)
	{
	  /* The CTRL_LOGOFF_EVENT is sent when *any* user logs off.
	     The below code sends a SIGHUP only if it is not performing the
	     default activity for SIGHUP.  Note that it is possible for two
	     SIGHUP signals to arrive if a process group leader is exiting
	     too.  Getting this 100% right is saved for a future cygwin mailing
	     list goad.  */
	  if (global_sigs[SIGHUP].sa_handler != SIG_DFL)
	    {
	      sig_send (myself_nowait, SIGHUP);
	      return TRUE;
	    }
	  return FALSE;
	}
    }

  if (ch_spawn.set_saw_ctrl_c ())
    return TRUE;

  /* We're only the process group leader when we have a valid pinfo structure.
     If we don't have one, then the parent "stub" will handle the signal. */
  if (!pinfo (cygwin_pid (GetCurrentProcessId ())))
    return TRUE;

  tty_min *t = cygwin_shared->tty.get_cttyp ();
  /* Ignore this if we're not the process group leader since it should be handled
     *by* the process group leader. */
  if (t && (!have_execed || have_execed_cygwin)
      && t->getpgid () == myself->pid &&
      (GetTickCount () - t->last_ctrl_c) >= MIN_CTRL_C_SLOP)
    /* Otherwise we just send a SIGINT to the process group and return TRUE (to indicate
       that we have handled the signal).  At this point, type should be
       a CTRL_C_EVENT or CTRL_BREAK_EVENT. */
    {
      int sig = SIGINT;
      /* If intr and quit are both mapped to ^C, send SIGQUIT on ^BREAK */
      if (type == CTRL_BREAK_EVENT
	  && t->ti.c_cc[VINTR] == 3 && t->ti.c_cc[VQUIT] == 3)
	sig = SIGQUIT;
      t->last_ctrl_c = GetTickCount ();
      killsys (-myself->pid, sig);
      t->last_ctrl_c = GetTickCount ();
      return TRUE;
    }

  return TRUE;
}

/* Function used by low level sig wrappers. */
extern "C" void __stdcall
set_process_mask (sigset_t newmask)
{
  set_signal_mask (_my_tls.sigmask, newmask);
}

extern "C" int
sighold (int sig)
{
  /* check that sig is in right range */
  if (sig < 0 || sig >= NSIG)
    {
      set_errno (EINVAL);
      syscall_printf ("signal %d out of range", sig);
      return -1;
    }
  sigset_t mask = _my_tls.sigmask;
  sigaddset (&mask, sig);
  set_signal_mask (_my_tls.sigmask, mask);
  return 0;
}

extern "C" int
sigrelse (int sig)
{
  /* check that sig is in right range */
  if (sig < 0 || sig >= NSIG)
    {
      set_errno (EINVAL);
      syscall_printf ("signal %d out of range", sig);
      return -1;
    }
  sigset_t mask = _my_tls.sigmask;
  sigdelset (&mask, sig);
  set_signal_mask (_my_tls.sigmask, mask);
  return 0;
}

extern "C" _sig_func_ptr
sigset (int sig, _sig_func_ptr func)
{
  sig_dispatch_pending ();
  _sig_func_ptr prev;

  /* check that sig is in right range */
  if (sig < 0 || sig >= NSIG || sig == SIGKILL || sig == SIGSTOP)
    {
      set_errno (EINVAL);
      syscall_printf ("SIG_ERR = sigset (%d, %p)", sig, func);
      return (_sig_func_ptr) SIG_ERR;
    }

  sigset_t mask = _my_tls.sigmask;
  /* If sig was in the signal mask return SIG_HOLD, otherwise return the
     previous disposition. */
  if (sigismember (&mask, sig))
    prev = SIG_HOLD;
  else
    prev = global_sigs[sig].sa_handler;
  /* If func is SIG_HOLD, add sig to the signal mask, otherwise set the
     disposition to func and remove sig from the signal mask. */
  if (func == SIG_HOLD)
    sigaddset (&mask, sig);
  else
    {
      /* No error checking.  The test which could return SIG_ERR has already
	 been made above. */
      signal (sig, func);
      sigdelset (&mask, sig);
    }
  set_signal_mask (_my_tls.sigmask, mask);
  return prev;
}

extern "C" int
sigignore (int sig)
{
  return sigset (sig, SIG_IGN) == SIG_ERR ? -1 : 0;
}

/* Update the signal mask for this process and return the old mask.
   Called from call_signal_handler */
extern "C" sigset_t
set_process_mask_delta ()
{
  sigset_t newmask, oldmask;

  if (_my_tls.deltamask & SIG_NONMASKABLE)
    oldmask = _my_tls.oldmask; /* from handle_sigsuspend */
  else
    oldmask = _my_tls.sigmask;
  newmask = (oldmask | _my_tls.deltamask) & ~SIG_NONMASKABLE;
  sigproc_printf ("oldmask %lx, newmask %lx, deltamask %lx", oldmask, newmask,
		  _my_tls.deltamask);
  _my_tls.sigmask = newmask;
  return oldmask;
}

/* Set the signal mask for this process.
   Note that some signals are unmaskable, as in UNIX.  */

void
set_signal_mask (sigset_t& setmask, sigset_t newmask)
{
  newmask &= ~SIG_NONMASKABLE;
  sigset_t mask_bits = setmask & ~newmask;
  sigproc_printf ("setmask %lx, newmask %lx, mask_bits %lx", setmask, newmask,
		  mask_bits);
  setmask = newmask;
  if (mask_bits)
    sig_dispatch_pending (true);
}

int __stdcall
sigpacket::process ()
{
  bool continue_now;
  struct sigaction dummy = global_sigs[SIGSTOP];

  if (si.si_signo != SIGCONT)
    continue_now = false;
  else
    {
      continue_now = ISSTATE (myself, PID_STOPPED);
      myself->stopsig = 0;
      myself->process_state &= ~PID_STOPPED;
      /* Clear pending stop signals */
      sig_clear (SIGSTOP);
      sig_clear (SIGTSTP);
      sig_clear (SIGTTIN);
      sig_clear (SIGTTOU);
    }

  switch (si.si_signo)
    {
    case SIGINT:
    case SIGQUIT:
    case SIGSTOP:
    case SIGTSTP:
      if (cygheap->ctty)
	cygheap->ctty->sigflush ();
      break;
    default:
      break;
    }

  int rc = 1;

  sigproc_printf ("signal %d processing", si.si_signo);
  struct sigaction& thissig = global_sigs[si.si_signo];

  myself->rusage_self.ru_nsignals++;

  void *handler = (void *) thissig.sa_handler;
  if (handler == SIG_IGN)
    {
      sigproc_printf ("signal %d ignored", si.si_signo);
      goto done;
    }

  if (have_execed)
    handler = NULL;

  if (tls)
    sigproc_printf ("using tls %p", tls);
  else
    {
      tls = cygheap->find_tls (si.si_signo);
      sigproc_printf ("using tls %p", tls);
    }

  if (si.si_signo == SIGKILL)
    goto exit_sig;
  if (si.si_signo == SIGSTOP)
    {
      sig_clear (SIGCONT);
      goto stop;
    }

  if (sigismember (&tls->sigwait_mask, si.si_signo))
    {
      tls->sigwait_mask = 0;
      goto dosig;
    }
  if (sigismember (&tls->sigmask, si.si_signo) || ISSTATE (myself, PID_STOPPED))
    {
      sigproc_printf ("signal %d blocked", si.si_signo);
      rc = -1;
      goto done;
    }

  /* Clear pending SIGCONT on stop signals */
  if (si.si_signo == SIGTSTP || si.si_signo == SIGTTIN || si.si_signo == SIGTTOU)
    sig_clear (SIGCONT);

  if (handler == (void *) SIG_DFL)
    {
      if (si.si_signo == SIGCHLD || si.si_signo == SIGIO || si.si_signo == SIGCONT || si.si_signo == SIGWINCH
	  || si.si_signo == SIGURG)
	{
	  sigproc_printf ("signal %d default is currently ignore", si.si_signo);
	  goto done;
	}

      if (si.si_signo == SIGTSTP || si.si_signo == SIGTTIN || si.si_signo == SIGTTOU)
	goto stop;

      goto exit_sig;
    }

  if (handler == (void *) SIG_ERR)
    goto exit_sig;

  goto dosig;

stop:
  handler = (void *) sig_handle_tty_stop;
  thissig = dummy;

dosig:
  if (ISSTATE (myself, PID_STOPPED) && !continue_now)
      rc = -1;		/* No signals delivered if stopped */
  else
    {
      /* Dispatch to the appropriate function. */
      sigproc_printf ("signal %d, signal handler %p", si.si_signo, handler);
      rc = setup_handler (handler, thissig, tls);
      continue_now = false;
    }

done:
  if (continue_now)
    {
      tls->sig = SIGCONT;
      SetEvent (tls->signal_arrived);
    }
  sigproc_printf ("returning %d", rc);
  return rc;

exit_sig:
  tls->signal_exit (si.si_signo);	/* never returns */
}

void
events_terminate ()
{
  exit_already = 1;
}

int
_cygtls::call_signal_handler ()
{
  int this_sa_flags = SA_RESTART;
  while (1)
    {
      lock ();
      if (!sig)
	{
	  unlock ();
	  break;
	}

      /* Pop the stack if the next "return address" is sigdelayed, since
	 this function is doing what sigdelayed would have done anyway. */
      if (retaddr () == (__stack_t) sigdelayed)
	pop ();

      debug_only_printf ("dealing with signal %d", sig);
      this_sa_flags = sa_flags;
      int thissig = sig;
      void (*thisfunc) (int) = func;

      sigset_t this_oldmask = set_process_mask_delta ();
      int this_errno = saved_errno;
      sig = 0;
      reset_signal_arrived ();
      unlock ();	// make sure synchronized
      if (!(this_sa_flags & SA_SIGINFO))
	{
	  incyg = false;
	  thisfunc (thissig);
	}
      else
	{
	  siginfo_t thissi = infodata;
	  void (*sigact) (int, siginfo_t *, void *) = (void (*) (int, siginfo_t *, void *)) thisfunc;
	  /* no ucontext_t information provided yet */
	  incyg = false;
	  sigact (thissig, &thissi, NULL);
	}
      incyg = true;
      set_signal_mask (_my_tls.sigmask, this_oldmask);
      if (this_errno >= 0)
	set_errno (this_errno);
    }

  return this_sa_flags & SA_RESTART || (this != _main_tls);
}

void
_cygtls::copy_context (CONTEXT *c)
{
  memcpy (&thread_context, c, __COPY_CONTEXT_SIZE);
}

void
_cygtls::signal_debugger (int sig)
{
  if (isinitialized () && being_debugged ())
    {
      char sigmsg[2 * sizeof (_CYGWIN_SIGNAL_STRING " ffffffff ffffffff")];
      __small_sprintf (sigmsg, _CYGWIN_SIGNAL_STRING " %d %p %p", sig, thread_id, &thread_context);
      OutputDebugString (sigmsg);
    }
}
