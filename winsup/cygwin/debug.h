/* debug.h

   Copyright 1998, 1999, 2000, 2001, 2002, 2003, 2004 Red Hat, Inc.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef MALLOC_DEBUG
#define MALLOC_CHECK do {} while (0)
#else
#include <stdlib.h>
#include "dlmalloc.h"
#define MALLOC_CHECK ({\
  debug_printf ("checking malloc pool");\
  (void) mallinfo ();\
})
#endif

#if !defined(_DEBUG_H_)
#define _DEBUG_H_

#define being_debugged() \
  (IsDebuggerPresent () /* || GetLastError () == ERROR_PROC_NOT_FOUND*/)

#ifndef DEBUGGING
# define cygbench(s)
# define ForceCloseHandle CloseHandle
# define ForceCloseHandle1(h, n) CloseHandle (h)
# define ForceCloseHandle2(h, n) CloseHandle (h)
# define ProtectHandle(h) do {} while (0)
# define ProtectHandle1(h,n) do {} while (0)
# define ProtectHandle2(h,n) do {} while (0)
# define ProtectHandleINH(h) do {} while (0)
# define ProtectHandle1INH(h,n) do {} while (0)
# define ProtectHandle2INH(h,n) do {} while (0)
# define debug_init() do {} while (0)
# define setclexec(h, nh, b) do {} while (0)
# define debug_fixup_after_fork_exec() do {} while (0)
# define VerifyHandle(h) do {} while (0)
# define console_printf small_printf

#else

# ifdef NO_DEBUG_DEFINES
#   undef NO_DEBUG_DEFINES
# else
#   define CloseHandle(h) \
	close_handle (__PRETTY_FUNCTION__, __LINE__, (h), #h, FALSE)
#   define ForceCloseHandle(h) \
	close_handle (__PRETTY_FUNCTION__, __LINE__, (h), #h, TRUE)
#   define ForceCloseHandle1(h,n) \
	close_handle (__PRETTY_FUNCTION__, __LINE__, (h), #n, TRUE)
#   define ForceCloseHandle2(h,n) \
	close_handle (__PRETTY_FUNCTION__, __LINE__, (h), n, TRUE)
# endif

# define ProtectHandle(h) add_handle (__PRETTY_FUNCTION__, __LINE__, (h), #h)
# define ProtectHandle1(h, n) add_handle (__PRETTY_FUNCTION__, __LINE__, (h), #n)
# define ProtectHandle2(h, n) add_handle (__PRETTY_FUNCTION__, __LINE__, (h), n)
# define ProtectHandleINH(h) add_handle (__PRETTY_FUNCTION__, __LINE__, (h), #h, 1)
# define ProtectHandle1INH(h, n) add_handle (__PRETTY_FUNCTION__, __LINE__, (h), #n, 1)
# define ProtectHandle2INH(h, n) add_handle (__PRETTY_FUNCTION__, __LINE__, (h), n, 1)
# define VerifyHandle(h) verify_handle (__PRETTY_FUNCTION__, __LINE__, (h))

void debug_init ();
void __stdcall add_handle (const char *, int, HANDLE, const char *, bool = false)
  __attribute__ ((regparm (3)));
void __stdcall verify_handle (const char *, int, HANDLE)
  __attribute__ ((regparm (3)));
bool __stdcall close_handle (const char *, int, HANDLE, const char *, bool)
  __attribute__ ((regparm (3)));
void __stdcall cygbench (const char *s) __attribute__ ((regparm (1)));
extern "C" void console_printf (const char *fmt,...);
void setclexec (HANDLE, HANDLE, bool);
void debug_fixup_after_fork_exec ();
extern int pinger;

struct handle_list
  {
    HANDLE h;
    const char *name;
    const char *func;
    int ln;
    bool inherited;
    DWORD pid;
    struct handle_list *next;
  };

#endif /*DEBUGGING*/
#endif /*_DEBUG_H_*/
