/* debug.h

   Copyright 1998, 1999, 2000, 2001 Red Hat, Inc.

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
  (void)mallinfo ();\
})
#endif

extern "C" {
DWORD __stdcall WFSO (HANDLE, DWORD) __attribute__ ((regparm(2)));
DWORD __stdcall WFMO (DWORD, CONST HANDLE *, BOOL, DWORD) __attribute__ ((regparm(3)));
}

#define WaitForSingleObject WFSO
#define WaitForMultipleObject WFMO

#if !defined(_DEBUG_H_)
#define _DEBUG_H_

void threadname_init ();
HANDLE __stdcall makethread (LPTHREAD_START_ROUTINE, LPVOID, DWORD, const char *) __attribute__ ((regparm(3)));
const char * __stdcall threadname (DWORD, int lockit = TRUE) __attribute__ ((regparm(2)));
void __stdcall regthread (const char *, DWORD) __attribute__ ((regparm(1)));
int __stdcall iscygthread ();

#ifndef DEBUGGING
# define cygbench(s)
# define ForceCloseHandle CloseHandle
# define ForceCloseHandle1(h, n) CloseHandle (h)
# define ForceCloseHandle2(h, n) CloseHandle (h)
# define ProtectHandle(h) do {} while (0)
# define ProtectHandle1(h,n) do {} while (0)
# define ProtectHandle2(h,n) do {} while (0)
# define debug_init() do {} while (0)
# define setclexec_pid(h, b) do {} while (0)
# define debug_fixup_after_fork() do {} while (0)

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

void debug_init ();
void __stdcall add_handle (const char *, int, HANDLE, const char *)
  __attribute__ ((regparm (3)));
BOOL __stdcall close_handle (const char *, int, HANDLE, const char *, BOOL)
  __attribute__ ((regparm (3)));
void __stdcall cygbench (const char *s) __attribute__ ((regparm (1)));
extern "C" void console_printf (const char *fmt,...);
void setclexec_pid (HANDLE, bool);
void debug_fixup_after_fork ();
extern int pinger;

#endif /*DEBUGGING*/
#endif /*_DEBUG_H_*/
