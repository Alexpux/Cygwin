/* winsup.h: main Cygwin header file.

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004,
   2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "config.h"

#define __INSIDE_CYGWIN__

#define NO_COPY __attribute__((nocommon)) __attribute__((section(".data_cygwin_nocopy")))
#define NO_COPY_INIT __attribute__((section(".data_cygwin_nocopy")))

#define EXPORT_ALIAS(sym,symalias) extern "C" __typeof (sym) symalias __attribute__ ((alias(#sym)));

/* Fun, fun, fun.  On Mingw64, WINVER is set according to the value of
   _WIN32_WINNT, on Mingw32 it's exactly the opposite... */
#define _WIN32_WINNT 0x0602
#define WINVER 0x0602

#define _NO_W32_PSEUDO_MODIFIERS

#include <sys/types.h>
#include <sys/strace.h>

/* Declarations for functions used in C and C++ code. */
#ifdef __cplusplus
extern "C" {
#endif
uid_t getuid32 ();
uid_t geteuid32 ();
int seteuid32 (uid_t);
gid_t getegid32 (void);
struct passwd *getpwuid32 (uid_t);
struct passwd *getpwnam (const char *);
struct __sFILE64 *fopen64 (const char *, const char *);
struct hostent *cygwin_gethostbyname (const char *name);
/* Don't enforce definition of in_addr_t. */
uint32_t cygwin_inet_addr (const char *cp);
int fcntl64 (int fd, int cmd, ...);
#ifdef __cplusplus
}
#endif

/* Note that MAX_PATH is defined in the windows headers */
/* There is also PATH_MAX and MAXPATHLEN.
   PATH_MAX is from Posix and does include the trailing NUL.
   MAXPATHLEN is from Unix.

   Thou shalt *not* use CYG_MAX_PATH anymore.  Use NT_MAX_PATH or
   dynamic allocation instead when accessing real files.  Use
   MAX_PATH in case you need a convenient small buffer when creating
   names for synchronization objects or named pipes. */
#define CYG_MAX_PATH (MAX_PATH)

/* There's no define for the maximum path length the NT kernel can handle.
   That's why we define our own to use in path length test and for path
   buffer sizes.  As MAX_PATH and PATH_MAX, this is defined including the
   trailing 0.  Internal buffers and internal path routines should use
   NT_MAX_PATH.  PATH_MAX as defined in limits.h is the maximum length of
   application provided path strings we handle. */
#define NT_MAX_PATH 32768

/* This definition allows to define wide char strings using macros as
   parameters.  See the definition of __CONCAT in newlib's sys/cdefs.h
   and accompanying comment. */
#define __WIDE(a) L ## a
#define _WIDE(a) __WIDE(a)

#include "winlean.h"

#ifdef __cplusplus

#include "wincap.h"

extern const unsigned char case_folded_lower[];
#define cyg_tolower(c) ((char) case_folded_lower[(unsigned char)(c)])
extern const unsigned char case_folded_upper[];
#define cyg_toupper(c) ((char) case_folded_upper[(unsigned char)(c)])

#ifndef MALLOC_DEBUG
#define cfree newlib_cfree_dont_use
#endif

/* Used as type by sys_wcstombs_alloc and sys_mbstowcs_alloc.  For a
   description see there. */
#define HEAP_NOTHEAP -1

/* Used to check if Cygwin DLL is dynamically loaded. */

extern int cygserver_running;

#define _MT_SAFE	// DELETEME someday

#define TITLESIZE 1024

#include "debug.h"

#include <wchar.h>

/**************************** Convenience ******************************/

/* Used to define status flag accessor methods */
#define IMPLEMENT_STATUS_FLAG(type,flag) \
  type flag (type val) { return (type) (status.flag = (val)); } \
  type flag () const { return (type) status.flag; }

/* Used when treating / and \ as equivalent. */
#define iswdirsep(ch) \
    ({ \
	WCHAR __c = (ch); \
	((__c) == L'/' || (__c) == L'\\'); \
    })

#define isdirsep(ch) \
    ({ \
	char __c = (ch); \
	((__c) == '/' || (__c) == '\\'); \
    })

/* Convert a signal to a signal mask */
#define SIGTOMASK(sig)	(1 << ((sig) - 1))

#define set_api_fatal_return(n) do {extern int __api_fatal_exit_val; __api_fatal_exit_val = (n);} while (0)

#undef issep
#define issep(ch) (strchr (" \t\n\r", (ch)) != NULL)

/* Every path beginning with / or \, as well as every path being X:
   or starting with X:/ or X:\ */
#define isabspath_u(p) \
  ((p)->Length && \
   (iswdirsep ((p)->Buffer[0]) || \
    ((p)->Length > sizeof (WCHAR) && iswalpha ((p)->Buffer[0]) \
    && (p)->Buffer[1] == L':' && \
    ((p)->Length == 2 * sizeof (WCHAR) || iswdirsep ((p)->Buffer[2])))))

#define iswabspath(p) \
  (iswdirsep (*(p)) || (iswalpha (*(p)) && (p)[1] == L':' && (!(p)[2] || iswdirsep ((p)[2]))))

#define isabspath(p) \
  (isdirsep (*(p)) || (isalpha (*(p)) && (p)[1] == ':' && (!(p)[2] || isdirsep ((p)[2]))))

/******************** Initialization/Termination **********************/

class per_process;
/* cygwin .dll initialization */
void dll_crt0 (per_process *) __asm__ ("_dll_crt0__FP11per_process");
extern "C" void __stdcall _dll_crt0 ();
void dll_crt0_1 (void *);
void dll_dllcrt0_1 (void *);

/* dynamically loaded dll initialization */
extern "C" PVOID dll_dllcrt0 (HMODULE, per_process *);

extern "C" void _pei386_runtime_relocator (per_process *);

#ifndef __x86_64__
/* dynamically loaded dll initialization for non-cygwin apps */
extern "C" int dll_noncygwin_dllcrt0 (HMODULE, per_process *);
#endif /* !__x86_64__ */

void __stdcall do_exit (int) __attribute__ ((regparm (1), noreturn));

/* libstdc++ malloc operator wrapper support.  */
extern struct per_process_cxx_malloc default_cygwin_cxx_malloc;

/* UID/GID */
void uinfo_init ();

#define ILLEGAL_UID ((uid_t)-1)
#define ILLEGAL_GID ((gid_t)-1)
#define ILLEGAL_SEEK ((off_t)-1)

#ifndef __x86_64__
#define ILLEGAL_UID16 ((__uid16_t)-1)
#define ILLEGAL_GID16 ((__gid16_t)-1)
#define uid16touid32(u16)  ((u16)==ILLEGAL_UID16?ILLEGAL_UID:(uid_t)(u16))
#define gid16togid32(g16)  ((g16)==ILLEGAL_GID16?ILLEGAL_GID:(gid_t)(g16))
#endif

/* Convert LARGE_INTEGER into long long */
#define get_ll(pl)  (((long long) (pl).HighPart << 32) | (pl).LowPart)

/* various events */
void events_init ();

void __stdcall close_all_files (bool = false);

/* debug_on_trap support. see exceptions.cc:try_to_debug() */
extern "C" void error_start_init (const char*);
extern "C" int try_to_debug (bool waitloop = 1);

void ld_preload ();
const char *find_first_notloaded_dll (class path_conv &);

/**************************** Miscellaneous ******************************/

void __stdcall set_std_handle (int);
int __stdcall stat_dev (DWORD, int, unsigned long, struct stat *);

ino_t __stdcall hash_path_name (ino_t hash, PUNICODE_STRING name) __attribute__ ((regparm(2)));
ino_t __stdcall hash_path_name (ino_t hash, PCWSTR name) __attribute__ ((regparm(2)));
ino_t __stdcall hash_path_name (ino_t hash, const char *name) __attribute__ ((regparm(2)));
void __stdcall nofinalslash (const char *src, char *dst) __attribute__ ((regparm(2)));

void *hook_or_detect_cygwin (const char *, const void *, WORD&, HANDLE h = NULL) __attribute__ ((regparm (3)));

/* Time related */
void __stdcall totimeval (struct timeval *, FILETIME *, int, int);
long __stdcall to_time_t (FILETIME *);
void __stdcall to_timestruc_t (FILETIME *, timestruc_t *);
void __stdcall time_as_timestruc_t (timestruc_t *);
void __stdcall timespec_to_filetime (const struct timespec *, FILETIME *);
void __stdcall timeval_to_filetime (const struct timeval *, FILETIME *);

/* Console related */
void __stdcall set_console_title (char *);
void init_console_handler (bool);

void init_global_security ();

void __set_winsock_errno (const char *fn, int ln) __attribute__ ((regparm(2)));
#define set_winsock_errno() __set_winsock_errno (__FUNCTION__, __LINE__)

extern bool wsock_started;

/* Printf type functions */
extern "C" void vapi_fatal (const char *, va_list ap) __attribute__ ((noreturn));
extern "C" void api_fatal (const char *, ...) __attribute__ ((noreturn));
int __small_sprintf (char *dst, const char *fmt, ...) /*__attribute__ ((regparm (2)))*/;
int __small_vsprintf (char *dst, const char *fmt, va_list ap) /*__attribute__ ((regparm (3)))*/;
int __small_swprintf (PWCHAR dst, const WCHAR *fmt, ...) /*__attribute__ ((regparm (2)))*/;
int __small_vswprintf (PWCHAR dst, const WCHAR *fmt, va_list ap) /*__attribute__ ((regparm (3)))*/;
void multiple_cygwin_problem (const char *, uintptr_t, uintptr_t);

extern "C" void vklog (int priority, const char *message, va_list ap);
extern "C" void klog (int priority, const char *message, ...);
bool child_copy (HANDLE, bool, ...);

int symlink_worker (const char *, const char *, bool, bool)
  __attribute__ ((regparm (3)));

class path_conv;

int __stdcall stat_worker (path_conv &pc, struct stat *buf) __attribute__ ((regparm (2)));

ino_t __stdcall readdir_get_ino (const char *path, bool dot_dot) __attribute__ ((regparm (2)));

/* mmap functions. */
enum mmap_region_status
  {
    MMAP_NONE,
    MMAP_RAISE_SIGBUS,
    MMAP_NORESERVE_COMMITED
  };
mmap_region_status mmap_is_attached_or_noreserve (void *addr, size_t len);
bool is_mmapped_region (caddr_t start_addr, caddr_t end_address);

extern inline bool flush_file_buffers (HANDLE h)
{
  return (GetFileType (h) != FILE_TYPE_PIPE) ? FlushFileBuffers (h) : true;
}
#define FlushFileBuffers flush_file_buffers

/* Make sure that regular ExitThread is never called */
#define ExitThread exit_thread

/**************************** Exports ******************************/

extern "C" {
int cygwin_select (int , fd_set *, fd_set *, fd_set *,
		   struct timeval *to);
int cygwin_gethostname (char *__name, size_t __len);
};

/*************************** Unsorted ******************************/

#define WM_ASYNCIO	0x8000		// WM_APP


#define STD_RBITS (S_IRUSR | S_IRGRP | S_IROTH)
#define STD_WBITS (S_IWUSR)
#define STD_XBITS (S_IXUSR | S_IXGRP | S_IXOTH)
#define NO_W ~(S_IWUSR | S_IWGRP | S_IWOTH)
#define NO_R ~(S_IRUSR | S_IRGRP | S_IROTH)
#define NO_X ~(S_IXUSR | S_IXGRP | S_IXOTH)


extern "C" char _data_start__, _data_end__, _bss_start__, _bss_end__;
extern "C" void (*__CTOR_LIST__) (void);
extern "C" void (*__DTOR_LIST__) (void);

#ifndef NO_GLOBALS_H
#define _RDATA	/* See globals.h */
#include "globals.h"

extern inline void clear_procimptoken ()
{
  if (hProcImpToken)
    {
      HANDLE old_procimp = hProcImpToken;
      hProcImpToken = NULL;
      CloseHandle (old_procimp);
    }
}
#endif /*NO_GLOBALS_H*/
#endif /* defined __cplusplus */
