/* winsup.h: main Cygwin header file.

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#define __INSIDE_CYGWIN__

#define strlen __builtin_strlen
#define strcmp __builtin_strcmp
#define strcpy __builtin_strcpy
#define memcpy __builtin_memcpy
#define memcmp __builtin_memcmp
#ifdef HAVE_BUILTIN_MEMSET
# define memset __builtin_memset
#endif

#define NO_COPY __attribute__((nocommon)) __attribute__((section(".data_cygwin_nocopy")))

#ifdef __cplusplus

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ >= 199900L
#define NEW_MACRO_VARARGS
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0500
#endif

#include <sys/types.h>
#include <sys/strace.h>

extern const char case_folded_lower[];
#define cyg_tolower(c) (case_folded_lower[(unsigned char)(c)])
extern const char case_folded_upper[];
#define cyg_toupper(c) (case_folded_upper[(unsigned char)(c)])

#ifndef MALLOC_DEBUG
#define cfree newlib_cfree_dont_use
#endif

#define WIN32_LEAN_AND_MEAN 1
#define _WINGDI_H
#define _WINUSER_H
#define _WINNLS_H
#define _WINVER_H
#define _WINNETWK_H
#define _WINSVC_H
#include <windows.h>
#include <wincrypt.h>
#include <lmcons.h>
#undef _WINGDI_H
#undef _WINUSER_H
#undef _WINNLS_H
#undef _WINVER_H
#undef _WINNETWK_H
#undef _WINSVC_H

#include "wincap.h"

/* The one function we use from winuser.h most of the time */
extern "C" DWORD WINAPI GetLastError (void);

enum codepage_type {ansi_cp, oem_cp};
extern codepage_type current_codepage;

UINT get_cp ();

int __stdcall sys_wcstombs(char *, const WCHAR *, int)
  __attribute__ ((regparm(3)));

int __stdcall sys_mbstowcs(WCHAR *, const char *, int)
  __attribute__ ((regparm(3)));

/* Used to check if Cygwin DLL is dynamically loaded. */
extern int dynamically_loaded;

extern int cygserver_running;

#define TITLESIZE 1024

/* status bit manipulation */
#define __ISSETF(what, x, prefix) \
  ((what)->status & prefix##_##x)
#define __SETF(what, x, prefix) \
  ((what)->status |= prefix##_##x)
#define __CLEARF(what, x, prefix) \
  ((what)->status &= ~prefix##_##x)
#define __CONDSETF(n, what, x, prefix) \
  ((n) ? __SETF (what, x, prefix) : __CLEARF (what, x, prefix))

#include "debug.h"

/* Events/mutexes */
extern HANDLE title_mutex;

/**************************** Convenience ******************************/

/* Used when treating / and \ as equivalent. */
#define isdirsep(ch) \
    ({ \
	char __c = (ch); \
	((__c) == '/' || (__c) == '\\'); \
    })

/* Convert a signal to a signal mask */
#define SIGTOMASK(sig)	(1<<((sig) - signal_shift_subtract))
extern unsigned int signal_shift_subtract;

#ifdef NEW_MACRO_VARARGS
# define api_fatal(...) __api_fatal ("%P: *** " __VA_ARGS__)
#else
# define api_fatal(fmt, args...) __api_fatal ("%P: *** " fmt,## args)
#endif

#undef issep
#define issep(ch) (strchr (" \t\n\r", (ch)) != NULL)

#define isabspath(p) \
  (isdirsep (*(p)) || (isalpha (*(p)) && (p)[1] == ':' && (!(p)[2] || isdirsep ((p)[2]))))

/******************** Initialization/Termination **********************/

class per_process;
/* cygwin .dll initialization */
void dll_crt0 (per_process *) __asm__ ("_dll_crt0__FP11per_process");
extern "C" void __stdcall _dll_crt0 ();

/* dynamically loaded dll initialization */
extern "C" int dll_dllcrt0 (HMODULE, per_process *);

/* dynamically loaded dll initialization for non-cygwin apps */
extern "C" int dll_noncygwin_dllcrt0 (HMODULE, per_process *);

/* exit the program */
extern "C" void __stdcall do_exit (int) __attribute__ ((noreturn));

/* UID/GID */
void uinfo_init (void);

#define ILLEGAL_UID16 ((__uid16_t)-1)
#define ILLEGAL_UID ((__uid32_t)-1)
#define ILLEGAL_GID16 ((__gid16_t)-1)
#define ILLEGAL_GID ((__gid32_t)-1)
#define ILLEGAL_SEEK ((__off64_t)-1)

#define uid16touid32(u16)  ((u16)==ILLEGAL_UID16?ILLEGAL_UID:(__uid32_t)(u16))
#define gid16togid32(g16)  ((g16)==ILLEGAL_GID16?ILLEGAL_GID:(__gid32_t)(g16))

extern "C" __uid32_t getuid32 (void);
extern "C" __uid32_t geteuid32 (void);
extern "C" struct passwd *getpwuid32 (__uid32_t);

/* various events */
void events_init (void);
void events_terminate (void);

void __stdcall close_all_files (void);

/* Invisible window initialization/termination. */
HWND __stdcall gethwnd (void);

/* Globals that handle initialization of winsock in a child process. */
extern HANDLE wsock32_handle;
extern HANDLE ws2_32_handle;

/* Globals that handle initialization of netapi in a child process. */
extern HANDLE netapi32_handle;

/* debug_on_trap support. see exceptions.cc:try_to_debug() */
extern "C" void error_start_init (const char*);
extern "C" int try_to_debug (bool waitloop = 1);

void set_file_api_mode (codepage_type);

extern int cygwin_finished_initializing;

/**************************** Miscellaneous ******************************/

void __stdcall set_std_handle (int);
int __stdcall writable_directory (const char *file);
int __stdcall stat_dev (DWORD, int, unsigned long, struct __stat64 *);
extern BOOL allow_ntsec;

unsigned long __stdcall hash_path_name (unsigned long hash, const char *name) __attribute__ ((regparm(2)));
void __stdcall nofinalslash (const char *src, char *dst) __attribute__ ((regparm(2)));
extern "C" char *__stdcall rootdir (char *full_path) __attribute__ ((regparm(1)));

/* String manipulation */
extern "C" char *__stdcall strccpy (char *s1, const char **s2, char c);
extern "C" int __stdcall strcasematch (const char *s1, const char *s2) __attribute__ ((regparm(2)));
extern "C" int __stdcall strncasematch (const char *s1, const char *s2, size_t n) __attribute__ ((regparm(3)));
extern "C" char *__stdcall strcasestr (const char *searchee, const char *lookfor) __attribute__ ((regparm(2)));

/* Time related */
void __stdcall totimeval (struct timeval *dst, FILETIME * src, int sub, int flag);
long __stdcall to_time_t (FILETIME * ptr);
void __stdcall to_timestruc_t (FILETIME * ptr, timestruc_t * out);
void __stdcall time_as_timestruc_t (timestruc_t * out);

void __stdcall set_console_title (char *);
void early_stuff_init ();

int __stdcall check_null_str (const char *name) __attribute__ ((regparm(1)));
int __stdcall check_null_empty_str (const char *name) __attribute__ ((regparm(1)));
int __stdcall check_null_empty_str_errno (const char *name) __attribute__ ((regparm(1)));
int __stdcall check_null_str_errno (const char *name) __attribute__ ((regparm(1)));
int __stdcall __check_null_invalid_struct (void *s, unsigned sz) __attribute__ ((regparm(2)));
int __stdcall __check_null_invalid_struct_errno (void *s, unsigned sz) __attribute__ ((regparm(2)));
int __stdcall __check_invalid_read_ptr_errno (const void *s, unsigned sz) __attribute__ ((regparm(2)));

#define check_null_invalid_struct(s) \
  __check_null_invalid_struct ((s), sizeof (*(s)))
#define check_null_invalid_struct_errno(s) \
  __check_null_invalid_struct_errno ((s), sizeof (*(s)))

struct iovec;
ssize_t check_iovec_for_read (const struct iovec *, int) __attribute__ ((regparm(2)));
ssize_t check_iovec_for_write (const struct iovec *, int) __attribute__ ((regparm(2)));

#define set_winsock_errno() __set_winsock_errno (__FUNCTION__, __LINE__)
void __set_winsock_errno (const char *fn, int ln) __attribute__ ((regparm(2)));

extern bool wsock_started;

/* Printf type functions */
extern "C" void __api_fatal (const char *, ...) __attribute__ ((noreturn));
extern "C" int __small_sprintf (char *dst, const char *fmt, ...) /*__attribute__ ((regparm (2)))*/;
extern "C" int __small_vsprintf (char *dst, const char *fmt, va_list ap) /*__attribute__ ((regparm (3)))*/;
extern void multiple_cygwin_problem (const char *, unsigned, unsigned);

class path_conv;
int __stdcall stat_worker (const char *name, struct __stat64 *buf, int nofollow,
			   path_conv *pc = NULL) __attribute__ ((regparm (3)));
int __stdcall low_priority_sleep (DWORD) __attribute__ ((regparm (1)));
#define SLEEP_0_STAY_LOW INFINITE

/**************************** Exports ******************************/

extern "C" {
int cygwin_select (int , fd_set *, fd_set *, fd_set *,
		   struct timeval *to);
int cygwin_gethostname (char *__name, size_t __len);

int kill_pgrp (pid_t, int);
int _kill (int, int);
int _raise (int sig);

extern DWORD binmode;
extern char _data_start__, _data_end__, _bss_start__, _bss_end__;
extern void (*__CTOR_LIST__) (void);
extern void (*__DTOR_LIST__) (void);
extern SYSTEM_INFO system_info;
};

/*************************** Unsorted ******************************/

#define WM_ASYNCIO	0x8000		// WM_APP

/* Note that MAX_PATH is defined in the windows headers */
/* There is also PATH_MAX and MAXPATHLEN.
   PATH_MAX is from Posix and does *not* include the trailing NUL.
   MAXPATHLEN is from Unix.

   Thou shalt use MAX_PATH throughout.  It avoids the NUL vs no-NUL
   issue and is neither of the Unixy ones [so we can punt on which
   one is the right one to use].  */

#define STD_RBITS (S_IRUSR | S_IRGRP | S_IROTH)
#define STD_WBITS (S_IWUSR)
#define STD_XBITS (S_IXUSR | S_IXGRP | S_IXOTH)
#define NO_W ~(S_IWUSR | S_IWGRP | S_IWOTH)
#define NO_R ~(S_IRUSR | S_IRGRP | S_IROTH)
#define NO_X ~(S_IXUSR | S_IXGRP | S_IXOTH)

/* The title on program start. */
extern char *old_title;
extern BOOL display_title;

extern HANDLE hMainThread;
extern HANDLE hMainProc;

extern bool cygwin_testing;
extern unsigned _cygwin_testing_magic;
extern HMODULE cygwin_hmodule;

extern char almost_null[];

#define winsock2_active (wsadata.wVersion >= 512)
#define winsock_active (wsadata.wVersion < 512)
extern struct WSAData wsadata;

#endif /* defined __cplusplus */
