/* sys/cygwin.h

   Copyright 1997, 1998, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
   2007, 2008, 2009, 2010 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _SYS_CYGWIN_H
#define _SYS_CYGWIN_H

#include <sys/types.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#define _CYGWIN_SIGNAL_STRING "cYgSiGw00f"

/* DEPRECATED INTERFACES.  These are restricted to MAX_PATH length.
   Don't use in modern applications. */
extern int cygwin_win32_to_posix_path_list (const char *, char *)
  __attribute__ ((deprecated));
extern int cygwin_win32_to_posix_path_list_buf_size (const char *)
  __attribute__ ((deprecated));
extern int cygwin_posix_to_win32_path_list (const char *, char *)
  __attribute__ ((deprecated));
extern int cygwin_posix_to_win32_path_list_buf_size (const char *)
  __attribute__ ((deprecated));
extern int cygwin_conv_to_win32_path (const char *, char *)
  __attribute__ ((deprecated));
extern int cygwin_conv_to_full_win32_path (const char *, char *)
  __attribute__ ((deprecated));
extern int cygwin_conv_to_posix_path (const char *, char *)
  __attribute__ ((deprecated));
extern int cygwin_conv_to_full_posix_path (const char *, char *)
  __attribute__ ((deprecated));

/* Use these interfaces in favor of the above. */

/* Possible 'what' values in calls to cygwin_conv_path/cygwin_create_path. */
enum
{
  CCP_POSIX_TO_WIN_A = 0, /* from is char*, to is char*       */
  CCP_POSIX_TO_WIN_W,	  /* from is char*, to is wchar_t*    */
  CCP_WIN_A_TO_POSIX,	  /* from is char*, to is char*       */
  CCP_WIN_W_TO_POSIX,	  /* from is wchar_t*, to is char*    */

  /* Or these values to the above as needed. */
  CCP_ABSOLUTE = 0,	  /* Request absolute path (default). */
  CCP_RELATIVE = 0x100    /* Request to keep path relative.   */
};
typedef unsigned int cygwin_conv_path_t;

/* If size is 0, cygwin_conv_path returns the required buffer size in bytes.
   Otherwise, it returns 0 on success, or -1 on error and errno is set to
   one of the below values:

    EINVAL        what has an invalid value.
    EFAULT        from or to point into nirvana.
    ENAMETOOLONG  the resulting path is longer than 32K, or, in case
		  of what == CCP_POSIX_TO_WIN_A, longer than MAX_PATH.
    ENOSPC        size is less than required for the conversion.
*/
extern ssize_t cygwin_conv_path (cygwin_conv_path_t what, const void *from,
				 void *to, size_t size);
/* Same, but handles path lists separated by colon or semicolon. */
extern ssize_t cygwin_conv_path_list (cygwin_conv_path_t what, const void *from,
				 void *to, size_t size);
/* Allocate a buffer for the conversion result using malloc(3), and return
   a pointer to it.  Returns NULL if something goes wrong with errno set
   to one of the above values, or to ENOMEM if malloc fails. */
extern void *cygwin_create_path (cygwin_conv_path_t what, const void *from);

extern pid_t cygwin_winpid_to_pid (int);
extern int cygwin_posix_path_list_p (const char *);
extern void cygwin_split_path (const char *, char *, char *);

struct __cygwin_perfile
{
  const char *name;
  unsigned flags;
};

/* External interface stuff */

/* Always add at the bottom.  Do not add new values in the middle. */
typedef enum
  {
    CW_LOCK_PINFO,
    CW_UNLOCK_PINFO,
    CW_GETTHREADNAME,
    CW_GETPINFO,
    CW_SETPINFO,
    CW_SETTHREADNAME,
    CW_GETVERSIONINFO,
    CW_READ_V1_MOUNT_TABLES,
    CW_USER_DATA,
    CW_PERFILE,
    CW_GET_CYGDRIVE_PREFIXES,
    CW_GETPINFO_FULL,
    CW_INIT_EXCEPTIONS,
    CW_GET_CYGDRIVE_INFO,
    CW_SET_CYGWIN_REGISTRY_NAME,
    CW_GET_CYGWIN_REGISTRY_NAME,
    CW_STRACE_TOGGLE,
    CW_STRACE_ACTIVE,
    CW_CYGWIN_PID_TO_WINPID,
    CW_EXTRACT_DOMAIN_AND_USER,
    CW_CMDLINE,
    CW_CHECK_NTSEC,
    CW_GET_ERRNO_FROM_WINERROR,
    CW_GET_POSIX_SECURITY_ATTRIBUTE,
    CW_GET_SHMLBA,
    CW_GET_UID_FROM_SID,
    CW_GET_GID_FROM_SID,
    CW_GET_BINMODE,
    CW_HOOK,
    CW_ARGV,
    CW_ENVP,
    CW_DEBUG_SELF,
    CW_SYNC_WINENV,
    CW_CYGTLS_PADSIZE,
    CW_SET_DOS_FILE_WARNING,
    CW_SET_PRIV_KEY,
    CW_SETERRNO,
    CW_EXIT_PROCESS,
    CW_SET_EXTERNAL_TOKEN,
    CW_GET_INSTKEY,
    CW_INT_SETLOCALE,
    CW_CVT_MNT_OPTS,
    CW_LST_MNT_OPTS,
    CW_STRERROR
  } cygwin_getinfo_types;

/* Token type for CW_SET_EXTERNAL_TOKEN */
enum
{
  CW_TOKEN_IMPERSONATION = 0,
  CW_TOKEN_RESTRICTED    = 1
};

#define CW_NEXTPID	0x80000000	/* or with pid to get next one */
unsigned long cygwin_internal (cygwin_getinfo_types, ...);

/* Flags associated with process_state */
enum
{
  PID_IN_USE	       = 0x00001, /* Entry in use. */
  PID_UNUSED	       = 0x00002, /* Available. */
  PID_STOPPED	       = 0x00004, /* Waiting for SIGCONT. */
  PID_TTYIN	       = 0x00008, /* Waiting for terminal input. */
  PID_TTYOU	       = 0x00010, /* Waiting for terminal output. */
  PID_NOTCYGWIN	       = 0x00020, /* Set if process is not a cygwin app. */
  PID_ACTIVE	       = 0x00040, /* Pid accepts signals. */
  PID_CYGPARENT	       = 0x00080, /* Set if parent was a cygwin app. */
  PID_MAP_RW	       = 0x00100, /* Flag to open map rw. */
  PID_MYSELF	       = 0x00200, /* Flag that pid is me. */
  PID_NOCLDSTOP	       = 0x00400, /* Set if no SIGCHLD signal on stop. */
  PID_INITIALIZING     = 0x00800, /* Set until ready to receive signals. */
  PID_USETTY	       = 0x01000, /* Setting this enables or disables cygwin's
				     tty support.  This is inherited by
				     all execed or forked processes. */
  PID_ALLPIDS	       = 0x02000, /* used by pinfo scanner */
  PID_EXECED	       = 0x04000, /* redirect to original pid info block */
  PID_NOREDIR	       = 0x08000, /* don't redirect if execed */
  PID_EXITED	       = 0x80000000 /* Free entry. */
};

#ifdef WINVER

/* This lives in the app and is initialized before jumping into the DLL.
   It should only contain stuff which the user's process needs to see, or
   which is needed before the user pointer is initialized, or is needed to
   carry inheritance information from parent to child.  Note that it cannot
   be used to carry inheritance information across exec!

   Remember, this structure is linked into the application's executable.
   Changes to this can invalidate existing executables, so we go to extra
   lengths to avoid having to do it.

   When adding/deleting members, remember to adjust {public,internal}_reserved.
   The size of the class shouldn't change [unless you really are prepared to
   invalidate all existing executables].  The program does a check (using
   SIZEOF_PER_PROCESS) to make sure you remember to make the adjustment.
*/

#ifdef __cplusplus
class MTinterface;
#endif

struct per_process_cxx_malloc;

struct per_process
{
  char *initial_sp;

  /* The offset of these 3 values can never change. */
  /* magic_biscuit is the size of this class and should never change. */
  unsigned long magic_biscuit;
  unsigned long dll_major;
  unsigned long dll_minor;

  struct _reent **impure_ptr_ptr;
  char ***envptr;

  /* Used to point to the memory machine we should use.  Usually these
     point back into the dll, but they can be overridden by the user. */
  void *(*malloc)(size_t);
  void (*free)(void *);
  void *(*realloc)(void *, size_t);

  int *fmode_ptr;

  int (*main)(int, char **, char **);
  void (**ctors)(void);
  void (**dtors)(void);

  /* For fork */
  void *data_start;
  void *data_end;
  void *bss_start;
  void *bss_end;

  void *(*calloc)(size_t, size_t);
  /* For future expansion of values set by the app. */
  void (*premain[4]) (int, char **, struct per_process *);

  /* non-zero of ctors have been run.  Inherited from parent. */
  int run_ctors_p;

  DWORD unused[7];

  /* Pointers to real operator new/delete functions for forwarding.  */
  struct per_process_cxx_malloc *cxx_malloc;

  HMODULE hmodule;

  DWORD api_major;		/* API version that this program was */
  DWORD api_minor;		/*  linked with */
  /* For future expansion, so apps won't have to be relinked if we
     add an item. */
  DWORD unused2[3];
  void *pseudo_reloc_start;
  void *pseudo_reloc_end;
  void *image_base;

#if defined (__INSIDE_CYGWIN__) && defined (__cplusplus)
  MTinterface *threadinterface;
#else
  void *threadinterface;
#endif
  struct _reent *impure_ptr;
};
#define per_process_overwrite ((unsigned) &(((struct per_process *) NULL)->threadinterface))

#ifdef _PATH_PASSWD
extern HANDLE cygwin_logon_user (const struct passwd *, const char *);
#endif
extern void cygwin_set_impersonation_token (const HANDLE);

/* included if <windows.h> is included */
extern int cygwin_attach_handle_to_fd (char *, int, HANDLE, mode_t, DWORD);

extern void cygwin_premain0 (int, char **, struct per_process *);
extern void cygwin_premain1 (int, char **, struct per_process *);
extern void cygwin_premain2 (int, char **, struct per_process *);
extern void cygwin_premain3 (int, char **, struct per_process *);

#ifdef __CYGWIN__
#include <sys/resource.h>

#define TTY_CONSOLE	0x40000000

#define EXTERNAL_PINFO_VERSION_16_BIT 0
#define EXTERNAL_PINFO_VERSION_32_BIT 1
#define EXTERNAL_PINFO_VERSION_32_LP  2
#define EXTERNAL_PINFO_VERSION EXTERNAL_PINFO_VERSION_32_LP

#ifndef _SYS_TYPES_H
typedef unsigned short __uid16_t;
typedef unsigned short __gid16_t;
typedef unsigned long __uid32_t;
typedef unsigned long __gid32_t;
#endif

struct external_pinfo
  {
  pid_t pid;
  pid_t ppid;
  DWORD exitcode;
  DWORD dwProcessId, dwSpawnedProcessId;
  __uid16_t uid;
  __gid16_t gid;
  pid_t pgid;
  pid_t sid;
  int ctty;
  mode_t umask;

  long start_time;
  struct rusage rusage_self;
  struct rusage rusage_children;

  char progname[MAX_PATH];

  DWORD strace_mask;
  DWORD version;

  DWORD process_state;

  /* Only available if version >= EXTERNAL_PINFO_VERSION_32_BIT */
  __uid32_t uid32;
  __gid32_t gid32;

  /* Only available if version >= EXTERNAL_PINFO_VERSION_32_LP */
  char *progname_long;
};
#endif /*__CYGWIN__*/
#endif /*WINVER*/

#ifdef __cplusplus
};
#endif
#endif /* _SYS_CYGWIN_H */
