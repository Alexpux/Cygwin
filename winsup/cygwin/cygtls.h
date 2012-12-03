/* cygtls.h

   Copyright 2003, 2004, 2005, 2008, 2009, 2010, 2011, 2012 Red Hat, Inc.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#pragma once

#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#define _NOMNTENT_FUNCS
#include <mntent.h>
#undef _NOMNTENT_FUNCS
#include <setjmp.h>

#define CYGTLS_INITIALIZED 0xc763173f

#ifndef CYG_MAX_PATH
# define CYG_MAX_PATH 260
#endif

#ifndef UNLEN
# define UNLEN 256
#endif

#define TLS_STACK_SIZE 256

#include "cygthread.h"

#define TP_NUM_C_BUFS 10
#define TP_NUM_W_BUFS 10

#ifdef CYGTLS_HANDLE
#include "thread.h"
#endif

#pragma pack(push,4)
/* Defined here to support auto rebuild of tlsoffsets.h. */
class tls_pathbuf
{
  int c_cnt;
  int w_cnt;
  char  *c_buf[TP_NUM_C_BUFS];
  WCHAR *w_buf[TP_NUM_W_BUFS];

public:
  void destroy ();
  friend class tmp_pathbuf;
  friend class _cygtls;
  friend class san;
};

class unionent
{
public:
  char *name;
  char **list;
  short port_proto_addrtype;
  short h_len;
  union
  {
    char *s_proto;
    char **h_addr_list;
  };
  enum struct_type
  {
    t_hostent, t_protoent, t_servent
  };
};

struct _local_storage
{
  /*
     Needed for the group functions
   */
  int grp_pos;

  /* dlfcn.cc */
  int dl_error;
  char dl_buffer[256];

  /* passwd.cc */
  struct passwd res;
  char pass[_PASSWORD_LEN];
  int pw_pos;

  /* path.cc */
  struct mntent mntbuf;
  int iteration;
  unsigned available_drives;
  char mnt_type[80];
  char mnt_opts[80];
  char mnt_fsname[CYG_MAX_PATH];
  char mnt_dir[CYG_MAX_PATH];

  /* select.cc */
  struct {
    HANDLE  sockevt;
    int     max_w4;
    LONG   *ser_num;			// note: malloced
    HANDLE *w4;				// note: malloced
  } select;

  /* strerror errno.cc */
  char strerror_buf[sizeof ("Unknown error -2147483648")];
  char strerror_r_buf[sizeof ("Unknown error -2147483648")];

  /* times.cc */
  char timezone_buf[20];

  /* strsig.cc */
  char signamebuf[sizeof ("Unknown signal 4294967295   ")];

  /* net.cc */
  char *ntoa_buf;			// note: malloced
  unionent *hostent_buf;		// note: malloced
  unionent *protoent_buf;		// note: malloced
  unionent *servent_buf;		// note: malloced

  /* cygthread.cc */
  char unknown_thread_name[30];

  /* syscalls.cc */
  int setmode_file;
  int setmode_mode;

  /* thread.cc */
  HANDLE cw_timer;

  /* All functions requiring temporary path buffers. */
  tls_pathbuf pathbufs;
  char ttybuf[32];
};

typedef struct struct_waitq
{
  int pid;
  int options;
  int status;
  HANDLE ev;
  void *rusage;			/* pointer to potential rusage */
  struct struct_waitq *next;
  HANDLE thread_ev;
} waitq;

/* Changes to the below structure may require acompanying changes to the very
   simple parser in the perl script 'gentls_offsets' (<<-- start parsing here).
   The union in this structure is used to force alignment between the version
   of the compiler used to generate tlsoffsets.h and the cygwin cross compiler.
*/

/*gentls_offsets*/
#include "cygerrno.h"
#include "security.h"

extern "C" int __sjfault (jmp_buf);
extern "C" int __ljfault (jmp_buf, int);

/*gentls_offsets*/

typedef uintptr_t __stack_t;

class _cygtls
{
public:
  /* Please keep these two declarations first */
  struct _local_storage locals;
  union
  {
    struct _reent local_clib;
    char __dontuse[8 * ((sizeof(struct _reent) + 4) / 8)];
  };
  /**/
  void (*func) /*gentls_offsets*/(int)/*gentls_offsets*/;
  int saved_errno;
  int sa_flags;
  sigset_t oldmask;
  sigset_t deltamask;
  int *errno_addr;
  sigset_t sigmask;
  sigset_t sigwait_mask;
  siginfo_t *sigwait_info;
  HANDLE signal_arrived;
  bool signal_waiting;
  struct ucontext thread_context;
  DWORD thread_id;
  siginfo_t infodata;
  struct pthread *tid;
  class cygthread *_ctinfo;
  class san *andreas;
  waitq wq;
  int sig;
  unsigned incyg;
  unsigned spinning;
  unsigned stacklock;
  __stack_t *stackptr;
  __stack_t stack[TLS_STACK_SIZE];
  unsigned initialized;

  /*gentls_offsets*/
  void init_thread (void *, DWORD (*) (void *, void *));
  static void call (DWORD (*) (void *, void *), void *);
  void remove (DWORD);
  void push (__stack_t addr) {*stackptr++ = (__stack_t) addr;}
  __stack_t pop () __attribute__ ((regparm (1)));
  __stack_t retaddr () {return stackptr[-1];}
  bool isinitialized () const
  {
    return initialized == CYGTLS_INITIALIZED;
  }
  bool interrupt_now (CONTEXT *, siginfo_t&, void *, struct sigaction&)
    __attribute__((regparm(3)));
  void __stdcall interrupt_setup (siginfo_t&, void *, struct sigaction&)
    __attribute__((regparm(3)));

  bool inside_kernel (CONTEXT *);
  void signal_exit (int) __attribute__ ((noreturn, regparm(2)));
  void copy_context (CONTEXT *) __attribute__ ((regparm(2)));
  void signal_debugger (int) __attribute__ ((regparm(2)));

#ifdef CYGTLS_HANDLE
  operator HANDLE () const {return tid ? tid->win32_obj_id : NULL;}
#endif
  int call_signal_handler () __attribute__ ((regparm (1)));
  void remove_wq (DWORD) __attribute__ ((regparm (1)));
  void fixup_after_fork () __attribute__ ((regparm (1)));
  void lock () __attribute__ ((regparm (1)));
  void unlock () __attribute__ ((regparm (1)));
  bool locked () __attribute__ ((regparm (1)));
  void create_signal_arrived ()
  {
    signal_arrived = CreateEvent (&sec_none_nih, false, false, NULL);
  }
  void set_signal_arrived (bool setit, HANDLE& h)
  {
    if (!setit)
      signal_waiting = false;
    else
      {
	if (!signal_arrived)
	  {
	    lock ();
	    create_signal_arrived ();
	    unlock ();
	  }
	h = signal_arrived;
	signal_waiting = true;
      }
  }
  void reset_signal_arrived () { signal_waiting = false; }
private:
  void call2 (DWORD (*) (void *, void *), void *, void *) __attribute__ ((regparm (3)));
  /*gentls_offsets*/
};
#pragma pack(pop)

/* FIXME: Find some way to autogenerate this value */
#ifdef __x86_64__
/* FIXME: Is that padding sufficent for the 64 bit stack? */
const int CYGTLS_PADSIZE = 12800;	/* Must be 16-byte aligned */
#else
const int CYGTLS_PADSIZE = 12700;
#endif

/*gentls_offsets*/

#ifdef __x86_64__
extern char *_tlsbase __asm__ ("%gs:8");
extern char *_tlstop __asm__ ("%gs:16");
#else
extern char *_tlsbase __asm__ ("%fs:4");
extern char *_tlstop __asm__ ("%fs:8");
#endif
#define _my_tls (*((_cygtls *) (_tlsbase - CYGTLS_PADSIZE)))
extern _cygtls *_main_tls;
extern _cygtls *_sig_tls;

class san
{
  san *_clemente;
  jmp_buf _context;
  int _errno;
  int _c_cnt;
  int _w_cnt;
public:
  int setup (int myerrno = 0) __attribute__ ((always_inline))
  {
    _clemente = _my_tls.andreas;
    _my_tls.andreas = this;
    _errno = myerrno;
    _c_cnt = _my_tls.locals.pathbufs.c_cnt;
    _w_cnt = _my_tls.locals.pathbufs.w_cnt;
    return __sjfault (_context);
  }
  void leave () __attribute__ ((always_inline))
  {
    if (_errno)
      set_errno (_errno);
    /* Restore tls_pathbuf counters in case of error. */
    _my_tls.locals.pathbufs.c_cnt = _c_cnt;
    _my_tls.locals.pathbufs.w_cnt = _w_cnt;
    __ljfault (_context, 1);
  }
  void reset () __attribute__ ((always_inline))
  {
    _my_tls.andreas = _clemente;
  }
};

class myfault
{
  san sebastian;
public:
  ~myfault () __attribute__ ((always_inline)) { sebastian.reset (); }
  inline int faulted () __attribute__ ((always_inline))
  {
    return sebastian.setup (0);
  }
  inline int faulted (void const *obj, int myerrno = 0) __attribute__ ((always_inline))
  {
    return !obj || !(*(const char **) obj) || sebastian.setup (myerrno);
  }
  inline int faulted (int myerrno) __attribute__ ((always_inline))
  {
    return sebastian.setup (myerrno);
  }
};

class set_signal_arrived
{
public:
  set_signal_arrived (bool setit, HANDLE& h) { _my_tls.set_signal_arrived (setit, h); }
  set_signal_arrived (HANDLE& h) { _my_tls.set_signal_arrived (true, h); }

  operator int () const {return _my_tls.signal_waiting;}
  ~set_signal_arrived () { _my_tls.reset_signal_arrived (); }
};

#define __getreent() (&_my_tls.local_clib)
/*gentls_offsets*/
