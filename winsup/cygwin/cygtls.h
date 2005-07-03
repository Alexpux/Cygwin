/* cygtls.h

   Copyright 2003, 2004, 2005 Red Hat, Inc.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _CYGTLS_H
#define _CYGTLS_H

#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <sys/time.h>
#define _NOMNTENT_FUNCS
#include <mntent.h>
#undef _NOMNTENT_FUNCS
#include <setjmp.h>

#ifndef _WINSOCK_H
/* Stupid hack: Including winsock.h explicitly causes too many problems. */
struct sockaddr_in
{
  short   sin_family;
  u_short sin_port;
  struct in_addr
  {
    union
    {
      struct
      {
	u_char s_b1, s_b2, s_b3, s_b4;
      } S_un_b;
      struct
      {
	u_short s_w1, s_w2;
      } S_un_w;
      u_long S_addr;
    } S_un;
  };
  struct  in_addr sin_addr;
  char    sin_zero[8];
};
typedef unsigned int SOCKET;
#endif

#define CYGTLS_INITIALIZED 0x43227
#define CYGTLS_EXCEPTION (0x43227 + true)
#define CYGTLSMAGIC "D0Ub313v31nm&G1c?";

#ifndef CYG_MAX_PATH
# define CYG_MAX_PATH 260
#endif

#ifndef UNLEN
# define UNLEN 256
#endif

#define TLS_STACK_SIZE 256

#include "cygthread.h"

#pragma pack(push,4)
struct _local_storage
{
  /*
     Needed for the group functions
   */
  struct __group16 grp;
  char *namearray[2];
  int grp_pos;

  /* console.cc */
  unsigned rarg;

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
  SOCKET exitsock;
  struct sockaddr_in exitsock_sin;

  /* strerror */
  char strerror_buf[20];

  /* sysloc.cc */
  char *process_ident;			// note: malloced
  int process_logopt;
  int process_facility;
  int process_logmask;

  /* times.cc */
  char timezone_buf[20];
  struct tm _localtime_buf;

  /* uinfo.cc */
  char username[UNLEN + 1];

  /* net.cc */
  char *ntoa_buf;			// note: malloced
  struct protoent *protoent_buf;	// note: malloced
  struct servent *servent_buf;		// note: malloced
  struct hostent *hostent_buf;		// note: malloced
  char signamebuf[sizeof ("Unknown signal 4294967295   ")];

  /* cygthread.cc */
  char unknown_thread_name[30];

  /* syscalls.cc */
  int setmode_file;
  int setmode_mode;
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

extern "C" int __sjfault (jmp_buf);
/*gentls_offsets*/

typedef __uint32_t __stack_t;
struct _cygtls
{
  void (*func) /*gentls_offsets*/(int)/*gentls_offsets*/;
  int saved_errno;
  int sa_flags;
  sigset_t oldmask;
  sigset_t deltamask;
  HANDLE event;
  int *errno_addr;
  unsigned initialized;
  sigset_t sigmask;
  sigset_t sigwait_mask;
  siginfo_t *sigwait_info;
  unsigned threadkill;
  siginfo_t infodata;
  struct pthread *tid;
  union
    {
      struct _reent local_clib;
      char __dontuse[8 * ((sizeof(struct _reent) + 4) / 8)];
    };
  struct _local_storage locals;
  class cygthread *_ctinfo;
  void *_myfault;
  int _myfault_errno;
  waitq wq;
  struct _cygtls *prev, *next;
  __stack_t *stackptr;
  int sig;
  unsigned incyg;
  unsigned spinning;
  unsigned stacklock;
  __stack_t stack[TLS_STACK_SIZE];
  unsigned padding[0];

  /*gentls_offsets*/
  static CRITICAL_SECTION protect_linked_list;
  static void init ();
  void init_thread (void *, DWORD (*) (void *, void *));
  static void call (DWORD (*) (void *, void *), void *);
  static void call2 (DWORD (*) (void *, void *), void *, void *) __attribute__ ((regparm (3)));
  static struct _cygtls *find_tls (int sig);
  void remove (DWORD);
  void push (__stack_t, bool) __attribute__ ((regparm (3)));
  __stack_t pop () __attribute__ ((regparm (1)));
  bool isinitialized () const {return initialized == CYGTLS_INITIALIZED || initialized == CYGTLS_EXCEPTION;}
  bool in_exception () const {return initialized == CYGTLS_EXCEPTION;}
  void set_state (bool);
  void reset_exception ();
  bool interrupt_now (CONTEXT *, int, void *, struct sigaction&)
    __attribute__((regparm(3)));
  void __stdcall interrupt_setup (int sig, void *handler,
				  struct sigaction& siga)
    __attribute__((regparm(3)));
  void init_threadlist_exceptions (struct _exception_list *);
#ifdef _THREAD_H
  operator HANDLE () const {return tid->win32_obj_id;}
#endif
  void set_siginfo (struct sigpacket *) __attribute__ ((regparm (3)));
  void set_threadkill () {threadkill = true;}
  void reset_threadkill () {threadkill = false;}
  int call_signal_handler () __attribute__ ((regparm (1)));
  void remove_wq (DWORD) __attribute__ ((regparm (1)));
  void fixup_after_fork () __attribute__ ((regparm (1)));
  void lock () __attribute__ ((regparm (1)));
  void unlock () __attribute__ ((regparm (1)));
  bool locked () __attribute__ ((regparm (1)));
  void*& fault_guarded () {return _myfault;}
  void return_from_fault ()
  {
    if (_myfault_errno)
      set_errno (_myfault_errno);
    longjmp ((int *) _myfault, 1);
  }
  int setup_fault (jmp_buf j, int myerrno) __attribute__ ((always_inline))
  {
    if (_myfault)
      return 0;
    _myfault = (void *) j;
    _myfault_errno = myerrno;
    return __sjfault (j);
  }
  void clear_fault (jmp_buf j) __attribute__ ((always_inline))
  {
    if (j == _myfault)
      _myfault = NULL;
  }
  /*gentls_offsets*/
};
#pragma pack(pop)

extern char *_tlsbase __asm__ ("%fs:4");
extern char *_tlstop __asm__ ("%fs:8");
#define _my_tls (((_cygtls *) _tlsbase)[-1])
extern _cygtls *_main_tls;

/*gentls_offsets*/
class myfault
{
  jmp_buf buf;
public:
  ~myfault () __attribute__ ((always_inline))
    {
      _my_tls.clear_fault (buf);
    }
  inline int faulted (int myerrno = 0) __attribute__ ((always_inline))
  {
    return _my_tls.setup_fault (buf, myerrno);
  }
};
/*gentls_offsets*/

#define __getreent() (&_my_tls.local_clib)

const int CYGTLS_PADSIZE  = (((char *) _main_tls->padding) - ((char *) _main_tls));
#endif /*_CYGTLS_H*/
