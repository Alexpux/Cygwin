/* pinfo.h: process table info

   Copyright 2000, 2001, 2002 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _PINFO_H
#define _PINFO_H
#include <sys/resource.h>
#include "thread.h"

struct commune_result
{
  char *s;
  int n;
  HANDLE handles[2];
};

enum picom
{
  PICOM_CMDLINE = 1,
  PICOM_FIFO = 2
};

class _pinfo
{
public:
  /* Cygwin pid */
  pid_t pid;

  /* Various flags indicating the state of the process.  See PID_
     constants below. */
  DWORD process_state;

  /* If hProcess is set, it's because it came from a
     CreateProcess call.  This means it's process relative
     to the thing which created the process.  That's ok because
     we only use this handle from the parent. */
  HANDLE hProcess;

#define PINFO_REDIR_SIZE ((char *) &myself.procinfo->hProcess - (char *) myself.procinfo)

  /* Handle associated with initial Windows pid which started it all. */
  HANDLE pid_handle;

  /* Handle to the logical parent of this pid. */
  HANDLE ppid_handle;

  /* Parent process id.  */
  pid_t ppid;

  /* dwProcessId contains the processid used for sending signals.  It
   * will be reset in a child process when it is capable of receiving
   * signals.
   */
  DWORD dwProcessId;

  /* Used to spawn a child for fork(), among other things. */
  char progname[CYG_MAX_PATH];

  /* User information.
     The information is derived from the GetUserName system call,
     with the name looked up in /etc/passwd and assigned a default value
     if not found.  This data resides in the shared data area (allowing
     tasks to store whatever they want here) so it's for informational
     purposes only. */
  __uid32_t uid;	/* User ID */
  __gid32_t gid;	/* Group ID */
  pid_t pgid;		/* Process group ID */
  pid_t sid;		/* Session ID */
  int ctty;		/* Control tty */
  bool has_pgid_children;/* True if we've forked or spawned children with our GID. */

  /* Resources used by process. */
  long start_time;
  struct rusage rusage_self;
  struct rusage rusage_children;

  /* Non-zero if process was stopped by a signal. */
  char stopsig;

  /* commune */
  pid_t hello_pid;
  HANDLE tothem;
  HANDLE fromthem;

  void exit (UINT n, bool norecord = 0) __attribute__ ((noreturn, regparm(2)));

  inline void set_has_pgid_children ()
  {
    if (pgid == pid)
      has_pgid_children = 1;
  }

  inline void set_has_pgid_children (bool val) {has_pgid_children = val;}

  inline sigset_t& getsigmask ()
  {
    return sig_mask;
  }

  inline void setsigmask (sigset_t mask)
  {
    sig_mask = mask;
  }

  void commune_recv ();
  commune_result commune_send (DWORD, ...);
  bool alive ();
  char *cmdline (size_t &);

  friend void __stdcall set_myself (pid_t, HANDLE);

  /* signals */
  HANDLE sendsig;
private:
  sigset_t sig_mask;
  CRITICAL_SECTION lock;
};

class pinfo
{
  HANDLE h;
  _pinfo *procinfo;
  bool destroy;
public:
  void init (pid_t n, DWORD create = 0, HANDLE h = NULL) __attribute__ ((regparm(3)));
  pinfo () {}
  pinfo (_pinfo *x): procinfo (x) {}
  pinfo (pid_t n) {init (n);}
  pinfo (pid_t n, int create) {init (n, create);}
  void release ();
  ~pinfo ()
  {
    if (destroy && procinfo)
      release ();
  }

  _pinfo *operator -> () const {return procinfo;}
  int operator == (pinfo *x) const {return x->procinfo == procinfo;}
  int operator == (pinfo &x) const {return x.procinfo == procinfo;}
  int operator == (void *x) const {return procinfo == x;}
  int operator == (int x) const {return (int) procinfo == (int) x;}
  int operator == (char *x) const {return (char *) procinfo == x;}
  _pinfo *operator * () const {return procinfo;}
  operator _pinfo * () const {return procinfo;}
  // operator bool () const {return (int) h;}
#ifndef _SIGPROC_H
  int remember () {system_printf ("remember is not here"); return 0;}
#else
  int remember ()
  {
    int res = proc_subproc (PROC_ADDCHILD, (DWORD) this);
    destroy = res ? false : true;
    return res;
  }
#endif
  HANDLE shared_handle () {return h;}
  void set_acl();
};

#define ISSTATE(p, f)	(!!((p)->process_state & f))
#define NOTSTATE(p, f)	(!((p)->process_state & f))

class winpids
{
  DWORD *pidlist;
  DWORD npidlist;
  pinfo *pinfolist;
  DWORD pinfo_access;		// access type for pinfo open
  DWORD (winpids::* enum_processes) (bool winpid);
  DWORD enum_init (bool winpid);
  DWORD enumNT (bool winpid);
  DWORD enum9x (bool winpid);
  void add (DWORD& nelem, bool, DWORD pid);
  static CRITICAL_SECTION cs;
public:
  DWORD npids;
  inline void reset () { npids = 0; release (); }
  void set (bool winpid);
  winpids (int): pinfo_access (0), enum_processes (&winpids::enum_init)
    { reset (); }
  winpids (DWORD acc = 0): pidlist (NULL), npidlist (0), pinfolist (NULL),
  			   enum_processes (&winpids::enum_init), npids (0)
  {
    pinfo_access = acc;
    set (0);
  }
  inline DWORD& winpid (int i) const {return pidlist[i];}
  inline _pinfo *operator [] (int i) const {return (_pinfo *) pinfolist[i];}
  ~winpids ();
  void release ();
  static void init ();
};

extern __inline pid_t
cygwin_pid (pid_t pid)
{
  return (pid_t) (wincap.has_negative_pids ()) ? -(int) pid : pid;
}

void __stdcall pinfo_init (char **, int);
void __stdcall set_myself (pid_t pid, HANDLE h = NULL);
extern pinfo myself;

#define _P_VFORK 0
#define _P_SYSTEM 512

extern void __stdcall pinfo_fixup_after_fork ();
extern HANDLE hexec_proc;

/* For mmaps across fork(). */
int __stdcall fixup_mmaps_after_fork (HANDLE parent);
/* for shm areas across fork (). */
int __stdcall fixup_shms_after_fork ();

void __stdcall fill_rusage (struct rusage *, HANDLE);
void __stdcall add_rusage (struct rusage *, struct rusage *);
#endif /*_PINFO_H*/
