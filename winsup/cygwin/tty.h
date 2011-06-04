/* tty.h: shared tty info for cygwin

   Copyright 2000, 2001, 2002, 2003, 2004, 2006, 2009, 2010, 2011 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _TTY_H
#define _TTY_H
/* tty tables */

#define INP_BUFFER_SIZE 256
#define OUT_BUFFER_SIZE 256
#define NTTYS		128
#define real_tty_attached(p)	((p)->ctty >= 0 && !iscons_dev ((p)->ctty))

/* Input/Output/ioctl events */

#define OUTPUT_DONE_EVENT	"cygtty.output.done"
#define IOCTL_REQUEST_EVENT	"cygtty.ioctl.request"
#define IOCTL_DONE_EVENT	"cygtty.ioctl.done"
#define RESTART_OUTPUT_EVENT	"cygtty.output.restart"
#define INPUT_AVAILABLE_EVENT	"cygtty.input.avail"
#define OUTPUT_MUTEX		"cygtty.output.mutex"
#define INPUT_MUTEX		"cygtty.input.mutex"
#define TTY_SLAVE_ALIVE		"cygtty.slave_alive"
#define TTY_MASTER_ALIVE	"cygtty.master_alive"

#include <sys/termios.h>

#ifndef MIN_CTRL_C_SLOP
#define MIN_CTRL_C_SLOP 50
#endif

#include <devices.h>
class tty_min
{
  pid_t sid;	/* Session ID of tty */
  struct status_flags
  {
    unsigned initialized : 1; /* Set if tty is initialized */
    unsigned rstcons     : 1; /* Set if console needs to be set to "non-cooked" */
  } status;

public:
  pid_t pgid;
  int output_stopped;
  fh_devices ntty;
  DWORD last_ctrl_c;	/* tick count of last ctrl-c */
  HWND hwnd;		/* Console window handle tty belongs to */

  IMPLEMENT_STATUS_FLAG (bool, initialized)
  IMPLEMENT_STATUS_FLAG (bool, rstcons)

  struct termios ti;
  struct winsize winsize;

  /* ioctl requests buffer */
  int cmd;
  union
  {
    struct termios termios;
    struct winsize winsize;
    int value;
    pid_t pid;
  } arg;
  /* XXX_retval variables holds master's completion codes. Error are stored as
   * -ERRNO
   */
  int ioctl_retval;
  int write_error;

  void setntty (_major_t t, int n) {ntty = (fh_devices) FHDEV (t, n);} 
  int getntty () const {return ntty;}
  int get_unit () const {return device::minor (ntty);}
  pid_t getpgid () const {return pgid;}
  void setpgid (int pid) {pgid = pid;}
  int getsid () const {return sid;}
  void setsid (pid_t tsid) {sid = tsid;}
  void kill_pgrp (int);
  int is_orphaned_process_group (int);
  HWND gethwnd () const {return hwnd;}
  void sethwnd (HWND wnd) {hwnd = wnd;}
  const char *ttyname () __attribute ((regparm (1)));
};

class fhandler_pty_master;

class tty: public tty_min
{
  HANDLE get_event (const char *fmt, PSECURITY_ATTRIBUTES sa,
		    BOOL manual_reset = FALSE);
    __attribute__ ((regparm (3)));
public:
  pid_t master_pid;	/* PID of tty master process */

  HANDLE from_master, to_master;

  int read_retval;
  bool was_opened;	/* True if opened at least once. */

  void init ();
  HANDLE open_inuse (ACCESS_MASK access);
  HANDLE create_inuse (PSECURITY_ATTRIBUTES);
  bool slave_alive ();
  HANDLE open_mutex (const char *mutex, ACCESS_MASK access);
  inline HANDLE open_output_mutex (ACCESS_MASK access)
    { return open_mutex (OUTPUT_MUTEX, access); }
  inline HANDLE open_input_mutex (ACCESS_MASK access)
    { return open_mutex (INPUT_MUTEX, access); }
  bool exists ();
  void set_master_closed () {master_pid = -1;}
  static void __stdcall create_master (int);
  static void __stdcall init_session ();
  friend class fhandler_pty_master;
};

class tty_list
{
  tty ttys[NTTYS];
  static HANDLE mutex;

public:
  tty * operator [](int n) {return ttys + device::minor (n);}
  int allocate (bool); /* true if allocate a tty, pty otherwise */
  int connect (int);
  void terminate ();
  void init ();
  tty_min *get_cttyp ();
  int __stdcall attach (int n) __attribute__ ((regparm (2)));
  static void __stdcall init_session ();
  friend class lock_ttys;
};

class lock_ttys
{
  bool release_me;
public:
  lock_ttys (DWORD = INFINITE);
  static void release ();
  void dont_release () {release_me = false;}
  ~lock_ttys ()
  {
    if (release_me)
      release ();
  }
};

extern "C" int ttyslot (void);
#endif /*_TTY_H*/
