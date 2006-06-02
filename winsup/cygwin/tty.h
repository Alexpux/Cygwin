/* tty.h: shared tty info for cygwin

   Copyright 2000, 2001, 2002, 2003, 2004 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

/* tty tables */

#define INP_BUFFER_SIZE 256
#define OUT_BUFFER_SIZE 256
#define NTTYS		128
#define real_tty_attached(p)	((p)->ctty >= 0 && (p)->ctty != TTY_CONSOLE)

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
  int ntty;
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

  tty_min (int t = -1, pid_t s = -1) : sid (s), ntty (t) {}
  void setntty (int n) {ntty = n;}
  pid_t getpgid () {return pgid;}
  void setpgid (int pid) {pgid = pid;}
  int getsid () {return sid;}
  void setsid (pid_t tsid) {sid = tsid;}
  void kill_pgrp (int sig);
  HWND gethwnd () {return hwnd;}
  void sethwnd (HWND wnd) {hwnd = wnd;}
};

class fhandler_pty_master;

class tty: public tty_min
{
  HANDLE get_event (const char *fmt, BOOL manual_reset = FALSE)
    __attribute__ ((regparm (3)));
public:
  pid_t master_pid;	/* PID of tty master process */

  HANDLE from_master, to_master;

  int read_retval;
  bool was_opened;	/* True if opened at least once. */

  void init ();
  HANDLE create_inuse (const char *);
  bool alive (const char *fmt);
  bool slave_alive ();
  bool master_alive ();
  HANDLE open_mutex (const char *mutex);
  HANDLE open_output_mutex ();
  HANDLE open_input_mutex ();
  bool exists ()
  {
    HANDLE h = open_output_mutex ();
    if (h)
      {
	CloseHandle (h);
	return 1;
      }
    return slave_alive ();
  }
  friend class fhandler_pty_master;
};

class tty_list
{
  tty ttys[NTTYS];

public:
  tty * operator [](int n) {return ttys + n;}
  int allocate_tty (bool); /* true if allocate a tty, pty otherwise */
  int connect_tty (int);
  void terminate ();
  void init ();
  tty_min *get_tty (int n);
};

void __stdcall tty_init ();
void __stdcall tty_terminate ();
int __stdcall attach_tty (int);
void __stdcall create_tty_master (int);
extern "C" int ttyslot (void);
