/* fhandler.h

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _FHANDLER_H_
#define _FHANDLER_H_

#include <sys/ioctl.h>
#include <fcntl.h>

enum
{
  FH_RBINARY	= 0x00001000,	/* binary read mode */
  FH_WBINARY	= 0x00002000,	/* binary write mode */
  FH_CLOEXEC	= 0x00004000,	/* close-on-exec */
  FH_RBINSET	= 0x00008000,	/* binary read mode has been explicitly set */
  FH_WBINSET	= 0x00010000,	/* binary write mode has been explicitly set */
  FH_APPEND	= 0x00020000,	/* always append */
  FH_ASYNC	= 0x00040000,	/* async I/O */
  FH_SIGCLOSE	= 0x00080000,	/* signal handler should close fd on interrupt */

  FH_SYMLINK	= 0x00100000,	/* is a symlink */
  FH_EXECABL	= 0x00200000,	/* file looked like it would run:
				 * ends in .exe or .bat or begins with #! */
  FH_W95LSBUG	= 0x00400000,	/* set when lseek is called as a flag that
				 * _write should check if we've moved beyond
				 * EOF, zero filling if so. */
  FH_NOHANDLE	= 0x00800000,	/* No handle associated with fhandler. */
  FH_NOEINTR	= 0x01000000,	/* Set if I/O should be uninterruptible. */
  FH_FFIXUP	= 0x02000000,	/* Set if need to fixup after fork. */
  FH_LOCAL	= 0x04000000,	/* File is unix domain socket */
  FH_SHUTRD	= 0x08000000,	/* Socket saw a SHUT_RD */
  FH_SHUTWR	= 0x10000000,	/* Socket saw a SHUT_WR */
  FH_ISREMOTE	= 0x10000000,	/* File is on a remote drive */
  FH_DCEXEC	= 0x20000000,	/* Don't care if this is executable */
  FH_HASACLS	= 0x40000000,	/* True if fs of file has ACLS */
  FH_QUERYOPEN	= 0x80000000,	/* open file without requesting either read
				   or write access */

  /* Device flags */

  /* Slow devices */
  FH_CONSOLE = 0x00000001,	/* is a console */
  FH_CONIN   = 0x00000002,	/* console input */
  FH_CONOUT  = 0x00000003,	/* console output */
  FH_TTYM    = 0x00000004,	/* is a tty master */
  FH_TTYS    = 0x00000005,	/* is a tty slave */
  FH_PTYM    = 0x00000006,	/* is a pty master */
  FH_SERIAL  = 0x00000007,	/* is a serial port */
  FH_PIPE    = 0x00000008,	/* is a pipe */
  FH_PIPER   = 0x00000009,	/* read end of a pipe */
  FH_PIPEW   = 0x0000000a,	/* write end of a pipe */
  FH_SOCKET  = 0x0000000b,	/* is a socket */
  FH_WINDOWS = 0x0000000c,	/* is a window */
  FH_SLOW    = 0x00000010,	/* "slow" device if below this */

  /* Fast devices */
  FH_DISK    = 0x00000010,	/* is a disk */
  FH_FLOPPY  = 0x00000011,	/* is a floppy */
  FH_TAPE    = 0x00000012,	/* is a tape */
  FH_NULL    = 0x00000013,	/* is the null device */
  FH_ZERO    = 0x00000014,	/* is the zero device */
  FH_RANDOM  = 0x00000015,	/* is a random device */
  FH_MEM     = 0x00000016,	/* is a mem device */
  FH_CLIPBOARD = 0x00000017,	/* is a clipboard device */
  FH_OSS_DSP = 0x00000018,	/* is a dsp audio device */
  FH_CYGDRIVE= 0x00000019,	/* /cygdrive/x */
  FH_PROC    = 0x0000001a,      /* /proc */
  FH_REGISTRY =0x0000001b,      /* /proc/registry */
  FH_PROCESS = 0x0000001c,      /* /proc/<n> */

  FH_NDEV    = 0x0000001d,      /* Maximum number of devices */
  FH_DEVMASK = 0x00000fff,	/* devices live here */
  FH_BAD     = 0xffffffff
};

#define FHDEVN(n)	((n) & FH_DEVMASK)
#define FHISSETF(x)	__ISSETF (this, x, FH)
#define FHSETF(x)	__SETF (this, x, FH)
#define FHCLEARF(x)	__CLEARF (this, x, FH)
#define FHCONDSETF(n, x) __CONDSETF(n, this, x, FH)

#define FHSTATOFF	0

/* fcntl flags used only internaly. */
#define O_NOSYMLINK 0x080000
#define O_DIROPEN   0x100000

/* newlib used to define O_NDELAY differently from O_NONBLOCK.  Now it
   properly defines both to be the same.  Unfortunately, we have to
   behave properly the old version, too, to accommodate older executables. */
#define OLD_O_NDELAY	(CYGWIN_VERSION_CHECK_FOR_OLD_O_NONBLOCK ? 4 : 0)

/* Care for the old O_NDELAY flag. If one of the flags is set,
   both flags are set. */
#define O_NONBLOCK_MASK (O_NONBLOCK | OLD_O_NDELAY)

#define UNCONNECTED     0
#define CONNECT_PENDING 1
#define CONNECTED       2

extern const char *windows_device_names[];
extern struct __cygwin_perfile *perfile_table;
#define __fmode (*(user_data->fmode_ptr))
extern const char proc[];
extern const int proc_len;

class select_record;
class path_conv;
class fhandler_disk_file;
typedef struct __DIR DIR;
struct dirent;
struct iovec;

enum line_edit_status
{
  line_edit_ok = 0,
  line_edit_input_done = 1,
  line_edit_signalled = 2,
  line_edit_error = 3,
  line_edit_pipe_full = 4
};

enum bg_check_types
{
  bg_error = -1,
  bg_eof = 0,
  bg_ok = 1,
  bg_signalled = 2
};

enum executable_states
{
  is_executable,
  dont_care_if_executable,
  not_executable = dont_care_if_executable,
  dont_know_if_executable
};

class fhandler_base
{
 protected:
  DWORD status;
 private:
  int access;
  HANDLE io_handle;

  unsigned long namehash;	/* hashed filename, used as inode num */

 protected:
  /* Full unix path name of this file */
  /* File open flags from open () and fcntl () calls */
  int openflags;

  char *rabuf;		/* used for crlf conversion in text files */
  size_t ralen;
  size_t raixget;
  size_t raixput;
  size_t rabuflen;

  const char *unix_path_name;
  const char *win32_path_name;
  DWORD open_status;
  HANDLE read_state;

 public:
  void set_name (const char * unix_path, const char *win32_path = NULL, int unit = 0);

  virtual fhandler_base& operator =(fhandler_base &x);
  fhandler_base (DWORD dev, int unit = 0);
  virtual ~fhandler_base ();

  /* Non-virtual simple accessor functions. */
  void set_io_handle (HANDLE x) { io_handle = x; }

  DWORD get_device () { return status & FH_DEVMASK; }
  virtual int get_unit () { return 0; }
  virtual BOOL is_slow () { return get_device () < FH_SLOW; }

  int get_access () { return access; }
  void set_access (int x) { access = x; }

  bool get_async () { return FHISSETF (ASYNC); }
  void set_async (int x) { FHCONDSETF (x, ASYNC); }

  int get_flags () { return openflags; }
  void set_flags (int x, int supplied_bin = 0);

  bool is_nonblocking ();
  void set_nonblocking (int yes);

  bool get_w_binary () { return FHISSETF (WBINSET) ? FHISSETF (WBINARY) : 1; }
  bool get_r_binary () { return FHISSETF (RBINSET) ? FHISSETF (RBINARY) : 1; }

  bool get_w_binset () { return FHISSETF (WBINSET); }
  bool get_r_binset () { return FHISSETF (RBINSET); }

  void set_w_binary (int b) { FHCONDSETF (b, WBINARY); FHSETF (WBINSET); }
  void set_r_binary (int b) { FHCONDSETF (b, RBINARY); FHSETF (RBINSET); }
  void clear_w_binary () {FHCLEARF (WBINARY); FHCLEARF (WBINSET); }
  void clear_r_binary () {FHCLEARF (RBINARY); FHCLEARF (RBINSET); }

  bool get_nohandle () { return FHISSETF (NOHANDLE); }
  void set_nohandle (int x) { FHCONDSETF (x, NOHANDLE); }

  void set_open_status () {open_status = status;}
  DWORD get_open_status () {return open_status;}
  void reset_to_open_binmode ()
  {
    set_flags ((get_flags () & ~(O_TEXT | O_BINARY))
	       | ((open_status & (FH_WBINARY | FH_RBINARY)
		   ? O_BINARY : O_TEXT)));
  }

  int get_default_fmode (int flags);

  bool get_r_no_interrupt () { return FHISSETF (NOEINTR); }
  void set_r_no_interrupt (bool b) { FHCONDSETF (b, NOEINTR); }

  bool get_close_on_exec () { return FHISSETF (CLOEXEC); }
  int set_close_on_exec_flag (int b) { return FHCONDSETF (b, CLOEXEC); }

  LPSECURITY_ATTRIBUTES get_inheritance (bool all = 0)
  {
    if (all)
      return get_close_on_exec () ? &sec_all_nih : &sec_all;
    else
      return get_close_on_exec () ? &sec_none_nih : &sec_none;
  }

  void set_check_win95_lseek_bug (int b = 1) { FHCONDSETF (b, W95LSBUG); }
  bool get_check_win95_lseek_bug () { return FHISSETF (W95LSBUG); }

  bool get_need_fork_fixup () { return FHISSETF (FFIXUP); }
  void set_need_fork_fixup () { FHSETF (FFIXUP); }

  virtual void set_close_on_exec (int val);

  virtual void fixup_before_fork_exec (DWORD) {}
  virtual void fixup_after_fork (HANDLE);
  virtual void fixup_after_exec (HANDLE) {}

  bool get_symlink_p () { return FHISSETF (SYMLINK); }
  void set_symlink_p (int val) { FHCONDSETF (val, SYMLINK); }
  void set_symlink_p () { FHSETF (SYMLINK); }

  bool get_socket_p () { return FHISSETF (LOCAL); }
  void set_socket_p (int val) { FHCONDSETF (val, LOCAL); }
  void set_socket_p () { FHSETF (LOCAL); }

  bool get_execable_p () { return FHISSETF (EXECABL); }
  void set_execable_p (executable_states val)
  {
    FHCONDSETF (val == is_executable, EXECABL);
    FHCONDSETF (val == dont_care_if_executable, DCEXEC);
  }
  void set_execable_p () { FHSETF (EXECABL); }
  bool dont_care_if_execable () { return FHISSETF (DCEXEC); }
  bool exec_state_isknown () { return FHISSETF (DCEXEC) || FHISSETF (EXECABL); }

  bool get_append_p () { return FHISSETF (APPEND); }
  void set_append_p (int val) { FHCONDSETF (val, APPEND); }
  void set_append_p () { FHSETF (APPEND); }

  bool get_query_open () { return FHISSETF (QUERYOPEN); }
  void set_query_open (bool val) { FHCONDSETF (val, QUERYOPEN); }

  bool get_readahead_valid () { return raixget < ralen; }
  int puts_readahead (const char *s, size_t len = (size_t) -1);
  int put_readahead (char value);

  int get_readahead ();
  int peek_readahead (int queryput = 0);

  int eat_readahead (int n);

  void set_readahead_valid (int val, int ch = -1);

  int get_readahead_into_buffer (char *buf, size_t buflen);

  bool has_acls () { return FHISSETF (HASACLS); }
  void set_has_acls (int val) { FHCONDSETF (val, HASACLS); }

  bool isremote () { return FHISSETF (ISREMOTE); }
  void set_isremote (int val) { FHCONDSETF (val, ISREMOTE); }

  const char *get_name () { return unix_path_name; }
  const char *get_win32_name () { return win32_path_name; }
  unsigned long get_namehash () { return namehash; }

  virtual void hclose (HANDLE h) {CloseHandle (h);}
  virtual void set_inheritance (HANDLE &h, int not_inheriting);

  /* fixup fd possibly non-inherited handles after fork */
  void fork_fixup (HANDLE parent, HANDLE &h, const char *name);

  virtual int open (path_conv *real_path, int flags, mode_t mode = 0);
  virtual int close ();
  virtual int __stdcall fstat (struct __stat64 *buf, path_conv *) __attribute__ ((regparm (3)));
  virtual int ioctl (unsigned int cmd, void *);
  virtual int fcntl (int cmd, void *);
  virtual char const * ttyname () { return get_name(); }
  virtual void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  virtual int write (const void *ptr, size_t len);
  virtual ssize_t readv (const struct iovec *, int iovcnt, ssize_t tot = -1);
  virtual ssize_t writev (const struct iovec *, int iovcnt, ssize_t tot = -1);
  virtual __off64_t lseek (__off64_t offset, int whence);
  virtual int lock (int, struct flock *);
  virtual void dump ();
  virtual int dup (fhandler_base *child);

  virtual HANDLE mmap (caddr_t *addr, size_t len, DWORD access,
		       int flags, __off64_t off);
  virtual int munmap (HANDLE h, caddr_t addr, size_t len);
  virtual int msync (HANDLE h, caddr_t addr, size_t len, int flags);
  virtual BOOL fixup_mmap_after_fork (HANDLE h, DWORD access, DWORD offset,
				      DWORD size, void *address);

  void *operator new (size_t, void *p) {return p;}

  virtual void init (HANDLE, DWORD, mode_t);

  virtual int tcflush (int);
  virtual int tcsendbreak (int);
  virtual int tcdrain ();
  virtual int tcflow (int);
  virtual int tcsetattr (int a, const struct termios *t);
  virtual int tcgetattr (struct termios *t);
  virtual int tcsetpgrp (const pid_t pid);
  virtual int tcgetpgrp ();
  virtual int is_tty () { return 0; }
  virtual BOOL is_device () { return TRUE; }
  virtual char *ptsname () { return NULL;}
  virtual class fhandler_socket *is_socket () { return 0; }
  virtual class fhandler_console *is_console () { return 0; }
  virtual int is_windows () {return 0; }

  virtual void raw_read (void *ptr, size_t& ulen);
  virtual int raw_write (const void *ptr, size_t ulen);

  /* Virtual accessor functions to hide the fact
     that some fd's have two handles. */
  virtual HANDLE& get_handle () { return io_handle; }
  virtual HANDLE& get_io_handle () { return io_handle; }
  virtual HANDLE& get_output_handle () { return io_handle; }
  virtual bool hit_eof () {return FALSE;}
  virtual select_record *select_read (select_record *s);
  virtual select_record *select_write (select_record *s);
  virtual select_record *select_except (select_record *s);
  virtual int ready_for_read (int fd, DWORD howlong);
  virtual const char * get_native_name ()
  {
    return windows_device_names[FHDEVN (status)];
  }
  virtual bg_check_types bg_check (int) {return bg_ok;}
  void clear_readahead ()
  {
    raixput = raixget = ralen = rabuflen = 0;
    rabuf = NULL;
  }
  void operator delete (void *);
  virtual HANDLE get_guard () const {return NULL;}
  virtual void set_eof () {}
  virtual DIR *opendir (path_conv& pc);
  virtual dirent *readdir (DIR *);
  virtual __off64_t telldir (DIR *);
  virtual void seekdir (DIR *, __off64_t);
  virtual void rewinddir (DIR *);
  virtual int closedir (DIR *);
};

class fhandler_socket: public fhandler_base
{
 private:
  int addr_family;
  int type;
  int connect_secret [4];
  HANDLE secret_event;
  struct _WSAPROTOCOL_INFOA *prot_info_ptr;
  char *sun_path;
  int had_connect_or_listen;

 public:
  fhandler_socket ();
  ~fhandler_socket ();
  int get_socket () { return (int) get_handle(); }
  fhandler_socket * is_socket () { return this; }

  bool saw_shutdown_read () const {return FHISSETF (SHUTRD);}
  bool saw_shutdown_write () const {return FHISSETF (SHUTWR);}

  void set_shutdown_read () {FHSETF (SHUTRD);}
  void set_shutdown_write () {FHSETF (SHUTWR);}

  bool is_unconnected () const {return had_connect_or_listen == UNCONNECTED;}
  bool is_connect_pending () const {return had_connect_or_listen == CONNECT_PENDING;}
  bool is_connected () const {return had_connect_or_listen == CONNECTED;}
  void set_connect_state (int newstate) { had_connect_or_listen = newstate; }

  int bind (const struct sockaddr *name, int namelen);
  int connect (const struct sockaddr *name, int namelen);
  int listen (int backlog);
  int accept (struct sockaddr *peer, int *len);
  int getsockname (struct sockaddr *name, int *namelen);
  int getpeername (struct sockaddr *name, int *namelen);

  ssize_t readv (const struct iovec *, int iovcnt, ssize_t tot = -1);
  int recvfrom (void *ptr, size_t len, int flags,
		struct sockaddr *from, int *fromlen);
  int recvmsg (struct msghdr *msg, int flags, ssize_t tot = -1);

  ssize_t writev (const struct iovec *, int iovcnt, ssize_t tot = -1);
  int sendto (const void *ptr, size_t len, int flags,
	      const struct sockaddr *to, int tolen);
  int sendmsg (const struct msghdr *msg, int flags, ssize_t tot = -1);

  int ioctl (unsigned int cmd, void *);
  int fcntl (int cmd, void *);
  __off64_t lseek (__off64_t, int) { return 0; }
  int shutdown (int how);
  int close ();
  void hclose (HANDLE) {close ();}
  int dup (fhandler_base *child);

  void set_close_on_exec (int val);
  virtual void fixup_before_fork_exec (DWORD);
  void fixup_after_fork (HANDLE);
  void fixup_after_exec (HANDLE);

  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
  void set_addr_family (int af) {addr_family = af;}
  int get_addr_family () {return addr_family;}
  void set_socket_type (int st) { type = st;}
  int get_socket_type () {return type;}
  void set_sun_path (const char *path);
  char *get_sun_path () {return sun_path;}
  void set_connect_secret ();
  void get_connect_secret (char*);
  HANDLE create_secret_event (int *secret = NULL);
  int check_peer_secret_event (struct sockaddr_in *peer, int *secret = NULL);
  void signal_secret_event ();
  void close_secret_event ();
  int __stdcall fstat (struct __stat64 *buf, path_conv *) __attribute__ ((regparm (3)));
};

class fhandler_pipe: public fhandler_base
{
  HANDLE guard;
  bool broken_pipe;
  HANDLE writepipe_exists;
  DWORD orig_pid;
  unsigned id;
 public:
  fhandler_pipe (DWORD devtype);
  __off64_t lseek (__off64_t offset, int whence);
  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
  void set_close_on_exec (int val);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  int close ();
  void create_guard (SECURITY_ATTRIBUTES *sa) {guard = CreateMutex (sa, FALSE, NULL);}
  int dup (fhandler_base *child);
  int ioctl (unsigned int cmd, void *);
  void fixup_after_fork (HANDLE);
  void fixup_after_exec (HANDLE);
  bool hit_eof ();
  void set_eof () {broken_pipe = true;}
  friend int make_pipe (int fildes[2], unsigned int psize, int mode);
  HANDLE get_guard () const {return guard;}
  int ready_for_read (int fd, DWORD howlong);
};

class fhandler_dev_raw: public fhandler_base
{
 protected:
  char *devbuf;
  size_t devbufsiz;
  size_t devbufstart;
  size_t devbufend;
  int eom_detected    : 1;
  int eof_detected    : 1;
  int lastblk_to_read : 1;
  int is_writing      : 1;
  int has_written     : 1;
  int varblkop	      : 1;
  int unit;

  virtual void clear (void);
  virtual int writebuf (void);

  /* returns not null, if `win_error' determines an end of media condition */
  virtual int is_eom(int win_error) = 0;
  /* returns not null, if `win_error' determines an end of file condition */
  virtual int is_eof(int win_error) = 0;

  fhandler_dev_raw (DWORD dev, int unit);

 public:
  ~fhandler_dev_raw (void);

  int get_unit () { return unit; }

  int open (path_conv *, int flags, mode_t mode = 0);
  int close (void);

  void raw_read (void *ptr, size_t& ulen);
  int raw_write (const void *ptr, size_t ulen);

  int dup (fhandler_base *child);

  int ioctl (unsigned int cmd, void *buf);

  void fixup_after_fork (HANDLE);
  void fixup_after_exec (HANDLE);
};

class fhandler_dev_floppy: public fhandler_dev_raw
{
 protected:
  virtual int is_eom (int win_error);
  virtual int is_eof (int win_error);

 public:
  fhandler_dev_floppy (int unit);

  virtual int open (path_conv *, int flags, mode_t mode = 0);
  virtual int close (void);

  virtual __off64_t lseek (__off64_t offset, int whence);

  virtual int ioctl (unsigned int cmd, void *buf);
};

class fhandler_dev_tape: public fhandler_dev_raw
{
  int lasterr;

  bool is_rewind_device () { return get_unit () < 128; }

 protected:
  virtual void clear (void);

  virtual int is_eom (int win_error);
  virtual int is_eof (int win_error);

 public:
  fhandler_dev_tape (int unit);

  virtual int open (path_conv *, int flags, mode_t mode = 0);
  virtual int close (void);

  virtual __off64_t lseek (__off64_t offset, int whence);

  virtual int __stdcall fstat (struct __stat64 *buf, path_conv *) __attribute__ ((regparm (3)));

  virtual int dup (fhandler_base *child);

  virtual int ioctl (unsigned int cmd, void *buf);

 private:
  int tape_write_marks (int marktype, DWORD len);
  int tape_get_pos (unsigned long *ret);
  int tape_set_pos (int mode, long count, BOOLEAN sfm_func = FALSE);
  int tape_erase (int mode);
  int tape_prepare (int action);
  BOOLEAN tape_get_feature (DWORD parm);
  int tape_get_blocksize (long *min, long *def, long *max, long *cur);
  int tape_set_blocksize (long count);
  int tape_status (struct mtget *get);
  int tape_compression (long count);
};

/* Standard disk file */

class fhandler_disk_file: public fhandler_base
{
 public:
  fhandler_disk_file ();
  fhandler_disk_file (DWORD devtype);

  int open (path_conv * real_path, int flags, mode_t mode);
  int close ();
  int lock (int, struct flock *);
  BOOL is_device () { return FALSE; }
  int __stdcall fstat (struct __stat64 *buf, path_conv *pc) __attribute__ ((regparm (3)));
  int __stdcall fstat_helper (struct __stat64 *buf, path_conv *pc,
			      FILETIME ftCreateionTime,
			      FILETIME ftLastAccessTime,
			      FILETIME ftLastWriteTime,
			      DWORD nFileSizeHigh,
			      DWORD nFileSizeLow,
			      DWORD nFileIndexHigh = 0,
			      DWORD nFileIndexLow = 0,
			      DWORD nNumberOfLinks = 1)
    __attribute__ ((regparm (3)));
  int __stdcall fstat_by_handle (struct __stat64 *buf, path_conv *pc) __attribute__ ((regparm (3)));
  int __stdcall fstat_by_name (struct __stat64 *buf, path_conv *pc) __attribute__ ((regparm (3)));

  HANDLE mmap (caddr_t *addr, size_t len, DWORD access, int flags, __off64_t off);
  int munmap (HANDLE h, caddr_t addr, size_t len);
  int msync (HANDLE h, caddr_t addr, size_t len, int flags);
  BOOL fixup_mmap_after_fork (HANDLE h, DWORD access, DWORD offset,
			      DWORD size, void *address);
  DIR *opendir (path_conv& pc);
  struct dirent *readdir (DIR *);
  __off64_t telldir (DIR *);
  void seekdir (DIR *, __off64_t);
  void rewinddir (DIR *);
  int closedir (DIR *);
};

class fhandler_cygdrive: public fhandler_disk_file
{
  int unit;
  int ndrives;
  const char *pdrive;
  void set_drives ();
 public:
  bool iscygdrive_root () const { return !unit; }
  fhandler_cygdrive (int unit);
  DIR *opendir (path_conv& pc);
  struct dirent *readdir (DIR *);
  __off64_t telldir (DIR *);
  void seekdir (DIR *, __off64_t);
  void rewinddir (DIR *);
  int closedir (DIR *);
  int __stdcall fstat (struct __stat64 *buf, path_conv *pc) __attribute__ ((regparm (3)));
};

class fhandler_serial: public fhandler_base
{
 private:
  size_t vmin_;				/* from termios */
  unsigned int vtime_;			/* from termios */
  pid_t pgrp_;
  int rts;				/* for Windows 9x purposes only */
  int dtr;				/* for Windows 9x purposes only */

 public:
  int overlapped_armed;
  OVERLAPPED io_status;
  DWORD ev;

  /* Constructor */
  fhandler_serial (int unit);

  int open (path_conv *, int flags, mode_t mode);
  int close ();
  void init (HANDLE h, DWORD a, mode_t flags);
  void overlapped_setup ();
  int dup (fhandler_base *child);
  void raw_read (void *ptr, size_t& ulen);
  int raw_write (const void *ptr, size_t ulen);
  int tcsendbreak (int);
  int tcdrain ();
  int tcflow (int);
  int ioctl (unsigned int cmd, void *);
  int tcsetattr (int a, const struct termios *t);
  int tcgetattr (struct termios *t);
  __off64_t lseek (__off64_t, int) { return 0; }
  int tcflush (int);
  void dump ();
  int is_tty () { return 1; }
  void fixup_after_fork (HANDLE parent);
  void fixup_after_exec (HANDLE);

  /* We maintain a pgrp so that tcsetpgrp and tcgetpgrp work, but we
     don't use it for permissions checking.  fhandler_tty_slave does
     permission checking on pgrps.  */
  virtual int tcgetpgrp () { return pgrp_; }
  virtual int tcsetpgrp (const pid_t pid) { pgrp_ = pid; return 0; }
  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
};

#define acquire_output_mutex(ms) \
  __acquire_output_mutex (__PRETTY_FUNCTION__, __LINE__, ms);

#define release_output_mutex() \
  __release_output_mutex (__PRETTY_FUNCTION__, __LINE__);

class tty;
class tty_min;
class fhandler_termios: public fhandler_base
{
 protected:
  HANDLE output_handle;
  virtual void doecho (const void *, DWORD) {};
  virtual int accept_input () {return 1;};
 public:
  tty_min *tc;
  fhandler_termios (DWORD dev, int unit = 0) :
  fhandler_base (dev, unit)
  {
    set_need_fork_fixup ();
  }
  HANDLE& get_output_handle () { return output_handle; }
  line_edit_status line_edit (const char *rptr, int nread, int always_accept = 0);
  void set_output_handle (HANDLE h) { output_handle = h; }
  void tcinit (tty_min *this_tc, int force = FALSE);
  virtual int is_tty () { return 1; }
  int tcgetpgrp ();
  int tcsetpgrp (int pid);
  bg_check_types bg_check (int sig);
  virtual DWORD __acquire_output_mutex (const char *fn, int ln, DWORD ms) {return 1;}
  virtual void __release_output_mutex (const char *fn, int ln) {}
  void fixup_after_fork (HANDLE);
  void fixup_after_exec (HANDLE parent) { fixup_after_fork (parent); }
  void echo_erase (int force = 0);
  virtual __off64_t lseek (__off64_t, int);
};

enum ansi_intensity
{
  INTENSITY_INVISIBLE,
  INTENSITY_DIM,
  INTENSITY_NORMAL,
  INTENSITY_BOLD
};

#define normal 0
#define gotesc 1
#define gotsquare 2
#define gotarg1 3
#define gotrsquare 4
#define gotcommand 5
#define gettitle 6
#define eattitle 7
#define MAXARGS 10

class dev_console
{
  WORD default_color, underline_color, dim_color;

  /* Used to determine if an input keystroke should be modified with META. */
  int meta_mask;

/* Output state */
  int state_;
  int args_[MAXARGS];
  int nargs_;
  unsigned rarg;
  bool saw_question_mark;

  char my_title_buf [TITLESIZE + 1];

  WORD current_win32_attr;
  ansi_intensity intensity;
  bool underline, blink, reverse;
  WORD fg, bg;

  /* saved cursor coordinates */
  int savex, savey;

  /* saved screen */
  COORD savebufsiz;
  PCHAR_INFO savebuf;

  struct
    {
      short Top, Bottom;
    } scroll_region;
  struct
    {
      SHORT winTop;
      SHORT winBottom;
      COORD dwWinSize;
      COORD dwBufferSize;
      COORD dwCursorPosition;
      WORD wAttributes;
    } info;

  COORD dwLastCursorPosition;
  DWORD dwLastButtonState;
  int nModifiers;

  bool insert_mode;
  bool use_mouse;
  bool raw_win32_keyboard_mode;
  friend class fhandler_console;
};

/* This is a input and output console handle */
class fhandler_console: public fhandler_termios
{
 private:
  static dev_console *dev_state;

/* Output calls */
  void set_default_attr ();
  WORD get_win32_attr ();

  BOOL fillin_info ();
  void clear_screen (int, int, int, int);
  void scroll_screen (int, int, int, int, int, int);
  void cursor_set (BOOL, int, int);
  void cursor_get (int *, int *);
  void cursor_rel (int, int);
  const unsigned char * write_normal (unsigned const char*, unsigned const char *);
  void char_command (char);
  BOOL set_raw_win32_keyboard_mode (BOOL);
  int output_tcsetattr (int a, const struct termios *t);

/* Input calls */
  int igncr_enabled ();
  int input_tcsetattr (int a, const struct termios *t);
  void set_cursor_maybe ();

 public:

  fhandler_console ();

  fhandler_console* is_console () { return this; }

  int open (path_conv *, int flags, mode_t mode = 0);

  int write (const void *ptr, size_t len);
  void doecho (const void *str, DWORD len) { (void) write (str, len); }
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  int close ();

  int tcflush (int);
  int tcsetattr (int a, const struct termios *t);
  int tcgetattr (struct termios *t);

  /* Special dup as we must dup two handles */
  int dup (fhandler_base *child);

  int ioctl (unsigned int cmd, void *);
  void init (HANDLE, DWORD, mode_t);
  bool mouse_aware () {return dev_state->use_mouse;}

  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
  void fixup_after_exec (HANDLE);
  void set_close_on_exec (int val);
  void fixup_after_fork (HANDLE parent);
  void set_input_state ();
  void send_winch_maybe ();
  static tty_min *get_tty_stuff (int);
};

class fhandler_tty_common: public fhandler_termios
{
 public:
  fhandler_tty_common (DWORD dev, int unit = 0)
    : fhandler_termios (dev, unit), output_done_event (NULL),
    ioctl_request_event (NULL), ioctl_done_event (NULL), output_mutex (NULL),
    input_mutex (NULL), input_available_event (NULL), inuse (NULL), ttynum (unit)
  {
    // nothing to do
  }
  HANDLE output_done_event;	// Raised by master when tty's output buffer
				// written. Write status in tty::write_retval.
  HANDLE ioctl_request_event;	// Raised by slave to perform ioctl() request.
				// Ioctl() request in tty::cmd/arg.
  HANDLE ioctl_done_event;	// Raised by master on ioctl() completion.
				// Ioctl() status in tty::ioctl_retval.
  HANDLE output_mutex, input_mutex;
  HANDLE input_available_event;
  HANDLE inuse;			// used to indicate that a tty is in use
  int ttynum;			// Master tty num.

  DWORD __acquire_output_mutex (const char *fn, int ln, DWORD ms);
  void __release_output_mutex (const char *fn, int ln);

  virtual int dup (fhandler_base *child);

  tty *get_ttyp () { return (tty *)tc; }
  int get_unit () { return ttynum; }

  int close ();
  void set_close_on_exec (int val);
  void fixup_after_fork (HANDLE parent);
  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
};

class fhandler_tty_slave: public fhandler_tty_common
{
 public:
  /* Constructor */
  fhandler_tty_slave ();
  fhandler_tty_slave (int);

  int open (path_conv *, int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  void init (HANDLE, DWORD, mode_t);

  int tcsetattr (int a, const struct termios *t);
  int tcgetattr (struct termios *t);
  int tcflush (int);
  int ioctl (unsigned int cmd, void *);

  __off64_t lseek (__off64_t, int) { return 0; }
  select_record *select_read (select_record *s);
  int cygserver_attach_tty (HANDLE*, HANDLE*);
};

class fhandler_pty_master: public fhandler_tty_common
{
  int pktmode;			// non-zero if pty in a packet mode.
 public:
  int need_nl;			// Next read should start with \n

  /* Constructor */
  fhandler_pty_master (DWORD devtype = FH_PTYM, int unit = -1);

  int process_slave_output (char *buf, size_t len, int pktmode_on);
  void doecho (const void *str, DWORD len);
  int accept_input ();
  int open (path_conv *, int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  int close ();

  int tcsetattr (int a, const struct termios *t);
  int tcgetattr (struct termios *t);
  int tcflush (int);
  int ioctl (unsigned int cmd, void *);

  __off64_t lseek (__off64_t, int) { return 0; }
  char *ptsname ();

  void set_close_on_exec (int val);
  bool hit_eof ();
};

class fhandler_tty_master: public fhandler_pty_master
{
 public:
  /* Constructor */
  fhandler_console *console;	// device handler to perform real i/o.

  fhandler_tty_master (int unit);
  int init (int);
  int init_console ();
  void fixup_after_fork (HANDLE parent);
  void fixup_after_exec (HANDLE);
};

class fhandler_dev_null: public fhandler_base
{
 public:
  fhandler_dev_null ();

  void dump ();
  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
};

class fhandler_dev_zero: public fhandler_base
{
 public:
  fhandler_dev_zero ();
  int open (path_conv *, int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  __off64_t lseek (__off64_t offset, int whence);

  void dump ();
};

class fhandler_dev_random: public fhandler_base
{
 protected:
  int unit;
  HCRYPTPROV crypt_prov;
  long pseudo;

  BOOL crypt_gen_random (void *ptr, size_t len);
  int pseudo_write (const void *ptr, size_t len);
  int pseudo_read (void *ptr, size_t len);

 public:
  fhandler_dev_random (int unit);
  int get_unit () { return unit; }
  int open (path_conv *, int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  __off64_t lseek (__off64_t offset, int whence);
  int close (void);
  int dup (fhandler_base *child);

  void dump ();
};

class fhandler_dev_mem: public fhandler_base
{
 protected:
  int unit;
  DWORD mem_size;
  __off64_t pos;

 public:
  fhandler_dev_mem (int unit);
  ~fhandler_dev_mem (void);

  int open (path_conv *, int flags, mode_t mode = 0);
  int write (const void *ptr, size_t ulen);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  __off64_t lseek (__off64_t offset, int whence);
  int close (void);
  int __stdcall fstat (struct __stat64 *buf, path_conv *) __attribute__ ((regparm (3)));
  int dup (fhandler_base *child);

  HANDLE mmap (caddr_t *addr, size_t len, DWORD access, int flags, __off64_t off);
  int munmap (HANDLE h, caddr_t addr, size_t len);
  int msync (HANDLE h, caddr_t addr, size_t len, int flags);
  BOOL fixup_mmap_after_fork (HANDLE h, DWORD access, DWORD offset,
			      DWORD size, void *address);

  void dump ();
} ;

class fhandler_dev_clipboard: public fhandler_base
{
 public:
  fhandler_dev_clipboard ();
  int is_windows (void) { return 1; }
  int open (path_conv *, int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  __off64_t lseek (__off64_t offset, int whence);
  int close (void);

  int dup (fhandler_base *child);

  void dump ();

 private:
  __off64_t pos;
  void *membuffer;
  size_t msize;
  bool eof;
};

class fhandler_windows: public fhandler_base
{
 private:
  HWND hWnd_;	// the window whose messages are to be retrieved by read() call
  int method_;  // write method (Post or Send)
 public:
  fhandler_windows ();
  int is_windows (void) { return 1; }
  int open (path_conv *, int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  int ioctl (unsigned int cmd, void *);
  __off64_t lseek (__off64_t, int) { return 0; }
  int close (void) { return 0; }

  void set_close_on_exec (int val);
  void fixup_after_fork (HANDLE parent);
  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
};

class fhandler_dev_dsp : public fhandler_base
{
 private:
  int audioformat_;
  int audiofreq_;
  int audiobits_;
  int audiochannels_;
  bool setupwav(const char *pData, int nBytes);
 public:
  fhandler_dev_dsp ();
  ~fhandler_dev_dsp();

  int open (path_conv *, int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  int ioctl (unsigned int cmd, void *);
  __off64_t lseek (__off64_t, int);
  int close (void);
  int dup (fhandler_base * child);
  void dump (void);
  void fixup_after_exec (HANDLE);
};

class fhandler_virtual : public fhandler_base
{
 protected:
  char *filebuf;
  size_t bufalloc, filesize;
  __off64_t position;
  int fileid; // unique within each class
 public:

  fhandler_virtual (DWORD devtype);
  virtual ~fhandler_virtual();

  virtual int exists();
  DIR *opendir (path_conv& pc);
  __off64_t telldir (DIR *);
  void seekdir (DIR *, __off64_t);
  void rewinddir (DIR *);
  int closedir (DIR *);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  __off64_t lseek (__off64_t, int);
  int dup (fhandler_base * child);
  int open (path_conv *, int flags, mode_t mode = 0);
  int close (void);
  int __stdcall fstat (struct stat *buf, path_conv *pc) __attribute__ ((regparm (3)));
  virtual bool fill_filebuf ();
  void fixup_after_exec (HANDLE);
};

class fhandler_proc: public fhandler_virtual
{
 public:
  fhandler_proc ();
  fhandler_proc (DWORD devtype);
  int exists();
  struct dirent *readdir (DIR *);
  static DWORD get_proc_fhandler(const char *path);

  int open (path_conv *real_path, int flags, mode_t mode = 0);
  int __stdcall fstat (struct __stat64 *buf, path_conv *) __attribute__ ((regparm (3)));
  bool fill_filebuf ();
};

class fhandler_registry: public fhandler_proc
{
 private:
  char *value_name;
 public:
  fhandler_registry ();
  int exists();
  struct dirent *readdir (DIR *);
  __off64_t telldir (DIR *);
  void seekdir (DIR *, __off64_t);
  void rewinddir (DIR *);
  int closedir (DIR *);

  int open (path_conv *real_path, int flags, mode_t mode = 0);
  int __stdcall fstat (struct __stat64 *buf, path_conv *) __attribute__ ((regparm (3)));
  bool fill_filebuf ();
  int close (void);
};

class pinfo;
class fhandler_process: public fhandler_proc
{
  pid_t pid;
 public:
  fhandler_process ();
  int exists();
  struct dirent *readdir (DIR *);
  int open (path_conv *real_path, int flags, mode_t mode = 0);
  int __stdcall fstat (struct __stat64 *buf, path_conv *) __attribute__ ((regparm (3)));
  bool fill_filebuf ();
};

typedef union
{
  char __base[sizeof (fhandler_base)];
  char __console[sizeof (fhandler_console)];
  char __cygdrive[sizeof (fhandler_cygdrive)];
  char __dev_clipboard[sizeof (fhandler_dev_clipboard)];
  char __dev_dsp[sizeof (fhandler_dev_dsp)];
  char __dev_floppy[sizeof (fhandler_dev_floppy)];
  char __dev_mem[sizeof (fhandler_dev_mem)];
  char __dev_null[sizeof (fhandler_dev_null)];
  char __dev_random[sizeof (fhandler_dev_random)];
  char __dev_raw[sizeof (fhandler_dev_raw)];
  char __dev_tape[sizeof (fhandler_dev_tape)];
  char __dev_zero[sizeof (fhandler_dev_zero)];
  char __disk_file[sizeof (fhandler_disk_file)];
  char __pipe[sizeof (fhandler_pipe)];
  char __proc[sizeof (fhandler_proc)];
  char __process[sizeof (fhandler_process)];
  char __pty_master[sizeof (fhandler_pty_master)];
  char __registry[sizeof (fhandler_registry)];
  char __serial[sizeof (fhandler_serial)];
  char __socket[sizeof (fhandler_socket)];
  char __termios[sizeof (fhandler_termios)];
  char __tty_common[sizeof (fhandler_tty_common)];
  char __tty_master[sizeof (fhandler_tty_master)];
  char __tty_slave[sizeof (fhandler_tty_slave)];
  char __virtual[sizeof (fhandler_virtual)];
  char __windows[sizeof (fhandler_windows)];
} fhandler_union;

struct select_record
{
  int fd;
  HANDLE h;
  fhandler_base *fh;
  bool saw_error;
  bool windows_handle;
  bool read_ready, write_ready, except_ready;
  bool read_selected, write_selected, except_selected;
  bool except_on_write;
  int (*startup) (select_record *me, class select_stuff *stuff);
  int (*peek) (select_record *, bool);
  int (*verify) (select_record *me, fd_set *readfds, fd_set *writefds,
		 fd_set *exceptfds);
  void (*cleanup) (select_record *me, class select_stuff *stuff);
  struct select_record *next;

  select_record (fhandler_base *in_fh = NULL) : fd (0), h (NULL),
		 fh (in_fh), saw_error (false), windows_handle (false),
		 read_ready (false), write_ready (false), except_ready (false),
		 read_selected (false), write_selected (false),
		 except_selected (false), except_on_write (false),
		 startup (NULL), peek (NULL), verify (NULL), cleanup (NULL),
		 next (NULL) {}
};

class select_stuff
{
 public:
  ~select_stuff ();
  select_stuff (): always_ready (0), windows_used (0), start (0)
  {
    memset (device_specific, 0, sizeof (device_specific));
  }
  bool always_ready, windows_used;
  select_record start;
  void *device_specific[FH_NDEV];

  int test_and_set (int i, fd_set *readfds, fd_set *writefds,
		     fd_set *exceptfds);
  int poll (fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
  int wait (fd_set *readfds, fd_set *writefds, fd_set *exceptfds, DWORD ms);
  void cleanup ();
};

int __stdcall set_console_state_for_spawn ();

#endif /* _FHANDLER_H_ */
