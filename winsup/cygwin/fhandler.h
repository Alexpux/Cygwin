/* fhandler.h

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004,
   2005, 2006 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _FHANDLER_H_
#define _FHANDLER_H_

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

extern const char *windows_device_names[];
extern struct __cygwin_perfile *perfile_table;
#define __fmode (*(user_data->fmode_ptr))
extern const char proc[];
extern const int proc_len;

class select_record;
class fhandler_disk_file;
typedef struct __DIR DIR;
struct dirent;
struct iovec;
struct __acl32;

enum dirent_states
{
  dirent_ok		= 0x0000,
  dirent_saw_dot	= 0x0001,
  dirent_saw_dot_dot	= 0x0002,
  dirent_saw_eof	= 0x0004,
  dirent_isroot		= 0x0008,
  dirent_set_d_ino	= 0x0010,
  dirent_get_d_ino	= 0x0020
};

enum conn_state
{
  unconnected = 0,
  connect_pending = 1,
  connected = 2,
  connect_failed = 3
};

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

enum query_state {
  no_query = 0,
  query_read_control = 1,
  query_stat_control = 2,
  query_write_control = 3,
  query_write_attributes = 4
};

class fhandler_base
{
  friend class dtable;
  friend void close_all_files (bool);

  struct status_flags
  {
    unsigned rbinary            : 1; /* binary read mode */
    unsigned rbinset            : 1; /* binary read mode explicitly set */
    unsigned wbinary            : 1; /* binary write mode */
    unsigned wbinset            : 1; /* binary write mode explicitly set */
    unsigned nohandle           : 1; /* No handle associated with fhandler. */
    unsigned uninterruptible_io : 1; /* Set if I/O should be uninterruptible. */
    unsigned append_mode        : 1; /* always append */
    unsigned did_lseek          : 1; /* set when lseek is called as a flag that
					_write should check if we've moved
					beyond EOF, zero filling or making
					file sparse if so. */
    unsigned query_open         : 3; /* open file without requesting either
					read or write access */
    unsigned close_on_exec      : 1; /* close-on-exec */
    unsigned need_fork_fixup    : 1; /* Set if need to fixup after fork. */
    unsigned has_changed	: 1; /* Flag used to set ctime on close. */

   public:
    status_flags () :
      rbinary (0), rbinset (0), wbinary (0), wbinset (0), nohandle (0),
      uninterruptible_io (0), append_mode (0), did_lseek (0),
      query_open (no_query), close_on_exec (0), need_fork_fixup (0),
      has_changed (0)
      {}
  } status, open_status;

 private:
  int access;
  HANDLE io_handle;

  __ino64_t namehash;	/* hashed filename, used as inode num */

 protected:
  /* File open flags from open () and fcntl () calls */
  int openflags;

  char *rabuf;		/* used for crlf conversion in text files */
  size_t ralen;
  size_t raixget;
  size_t raixput;
  size_t rabuflen;

  DWORD fs_flags;
  HANDLE read_state;
  path_conv pc;

 public:
  class fhandler_base *archetype;
  int usecount;

  void set_name (path_conv &pc);
  int error () const {return pc.error;}
  void set_error (int error) {pc.error = error;}
  bool exists () const {return pc.exists ();}
  int pc_binmode () const {return pc.binmode ();}
  device& dev () {return pc.dev;}
  operator DWORD& () {return (DWORD&) pc;}
  virtual size_t size () const {return sizeof (*this);}

  virtual fhandler_base& operator =(fhandler_base &x);
  fhandler_base ();
  virtual ~fhandler_base ();

  /* Non-virtual simple accessor functions. */
  void set_io_handle (HANDLE x) { io_handle = x; }

  DWORD& get_device () { return dev ().devn; }
  DWORD get_major () { return dev ().major; }
  DWORD get_minor () { return dev ().minor; }
  virtual int get_unit () { return dev ().minor; }

  int get_access () const { return access; }
  void set_access (int x) { access = x; }

  int get_flags () { return openflags; }
  void set_flags (int x, int supplied_bin = 0);

  bool is_nonblocking ();
  void set_nonblocking (int yes);

  bool wbinary () const { return status.wbinset ? status.wbinary : 1; }
  bool rbinary () const { return status.rbinset ? status.rbinary : 1; }

  void wbinary (bool b) {status.wbinary = b; status.wbinset = 1;}
  void rbinary (bool b) {status.rbinary = b; status.rbinset = 1;}

  void set_open_status () {open_status = status;}
  void reset_to_open_binmode ()
  {
    set_flags ((get_flags () & ~(O_TEXT | O_BINARY))
	       | ((open_status.wbinary || open_status.rbinary)
		   ? O_BINARY : O_TEXT));
  }

  IMPLEMENT_STATUS_FLAG (bool, wbinset)
  IMPLEMENT_STATUS_FLAG (bool, rbinset)
  IMPLEMENT_STATUS_FLAG (bool, nohandle)
  IMPLEMENT_STATUS_FLAG (bool, uninterruptible_io)
  IMPLEMENT_STATUS_FLAG (bool, append_mode)
  IMPLEMENT_STATUS_FLAG (bool, did_lseek)
  IMPLEMENT_STATUS_FLAG (query_state, query_open)
  IMPLEMENT_STATUS_FLAG (bool, close_on_exec)
  IMPLEMENT_STATUS_FLAG (bool, need_fork_fixup)
  IMPLEMENT_STATUS_FLAG (bool, has_changed)

  int get_default_fmode (int flags);

  virtual void set_close_on_exec (bool val);

  LPSECURITY_ATTRIBUTES get_inheritance (bool all = 0)
  {
    if (all)
      return close_on_exec () ? &sec_all_nih : &sec_all;
    else
      return close_on_exec () ? &sec_none_nih : &sec_none;
  }

  virtual void fixup_before_fork_exec (DWORD) {}
  virtual void fixup_after_fork (HANDLE);
  virtual void fixup_after_exec ();
  void create_read_state (LONG n)
  {
    read_state = CreateSemaphore (&sec_none_nih, 0, n, NULL);
    ProtectHandle (read_state);
  }

  void signal_read_state (LONG n)
  {
    ReleaseSemaphore (read_state, n, NULL);
  }

  void set_fs_flags (DWORD flags) { fs_flags = flags; }
  bool get_fs_flags (DWORD flagval = UINT32_MAX)
    { return (fs_flags & (flagval)); }

  bool get_readahead_valid () { return raixget < ralen; }
  int puts_readahead (const char *s, size_t len = (size_t) -1);
  int put_readahead (char value);

  int get_readahead ();
  int peek_readahead (int queryput = 0);

  int eat_readahead (int n);

  void set_readahead_valid (int val, int ch = -1);

  int get_readahead_into_buffer (char *buf, size_t buflen);

  bool has_acls () const { return pc.has_acls (); }

  bool isremote () { return pc.isremote (); }

  bool has_attribute (DWORD x) const {return pc.has_attribute (x);}
  const char *get_name () const { return pc.normalized_path; }
  const char *get_win32_name () { return pc.get_win32 (); }
    __ino64_t get_namehash () { return namehash ?: namehash = hash_path_name (0, get_win32_name ()); }
  /* Returns name used for /proc/<pid>/fd in buf. */
  virtual char *get_proc_fd_name (char *buf);

  virtual void hclose (HANDLE h) {CloseHandle (h);}
  virtual void set_no_inheritance (HANDLE &h, int not_inheriting);

  /* fixup fd possibly non-inherited handles after fork */
  bool fork_fixup (HANDLE parent, HANDLE &h, const char *name);
  virtual bool need_fixup_before () const {return false;}

  int open_9x (int flags, mode_t mode = 0);
  virtual int open (int flags, mode_t mode = 0);
  int open_fs (int flags, mode_t mode = 0);
  virtual int close ();
  int close_fs ();
  virtual int __stdcall fstat (struct __stat64 *buf) __attribute__ ((regparm (2)));
  int __stdcall fstat_fs (struct __stat64 *buf) __attribute__ ((regparm (2)));
  int __stdcall fstat_helper (struct __stat64 *buf,
			      FILETIME ftChangeTime,
			      FILETIME ftLastAccessTime,
			      FILETIME ftLastWriteTime,
			      DWORD dwVolumeSerialNumber,
			      ULONGLONG nFileSize,
			      LONGLONG nAllocSize,
			      ULONGLONG nFileIndex,
			      DWORD nNumberOfLinks,
			      DWORD dwFileAttributes)
    __attribute__ ((regparm (3)));
  int __stdcall fstat_by_handle (struct __stat64 *buf) __attribute__ ((regparm (2)));
  int __stdcall fstat_by_name (struct __stat64 *buf) __attribute__ ((regparm (2)));
  int utimes_fs (const struct timeval *) __attribute__ ((regparm (2)));
  virtual int __stdcall fchmod (mode_t mode) __attribute__ ((regparm (1)));
  virtual int __stdcall fchown (__uid32_t uid, __gid32_t gid) __attribute__ ((regparm (2)));
  virtual int __stdcall facl (int, int, __acl32 *) __attribute__ ((regparm (3)));
  virtual int __stdcall fadvise (_off64_t, _off64_t, int) __attribute__ ((regparm (3)));
  virtual int __stdcall ftruncate (_off64_t, bool) __attribute__ ((regparm (3)));
  virtual int __stdcall link (const char *) __attribute__ ((regparm (2)));
  virtual int __stdcall utimes (const struct timeval *) __attribute__ ((regparm (2)));
  virtual int __stdcall fsync () __attribute__ ((regparm (1)));
  virtual int ioctl (unsigned int cmd, void *);
  virtual int fcntl (int cmd, void *);
  virtual char const *ttyname () { return get_name (); }
  virtual void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  virtual int write (const void *ptr, size_t len);
  virtual ssize_t readv (const struct iovec *, int iovcnt, ssize_t tot = -1);
  virtual ssize_t writev (const struct iovec *, int iovcnt, ssize_t tot = -1);
  virtual ssize_t __stdcall pread (void *, size_t, _off64_t) __attribute__ ((regparm (3)));
  virtual ssize_t __stdcall pwrite (void *, size_t, _off64_t) __attribute__ ((regparm (3)));
  virtual _off64_t lseek (_off64_t offset, int whence);
  virtual int lock (int, struct __flock64 *);
  virtual int dup (fhandler_base *child);

  virtual HANDLE mmap (caddr_t *addr, size_t len, int prot,
		       int flags, _off64_t off);
  virtual int munmap (HANDLE h, caddr_t addr, size_t len);
  virtual int msync (HANDLE h, caddr_t addr, size_t len, int flags);
  virtual bool fixup_mmap_after_fork (HANDLE h, int prot, int flags,
				      _off64_t offset, DWORD size,
				      void *address);

  void *operator new (size_t, void *p) __attribute__ ((nothrow)) {return p;}

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
  virtual bool isdevice () { return true; }
  virtual bool isfifo () { return false; }
  virtual char *ptsname () { return NULL;}
  virtual class fhandler_socket *is_socket () { return NULL; }
  virtual class fhandler_console *is_console () { return 0; }
  virtual int is_windows () {return 0; }

  virtual void raw_read (void *ptr, size_t& ulen);
  virtual int raw_write (const void *ptr, size_t ulen);

  /* Virtual accessor functions to hide the fact
     that some fd's have two handles. */
  virtual HANDLE& get_handle () { return io_handle; }
  virtual HANDLE& get_io_handle () { return io_handle; }
  virtual HANDLE& get_output_handle () { return io_handle; }
  virtual bool hit_eof () {return false;}
  virtual select_record *select_read (select_record *s);
  virtual select_record *select_write (select_record *s);
  virtual select_record *select_except (select_record *s);
  virtual int ready_for_read (int fd, DWORD howlong);
  virtual const char *get_native_name ()
  {
    return dev ().native;
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
  virtual int mkdir (mode_t mode);
  virtual int rmdir ();
  virtual DIR *opendir ();
  virtual int readdir (DIR *, dirent *) __attribute__ ((regparm (3)));
  virtual _off64_t telldir (DIR *);
  virtual void seekdir (DIR *, _off64_t);
  virtual void rewinddir (DIR *);
  virtual int closedir (DIR *);
  virtual bool is_slow () {return 0;}
  bool is_auto_device () {return isdevice () && !dev ().isfs ();}
  bool is_fs_special () {return pc.is_fs_special ();}
  bool issymlink () {return pc.issymlink ();}
  bool device_access_denied (int) __attribute__ ((regparm (2)));
  int fhaccess (int flags) __attribute__ ((regparm (2)));
  friend class fhandler_fifo;
};

class fhandler_mailslot : public fhandler_base
{
 public:
  fhandler_mailslot ();
  int __stdcall fstat (struct __stat64 *buf) __attribute__ ((regparm (2)));
  int open (int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  int ioctl (unsigned int cmd, void *);
  select_record *select_read (select_record *s);
};

struct wsa_event
{
  LONG serial_number;
  long events;
  int  connect_errorcode;
  pid_t owner;
};

class fhandler_socket: public fhandler_base
{
 private:
  int addr_family;
  int type;
  int connect_secret[4];

  wsa_event *wsock_events;
  HANDLE wsock_mtx;
  HANDLE wsock_evt;
 public:
  bool init_events ();
  int evaluate_events (const long event_mask, long &events, const bool erase);
  const HANDLE wsock_event () const { return wsock_evt; }
  const LONG serial_number () const { return wsock_events->serial_number; }
 private:
  int wait_for_events (const long event_mask);
  void release_events ();

  pid_t     sec_pid;
  __uid32_t sec_uid;
  __gid32_t sec_gid;
  pid_t     sec_peer_pid;
  __uid32_t sec_peer_uid;
  __gid32_t sec_peer_gid;
  void af_local_set_secret (char *);
  void af_local_setblocking (bool &, bool &);
  void af_local_unsetblocking (bool, bool);
  void af_local_set_cred ();
  void af_local_copy (fhandler_socket *);
  bool af_local_recv_secret ();
  bool af_local_send_secret ();
  bool af_local_recv_cred ();
  bool af_local_send_cred ();
  int af_local_accept ();
 public:
  int af_local_connect ();
  void af_local_set_sockpair_cred ();

 private:
  char *sun_path;
  struct status_flags
  {
    unsigned async_io              : 1; /* async I/O */
    unsigned saw_shutdown_read     : 1; /* Socket saw a SHUT_RD */
    unsigned saw_shutdown_write    : 1; /* Socket saw a SHUT_WR */
    unsigned saw_reuseaddr         : 1; /* Socket saw SO_REUSEADDR call */
    unsigned listener              : 1; /* listen called */
    unsigned connect_state         : 2;
   public:
    status_flags () :
      async_io (0), saw_shutdown_read (0), saw_shutdown_write (0),
      listener (0), connect_state (unconnected)
      {}
  } status;

 public:
  fhandler_socket ();
  ~fhandler_socket ();
  int get_socket () { return (int) get_handle(); }
  fhandler_socket *is_socket () { return this; }

  IMPLEMENT_STATUS_FLAG (bool, async_io)
  IMPLEMENT_STATUS_FLAG (bool, saw_shutdown_read)
  IMPLEMENT_STATUS_FLAG (bool, saw_shutdown_write)
  IMPLEMENT_STATUS_FLAG (bool, saw_reuseaddr)
  IMPLEMENT_STATUS_FLAG (bool, listener)
  IMPLEMENT_STATUS_FLAG (conn_state, connect_state)

  int bind (const struct sockaddr *name, int namelen);
  int connect (const struct sockaddr *name, int namelen);
  int listen (int backlog);
  int accept (struct sockaddr *peer, int *len);
  int getsockname (struct sockaddr *name, int *namelen);
  int getpeername (struct sockaddr *name, int *namelen);
  int getpeereid (pid_t *pid, __uid32_t *euid, __gid32_t *egid);

  int open (int flags, mode_t mode = 0);
  ssize_t readv (const struct iovec *, int iovcnt, ssize_t tot = -1);
  inline ssize_t recv_internal (struct _WSABUF *wsabuf, DWORD wsacnt,
  				DWORD flags,
				struct sockaddr *from, int *fromlen);
  ssize_t recvfrom (void *ptr, size_t len, int flags,
		    struct sockaddr *from, int *fromlen);
  ssize_t recvmsg (struct msghdr *msg, int flags);

  ssize_t writev (const struct iovec *, int iovcnt, ssize_t tot = -1);
  inline ssize_t send_internal (struct _WSABUF *wsabuf, DWORD wsacnt, int flags,
				const struct sockaddr *to, int tolen);
  ssize_t sendto (const void *ptr, size_t len, int flags,
	      const struct sockaddr *to, int tolen);
  ssize_t sendmsg (const struct msghdr *msg, int flags);

  int ioctl (unsigned int cmd, void *);
  int fcntl (int cmd, void *);
  _off64_t lseek (_off64_t, int) { return 0; }
  int shutdown (int how);
  int close ();
  void hclose (HANDLE) {close ();}
  int dup (fhandler_base *child);

  void set_close_on_exec (bool val);
  void fixup_after_fork (HANDLE);
  char *get_proc_fd_name (char *buf);

  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
  int ready_for_read (int, DWORD) { return true; }
  void set_addr_family (int af) {addr_family = af;}
  int get_addr_family () {return addr_family;}
  void set_socket_type (int st) { type = st;}
  int get_socket_type () {return type;}
  void set_sun_path (const char *path);
  char *get_sun_path () {return sun_path;}

  int __stdcall fstat (struct __stat64 *buf) __attribute__ ((regparm (2)));
  int __stdcall fchmod (mode_t mode) __attribute__ ((regparm (1)));
  int __stdcall fchown (__uid32_t uid, __gid32_t gid) __attribute__ ((regparm (2)));
  int __stdcall facl (int, int, __acl32 *) __attribute__ ((regparm (3)));
  int __stdcall link (const char *) __attribute__ ((regparm (2)));
  bool is_slow () {return 1;}
};

class fhandler_pipe: public fhandler_base
{
protected:
  HANDLE guard;
  bool broken_pipe;
  HANDLE writepipe_exists;
  DWORD orig_pid;
  unsigned id;
public:
  fhandler_pipe ();
  _off64_t lseek (_off64_t offset, int whence);
  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
  char *get_proc_fd_name (char *buf);
  void set_close_on_exec (bool val);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  int open (int flags, mode_t mode = 0);
  int close ();
  void create_guard (SECURITY_ATTRIBUTES *sa)
  {
    guard = CreateMutex (sa, FALSE, NULL);
    ProtectHandleINH (guard);
  }
  int dup (fhandler_base *child);
  int ioctl (unsigned int cmd, void *);
  int __stdcall fadvise (_off64_t, _off64_t, int) __attribute__ ((regparm (3)));
  int __stdcall ftruncate (_off64_t, bool) __attribute__ ((regparm (3)));
  void fixup_in_child ();
  virtual void fixup_after_fork (HANDLE);
  void fixup_after_exec ();
  bool hit_eof ();
  void set_eof () {broken_pipe = true;}
  HANDLE get_guard () const {return guard;}
  int ready_for_read (int fd, DWORD howlong);
  static int create (fhandler_pipe *[2], unsigned, int, bool = false);
  bool is_slow () {return true;}
  static int create_selectable (LPSECURITY_ATTRIBUTES, HANDLE&, HANDLE&, DWORD, bool);
  friend class fhandler_fifo;
};

class fhandler_fifo: public fhandler_pipe
{
  HANDLE output_handle;
  long read_use;
  long write_use;
  virtual HANDLE& get_io_handle () { return io_handle ?: output_handle; }
public:
  fhandler_fifo ();
  int open (int flags, mode_t mode = 0);
  int open_not_mine (int flags) __attribute__ ((regparm (2)));
  int close ();
  void set_use (int flags) __attribute__ ((regparm (2)));
  bool isfifo () { return true; }
  HANDLE& get_output_handle () { return output_handle; }
  void set_output_handle (HANDLE h) { output_handle = h; }
  void set_use ();
  int dup (fhandler_base *child);
  bool is_slow () {return true;}
  void close_one_end ();
};

class fhandler_dev_raw: public fhandler_base
{
 protected:
  char *devbuf;
  size_t devbufsiz;
  size_t devbufstart;
  size_t devbufend;
  struct status_flags
  {
    unsigned lastblk_to_read : 1;
   public:
    status_flags () : lastblk_to_read (0) {}
  } status;

  IMPLEMENT_STATUS_FLAG (bool, lastblk_to_read)

  fhandler_dev_raw ();

 public:
  ~fhandler_dev_raw ();

  int open (int flags, mode_t mode = 0);

  int __stdcall fstat (struct __stat64 *buf) __attribute__ ((regparm (2)));

  int dup (fhandler_base *child);
  int ioctl (unsigned int cmd, void *buf);

  void fixup_after_fork (HANDLE);
  void fixup_after_exec ();
};

class fhandler_dev_floppy: public fhandler_dev_raw
{
 private:
  _off64_t drive_size;
  unsigned long bytes_per_sector;
  struct status_flags
  {
    unsigned eom_detected    : 1;
   public:
    status_flags () : eom_detected (0) {}
  } status;

  IMPLEMENT_STATUS_FLAG (bool, eom_detected)

  inline _off64_t get_current_position ();
  int get_drive_info (struct hd_geometry *geo);

  BOOL write_file (const void *buf, DWORD to_write, DWORD *written, int *err);
  BOOL read_file (void *buf, DWORD to_read, DWORD *read, int *err);

 public:
  fhandler_dev_floppy ();

  int open (int flags, mode_t mode = 0);
  int dup (fhandler_base *child);
  void raw_read (void *ptr, size_t& ulen);
  int raw_write (const void *ptr, size_t ulen);
  _off64_t lseek (_off64_t offset, int whence);
  int ioctl (unsigned int cmd, void *buf);
};

class fhandler_dev_tape: public fhandler_dev_raw
{
  HANDLE mt_mtx;
  HANDLE mt_evt;

  bool is_rewind_device () { return get_minor () < 128; }
  unsigned int driveno () { return (unsigned int) get_minor () & 0x7f; }
  void drive_init ();

  inline bool _lock ();
  inline int unlock (int ret = 0);

 public:
  fhandler_dev_tape ();

  virtual int open (int flags, mode_t mode = 0);
  virtual int close ();

  void raw_read (void *ptr, size_t& ulen);
  int raw_write (const void *ptr, size_t ulen);

  virtual _off64_t lseek (_off64_t offset, int whence);

  virtual int __stdcall fstat (struct __stat64 *buf) __attribute__ ((regparm (2)));

  virtual int dup (fhandler_base *child);
  virtual void fixup_after_fork (HANDLE parent);
  virtual void set_close_on_exec (bool val);
  virtual int ioctl (unsigned int cmd, void *buf);
};

/* Standard disk file */

class fhandler_disk_file: public fhandler_base
{
  void touch_ctime ();
  int readdir_helper (DIR *, dirent *, DWORD, DWORD, char *) __attribute__ ((regparm (3)));
  int readdir_9x (DIR *, dirent *) __attribute__ ((regparm (3)));

 public:
  fhandler_disk_file ();
  fhandler_disk_file (path_conv &pc);

  int open (int flags, mode_t mode);
  int close ();
  int lock (int, struct __flock64 *);
  bool isdevice () { return false; }
  int __stdcall fstat (struct __stat64 *buf) __attribute__ ((regparm (2)));
  int __stdcall fchmod (mode_t mode) __attribute__ ((regparm (1)));
  int __stdcall fchown (__uid32_t uid, __gid32_t gid) __attribute__ ((regparm (2)));
  int __stdcall facl (int, int, __acl32 *) __attribute__ ((regparm (3)));
  int __stdcall fadvise (_off64_t, _off64_t, int) __attribute__ ((regparm (3)));
  int __stdcall ftruncate (_off64_t, bool) __attribute__ ((regparm (3)));
  int __stdcall link (const char *) __attribute__ ((regparm (2)));
  int __stdcall utimes (const struct timeval *) __attribute__ ((regparm (2)));

  HANDLE mmap (caddr_t *addr, size_t len, int prot, int flags, _off64_t off);
  int munmap (HANDLE h, caddr_t addr, size_t len);
  int msync (HANDLE h, caddr_t addr, size_t len, int flags);
  bool fixup_mmap_after_fork (HANDLE h, int prot, int flags,
			      _off64_t offset, DWORD size, void *address);
  int mkdir (mode_t mode);
  int rmdir ();
  DIR *opendir ();
  int readdir (DIR *, dirent *) __attribute__ ((regparm (3)));
  _off64_t telldir (DIR *);
  void seekdir (DIR *, _off64_t);
  void rewinddir (DIR *);
  int closedir (DIR *);

  ssize_t __stdcall pread (void *, size_t, _off64_t) __attribute__ ((regparm (3)));
  ssize_t __stdcall pwrite (void *, size_t, _off64_t) __attribute__ ((regparm (3)));
};

class fhandler_cygdrive: public fhandler_disk_file
{
  int ndrives;
  const char *pdrive;
  void set_drives ();
 public:
  fhandler_cygdrive ();
  int open (int flags, mode_t mode);
  int close ();
  DIR *opendir ();
  int readdir (DIR *, dirent *) __attribute__ ((regparm (3)));
  void rewinddir (DIR *);
  int closedir (DIR *);
  int __stdcall fstat (struct __stat64 *buf) __attribute__ ((regparm (2)));
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
  fhandler_serial ();

  int open (int flags, mode_t mode);
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
  int switch_modem_lines (int set, int clr);
  int tcsetattr (int a, const struct termios *t);
  int tcgetattr (struct termios *t);
  _off64_t lseek (_off64_t, int) { return 0; }
  int tcflush (int);
  int is_tty () { return 1; }
  void fixup_after_fork (HANDLE parent);
  void fixup_after_exec ();

  /* We maintain a pgrp so that tcsetpgrp and tcgetpgrp work, but we
     don't use it for permissions checking.  fhandler_tty_slave does
     permission checking on pgrps.  */
  virtual int tcgetpgrp () { return pgrp_; }
  virtual int tcsetpgrp (const pid_t pid) { pgrp_ = pid; return 0; }
  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
  bool is_slow () {return 1;}
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
  fhandler_termios () :
  fhandler_base ()
  {
    need_fork_fixup (true);
  }
  HANDLE& get_output_handle () { return output_handle; }
  line_edit_status line_edit (const char *rptr, int nread, termios&);
  void set_output_handle (HANDLE h) { output_handle = h; }
  void tcinit (tty_min *this_tc, bool force = false);
  virtual int is_tty () { return 1; }
  int tcgetpgrp ();
  int tcsetpgrp (int pid);
  bg_check_types bg_check (int sig);
  virtual DWORD __acquire_output_mutex (const char *fn, int ln, DWORD ms) {return 1;}
  virtual void __release_output_mutex (const char *fn, int ln) {}
  void echo_erase (int force = 0);
  virtual _off64_t lseek (_off64_t, int);
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
  bool alternate_charset_active;
  bool metabit;

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

  bool con_to_str (char *d, const char *s, DWORD sz);
  bool str_to_con (char *d, const char *s, DWORD sz);
  void set_color (HANDLE);
  bool fillin_info (HANDLE);
  void set_default_attr ();

  friend class fhandler_console;
};

/* This is a input and output console handle */
class fhandler_console: public fhandler_termios
{
 private:
  static dev_console *dev_state;
  static bool invisible_console;

/* Output calls */
  void set_default_attr ();

  void clear_screen (int, int, int, int);
  void scroll_screen (int, int, int, int, int, int);
  void cursor_set (bool, int, int);
  void cursor_get (int *, int *);
  void cursor_rel (int, int);
  const unsigned char *write_normal (unsigned const char*, unsigned const char *);
  void char_command (char);
  bool set_raw_win32_keyboard_mode (bool);
  int output_tcsetattr (int a, const struct termios *t);

/* Input calls */
  int igncr_enabled ();
  int input_tcsetattr (int a, const struct termios *t);
  void set_cursor_maybe ();

 public:
  fhandler_console ();

  fhandler_console* is_console () { return this; }

  int open (int flags, mode_t mode = 0);

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
  void fixup_after_fork_exec (bool);
  void fixup_after_exec () {fixup_after_fork_exec (true);}
  void fixup_after_fork (HANDLE) {fixup_after_fork_exec (false);}
  void set_close_on_exec (bool val);
  void set_input_state ();
  void send_winch_maybe ();
  static tty_min *get_tty_stuff (int);
  bool is_slow () {return 1;}
  static bool need_invisible ();
  static bool has_a () {return !invisible_console;}
};

class fhandler_tty_common: public fhandler_termios
{
 public:
  fhandler_tty_common ()
    : fhandler_termios (), output_done_event (NULL),
    ioctl_request_event (NULL), ioctl_done_event (NULL), output_mutex (NULL),
    input_mutex (NULL), input_available_event (NULL)
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

  DWORD __acquire_output_mutex (const char *fn, int ln, DWORD ms);
  void __release_output_mutex (const char *fn, int ln);

  tty *get_ttyp () { return (tty *) tc; }

  int close ();
  _off64_t lseek (_off64_t, int);
  void set_close_on_exec (bool val);
  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
  bool is_slow () {return 1;}
};

class fhandler_tty_slave: public fhandler_tty_common
{
  HANDLE inuse;			// used to indicate that a tty is in use
 public:
  /* Constructor */
  fhandler_tty_slave ();

  int open (int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  void init (HANDLE, DWORD, mode_t);

  int tcsetattr (int a, const struct termios *t);
  int tcgetattr (struct termios *t);
  int tcflush (int);
  int ioctl (unsigned int cmd, void *);
  int close ();
  int dup (fhandler_base *child);
  void fixup_after_fork (HANDLE parent);
  void fixup_after_exec ();

  select_record *select_read (select_record *s);
  int cygserver_attach_tty (HANDLE*, HANDLE*);
  int get_unit ();
  virtual char const *ttyname () { return pc.dev.name; }
};

class fhandler_pty_master: public fhandler_tty_common
{
  int pktmode;			// non-zero if pty in a packet mode.
public:
  int need_nl;			// Next read should start with \n
  DWORD dwProcessId;		// Owner of master handles

  /* Constructor */
  fhandler_pty_master ();

  int process_slave_output (char *buf, size_t len, int pktmode_on);
  void doecho (const void *str, DWORD len);
  int accept_input ();
  int open (int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  int close ();

  int tcsetattr (int a, const struct termios *t);
  int tcgetattr (struct termios *t);
  int tcflush (int);
  int ioctl (unsigned int cmd, void *);

  char *ptsname ();

  HANDLE from_master, to_master;
  bool hit_eof ();
  bool setup (bool);
  int dup (fhandler_base *);
  void fixup_after_fork (HANDLE parent);
  void fixup_after_exec ();
};

class fhandler_tty_master: public fhandler_pty_master
{
 public:
  /* Constructor */
  fhandler_console *console;	// device handler to perform real i/o.

  fhandler_tty_master ();
  int init ();
  int init_console ();
  void set_winsize (bool);
  bool is_slow () {return 1;}
};

class fhandler_dev_null: public fhandler_base
{
 public:
  fhandler_dev_null ();
  int open (int, mode_t);

  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
};

class fhandler_dev_zero: public fhandler_base
{
 public:
  fhandler_dev_zero ();
  int open (int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  _off64_t lseek (_off64_t offset, int whence);

  virtual HANDLE mmap (caddr_t *addr, size_t len, int prot,
		       int flags, _off64_t off);
  virtual int munmap (HANDLE h, caddr_t addr, size_t len);
  virtual int msync (HANDLE h, caddr_t addr, size_t len, int flags);
  virtual bool fixup_mmap_after_fork (HANDLE h, int prot, int flags,
				      _off64_t offset, DWORD size,
				      void *address);
};

class fhandler_dev_random: public fhandler_base
{
 protected:
  HCRYPTPROV crypt_prov;
  long pseudo;

  bool crypt_gen_random (void *ptr, size_t len);
  int pseudo_write (const void *ptr, size_t len);
  int pseudo_read (void *ptr, size_t len);

 public:
  fhandler_dev_random ();
  int open (int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  _off64_t lseek (_off64_t offset, int whence);
  int close ();
  int dup (fhandler_base *child);
};

class fhandler_dev_mem: public fhandler_base
{
 protected:
  DWORD mem_size;
  _off64_t pos;

 public:
  fhandler_dev_mem ();
  ~fhandler_dev_mem ();

  int open (int flags, mode_t mode = 0);
  int write (const void *ptr, size_t ulen);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  _off64_t lseek (_off64_t offset, int whence);
  int __stdcall fstat (struct __stat64 *buf) __attribute__ ((regparm (2)));
  int dup (fhandler_base *child);

  HANDLE mmap (caddr_t *addr, size_t len, int prot, int flags, _off64_t off);
  int munmap (HANDLE h, caddr_t addr, size_t len);
  int msync (HANDLE h, caddr_t addr, size_t len, int flags);
  bool fixup_mmap_after_fork (HANDLE h, int prot, int flags,
			      _off64_t offset, DWORD size, void *address);
} ;

class fhandler_dev_clipboard: public fhandler_base
{
  _off64_t pos;
  void *membuffer;
  size_t msize;
  bool eof;
 public:
  fhandler_dev_clipboard ();
  int is_windows () { return 1; }
  int open (int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  _off64_t lseek (_off64_t offset, int whence);
  int close ();

  int dup (fhandler_base *child);
  void fixup_after_exec ();
};

class fhandler_windows: public fhandler_base
{
 private:
  HWND hWnd_;	// the window whose messages are to be retrieved by read() call
  int method_;  // write method (Post or Send)
 public:
  fhandler_windows ();
  int is_windows () { return 1; }
  int open (int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  int ioctl (unsigned int cmd, void *);
  _off64_t lseek (_off64_t, int) { return 0; }
  int close () { return 0; }

  void set_close_on_exec (bool val);
  void fixup_after_fork (HANDLE parent);
  select_record *select_read (select_record *s);
  select_record *select_write (select_record *s);
  select_record *select_except (select_record *s);
  bool is_slow () {return 1;}
};

class fhandler_dev_dsp: public fhandler_base
{
 public:
  class Audio;
  class Audio_out;
  class Audio_in;
 private:
  int audioformat_;
  int audiofreq_;
  int audiobits_;
  int audiochannels_;
  Audio_out *audio_out_;
  Audio_in  *audio_in_;
 public:
  fhandler_dev_dsp ();

  int open (int flags, mode_t mode = 0);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  int ioctl (unsigned int cmd, void *);
  _off64_t lseek (_off64_t, int);
  int close ();
  int dup (fhandler_base *child);
  void fixup_after_fork (HANDLE parent);
  void fixup_after_exec ();
 private:
  void close_audio_in ();
  void close_audio_out (bool immediately = false);
};

class fhandler_virtual : public fhandler_base
{
 protected:
  char *filebuf;
  size_t bufalloc;
  _off64_t filesize;
  _off64_t position;
  int fileid; // unique within each class
 public:

  fhandler_virtual ();
  virtual ~fhandler_virtual();

  virtual int exists();
  virtual DIR *opendir ();
  _off64_t telldir (DIR *);
  void seekdir (DIR *, _off64_t);
  void rewinddir (DIR *);
  int closedir (DIR *);
  int write (const void *ptr, size_t len);
  void __stdcall read (void *ptr, size_t& len) __attribute__ ((regparm (3)));
  _off64_t lseek (_off64_t, int);
  int dup (fhandler_base *child);
  int open (int flags, mode_t mode = 0);
  int close ();
  int __stdcall fstat (struct stat *buf) __attribute__ ((regparm (2)));
  int __stdcall fchmod (mode_t mode) __attribute__ ((regparm (1)));
  int __stdcall fchown (__uid32_t uid, __gid32_t gid) __attribute__ ((regparm (2)));
  int __stdcall facl (int, int, __acl32 *) __attribute__ ((regparm (3)));
  virtual bool fill_filebuf ();
  char *get_filebuf () { return filebuf; }
  void fixup_after_exec ();
};

class fhandler_proc: public fhandler_virtual
{
 public:
  fhandler_proc ();
  int exists();
  int readdir (DIR *, dirent *) __attribute__ ((regparm (3)));
  static DWORD get_proc_fhandler(const char *path);

  int open (int flags, mode_t mode = 0);
  int __stdcall fstat (struct __stat64 *buf) __attribute__ ((regparm (2)));
  bool fill_filebuf ();
};

class fhandler_netdrive: public fhandler_virtual
{
 public:
  fhandler_netdrive ();
  int exists();
  int readdir (DIR *, dirent *) __attribute__ ((regparm (3)));
  void seekdir (DIR *, _off64_t);
  void rewinddir (DIR *);
  int closedir (DIR *);
  int open (int flags, mode_t mode = 0);
  int __stdcall fstat (struct __stat64 *buf) __attribute__ ((regparm (2)));
};

class fhandler_registry: public fhandler_proc
{
 private:
  char *value_name;
 public:
  fhandler_registry ();
  int exists();
  int readdir (DIR *, dirent *) __attribute__ ((regparm (3)));
  _off64_t telldir (DIR *);
  void seekdir (DIR *, _off64_t);
  void rewinddir (DIR *);
  int closedir (DIR *);

  int open (int flags, mode_t mode = 0);
  int __stdcall fstat (struct __stat64 *buf) __attribute__ ((regparm (2)));
  bool fill_filebuf ();
  int close ();
};

class pinfo;
class fhandler_process: public fhandler_proc
{
  pid_t pid;
 public:
  fhandler_process ();
  int exists();
  DIR *opendir ();
  int readdir (DIR *, dirent *) __attribute__ ((regparm (3)));
  int open (int flags, mode_t mode = 0);
  int __stdcall fstat (struct __stat64 *buf) __attribute__ ((regparm (2)));
  bool fill_filebuf ();
};

struct fhandler_nodevice: public fhandler_base
{
  fhandler_nodevice ();
  int open (int flags, mode_t mode = 0);
  // int __stdcall fstat (struct __stat64 *buf, path_conv *);
};

#define report_tty_counts(fh, call, use_op) \
  termios_printf ("%s %s, %susecount %d",\
		  fh->ttyname (), call,\
		  use_op, ((fhandler_tty_slave *) fh)->archetype->usecount);

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
  char __fifo[sizeof (fhandler_fifo)];
  char __mailslot[sizeof (fhandler_mailslot)];
  char __netdrive[sizeof (fhandler_netdrive)];
  char __nodevice[sizeof (fhandler_nodevice)];
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
  int thread_errno;
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
  void set_select_errno () {__seterrno (); thread_errno = errno;}
  int saw_error () {return thread_errno;}

  select_record (fhandler_base *in_fh = NULL) : fd (0), h (NULL),
		 fh (in_fh), thread_errno (0), windows_handle (false),
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
  bool always_ready, windows_used;
  select_record start;
  void *device_specific_pipe;
  void *device_specific_socket;
  void *device_specific_serial;
  void *device_specific_mailslot;

  int test_and_set (int i, fd_set *readfds, fd_set *writefds,
		     fd_set *exceptfds);
  int poll (fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
  int wait (fd_set *readfds, fd_set *writefds, fd_set *exceptfds, DWORD ms);
  void cleanup ();
  select_stuff (): always_ready (0), windows_used (0), start (0),
		   device_specific_pipe (0),
		   device_specific_socket (0),
		   device_specific_serial (0),
		   device_specific_mailslot (0) {}
};

void __stdcall set_console_state_for_spawn (bool);
#endif /* _FHANDLER_H_ */
