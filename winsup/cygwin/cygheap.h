/* cygheap.h: Cygwin heap manager.

   Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
   2011, 2012, 2013 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "hires.h"
#include "cygheap_malloc.h"

#define incygheap(s) (cygheap && ((char *) (s) >= (char *) cygheap) && ((char *) (s) <= ((char *) cygheap_max)))

struct _cmalloc_entry
{
  union
  {
    DWORD b;
    char *ptr;
  };
  struct _cmalloc_entry *prev;
  char data[0];
};

struct cygheap_root_mount_info
{
  char posix_path[CYG_MAX_PATH];
  unsigned posix_pathlen;
  char native_path[CYG_MAX_PATH];
  unsigned native_pathlen;
  bool caseinsensitive;
};

/* CGF: FIXME This doesn't belong here */

class cygheap_root
{
  /* Root directory information.
     This is used after a chroot is called. */
  struct cygheap_root_mount_info *m;

public:
  bool posix_ok (const char *path)
  {
    if (!m)
      return 1;
    return path_prefix_p (m->posix_path, path, m->posix_pathlen,
			  m->caseinsensitive);
  }
  bool ischroot_native (const char *path)
  {
    if (!m)
      return 1;
    return strncasematch (m->native_path, path, m->native_pathlen)
	    && (path[m->native_pathlen] == '\\' || !path[m->native_pathlen]);
  }
  const char *unchroot (const char *path)
  {
    if (!m)
      return path;
    const char *p = path + m->posix_pathlen;
    if (!*p)
      p = "/";
    return p;
  }
  bool exists () {return !!m;}
  void set (const char *, const char *, bool);
  size_t posix_length () const { return m->posix_pathlen; }
  const char *posix_path () const { return m->posix_path; }
  size_t native_length () const { return m->native_pathlen; }
  const char *native_path () const { return m->native_path; }
};

enum homebodies
{
  CH_HOMEDRIVE,
  CH_HOMEPATH,
  CH_HOME
};

class cygheap_user
{
  /* Extendend user information.
     The information is derived from the internal_getlogin call
     when on a NT system. */
  char  *pname;		/* user's name */
  char  *plogsrv;       /* Logon server, may be FQDN */
  char  *pdomain;       /* Logon domain of the user */
  char  *homedrive;	/* User's home drive */
  char  *homepath;	/* User's home path */
  char  *psystemroot;	/* Value of SYSTEMROOT */
  char  *pwinname;	/* User's name as far as Windows knows it */
  char  *puserprof;	/* User profile */
  cygsid effec_cygsid;  /* buffer for user's SID */
  cygsid saved_cygsid;  /* Remains intact even after impersonation */
public:
  __uid32_t saved_uid;     /* Remains intact even after impersonation */
  __gid32_t saved_gid;     /* Ditto */
  __uid32_t real_uid;      /* Remains intact on seteuid, replaced by setuid */
  __gid32_t real_gid;      /* Ditto */
  user_groups groups;      /* Primary and supp SIDs */

  /* token is needed if set(e)uid should be called. It can be set by a call
     to `set_impersonation_token()'. */
  HANDLE external_token;
  HANDLE internal_token;
  HANDLE curr_primary_token;
  HANDLE curr_imp_token;
  bool ext_token_is_restricted;  /* external_token is restricted token */
  bool curr_token_is_restricted; /* curr_primary_token is restricted token */
  bool setuid_to_restricted;     /* switch to restricted token by setuid () */

  /* CGF 2002-06-27.  I removed the initializaton from this constructor
     since this class is always allocated statically.  That means that everything
     is zero anyway so there is no need to initialize it to zero.  Since the
     token initialization is always handled during process startup as well,
     I've removed the constructor entirely.  Please reinstate this if this
     situation ever changes.
  cygheap_user () : pname (NULL), plogsrv (NULL), pdomain (NULL),
		    homedrive (NULL), homepath (NULL),
		    token (INVALID_HANDLE_VALUE) {}
  */

  ~cygheap_user ();

  void init ();
  void set_name (const char *new_name);
  const char *name () const { return pname; }

  const char *env_logsrv (const char *, size_t);
  const char *env_homepath (const char *, size_t);
  const char *env_homedrive (const char *, size_t);
  const char *env_userprofile (const char *, size_t);
  const char *env_domain (const char *, size_t);
  const char *env_name (const char *, size_t);
  const char *env_systemroot (const char *, size_t);

  const char *logsrv ()
  {
    const char *p = env_logsrv ("LOGONSERVER=", sizeof ("LOGONSERVER=") - 1);
    return (p == almost_null) ? NULL : p;
  }
  const char *winname ()
  {
    const char *p = env_name ("USERNAME=", sizeof ("USERNAME=") - 1);
    return (p == almost_null) ? NULL : p;
  }
  const char *domain ()
  {
    const char *p = env_domain ("USERDOMAIN=", sizeof ("USERDOMAIN=") - 1);
    return (p == almost_null) ? NULL : p;
  }
  BOOL set_sid (PSID new_sid) {return (BOOL) (effec_cygsid = new_sid);}
  BOOL set_saved_sid () { return (BOOL) (saved_cygsid = effec_cygsid); }
  PSID sid () { return effec_cygsid; }
  PSID saved_sid () { return saved_cygsid; }
  const char *ontherange (homebodies what, struct passwd * = NULL);
#define NO_IMPERSONATION NULL
  bool issetuid () const { return curr_imp_token != NO_IMPERSONATION; }
  HANDLE primary_token () { return curr_primary_token; }
  HANDLE imp_token () { return curr_imp_token; }
  void deimpersonate ()
  {
    RevertToSelf ();
  }
  bool reimpersonate ()
  {
    if (issetuid ())
      return ImpersonateLoggedOnUser (primary_token ());
    return true;
  }
  bool has_impersonation_tokens ()
    { return external_token != NO_IMPERSONATION
	     || internal_token != NO_IMPERSONATION
	     || curr_primary_token != NO_IMPERSONATION; }
  void close_impersonation_tokens ()
  {
    if (curr_imp_token != NO_IMPERSONATION)
      CloseHandle (curr_imp_token);
    if (curr_primary_token != NO_IMPERSONATION
	&& curr_primary_token != external_token
	&& curr_primary_token != internal_token)
      CloseHandle (curr_primary_token);
    if (external_token != NO_IMPERSONATION)
      CloseHandle (external_token);
    if (internal_token != NO_IMPERSONATION)
      CloseHandle (internal_token);
  }
  PWCHAR get_windows_id (PWCHAR buf)
  {
    return effec_cygsid.string (buf);
  }
  char *get_windows_id (char *buf)
  {
    return effec_cygsid.string (buf);
  }

  const char __reg3 *test_uid (char *&, const char *, size_t);
};

/* cwd cache stuff.  */

enum fcwd_version_t {
  FCWD_OLD,
  FCWD_W7,
  FCWD_W8
};

/* This class is used to store the CWD starting with Windows Vista.
   The CWD storage in the RTL_USER_PROCESS_PARAMETERS block is only
   an afterthought now.  The actual CWD storage is a FAST_CWD structure
   which is allocated on the process heap.  The new method only requires
   minimal locking and it's much more multi-thread friendly.  Presumably
   it minimizes contention when accessing the CWD.
   The class fcwd_access_t is supposed to encapsulate the gory implementation
   details depending on OS version from the calling functions. */
class fcwd_access_t {
  /* This is the layout used in Windows 8 developer preview. */
  struct FAST_CWD_8 {
    LONG           ReferenceCount;	/* Only release when this is 0. */
    HANDLE         DirectoryHandle;
    ULONG          OldDismountCount;	/* Reflects the system DismountCount
					   at the time the CWD has been set. */
    UNICODE_STRING Path;		/* Path's Buffer member always refers
					   to the following Buffer array. */
    LONG           FSCharacteristics;	/* Taken from FileFsDeviceInformation */
    WCHAR          Buffer[MAX_PATH];
  };
  /* This is the layout used in Windows 7 and Vista. */
  struct FAST_CWD_7 {
    UNICODE_STRING Path;		/* Path's Buffer member always refers
					   to the following Buffer array. */
    HANDLE         DirectoryHandle;
    LONG           FSCharacteristics;	/* Taken from FileFsDeviceInformation */
    LONG           ReferenceCount;	/* Only release when this is 0. */
    ULONG          OldDismountCount;	/* Reflects the system DismountCount
					   at the time the CWD has been set. */
    WCHAR          Buffer[MAX_PATH];
  };
  /* This is the old FAST_CWD structure up to the patch from KB 2393802,
     release in February 2011. */
  struct FAST_CWD_OLD {
    LONG           ReferenceCount;	/* Only release when this is 0. */
    HANDLE         DirectoryHandle;
    ULONG          OldDismountCount;	/* Reflects the system DismountCount
					   at the time the CWD has been set. */
    UNICODE_STRING Path;		/* Path's Buffer member always refers
					   to the following Buffer array. */
    WCHAR          Buffer[MAX_PATH];
  };
  union {
    FAST_CWD_OLD fold;
    FAST_CWD_7   f7;
    FAST_CWD_8   f8;
  };

#define IMPLEMENT(type, name) \
  type name () { \
    switch (fast_cwd_version ()) { \
      case FCWD_OLD: \
      default: \
	return fold.name; \
      case FCWD_W7: \
	return f7.name; \
      case FCWD_W8: \
	return f8.name; \
    } \
  }
  IMPLEMENT (LONG &, ReferenceCount)
  IMPLEMENT (HANDLE &, DirectoryHandle)
  IMPLEMENT (ULONG &, OldDismountCount)
  IMPLEMENT (UNICODE_STRING &, Path)
  IMPLEMENT (WCHAR *, Buffer)
  void SetFSCharacteristics (LONG val);
  static fcwd_version_t &fast_cwd_version (void);

public:
  void CopyPath (UNICODE_STRING &target);
  void Free (PVOID heap);
  void FillIn (HANDLE dir, PUNICODE_STRING name, ULONG old_dismount_count);
  static void SetDirHandleFromBufferPointer (PWCHAR buf_p, HANDLE dir);
  static void SetVersionFromPointer (PBYTE buf_p, bool is_buffer);
};

class cwdstuff
{
private:
  char *posix;
  HANDLE dir;
  DWORD drive_length;
  int error;		/* This contains an errno number which corresponds
			   to the problem with this path when trying to start
			   a native Win32 application.  See cwdstuff::set for
			   how it gets set.  See child_info_spawn::worker for how
			   it's evaluated. */

  friend class fcwd_access_t;
  /* fast_cwd_ptr is a pointer to the global RtlpCurDirRef pointer in
     ntdll.dll pointing to the FAST_CWD structure which constitutes the CWD.
     Unfortunately RtlpCurDirRef is not exported from ntdll.dll. */
  fcwd_access_t **fast_cwd_ptr;
  /* Type of FAST_CWD used on this system.  Keeping this information
     available in shared memory avoids to test for the version every time
     around.  Default to new version. */
  fcwd_version_t fast_cwd_version;
  void override_win32_cwd (bool, ULONG);

public:
  UNICODE_STRING win32;
  static muto cwd_lock;
  const char *get_posix () const { return posix; };
  void reset_posix (wchar_t *);
  char *get (char *, int = 1, int = 0, unsigned = NT_MAX_PATH);
  HANDLE get_handle () { return dir; }
  DWORD get_drive (char * dst)
  {
    cwd_lock.acquire ();
    DWORD ret = sys_wcstombs (dst, NT_MAX_PATH, win32.Buffer, drive_length);
    cwd_lock.release ();
    return ret;
  }
  int get_error () const { return error; }
  const char *get_error_desc () const;
  void init ();
  int set (path_conv *, const char *);
};

#ifdef DEBUGGING
struct cygheap_debug
{
  handle_list starth;
  handle_list freeh[500];
};
#endif

struct cygheap_locale
{
  mbtowc_p mbtowc;
  wctomb_p wctomb;
  char charset[ENCODING_LEN + 1];
};

struct user_heap_info
{
  void *base;
  void *ptr;
  void *top;
  void *max;
  unsigned chunk;
  unsigned slop;
};

struct hook_chain
{
  void **loc;
  const void *func;
  struct hook_chain *next;
};

struct mini_cygheap
{
  cygheap_locale locale;
};

struct init_cygheap: public mini_cygheap
{
  _cmalloc_entry *chain;
  char *buckets[32];
  WCHAR installation_root[PATH_MAX];
  UNICODE_STRING installation_key;
  WCHAR installation_key_buf[18];
  cygheap_root root;
  cygheap_user user;
  user_heap_info user_heap;
  mode_t umask;
  unsigned long rlim_core;
  HANDLE console_h;
  cwdstuff cwd;
  dtable fdtab;
#ifdef DEBUGGING
  cygheap_debug debug;
#endif
  struct sigaction *sigs;

  fhandler_termios *ctty;	/* Current tty */
  struct _cygtls **threadlist;
  size_t sthreads;
  pid_t pid;			/* my pid */
  struct {			/* Equivalent to using LIST_HEAD. */
    struct inode_t *lh_first;
  } inode_list;			/* Global inode pointer for adv. locking. */
  hook_chain hooks;
  void close_ctty ();
  void init_installation_root ();
  void __reg1 init_tls_list ();;
  void __reg2 add_tls (_cygtls *);
  void __reg3 remove_tls (_cygtls *, DWORD);
  _cygtls __reg3 *find_tls (int, bool&);
};


#define _CYGHEAPSIZE_SLOP (128 * 1024)
#define CYGHEAPSIZE (sizeof (init_cygheap) + (20000 * sizeof (fhandler_union)) + _CYGHEAPSIZE_SLOP)
#define CYGHEAPSIZE_MIN (sizeof (init_cygheap) + (10000 * sizeof (fhandler_union)))

extern init_cygheap *cygheap;
extern void *cygheap_max;

class cygheap_fdmanip
{
 protected:
  int fd;
  bool locked;
 public:
  cygheap_fdmanip (): fd (-1), locked (false) {}
  virtual ~cygheap_fdmanip ()
  {
    if (locked)
      cygheap->fdtab.unlock ();
  }
  virtual void release () { cygheap->fdtab.release (fd); }
  operator int &() {return fd;}
  operator fhandler_base* &() {return cygheap->fdtab[fd];}
  operator fhandler_socket* () const {return reinterpret_cast<fhandler_socket *> (cygheap->fdtab[fd]);}
  operator fhandler_pipe* () const {return reinterpret_cast<fhandler_pipe *> (cygheap->fdtab[fd]);}
  void operator = (fhandler_base *fh) {cygheap->fdtab[fd] = fh;}
  fhandler_base *operator -> () const {return cygheap->fdtab[fd];}
  bool isopen () const
  {
    if (cygheap->fdtab[fd])
      return true;
    set_errno (EBADF);
    return false;
  }
};

class cygheap_fdnew : public cygheap_fdmanip
{
 public:
  cygheap_fdnew (int seed_fd = -1, bool lockit = true)
  {
    if (lockit)
      cygheap->fdtab.lock ();
    if (seed_fd < 0)
      fd = cygheap->fdtab.find_unused_handle ();
    else
      fd = cygheap->fdtab.find_unused_handle (seed_fd + 1);
    if (fd >= 0)
      locked = lockit;
    else
      {
	set_errno (EMFILE);
	if (lockit)
	  cygheap->fdtab.unlock ();
	locked = false;
      }
  }
  ~cygheap_fdnew ()
  {
    if (cygheap->fdtab[fd])
      cygheap->fdtab[fd]->inc_refcnt ();
  }
  void operator = (fhandler_base *fh) {cygheap->fdtab[fd] = fh;}
};

class cygheap_fdget : public cygheap_fdmanip
{
  fhandler_base *fh;
public:
  cygheap_fdget (int fd, bool lockit = false, bool do_set_errno = true)
  {
    if (lockit)
      cygheap->fdtab.lock ();
    if (fd >= 0 && fd < (int) cygheap->fdtab.size && cygheap->fdtab[fd] != NULL)
      {
	this->fd = fd;
	locked = lockit;
	fh = cygheap->fdtab[fd];
	fh->inc_refcnt ();
      }
    else
      {
	this->fd = -1;
	if (do_set_errno)
	  set_errno (EBADF);
	if (lockit)
	  cygheap->fdtab.unlock ();
	locked = false;
	fh = NULL;
      }
  }
  ~cygheap_fdget ()
  {
    if (fh && fh->dec_refcnt () <= 0)
      {
	debug_only_printf ("deleting fh %p", fh);
	delete fh;
      }
  }
  void release () { cygheap->fdtab.release (fd); }
};

class cygheap_fdenum : public cygheap_fdmanip
{
 public:
  cygheap_fdenum (bool lockit = false)
  {
    locked = lockit;
    if (lockit)
      cygheap->fdtab.lock ();
    fd = -1;
  }
  int next ()
  {
    while (++fd < (int) cygheap->fdtab.size)
      if (cygheap->fdtab[fd] != NULL)
	return fd;
    return -1;
  }
  void rewind ()
  {
    fd = -1;
  }
};

void __stdcall cygheap_fixup_in_child (bool);
void __stdcall cygheap_init ();
extern char _cygheap_start[] __attribute__((section(".idata")));
