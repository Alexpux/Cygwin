/* syscalls.cc: syscalls

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#define fstat __FOOfstat__
#define lstat __FOOlstat__
#define stat __FOOstat__
#define _close __FOO_close__
#define _lseek __FOO_lseek__
#define _open __FOO_open__
#define _read __FOO_read__
#define _write __FOO_write__
#define _open64 __FOO_open64__
#define _lseek64 __FOO_lseek64__
#define _fstat64 __FOO_fstat64__

#include "winsup.h"
#include <sys/stat.h>
#include <sys/vfs.h> /* needed for statfs */
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <stdio.h>
#include <process.h>
#include <utmp.h>
#include <sys/uio.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <setjmp.h>
#include <winnls.h>
#include <wininet.h>
#include <lmcons.h> /* for UNLEN */
#include <rpc.h>

#undef fstat
#undef lstat
#undef stat

#include <cygwin/version.h>
#include <sys/cygwin.h>
#include "cygerrno.h"
#include "perprocess.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "sigproc.h"
#include "pinfo.h"
#include "shared_info.h"
#include "cygheap.h"
#define NEED_VFORK
#include "perthread.h"
#include "pwdgrp.h"
#include "cpuid.h"
#include "registry.h"

#undef _close
#undef _lseek
#undef _open
#undef _read
#undef _write
#undef _open64
#undef _lseek64
#undef _fstat64

SYSTEM_INFO system_info;

static int __stdcall mknod_worker (const char *, mode_t, mode_t, _major_t,
				   _minor_t);

static int __stdcall stat_worker (const char *name, struct __stat64 *buf,
				  int nofollow) __attribute__ ((regparm (3)));

/* Close all files and process any queued deletions.
   Lots of unix style applications will open a tmp file, unlink it,
   but never call close.  This function is called by _exit to
   ensure we don't leave any such files lying around.  */

void __stdcall
close_all_files ()
{
  cygheap->fdtab.lock ();

  fhandler_base *fh;
  for (int i = 0; i < (int) cygheap->fdtab.size; i++)
    if ((fh = cygheap->fdtab[i]) != NULL)
      {
#ifdef DEBUGGING
	debug_printf ("closing fd %d", i);
#endif
	fh->close ();
	cygheap->fdtab.release (i);
      }

  if (cygheap->ctty)
    cygheap->close_ctty ();

  cygheap->fdtab.unlock ();
  user_shared->delqueue.process_queue ();
}

int
dup (int fd)
{
  return cygheap->fdtab.dup2 (fd, cygheap_fdnew ());
}

int
dup2 (int oldfd, int newfd)
{
  return cygheap->fdtab.dup2 (oldfd, newfd);
}

extern "C" int
unlink (const char *ourname)
{
  int res = -1;
  DWORD devn;

  path_conv win32_name (ourname, PC_SYM_NOFOLLOW | PC_FULL);

  if (win32_name.error)
    {
      set_errno (win32_name.error);
      goto done;
    }

  if ((devn = win32_name.get_devn ()) == FH_PROC || devn == FH_REGISTRY
      || devn == FH_PROCESS)
    {
      set_errno (EROFS);
      goto done;
    }

  syscall_printf ("_unlink (%s)", win32_name.get_win32 ());

  if (!win32_name.exists ())
    {
      syscall_printf ("unlinking a nonexistent file");
      set_errno (ENOENT);
      goto done;
    }
  else if (win32_name.isdir ())
    {
      syscall_printf ("unlinking a directory");
      set_errno (EPERM);
      goto done;
    }

  /* Windows won't check the directory mode, so we do that ourselves.  */
  if (!writable_directory (win32_name))
    {
      syscall_printf ("non-writable directory");
      set_errno (EPERM);
      goto done;
    }

  bool setattrs;
  if (!((DWORD) win32_name & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM)))
    setattrs = false;
  else
    {
      /* Allow us to delete even if read-only */
      setattrs = SetFileAttributes (win32_name,
				    (DWORD) win32_name
				    & ~(FILE_ATTRIBUTE_READONLY
					| FILE_ATTRIBUTE_SYSTEM));
    }
  /* Attempt to use "delete on close" semantics to handle removing
     a file which may be open. */
  if (wincap.has_delete_on_close ())
    {
      HANDLE h;
      h = CreateFile (win32_name, 0, FILE_SHARE_READ, &sec_none_nih,
		      OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, 0);
      if (h != INVALID_HANDLE_VALUE)
	{
	  if (wincap.has_hard_links () && setattrs)
	    (void) SetFileAttributes (win32_name, (DWORD) win32_name);
	  BOOL res = CloseHandle (h);
	  syscall_printf ("%d = CloseHandle (%p)", res, h);
	  if (GetFileAttributes (win32_name) == INVALID_FILE_ATTRIBUTES
	      || !win32_name.isremote ())
	    {
	      syscall_printf ("CreateFile (FILE_FLAG_DELETE_ON_CLOSE) succeeded");
	      goto ok;
	    }
	  else
	    {
	      syscall_printf ("CreateFile (FILE_FLAG_DELETE_ON_CLOSE) failed");
	      if (setattrs)
		SetFileAttributes (win32_name, (DWORD) win32_name & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM));
	    }
	}
    }

  /* Try a delete with attributes reset */
  if (DeleteFile (win32_name))
    {
      syscall_printf ("DeleteFile after CreateFile/CloseHandle succeeded");
      goto ok;
    }

  DWORD lasterr;
  lasterr = GetLastError ();

  (void) SetFileAttributes (win32_name, (DWORD) win32_name);

  /* Windows 9x seems to report ERROR_ACCESS_DENIED rather than sharing
     violation.  So, set lasterr to ERROR_SHARING_VIOLATION in this case
     to simplify tests. */
  if (wincap.access_denied_on_delete () && lasterr == ERROR_ACCESS_DENIED
      && !win32_name.isremote ())
    lasterr = ERROR_SHARING_VIOLATION;

  /* FILE_FLAGS_DELETE_ON_CLOSE was a bust.  If this is a sharing
     violation, then queue the file for deletion when the process
     exits.  Otherwise, punt. */
  if (lasterr != ERROR_SHARING_VIOLATION)
    goto err;

  syscall_printf ("couldn't delete file, err %d", lasterr);

  /* Add file to the "to be deleted" queue. */
  user_shared->delqueue.queue_file (win32_name);

 /* Success condition. */
 ok:
  res = 0;
  goto done;

 /* Error condition. */
 err:
  __seterrno ();
  res = -1;

 done:
  syscall_printf ("%d = unlink (%s)", res, ourname);
  return res;
}

extern "C" int
_remove_r (struct _reent *, const char *ourname)
{
  path_conv win32_name (ourname, PC_SYM_NOFOLLOW | PC_FULL);

  if (win32_name.error)
    {
      set_errno (win32_name.error);
      syscall_printf ("-1 = remove (%s)", ourname);
      return -1;
    }

  return win32_name.isdir () ? rmdir (ourname) : unlink (ourname);
}

extern "C" int
remove (const char *ourname)
{
  path_conv win32_name (ourname, PC_SYM_NOFOLLOW | PC_FULL);

  if (win32_name.error)
    {
      set_errno (win32_name.error);
      syscall_printf ("-1 = remove (%s)", ourname);
      return -1;
    }

  return win32_name.isdir () ? rmdir (ourname) : unlink (ourname);
}

extern "C" pid_t
getpid ()
{
  return myself->pid;
}

extern "C" pid_t
_getpid_r (struct _reent *)
{
  return getpid ();
}

/* getppid: POSIX 4.1.1.1 */
extern "C" pid_t
getppid ()
{
  return myself->ppid;
}

/* setsid: POSIX 4.3.2.1 */
extern "C" pid_t
setsid (void)
{
#ifdef NEWVFORK
  vfork_save *vf = vfork_storage.val ();
  /* This is a horrible, horrible kludge */
  if (vf && vf->pid < 0)
    {
      pid_t pid = fork ();
      if (pid > 0)
	{
	  syscall_printf ("longjmping due to vfork");
	  vf->restore_pid (pid);
	}
      /* assuming that fork was successful */
    }
#endif

  if (myself->pgid == myself->pid)
    syscall_printf ("hmm.  pgid %d pid %d", myself->pgid, myself->pid);
  else
    {
      if (myself->ctty >= 0 && cygheap->open_fhs <= 0)
	{
	  syscall_printf ("freeing console");
	  FreeConsole ();
	}
      myself->ctty = -1;
      myself->sid = getpid ();
      myself->pgid = getpid ();
      if (cygheap->ctty)
	cygheap->close_ctty ();
      syscall_printf ("sid %d, pgid %d, ctty %d, open_fhs %d", myself->sid,
		      myself->pgid, myself->ctty, cygheap->open_fhs);
      return myself->sid;
    }

  set_errno (EPERM);
  return -1;
}

extern "C" pid_t
getsid (pid_t pid)
{
  pid_t res;
  if (!pid)
    res = myself->sid;
  else
    {
      pinfo p (pid);
      if (p)
	res = p->sid;
      else
	{
	  set_errno (ESRCH);
	  res = -1;
	}
    }
  return res;
}

extern "C" ssize_t
read (int fd, void *ptr, size_t len)
{
  const iovec iov =
    {
      iov_base: ptr,
      iov_len: len
    };

  return readv (fd, &iov, 1);
}

extern "C" ssize_t _read (int, void *, size_t)
  __attribute__ ((alias ("read")));

extern "C" ssize_t
write (int fd, const void *ptr, size_t len)
{
  const struct iovec iov =
    {
      iov_base: (void *) ptr,	// const_cast
      iov_len: len
    };

  return writev (fd, &iov, 1);
}

extern "C" ssize_t _write (int fd, const void *ptr, size_t len)
  __attribute__ ((alias ("write")));

extern "C" ssize_t
readv (int fd, const struct iovec *const iov, const int iovcnt)
{
  extern int sigcatchers;
  const int e = get_errno ();

  int res = -1;

  const ssize_t tot = check_iovec_for_read (iov, iovcnt);

  if (tot <= 0)
    {
      res = tot;
      goto done;
    }

  while (1)
    {
      sig_dispatch_pending ();

      cygheap_fdget cfd (fd);
      if (cfd < 0)
	break;

      if ((cfd->get_flags () & O_ACCMODE) == O_WRONLY)
	{
	  set_errno (EBADF);
	  break;
	}

      DWORD wait = cfd->is_nonblocking () ? 0 : INFINITE;

      /* Could block, so let user know we at least got here.  */
      syscall_printf ("readv (%d, %p, %d) %sblocking, sigcatchers %d",
		      fd, iov, iovcnt, wait ? "" : "non", sigcatchers);

      if (wait && (!cfd->is_slow () || cfd->get_r_no_interrupt ()))
	debug_printf ("no need to call ready_for_read");
      else if (!cfd->ready_for_read (fd, wait))
	{
	  res = -1;
	  goto out;
	}

      /* FIXME: This is not thread safe.  We need some method to
	 ensure that an fd, closed in another thread, aborts I/O
	 operations. */
      if (!cfd.isopen ())
	break;

      /* Check to see if this is a background read from a "tty",
	 sending a SIGTTIN, if appropriate */
      res = cfd->bg_check (SIGTTIN);

      if (!cfd.isopen ())
	{
	  res = -1;
	  break;
	}

      if (res > bg_eof)
	{
	  myself->process_state |= PID_TTYIN;
	  if (!cfd.isopen ())
	    {
	      res = -1;
	      break;
	    }
	  res = cfd->readv (iov, iovcnt, tot);
	  myself->process_state &= ~PID_TTYIN;
	}

    out:
      if (res >= 0 || get_errno () != EINTR || !_my_tls.call_signal_handler ())
	break;
      set_errno (e);
    }

done:
  syscall_printf ("%d = readv (%d, %p, %d), errno %d", res, fd, iov, iovcnt,
		  get_errno ());
  MALLOC_CHECK;
  return res;
}

extern "C" ssize_t
writev (const int fd, const struct iovec *const iov, const int iovcnt)
{
  int res = -1;
  sig_dispatch_pending ();
  const ssize_t tot = check_iovec_for_write (iov, iovcnt);

  cygheap_fdget cfd (fd);
  if (cfd < 0)
    goto done;

  if (tot <= 0)
    {
      res = tot;
      goto done;
    }

  if ((cfd->get_flags () & O_ACCMODE) == O_RDONLY)
    {
      set_errno (EBADF);
      goto done;
    }

  /* Could block, so let user know we at least got here.  */
  if (fd == 1 || fd == 2)
    paranoid_printf ("writev (%d, %p, %d)", fd, iov, iovcnt);
  else
    syscall_printf  ("writev (%d, %p, %d)", fd, iov, iovcnt);

  res = cfd->bg_check (SIGTTOU);

  if (res > (int) bg_eof)
    {
      myself->process_state |= PID_TTYOU;
      res = cfd->writev (iov, iovcnt, tot);
      myself->process_state &= ~PID_TTYOU;
    }

done:
  if (fd == 1 || fd == 2)
    paranoid_printf ("%d = write (%d, %p, %d), errno %d",
		     res, fd, iov, iovcnt, get_errno ());
  else
    syscall_printf ("%d = write (%d, %p, %d), errno %d",
		    res, fd, iov, iovcnt, get_errno ());

  MALLOC_CHECK;
  return res;
}

/* _open */
/* newlib's fcntl.h defines _open as taking variable args so we must
   correspond.  The third arg if it exists is: mode_t mode. */
extern "C" int
open (const char *unix_path, int flags, ...)
{
  int res = -1;
  va_list ap;
  mode_t mode = 0;
  sig_dispatch_pending ();

  syscall_printf ("open (%s, %p)", unix_path, flags);
  if (!check_null_empty_str_errno (unix_path))
    {
      /* check for optional mode argument */
      va_start (ap, flags);
      mode = va_arg (ap, mode_t);
      va_end (ap);

      fhandler_base *fh;
      cygheap_fdnew fd;

      if (fd >= 0)
	{
	  if (!(fh = build_fh_name (unix_path, NULL, PC_SYM_FOLLOW)))
	    res = -1;		// errno already set
	  else if (fh->is_fs_special () && fh->device_access_denied (flags))
	    {
	      delete fh;
	      res = -1;
	    }
	  else if (!fh->open (flags, (mode & 07777) & ~cygheap->umask))
	    {
	      delete fh;
	      res = -1;
	    }
	  else
	    {
	      cygheap->fdtab[fd] = fh;
	      if ((res = fd) <= 2)
		set_std_handle (res);
	    }
	}
    }

  syscall_printf ("%d = open (%s, %p)", res, unix_path, flags);
  return res;
}

extern "C" int _open (const char *, int flags, ...)
  __attribute__ ((alias ("open")));

extern "C" int _open64 (const char *, int flags, ...)
  __attribute__ ((alias ("open")));

extern "C" _off64_t
lseek64 (int fd, _off64_t pos, int dir)
{
  _off64_t res;

  if (dir != SEEK_SET && dir != SEEK_CUR && dir != SEEK_END)
    {
      set_errno (EINVAL);
      res = -1;
    }
  else
    {
      cygheap_fdget cfd (fd);
      if (cfd >= 0)
	res = cfd->lseek (pos, dir);
      else
	res = -1;
    }
  syscall_printf ("%d = lseek (%d, %D, %d)", res, fd, pos, dir);

  return res;
}

extern "C" int _lseek64 (int fd, _off64_t pos, int dir)
  __attribute__ ((alias ("lseek64")));

extern "C" _off_t
lseek (int fd, _off_t pos, int dir)
{
  return lseek64 (fd, (_off64_t) pos, dir);
}

extern "C" _off_t _lseek (int, _off_t, int)
  __attribute__ ((alias ("lseek")));

extern "C" int
close (int fd)
{
  int res;

  syscall_printf ("close (%d)", fd);

  MALLOC_CHECK;
  cygheap_fdget cfd (fd, true);
  if (cfd < 0)
    res = -1;
  else
    {
      res = cfd->close ();
      cfd.release ();
    }

  syscall_printf ("%d = close (%d)", res, fd);
  MALLOC_CHECK;
  return res;
}

extern "C" int _close (int) __attribute__ ((alias ("close")));

extern "C" int
isatty (int fd)
{
  int res;

  cygheap_fdget cfd (fd);
  if (cfd < 0)
    res = 0;
  else
    res = cfd->is_tty ();
  syscall_printf ("%d = isatty (%d)", res, fd);
  return res;
}

/* Under NT, try to make a hard link using backup API.  If that
   fails or we are Win 95, just copy the file.
   FIXME: We should actually be checking partition type, not OS.
   Under NTFS, we should support hard links.  On FAT partitions,
   we should just copy the file.
*/

extern "C" int
link (const char *a, const char *b)
{
  int res = -1;
  path_conv real_a (a, PC_SYM_NOFOLLOW | PC_FULL);
  path_conv real_b (b, PC_SYM_NOFOLLOW | PC_FULL);
  extern bool allow_winsymlinks;

  if (real_a.error)
    {
      set_errno (real_a.error);
      goto done;
    }

  if (real_b.error)
    {
      set_errno (real_b.case_clash ? ECASECLASH : real_b.error);
      goto done;
    }

  if (real_b.exists ())
    {
      syscall_printf ("file '%s' exists?", (char *) real_b);
      set_errno (EEXIST);
      goto done;
    }

  if (real_b[strlen (real_b) - 1] == '.')
    {
      syscall_printf ("trailing dot, bailing out");
      set_errno (EINVAL);
      goto done;
    }

  /* Shortcut hack. */
  char new_lnk_buf[CYG_MAX_PATH + 5];
  if (allow_winsymlinks && real_a.is_lnk_symlink () && !real_b.case_clash)
    {
      strcpy (new_lnk_buf, b);
      strcat (new_lnk_buf, ".lnk");
      b = new_lnk_buf;
      real_b.check (b, PC_SYM_NOFOLLOW | PC_FULL);
    }
  /* Try to make hard link first on Windows NT */
  if (wincap.has_hard_links ())
    {
      if (CreateHardLinkA (real_b, real_a, NULL))
	goto success;

      HANDLE hFileSource;

      WIN32_STREAM_ID StreamId;
      DWORD dwBytesWritten;
      LPVOID lpContext;
      DWORD cbPathLen;
      DWORD StreamSize;
      WCHAR wbuf[CYG_MAX_PATH];

      BOOL bSuccess;

      hFileSource = CreateFile (real_a, FILE_WRITE_ATTRIBUTES,
				FILE_SHARE_READ | FILE_SHARE_WRITE /*| FILE_SHARE_DELETE*/,
				&sec_none_nih, // sa
				OPEN_EXISTING, 0, NULL);

      if (hFileSource == INVALID_HANDLE_VALUE)
	{
	  syscall_printf ("cannot open source, %E");
	  goto docopy;
	}

      cbPathLen = sys_mbstowcs (wbuf, real_b, CYG_MAX_PATH) * sizeof (WCHAR);

      StreamId.dwStreamId = BACKUP_LINK;
      StreamId.dwStreamAttributes = 0;
      StreamId.dwStreamNameSize = 0;
      StreamId.Size.HighPart = 0;
      StreamId.Size.LowPart = cbPathLen;

      StreamSize = sizeof (WIN32_STREAM_ID) - sizeof (WCHAR**) +
		   StreamId.dwStreamNameSize;

      lpContext = NULL;
      /* Write the WIN32_STREAM_ID */
      bSuccess = BackupWrite (
	hFileSource,
	 (LPBYTE) &StreamId,	// buffer to write
	StreamSize,		// number of bytes to write
	&dwBytesWritten,
	FALSE,			// don't abort yet
	FALSE,			// don't process security
	&lpContext);

      if (bSuccess)
	{
	  /* write the buffer containing the path */
	  /* FIXME: BackupWrite sometimes traps if linkname is invalid.
	     Need to handle. */
	  bSuccess = BackupWrite (
		hFileSource,
		 (LPBYTE) wbuf,	// buffer to write
		cbPathLen,	// number of bytes to write
		&dwBytesWritten,
		FALSE,		// don't abort yet
		FALSE,		// don't process security
		&lpContext
		);

	  if (!bSuccess)
	    syscall_printf ("cannot write linkname, %E");

	  /* Free context */
	  BackupWrite (
	    hFileSource,
	    NULL,		// buffer to write
	    0,			// number of bytes to write
	    &dwBytesWritten,
	    TRUE,		// abort
	    FALSE,		// don't process security
	    &lpContext);
	}
      else
	syscall_printf ("cannot write streamId, %E");

      CloseHandle (hFileSource);

      if (!bSuccess)
	goto docopy;

    success:
      res = 0;
      if (!allow_winsymlinks && real_a.is_lnk_symlink ())
	SetFileAttributes (real_b, (DWORD) real_a
				   | FILE_ATTRIBUTE_SYSTEM
				   | FILE_ATTRIBUTE_READONLY);

      goto done;
    }
docopy:
  /* do this with a copy */
  if (CopyFileA (real_a, real_b, 1))
    res = 0;
  else
    __seterrno ();

done:
  syscall_printf ("%d = link (%s, %s)", res, a, b);
  return res;
}

/* chown: POSIX 5.6.5.1 */
/*
 * chown () is only implemented for Windows NT.  Under other operating
 * systems, it is only a stub that always returns zero.
 */
static int
chown_worker (const char *name, unsigned fmode, __uid32_t uid, __gid32_t gid)
{
  int res;

  if (check_null_empty_str_errno (name))
    return -1;

  if (!wincap.has_security ())  // real chown only works on NT
    res = 0;			// return zero (and do nothing) under Windows 9x
  else
    {
      /* we need Win32 path names because of usage of Win32 API functions */
      path_conv win32_path (PC_NONULLEMPTY, name, fmode);

      if (win32_path.error)
	{
	  set_errno (win32_path.error);
	  res = -1;
	  goto done;
	}

      /* FIXME: This makes chown on a device succeed always.  Someday we'll want
	 to actually allow chown to work properly on devices. */
      if (win32_path.is_auto_device () && !win32_path.issocket ())
	{
	  res = 0;
	  goto done;
	}

      mode_t attrib = 0;
      if (win32_path.isdir ())
	attrib |= S_IFDIR;
      res = get_file_attribute (win32_path.has_acls (),
				win32_path.get_win32 (),
				&attrib);
      if (!res)
	 res = set_file_attribute (win32_path.has_acls (), win32_path, uid,
				   gid, attrib);
      if (res != 0 && (!win32_path.has_acls () || !allow_ntsec))
	{
	  /* fake - if not supported, pretend we're like win95
	     where it just works */
	  res = 0;
	}
    }

done:
  syscall_printf ("%d = %schown (%s,...)",
		  res, (fmode & PC_SYM_NOFOLLOW) ? "l" : "", name);
  return res;
}

extern "C" int
chown32 (const char * name, __uid32_t uid, __gid32_t gid)
{
  return chown_worker (name, PC_SYM_FOLLOW, uid, gid);
}

extern "C" int
chown (const char * name, __uid16_t uid, __gid16_t gid)
{
  return chown_worker (name, PC_SYM_FOLLOW,
		       uid16touid32 (uid), gid16togid32 (gid));
}

extern "C" int
lchown32 (const char * name, __uid32_t uid, __gid32_t gid)
{
  return chown_worker (name, PC_SYM_NOFOLLOW, uid, gid);
}

extern "C" int
lchown (const char * name, __uid16_t uid, __gid16_t gid)
{
  return chown_worker (name, PC_SYM_NOFOLLOW,
		       uid16touid32 (uid), gid16togid32 (gid));
}

extern "C" int
fchown32 (int fd, __uid32_t uid, __gid32_t gid)
{
  cygheap_fdget cfd (fd);
  if (cfd < 0)
    {
      syscall_printf ("-1 = fchown (%d,...)", fd);
      return -1;
    }

  const char *path = cfd->get_name ();

  if (path == NULL)
    {
      syscall_printf ("-1 = fchown (%d,...) (no name)", fd);
      set_errno (ENOSYS);
      return -1;
    }

  syscall_printf ("fchown (%d,...): calling chown_worker (%s,FOLLOW,...)",
		  fd, path);
  return chown_worker (path, PC_SYM_FOLLOW, uid, gid);
}

extern "C" int
fchown (int fd, __uid16_t uid, __gid16_t gid)
{
  return fchown32 (fd, uid16touid32 (uid), gid16togid32 (gid));
}

/* umask: POSIX 5.3.3.1 */
extern "C" mode_t
umask (mode_t mask)
{
  mode_t oldmask;

  oldmask = cygheap->umask;
  cygheap->umask = mask & 0777;
  return oldmask;
}

int
chmod_device (path_conv& pc, mode_t mode)
{
  return mknod_worker (pc, pc.dev.mode & S_IFMT, mode, pc.dev.major, pc.dev.minor);
}

/* chmod: POSIX 5.6.4.1 */
extern "C" int
chmod (const char *path, mode_t mode)
{
  int res = -1;

  path_conv win32_path (path);

  if (win32_path.error)
    {
      set_errno (win32_path.error);
      goto done;
    }

  /* FIXME: This makes chmod on a device succeed always.  Someday we'll want
     to actually allow chmod to work properly on devices. */
  if (win32_path.is_auto_device ())
    {
      res = 0;
      goto done;
    }
  if (win32_path.is_fs_special ())
    {
      res = chmod_device (win32_path, mode);
      goto done;
    }

  if (!win32_path.exists ())
    __seterrno ();
  else
    {
      /* temporary erase read only bit, to be able to set file security */
      SetFileAttributes (win32_path, (DWORD) win32_path & ~FILE_ATTRIBUTE_READONLY);

      if (win32_path.isdir ())
	mode |= S_IFDIR;
      if (!set_file_attribute (win32_path.has_acls (), win32_path,
			       ILLEGAL_UID, ILLEGAL_GID, mode)
	  && allow_ntsec)
	res = 0;

      /* if the mode we want has any write bits set, we can't
	 be read only. */
      if (mode & (S_IWUSR | S_IWGRP | S_IWOTH))
	(DWORD) win32_path &= ~FILE_ATTRIBUTE_READONLY;
      else
	(DWORD) win32_path |= FILE_ATTRIBUTE_READONLY;

      if (!win32_path.is_lnk_symlink () && S_ISLNK (mode) || S_ISSOCK (mode))
	(DWORD) win32_path |= FILE_ATTRIBUTE_SYSTEM;

      if (!SetFileAttributes (win32_path, win32_path))
	__seterrno ();
      else if (!allow_ntsec)
	/* Correct NTFS security attributes have higher priority */
	res = 0;
    }

done:
  syscall_printf ("%d = chmod (%s, %p)", res, path, mode);
  return res;
}

/* fchmod: P96 5.6.4.1 */

extern "C" int
fchmod (int fd, mode_t mode)
{
  cygheap_fdget cfd (fd);
  if (cfd < 0)
    {
      syscall_printf ("-1 = fchmod (%d, 0%o)", fd, mode);
      return -1;
    }

  const char *path = cfd->get_name ();

  if (path == NULL)
    {
      syscall_printf ("-1 = fchmod (%d, 0%o) (no name)", fd, mode);
      set_errno (ENOSYS);
      return -1;
    }

  syscall_printf ("fchmod (%d, 0%o): calling chmod (%s, 0%o)",
		  fd, mode, path, mode);
  return chmod (path, mode);
}

static void
stat64_to_stat32 (struct __stat64 *src, struct __stat32 *dst)
{
  dst->st_dev = ((src->st_dev >> 8) & 0xff00) | (src->st_dev & 0xff);
  dst->st_ino = ((unsigned) (src->st_ino >> 32)) | (unsigned) src->st_ino;
  dst->st_mode = src->st_mode;
  dst->st_nlink = src->st_nlink;
  dst->st_uid = src->st_uid;
  dst->st_gid = src->st_gid;
  dst->st_rdev = ((src->st_rdev >> 8) & 0xff00) | (src->st_rdev & 0xff);
  dst->st_size = src->st_size;
  dst->st_atim = src->st_atim;
  dst->st_mtim = src->st_mtim;
  dst->st_ctim = src->st_ctim;
  dst->st_blksize = src->st_blksize;
  dst->st_blocks = src->st_blocks;
}

extern "C" int
fstat64 (int fd, struct __stat64 *buf)
{
  int res;

  cygheap_fdget cfd (fd);
  if (cfd < 0)
    res = -1;
  else
    {
      memset (buf, 0, sizeof (struct __stat64));
      res = cfd->fstat (buf);
      if (!res)
	{
	  if (!buf->st_ino)
	    buf->st_ino = hash_path_name (0, cfd->get_win32_name ());
	  if (!buf->st_dev)
	    buf->st_dev = cfd->get_device ();
	  if (!buf->st_rdev)
	    buf->st_rdev = buf->st_dev;
	}
    }

  syscall_printf ("%d = fstat (%d, %p)", res, fd, buf);
  return res;
}

extern "C" int
_fstat64_r (struct _reent *ptr, int fd, struct __stat64 *buf)
{
  int ret;

  set_errno (0);
  if ((ret = fstat64 (fd, buf)) == -1 && get_errno () != 0)
    ptr->_errno = get_errno ();
  return ret;
}

extern "C" int
fstat (int fd, struct __stat32 *buf)
{
  struct __stat64 buf64;
  int ret = fstat64 (fd, &buf64);
  if (!ret)
    stat64_to_stat32 (&buf64, buf);
  return ret;
}

extern "C" int
_fstat_r (struct _reent *ptr, int fd, struct __stat32 *buf)
{
  int ret;

  set_errno (0);
  if ((ret = fstat (fd, buf)) == -1 && get_errno () != 0)
    ptr->_errno = get_errno ();
  return ret;
}

/* fsync: P96 6.6.1.1 */
extern "C" int
fsync (int fd)
{
  cygheap_fdget cfd (fd);
  if (cfd < 0)
    {
      syscall_printf ("-1 = fsync (%d)", fd);
      return -1;
    }

  if (FlushFileBuffers (cfd->get_handle ()) == 0)
    {
      __seterrno ();
      return -1;
    }
  return 0;
}

/* sync: standards? */
extern "C" int
sync ()
{
  return 0;
}

suffix_info stat_suffixes[] =
{
  suffix_info ("", 1),
  suffix_info (".exe", 1),
  suffix_info (NULL)
};

/* Cygwin internal */
static int __stdcall
stat_worker (const char *name, struct __stat64 *buf, int nofollow)
{
  int res = -1;
  fhandler_base *fh = NULL;

  if (check_null_invalid_struct_errno (buf))
    goto done;

  fh = build_fh_name (name, NULL, (nofollow ? PC_SYM_NOFOLLOW : PC_SYM_FOLLOW)
		      		  | PC_FULL, stat_suffixes);

  if (fh->error ())
    {
      debug_printf ("got %d error from build_fh_name", fh->error ());
      set_errno (fh->error ());
    }
  else
    {
      debug_printf ("(%s, %p, %d, %p), file_attributes %d", name, buf, nofollow,
		    fh, (DWORD) *fh);
      memset (buf, 0, sizeof (*buf));
      res = fh->fstat (buf);
      if (!res)
	{
	  if (!buf->st_ino)
	    buf->st_ino = hash_path_name (0, fh->get_win32_name ());
	  if (!buf->st_dev)
	    buf->st_dev = fh->get_device ();
	  if (!buf->st_rdev)
	    buf->st_rdev = buf->st_dev;
	}
    }

 done:
  if (fh)
    delete fh;
  MALLOC_CHECK;
  syscall_printf ("%d = (%s, %p)", res, name, buf);
  return res;
}

extern "C" int
stat64 (const char *name, struct __stat64 *buf)
{
  syscall_printf ("entering");
  return stat_worker (name, buf, 0);
}

extern "C" int
_stat64_r (struct _reent *ptr, const char *name, struct __stat64 *buf)
{
  int ret;

  set_errno (0);
  if ((ret = stat64 (name, buf)) == -1 && get_errno () != 0)
    ptr->_errno = get_errno ();
  return ret;
}

extern "C" int
stat (const char *name, struct __stat32 *buf)
{
  struct __stat64 buf64;
  int ret = stat64 (name, &buf64);
  if (!ret)
    stat64_to_stat32 (&buf64, buf);
  return ret;
}

extern "C" int
_stat_r (struct _reent *ptr, const char *name, struct __stat32 *buf)
{
  int ret;

  set_errno (0);
  if ((ret = stat (name, buf)) == -1 && get_errno () != 0)
    ptr->_errno = get_errno ();
  return ret;
}

/* lstat: Provided by SVR4 and 4.3+BSD, POSIX? */
extern "C" int
lstat64 (const char *name, struct __stat64 *buf)
{
  syscall_printf ("entering");
  return stat_worker (name, buf, 1);
}

/* lstat: Provided by SVR4 and 4.3+BSD, POSIX? */
extern "C" int
lstat (const char *name, struct __stat32 *buf)
{
  struct __stat64 buf64;
  int ret = lstat64 (name, &buf64);
  if (!ret)
    stat64_to_stat32 (&buf64, buf);
  return ret;
}

extern "C" int
access (const char *fn, int flags)
{
  // flags were incorrectly specified
  int res = -1;
  if (flags & ~(F_OK|R_OK|W_OK|X_OK))
    set_errno (EINVAL);
  else
    {
      fhandler_base *fh = build_fh_name (fn, NULL, PC_SYM_FOLLOW | PC_FULL, stat_suffixes);
      res =  fh->fhaccess (flags);
      delete fh;
    }
  debug_printf ("returning %d", res);
  return res;
}

extern "C" int
rename (const char *oldpath, const char *newpath)
{
  int res = 0;
  char *lnk_suffix = NULL;

  path_conv real_old (oldpath, PC_SYM_NOFOLLOW);

  if (real_old.error)
    {
      syscall_printf ("-1 = rename (%s, %s)", oldpath, newpath);
      set_errno (real_old.error);
      return -1;
    }

  path_conv real_new (newpath, PC_SYM_NOFOLLOW);

  /* Shortcut hack. */
  char new_lnk_buf[CYG_MAX_PATH + 5];
  if (real_old.is_lnk_symlink () && !real_new.error && !real_new.case_clash)
    {
      strcpy (new_lnk_buf, newpath);
      strcat (new_lnk_buf, ".lnk");
      newpath = new_lnk_buf;
      real_new.check (newpath, PC_SYM_NOFOLLOW);
    }

  if (real_new.error || real_new.case_clash)
    {
      syscall_printf ("-1 = rename (%s, %s)", oldpath, newpath);
      set_errno (real_new.case_clash ? ECASECLASH : real_new.error);
      return -1;
    }

  if (!writable_directory (real_old) || !writable_directory (real_new))
    {
      syscall_printf ("-1 = rename (%s, %s)", oldpath, newpath);
      set_errno (EACCES);
      return -1;
    }

  if (!real_old.exists ()) /* file to move doesn't exist */
    {
       syscall_printf ("file to move doesn't exist");
       set_errno (ENOENT);
       return (-1);
    }

  /* Destination file exists and is read only, change that or else
     the rename won't work. */
  if (real_new.has_attribute (FILE_ATTRIBUTE_READONLY))
    SetFileAttributes (real_new, (DWORD) real_new & ~FILE_ATTRIBUTE_READONLY);

  /* Shortcut hack No. 2, part 1 */
  if (!real_old.issymlink () && !real_new.error && real_new.is_lnk_symlink ()
      && (lnk_suffix = strrchr (real_new.get_win32 (), '.')))
     *lnk_suffix = '\0';

  if (MoveFile (real_old, real_new))
    goto done;

  res = -1;
  if (wincap.has_move_file_ex ())
    {
      if (MoveFileEx (real_old.get_win32 (), real_new.get_win32 (),
		      MOVEFILE_REPLACE_EXISTING))
	res = 0;
    }
  else if (GetLastError () == ERROR_ALREADY_EXISTS
	   || GetLastError () == ERROR_FILE_EXISTS)
    {
      syscall_printf ("try win95 hack");
      for (int i = 0; i < 2; i++)
	{
	  if (!DeleteFileA (real_new.get_win32 ()) &&
	      GetLastError () != ERROR_FILE_NOT_FOUND)
	    {
	      syscall_printf ("deleting %s to be paranoid",
			      real_new.get_win32 ());
	      break;
	    }
	  else if (MoveFile (real_old.get_win32 (), real_new.get_win32 ()))
	    {
	      res = 0;
	      break;
	    }
	}
    }

done:
  if (res)
    {
      __seterrno ();
      /* Reset R/O attributes if neccessary. */
      if (real_new.has_attribute (FILE_ATTRIBUTE_READONLY))
	SetFileAttributes (real_new, real_new);
    }
  else
    {
      /* make the new file have the permissions of the old one */
      DWORD attr = real_old;
#ifdef HIDDEN_DOT_FILES
      char *c = strrchr (real_old.get_win32 (), '\\');
      if ((c && c[1] == '.') || *real_old.get_win32 () == '.')
	attr &= ~FILE_ATTRIBUTE_HIDDEN;
      c = strrchr (real_new.get_win32 (), '\\');
      if ((c && c[1] == '.') || *real_new.get_win32 () == '.')
	attr |= FILE_ATTRIBUTE_HIDDEN;
#endif
      SetFileAttributes (real_new, attr);

      /* Shortcut hack, No. 2, part 2 */
      /* if the new filename was an existing shortcut, remove it now if the
	 new filename is equal to the shortcut name without .lnk suffix. */
      if (lnk_suffix)
	{
	  *lnk_suffix = '.';
	  DeleteFile (real_new);
	}
    }

  syscall_printf ("%d = rename (%s, %s)", res, (char *) real_old,
		  (char *) real_new);

  return res;
}

extern "C" int
system (const char *cmdstring)
{
  pthread_testcancel ();

  if (check_null_empty_str_errno (cmdstring))
    return -1;

  int res;
  const char* command[4];

  if (cmdstring == (const char *) NULL)
    return 1;

  command[0] = "sh";
  command[1] = "-c";
  command[2] = cmdstring;
  command[3] = (const char *) NULL;

  if ((res = spawnvp (_P_SYSTEM, "sh", command)) == -1)
    {
      // when exec fails, return value should be as if shell
      // executed exit (127)
      res = 127;
    }

  return res;
}

extern "C" int
setdtablesize (int size)
{
  if (size <= (int)cygheap->fdtab.size || cygheap->fdtab.extend (size - cygheap->fdtab.size))
    return 0;

  return -1;
}

extern "C" int
getdtablesize ()
{
  return cygheap->fdtab.size > OPEN_MAX ? cygheap->fdtab.size : OPEN_MAX;
}

extern "C" size_t
getpagesize ()
{
  if (!system_info.dwPageSize)
    GetSystemInfo (&system_info);
  return (int) system_info.dwPageSize;
}

size_t
getshmlba ()
{
  if (!system_info.dwAllocationGranularity)
    GetSystemInfo (&system_info);
  return system_info.dwAllocationGranularity;
}

static int
check_posix_perm (const char *fname, int v)
{
  /* Windows 95/98/ME don't support file system security at all. */
  if (!wincap.has_security ())
    return 0;

  /* ntea is ok for supporting permission bits but it doesn't support
     full POSIX security settings. */
  if (v == _PC_POSIX_PERMISSIONS && allow_ntea)
    return 1;

  if (!allow_ntsec)
    return 0;

  char *root = rootdir (strcpy ((char *)alloca (strlen (fname)), fname));

  if (!allow_smbntsec
      && ((root[0] == '\\' && root[1] == '\\')
	  || GetDriveType (root) == DRIVE_REMOTE))
    return 0;

  DWORD vsn, len, flags;
  if (!GetVolumeInformation (root, NULL, 0, &vsn, &len, &flags, NULL, 16))
    {
      __seterrno ();
      return 0;
    }

  return (flags & FS_PERSISTENT_ACLS) ? 1 : 0;
}

/* FIXME: not all values are correct... */
extern "C" long int
fpathconf (int fd, int v)
{
  cygheap_fdget cfd (fd);
  if (cfd < 0)
    return -1;
  switch (v)
    {
    case _PC_LINK_MAX:
      return _POSIX_LINK_MAX;
    case _PC_MAX_CANON:
    case _PC_MAX_INPUT:
      if (isatty (fd))
	return _POSIX_MAX_CANON;
      else
	{
	  set_errno (EBADF);
	  return -1;
	}
    case _PC_NAME_MAX:
    case _PC_PATH_MAX:
      return PATH_MAX;
    case _PC_PIPE_BUF:
      return PIPE_BUF;
    case _PC_CHOWN_RESTRICTED:
    case _PC_NO_TRUNC:
      return -1;
    case _PC_VDISABLE:
      if (cfd->is_tty ())
	return -1;
      else
	{
	  set_errno (EBADF);
	  return -1;
	}
    case _PC_POSIX_PERMISSIONS:
    case _PC_POSIX_SECURITY:
      if (cfd->get_device () == FH_FS)
	return check_posix_perm (cfd->get_win32_name (), v);
      set_errno (EINVAL);
      return -1;
    default:
      set_errno (EINVAL);
      return -1;
    }
}

extern "C" long int
pathconf (const char *file, int v)
{
  switch (v)
    {
    case _PC_PATH_MAX:
      if (check_null_empty_str_errno (file))
	  return -1;
      return PATH_MAX - strlen (file);
    case _PC_NAME_MAX:
      return PATH_MAX;
    case _PC_LINK_MAX:
      return _POSIX_LINK_MAX;
    case _PC_MAX_CANON:
    case _PC_MAX_INPUT:
      return _POSIX_MAX_CANON;
    case _PC_PIPE_BUF:
      return PIPE_BUF;
    case _PC_CHOWN_RESTRICTED:
    case _PC_NO_TRUNC:
      return -1;
    case _PC_VDISABLE:
      return -1;
    case _PC_POSIX_PERMISSIONS:
    case _PC_POSIX_SECURITY:
      {
	path_conv full_path (file, PC_SYM_FOLLOW | PC_FULL);
	if (full_path.error)
	  {
	    set_errno (full_path.error);
	    return -1;
	  }
	if (full_path.is_auto_device ())
	  {
	    set_errno (EINVAL);
	    return -1;
	  }
	return check_posix_perm (full_path, v);
      }
    default:
      set_errno (EINVAL);
      return -1;
    }
}

extern "C" char *
ttyname (int fd)
{
  char *name;
  cygheap_fdget cfd (fd);
  if (cfd < 0 || !cfd->is_tty ())
    return 0;
  name = (char *) (cfd->ttyname ());
  debug_printf ("returning %s", name);
  return name;
}

extern "C" char *
ctermid (char *str)
{
  static NO_COPY char buf[16];
  if (str == NULL)
    str = buf;
  if (!real_tty_attached (myself))
    strcpy (str, "/dev/conin");
  else
    __small_sprintf (str, "/dev/tty%d", myself->ctty);
  return str;
}

/* Tells stdio if it should do the cr/lf conversion for this file */
extern "C" int
_cygwin_istext_for_stdio (int fd)
{
  if (CYGWIN_VERSION_OLD_STDIO_CRLF_HANDLING)
    {
      syscall_printf ("fd %d: old API", fd);
      return 0; /* we do it for old apps, due to getc/putc macros */
    }

  cygheap_fdget cfd (fd, false, false);
  if (cfd < 0)
    {
      syscall_printf ("fd %d: not open", fd);
      return 0;
    }

#if 0
  if (cfd->get_device () != FH_FS)
    {
      syscall_printf ("fd not disk file.  Defaulting to binary.");
      return 0;
    }
#endif

  if (cfd->get_w_binary () || cfd->get_r_binary ())
    {
      syscall_printf ("fd %d: opened as binary", fd);
      return 0;
    }

  syscall_printf ("fd %d: defaulting to text", fd);
  return 1;
}

/* internal newlib function */
extern "C" int _fwalk (struct _reent *ptr, int (*function) (FILE *));

static int setmode_mode;
static int setmode_file;

static int
setmode_helper (FILE *f)
{
  if (fileno (f) != setmode_file)
    {
      syscall_printf ("improbable, but %d != %d", fileno (f), setmode_file);
      return 0;
    }
  syscall_printf ("file was %s now %s", f->_flags & __SCLE ? "text" : "binary",
		  setmode_mode & O_TEXT ? "text" : "binary");
  if (setmode_mode & O_TEXT)
    f->_flags |= __SCLE;
  else
    f->_flags &= ~__SCLE;
  return 0;
}

extern "C" int
getmode (int fd)
{
  cygheap_fdget cfd (fd);
  if (cfd < 0)
    return -1;

  return cfd->get_flags () & (O_BINARY | O_TEXT);
}

/* Set a file descriptor into text or binary mode, returning the
   previous mode.  */

extern "C" int
setmode (int fd, int mode)
{
  cygheap_fdget cfd (fd);
  if (cfd < 0)
    return -1;
  if (mode != O_BINARY  && mode != O_TEXT && mode != 0)
    {
      set_errno (EINVAL);
      return -1;
    }

  /* Note that we have no way to indicate the case that writes are
     binary but not reads, or vice-versa.  These cases can arise when
     using the tty or console interface.  People using those
     interfaces should not use setmode.  */

  int res;
  if (cfd->get_w_binary () && cfd->get_r_binary ())
    res = O_BINARY;
  else if (cfd->get_w_binset () && cfd->get_r_binset ())
    res = O_TEXT;	/* Specifically set O_TEXT */
  else
    res = 0;

  if (!mode)
    cfd->reset_to_open_binmode ();
  else
    cfd->set_flags ((cfd->get_flags () & ~(O_TEXT | O_BINARY)) | mode);

  if (_cygwin_istext_for_stdio (fd))
    setmode_mode = O_TEXT;
  else
    setmode_mode = O_BINARY;
  setmode_file = fd;
  _fwalk (_REENT, setmode_helper);

  syscall_printf ("(%d<%s>, %p) returning %s", fd, cfd->get_name (),
		  mode, res & O_TEXT ? "text" : "binary");
  return res;
}

extern "C" int
ftruncate64 (int fd, _off64_t length)
{
  int res = -1;

  if (length < 0)
    set_errno (EINVAL);
  else
    {
      cygheap_fdget cfd (fd);
      if (cfd >= 0)
	{
	  HANDLE h = cygheap->fdtab[fd]->get_handle ();

	  if (cfd->get_handle ())
	    {
	      /* remember curr file pointer location */
	      _off64_t prev_loc = cfd->lseek (0, SEEK_CUR);

	      cfd->lseek (length, SEEK_SET);
	      if (!SetEndOfFile (h))
		__seterrno ();
	      else
		res = 0;

	      /* restore original file pointer location */
	      cfd->lseek (prev_loc, SEEK_SET);
	    }
	}
    }

  syscall_printf ("%d = ftruncate (%d, %D)", res, fd, length);
  return res;
}

/* ftruncate: P96 5.6.7.1 */
extern "C" int
ftruncate (int fd, _off_t length)
{
  return ftruncate64 (fd, (_off64_t)length);
}

/* truncate: Provided by SVR4 and 4.3+BSD.  Not part of POSIX.1 or XPG3 */
extern "C" int
truncate64 (const char *pathname, _off64_t length)
{
  int fd;
  int res = -1;

  fd = open (pathname, O_RDWR);

  if (fd == -1)
    set_errno (EBADF);
  else
    {
      res = ftruncate64 (fd, length);
      close (fd);
    }
  syscall_printf ("%d = truncate (%s, %d)", res, pathname, length);

  return res;
}

/* truncate: Provided by SVR4 and 4.3+BSD.  Not part of POSIX.1 or XPG3 */
extern "C" int
truncate (const char *pathname, _off_t length)
{
  return truncate64 (pathname, (_off64_t)length);
}

extern "C" long
get_osfhandle (int fd)
{
  long res;

  cygheap_fdget cfd (fd);
  if (cfd >= 0)
    res = (long) cfd->get_handle ();
  else
    res = -1;

  syscall_printf ("%d = get_osfhandle (%d)", res, fd);
  return res;
}

extern "C" int
statfs (const char *fname, struct statfs *sfs)
{
  if (!sfs)
    {
      set_errno (EFAULT);
      return -1;
    }

  path_conv full_path (fname, PC_SYM_FOLLOW | PC_FULL);
  const char *root = full_path.root_dir ();

  syscall_printf ("statfs %s", root);

  /* GetDiskFreeSpaceEx must be called before GetDiskFreeSpace on
     WinME, to avoid the MS KB 314417 bug */
  ULARGE_INTEGER availb, freeb, totalb;
  BOOL status = GetDiskFreeSpaceEx (root, &availb, &totalb, &freeb);

  DWORD spc, bps, availc, freec, totalc;

  if (!GetDiskFreeSpace (root, &spc, &bps, &freec, &totalc))
    {
      __seterrno ();
      return -1;
    }

  if (status)
    {
      availc = availb.QuadPart / (spc*bps);
      totalc = totalb.QuadPart / (spc*bps);
      freec = freeb.QuadPart / (spc*bps);
    }
  else
    availc = freec;

  DWORD vsn, maxlen, flags;

  if (!GetVolumeInformation (root, NULL, 0, &vsn, &maxlen, &flags, NULL, 0))
    {
      __seterrno ();
      return -1;
    }
  sfs->f_type = flags;
  sfs->f_bsize = spc*bps;
  sfs->f_blocks = totalc;
  sfs->f_bavail = availc;
  sfs->f_bfree = freec;
  sfs->f_files = -1;
  sfs->f_ffree = -1;
  sfs->f_fsid = vsn;
  sfs->f_namelen = maxlen;
  return 0;
}

extern "C" int
fstatfs (int fd, struct statfs *sfs)
{
  cygheap_fdget cfd (fd);
  if (cfd < 0)
    return -1;
  return statfs (cfd->get_name (), sfs);
}

/* setpgid: POSIX 4.3.3.1 */
extern "C" int
setpgid (pid_t pid, pid_t pgid)
{
  int res = -1;
  if (pid == 0)
    pid = getpid ();
  if (pgid == 0)
    pgid = pid;

  if (pgid < 0)
    {
      set_errno (EINVAL);
      goto out;
    }
  else
    {
      pinfo p (pid, PID_MAP_RW);
      if (!p)
	{
	  set_errno (ESRCH);
	  goto out;
	}
      /* A process may only change the process group of itself and its children */
      if (p == myself || p->ppid == myself->pid)
	{
	  p->pgid = pgid;
	  if (p->pid != p->pgid)
	    p->set_has_pgid_children (0);
	  res = 0;
	}
      else
	{
	  set_errno (EPERM);
	  goto out;
	}
    }
out:
  syscall_printf ("pid %d, pgid %d, res %d", pid, pgid, res);
  return res;
}

extern "C" pid_t
getpgid (pid_t pid)
{
  if (pid == 0)
    pid = getpid ();

  pinfo p (pid);
  if (p == 0)
    {
      set_errno (ESRCH);
      return -1;
    }
  return p->pgid;
}

extern "C" int
setpgrp (void)
{
  return setpgid (0, 0);
}

extern "C" pid_t
getpgrp (void)
{
  return getpgid (0);
}

extern "C" char *
ptsname (int fd)
{
  cygheap_fdget cfd (fd);
  if (cfd < 0)
    return 0;
  return (char *) (cfd->ptsname ());
}

/* FIXME: what is this? */
extern "C" int __declspec(dllexport)
regfree ()
{
  return 0;
}

static int __stdcall
mknod_worker (const char *path, mode_t type, mode_t mode, _major_t major,
	      _minor_t minor)
{
  char buf[sizeof (":\\00000000:00000000:00000000") + CYG_MAX_PATH];
  sprintf (buf, ":\\%x:%x:%x", major, minor,
	   type | (mode & (S_IRWXU | S_IRWXG | S_IRWXO)));
  return symlink_worker (buf, path, true, true);
}

extern "C" int
mknod32 (const char *path, mode_t mode, __dev32_t dev)
{
  if (check_null_empty_str_errno (path))
    return -1;

  if (strlen (path) >= CYG_MAX_PATH)
    return -1;

  path_conv w32path (path, PC_SYM_NOFOLLOW | PC_FULL);
  if (w32path.exists ())
    {
      set_errno (EEXIST);
      return -1;
    }

  mode_t type = mode & S_IFMT;
  _major_t major = _major (dev);
  _minor_t minor = _minor (dev);
  switch (type)
    {
    case S_IFCHR:
    case S_IFBLK:
      break;

    case S_IFIFO:
      major = _major (FH_FIFO);
      minor = _minor (FH_FIFO);
      break;

    case 0:
    case S_IFREG:
      {
	int fd = open (path, O_CREAT, mode);
	if (fd < 0)
	  return -1;
	close (fd);
	return 0;
      }

    default:
      set_errno (EINVAL);
      return -1;
    }

  return mknod_worker (w32path, type, mode, major, minor);
}

extern "C" int
mknod (const char *_path, mode_t mode, __dev16_t dev)
{
  return mknod32 (_path, mode, (__dev32_t) dev);
}

extern "C" int
mkfifo (const char *_path, mode_t mode)
{
  set_errno (ENOSYS);	// FIXME
  return -1;
}

/* seteuid: standards? */
extern "C" int
seteuid32 (__uid32_t uid)
{
  debug_printf ("uid: %u myself->gid: %u", uid, myself->gid);

  if (uid == myself->uid && !cygheap->user.groups.ischanged)
    {
      debug_printf ("Nothing happens");
      return 0;
    }

  cygsid usersid;
  user_groups &groups = cygheap->user.groups;
  HANDLE ptok, new_token = INVALID_HANDLE_VALUE;
  struct passwd * pw_new;
  bool token_is_internal, issamesid;
  char dacl_buf[MAX_DACL_LEN (5)];
  TOKEN_DEFAULT_DACL tdacl = {};

  pw_new = internal_getpwuid (uid);
  if (!wincap.has_security () && pw_new)
    goto success_9x;
  if (!usersid.getfrompw (pw_new))
    {
      set_errno (EINVAL);
      return -1;
    }

  RevertToSelf ();
  if (!OpenProcessToken (hMainProc, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &ptok))
    {
      __seterrno ();
      goto failed_ptok;;
    }

  /* Verify if the process token is suitable. */
  if (verify_token (ptok, usersid, groups))
    new_token = ptok;
  /* Verify if the external token is suitable */
  else if (cygheap->user.external_token != INVALID_HANDLE_VALUE
	   && verify_token (cygheap->user.external_token, usersid, groups))
    new_token = cygheap->user.external_token;
  /* Verify if the current token (internal or former external) is suitable */
  else if (cygheap->user.current_token != INVALID_HANDLE_VALUE
	   && cygheap->user.current_token != cygheap->user.external_token
	   && verify_token (cygheap->user.current_token, usersid, groups,
			    &token_is_internal))
    new_token = cygheap->user.current_token;
  /* Verify if the internal token is suitable */
  else if (cygheap->user.internal_token != INVALID_HANDLE_VALUE
	   && cygheap->user.internal_token != cygheap->user.current_token
	   && verify_token (cygheap->user.internal_token, usersid, groups,
			    &token_is_internal))
    new_token = cygheap->user.internal_token;

  debug_printf ("Found token %d", new_token);

  /* Set process def dacl to allow access to impersonated token */
  if (sec_acl ((PACL) dacl_buf, true, true, usersid))
    {
      tdacl.DefaultDacl = (PACL) dacl_buf;
      if (!SetTokenInformation (ptok, TokenDefaultDacl,
				&tdacl, sizeof dacl_buf))
	debug_printf ("SetTokenInformation"
		      "(TokenDefaultDacl): %E");
    }

  /* If no impersonation token is available, try to
     authenticate using NtCreateToken () or subauthentication. */
  if (new_token == INVALID_HANDLE_VALUE)
    {
      new_token = create_token (usersid, groups, pw_new);
      if (new_token == INVALID_HANDLE_VALUE)
	{
	  /* create_token failed. Try subauthentication. */
	  debug_printf ("create token failed, try subauthentication.");
	  new_token = subauth (pw_new);
	  if (new_token == INVALID_HANDLE_VALUE)
	    goto failed;
	}
      /* Keep at most one internal token */
      if (cygheap->user.internal_token != INVALID_HANDLE_VALUE)
	CloseHandle (cygheap->user.internal_token);
      cygheap->user.internal_token = new_token;
    }
  if (new_token != ptok)
    {
      /* Avoid having HKCU use default user */
      load_registry_hive (usersid);

      /* Try setting owner to same value as user. */
      if (!SetTokenInformation (new_token, TokenOwner,
				&usersid, sizeof usersid))
	debug_printf ("SetTokenInformation(user.token, "
		      "TokenOwner): %E");
      /* Try setting primary group in token to current group */
      if (!SetTokenInformation (new_token, TokenPrimaryGroup,
				&groups.pgsid, sizeof (cygsid)))
	debug_printf ("SetTokenInformation(user.token, "
		      "TokenPrimaryGroup): %E");
      /* Try setting default DACL */
      if (tdacl.DefaultDacl
	  && !SetTokenInformation (new_token, TokenDefaultDacl,
				   &tdacl, sizeof (tdacl)))
	debug_printf ("SetTokenInformation (TokenDefaultDacl): %E");
    }

  CloseHandle (ptok);
  issamesid = (usersid == cygheap->user.sid ());
  cygheap->user.set_sid (usersid);
  cygheap->user.current_token = new_token == ptok ? INVALID_HANDLE_VALUE
						  : new_token;
  if (!issamesid) /* MS KB 199190 */
    RegCloseKey (HKEY_CURRENT_USER);
  cygheap->user.reimpersonate ();
  if (!issamesid)
    user_shared_initialize (true);

success_9x:
  cygheap->user.set_name (pw_new->pw_name);
  myself->uid = uid;
  groups.ischanged = FALSE;
  return 0;

failed:
  CloseHandle (ptok);
failed_ptok:
  cygheap->user.reimpersonate ();
  return -1;
}

extern "C" int
seteuid (__uid16_t uid)
{
  return seteuid32 (uid16touid32 (uid));
}

/* setuid: POSIX 4.2.2.1 */
extern "C" int
setuid32 (__uid32_t uid)
{
  int ret = seteuid32 (uid);
  if (!ret)
    cygheap->user.real_uid = myself->uid;
  debug_printf ("real: %d, effective: %d", cygheap->user.real_uid, myself->uid);
  return ret;
}

extern "C" int
setuid (__uid16_t uid)
{
  return setuid32 (uid16touid32 (uid));
}

extern "C" int
setreuid32 (__uid32_t ruid, __uid32_t euid)
{
  int ret = 0;
  bool tried = false;
  __uid32_t old_euid = myself->uid;

  if (ruid != ILLEGAL_UID && cygheap->user.real_uid != ruid && euid != ruid)
    tried = !(ret = seteuid32 (ruid));
  if (!ret && euid != ILLEGAL_UID)
    ret = seteuid32 (euid);
  if (tried && (ret || euid == ILLEGAL_UID) && seteuid32 (old_euid))
    system_printf ("Cannot restore original euid %u", old_euid);
  if (!ret && ruid != ILLEGAL_UID)
    cygheap->user.real_uid = ruid;
  debug_printf ("real: %u, effective: %u", cygheap->user.real_uid, myself->uid);
  return ret;
}

extern "C" int
setreuid (__uid16_t ruid, __uid16_t euid)
{
  return setreuid32 (uid16touid32 (ruid), uid16touid32 (euid));
}

/* setegid: from System V.  */
extern "C" int
setegid32 (__gid32_t gid)
{
  debug_printf ("new egid: %u current: %u", gid, myself->gid);

  if (gid == myself->gid || !wincap.has_security ())
    {
      myself->gid = gid;
      return 0;
    }

  user_groups * groups = &cygheap->user.groups;
  cygsid gsid;
  HANDLE ptok;
  struct __group32 * gr = internal_getgrgid (gid);

  if (!gsid.getfromgr (gr))
    {
      set_errno (EINVAL);
      return -1;
    }
  myself->gid = gid;

  groups->update_pgrp (gsid);
  /* If impersonated, update primary group and revert */
  if (cygheap->user.issetuid ())
    {
      if (!SetTokenInformation (cygheap->user.token (),
				TokenPrimaryGroup,
				&gsid, sizeof gsid))
	debug_printf ("SetTokenInformation(thread, "
		      "TokenPrimaryGroup): %E");
      RevertToSelf ();
    }
  if (!OpenProcessToken (hMainProc, TOKEN_ADJUST_DEFAULT, &ptok))
    debug_printf ("OpenProcessToken(): %E");
  else
    {
      if (!SetTokenInformation (ptok, TokenPrimaryGroup,
				&gsid, sizeof gsid))
	debug_printf ("SetTokenInformation(process, "
		      "TokenPrimaryGroup): %E");
      CloseHandle (ptok);
    }
  if (cygheap->user.issetuid ()
      && !ImpersonateLoggedOnUser (cygheap->user.token ()))
    system_printf ("Impersonating in setegid failed: %E");
  return 0;
}

extern "C" int
setegid (__gid16_t gid)
{
  return setegid32 (gid16togid32 (gid));
}

/* setgid: POSIX 4.2.2.1 */
extern "C" int
setgid32 (__gid32_t gid)
{
  int ret = setegid32 (gid);
  if (!ret)
    cygheap->user.real_gid = myself->gid;
  return ret;
}

extern "C" int
setgid (__gid16_t gid)
{
  int ret = setegid32 (gid16togid32 (gid));
  if (!ret)
    cygheap->user.real_gid = myself->gid;
  return ret;
}

extern "C" int
setregid32 (__gid32_t rgid, __gid32_t egid)
{
  int ret = 0;
  bool tried = false;
  __gid32_t old_egid = myself->gid;

  if (rgid != ILLEGAL_GID && cygheap->user.real_gid != rgid && egid != rgid)
    tried = !(ret = setegid32 (rgid));
  if (!ret && egid != ILLEGAL_GID)
    ret = setegid32 (egid);
  if (tried && (ret || egid == ILLEGAL_GID) && setegid32 (old_egid))
    system_printf ("Cannot restore original egid %u", old_egid);
  if (!ret && rgid != ILLEGAL_GID)
    cygheap->user.real_gid = rgid;
  debug_printf ("real: %u, effective: %u", cygheap->user.real_gid, myself->gid);
  return ret;
}

extern "C" int
setregid (__gid16_t rgid, __gid16_t egid)
{
  return setregid32 (gid16togid32 (rgid), gid16togid32 (egid));
}

/* chroot: privileged Unix system call.  */
/* FIXME: Not privileged here. How should this be done? */
extern "C" int
chroot (const char *newroot)
{
  path_conv path (newroot, PC_SYM_FOLLOW | PC_FULL | PC_POSIX);

  int ret;
  if (path.error)
    ret = -1;
  else if (!path.exists ())
    {
      set_errno (ENOENT);
      ret = -1;
    }
  else if (!path.isdir ())
    {
      set_errno (ENOTDIR);
      ret = -1;
    }
  else
    {
      cygheap->root.set (path.normalized_path, path);
      ret = 0;
    }

  syscall_printf ("%d = chroot (%s)", ret ? get_errno () : 0,
				      newroot ? newroot : "NULL");
  return ret;
}

extern "C" int
creat (const char *path, mode_t mode)
{
  return open (path, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

extern "C" void
__assertfail ()
{
  exit (99);
}

extern "C" int
getw (FILE *fp)
{
  int w, ret;
  ret = fread (&w, sizeof (int), 1, fp);
  return ret != 1 ? EOF : w;
}

extern "C" int
putw (int w, FILE *fp)
{
  int ret;
  ret = fwrite (&w, sizeof (int), 1, fp);
  if (feof (fp) || ferror (fp))
    return -1;
  return 0;
}

extern "C" int
wcscmp (const wchar_t *s1, const wchar_t *s2)
{
  while (*s1  && *s1 == *s2)
    {
      s1++;
      s2++;
    }

  return (* (unsigned short *) s1) - (* (unsigned short *) s2);
}

extern "C" size_t
wcslen (const wchar_t *s1)
{
  int l = 0;
  while (s1[l])
    l++;
  return l;
}

/* FIXME: to do this right, maybe work out the usoft va_list machine
   and use wsvprintfW instead?
*/
extern "C" int
wprintf (const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start (ap, fmt);
  ret = vprintf (fmt, ap);
  va_end (ap);
  return ret;
}

extern "C" int
vhangup ()
{
  set_errno (ENOSYS);
  return -1;
}

extern "C" _PTR
memccpy (_PTR out, const _PTR in, int c, size_t len)
{
  const char *inc = (char *) in;
  char *outc = (char *) out;

  while (len)
    {
      char x = *inc++;
      *outc++ = x;
      if (x == c)
	return outc;
      len --;
    }
  return 0;
}

extern "C" int
nice (int incr)
{
  DWORD priority[] =
    {
      IDLE_PRIORITY_CLASS,
      IDLE_PRIORITY_CLASS,
      NORMAL_PRIORITY_CLASS,
      HIGH_PRIORITY_CLASS,
      REALTIME_PRIORITY_CLASS,
      REALTIME_PRIORITY_CLASS
    };
  int curr = 2;

  switch (GetPriorityClass (hMainProc))
    {
      case IDLE_PRIORITY_CLASS:
	curr = 1;
	break;
      case NORMAL_PRIORITY_CLASS:
	curr = 2;
	break;
      case HIGH_PRIORITY_CLASS:
	curr = 3;
	break;
      case REALTIME_PRIORITY_CLASS:
	curr = 4;
	break;
    }
  if (incr > 0)
    incr = -1;
  else if (incr < 0)
    incr = 1;

  if (SetPriorityClass (hMainProc, priority[curr + incr]) == FALSE)
    {
      __seterrno ();
      return -1;
    }

  return 0;
}

/*
 * Find the first bit set in I.
 */

extern "C" int
ffs (int i)
{
  static const unsigned char table[] =
    {
      0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
      6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
      7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
      7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
      8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
      8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
      8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
      8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8
    };
  unsigned long int a;
  unsigned long int x = i & -i;

  a = x <= 0xffff ? (x <= 0xff ? 0 : 8) : (x <= 0xffffff ?  16 : 24);

  return table[x >> a] + a;
}

static void
locked_append (int fd, const void * buf, size_t size)
{
  struct __flock64 lock_buffer = {F_WRLCK, SEEK_SET, 0, 0, 0};
  int count = 0;

  do
    if ((lock_buffer.l_start = lseek64 (fd, 0, SEEK_END)) != (_off64_t)-1
	&& fcntl_worker (fd, F_SETLKW, &lock_buffer) != -1)
      {
	if (lseek64 (fd, 0, SEEK_END) != (_off64_t)-1)
	  write (fd, buf, size);
	lock_buffer.l_type = F_UNLCK;
	fcntl_worker (fd, F_SETLK, &lock_buffer);
	break;
      }
  while (count++ < 1000
	 && (errno == EACCES || errno == EAGAIN)
	 && !usleep (1000));
}

extern "C" void
updwtmp (const char *wtmp_file, const struct utmp *ut)
{
  int fd;

  if ((fd = open (wtmp_file, O_WRONLY | O_BINARY, 0)) >= 0)
    {
      locked_append (fd, ut, sizeof *ut);
      close (fd);
    }
}

extern "C" void
logwtmp (const char *line, const char *user, const char *host)
{
  struct utmp ut;
  memset (&ut, 0, sizeof ut);
  ut.ut_type = USER_PROCESS;
  ut.ut_pid = getpid ();
  if (line)
    strncpy (ut.ut_line, line, sizeof ut.ut_line);
  time (&ut.ut_time);
  if (user)
    strncpy (ut.ut_user, user, sizeof ut.ut_user);
  if (host)
    strncpy (ut.ut_host, host, sizeof ut.ut_host);
  updwtmp (_PATH_WTMP, &ut);
}

extern "C" void
login (struct utmp *ut)
{
  pututline (ut);
  endutent ();
  updwtmp (_PATH_WTMP, ut);
}

extern "C" int
logout (char *line)
{
  struct utmp ut_buf, *ut;

  memset (&ut_buf, 0, sizeof ut_buf);
  strncpy (ut_buf.ut_line, line, sizeof ut_buf.ut_line);
  setutent ();
  ut = getutline (&ut_buf);

  if (ut)
    {
      ut->ut_type = DEAD_PROCESS;
      memset (ut->ut_user, 0, sizeof ut->ut_user);
      memset (ut->ut_host, 0, sizeof ut->ut_host);
      time (&ut->ut_time);
      debug_printf ("set logout time for %s", line);
      pututline (ut);
      endutent ();
      return 1;
    }
  return 0;
}

static int utmp_fd = -1;
static bool utmp_readonly = false;
static char *utmp_file = (char *) _PATH_UTMP;

static void
internal_setutent (bool force_readwrite)
{
  if (force_readwrite && utmp_readonly)
    endutent ();
  if (utmp_fd < 0)
    {
      utmp_fd = open (utmp_file, O_RDWR | O_BINARY);
      /* If open fails, we assume an unprivileged process (who?).  In this
	 case we try again for reading only unless the process calls
	 pututline() (==force_readwrite) in which case opening just fails. */
      if (utmp_fd < 0 && !force_readwrite)
	{
	  utmp_fd = open (utmp_file, O_RDONLY | O_BINARY);
	  if (utmp_fd >= 0)
	    utmp_readonly = true;
	}
    }
  else
    lseek (utmp_fd, 0, SEEK_SET);
}

extern "C" void
setutent ()
{
  internal_setutent (false);
}

extern "C" void
endutent ()
{
  if (utmp_fd >= 0)
    {
      close (utmp_fd);
      utmp_fd = -1;
      utmp_readonly = false;
    }
}

extern "C" void
utmpname (_CONST char *file)
{
  if (check_null_empty_str (file))
    {
      debug_printf ("Invalid file");
      return;
    }
  endutent ();
  utmp_file = strdup (file);
  debug_printf ("New UTMP file: %s", utmp_file);
}

/* Note: do not make NO_COPY */
static struct utmp utmp_data_buf[16];
static unsigned utix = 0;
#define nutdbuf (sizeof (utmp_data_buf) / sizeof (utmp_data_buf[0]))
#define utmp_data ({ \
  if (utix > nutdbuf) \
    utix = 0; \
  utmp_data_buf + utix++; \
})

extern "C" struct utmp *
getutent ()
{
  if (utmp_fd < 0)
    {
      internal_setutent (false);
      if (utmp_fd < 0)
	return NULL;
    }

  utmp *ut = utmp_data;
  if (read (utmp_fd, ut, sizeof *ut) != sizeof *ut)
    return NULL;
  return ut;
}

extern "C" struct utmp *
getutid (struct utmp *id)
{
  if (check_null_invalid_struct_errno (id))
    return NULL;
  if (utmp_fd < 0)
    {
      internal_setutent (false);
      if (utmp_fd < 0)
	return NULL;
    }

  utmp *ut = utmp_data;
  while (read (utmp_fd, ut, sizeof *ut) == sizeof *ut)
    {
      switch (id->ut_type)
	{
	case RUN_LVL:
	case BOOT_TIME:
	case OLD_TIME:
	case NEW_TIME:
	  if (id->ut_type == ut->ut_type)
	    return ut;
	  break;
	case INIT_PROCESS:
	case LOGIN_PROCESS:
	case USER_PROCESS:
	case DEAD_PROCESS:
	   if (strncmp (id->ut_id, ut->ut_id, UT_IDLEN) == 0)
	    return ut;
	  break;
	default:
	  return NULL;
	}
    }
  return NULL;
}

extern "C" struct utmp *
getutline (struct utmp *line)
{
  if (check_null_invalid_struct_errno (line))
    return NULL;
  if (utmp_fd < 0)
    {
      internal_setutent (false);
      if (utmp_fd < 0)
	return NULL;
    }

  utmp *ut = utmp_data;
  while (read (utmp_fd, ut, sizeof *ut) == sizeof *ut)
    if ((ut->ut_type == LOGIN_PROCESS ||
	 ut->ut_type == USER_PROCESS) &&
	!strncmp (ut->ut_line, line->ut_line, sizeof (ut->ut_line)))
      return ut;

  return NULL;
}

extern "C" void
pututline (struct utmp *ut)
{
  if (check_null_invalid_struct (ut))
    return;
  internal_setutent (true);
  if (utmp_fd < 0)
    {
      debug_printf ("error: utmp_fd %d", utmp_fd);
      return;
    }
  debug_printf ("ut->ut_type %d, ut->ut_pid %d, ut->ut_line '%s', ut->ut_id '%s'\n",
		ut->ut_type, ut->ut_pid, ut->ut_line, ut->ut_id);
  debug_printf ("ut->ut_user '%s', ut->ut_host '%s'\n",
		ut->ut_user, ut->ut_host);

  struct utmp *u;
  if ((u = getutid (ut)))
    {
      lseek (utmp_fd, -sizeof *ut, SEEK_CUR);
      write (utmp_fd, ut, sizeof *ut);
    }
  else
    locked_append (utmp_fd, ut, sizeof *ut);
}

extern "C"
long gethostid (void)
{
  unsigned data[13] = {0x92895012,
		       0x10293412,
		       0x29602018,
		       0x81928167,
		       0x34601329,
		       0x75630198,
		       0x89860395,
		       0x62897564,
		       0x00194362,
		       0x20548593,
		       0x96839102,
		       0x12219854,
		       0x00290012};

  bool has_cpuid = false;

  DWORD opmask = SetThreadAffinityMask (GetCurrentThread (), 1);
  if (!opmask)
    debug_printf ("SetThreadAffinityMask to 1 failed, %E");

  if (!can_set_flag (0x00040000))
    debug_printf ("386 processor - no cpuid");
  else
    {
      debug_printf ("486 processor");
      if (can_set_flag (0x00200000))
	{
	  debug_printf ("processor supports CPUID instruction");
	  has_cpuid = true;
	}
      else
	debug_printf ("processor does not support CPUID instruction");
    }
  if (has_cpuid)
    {
      unsigned maxf, unused[3];
      cpuid (&maxf, &unused[0], &unused[1], &unused[2], 0);
      maxf &= 0xffff;
      if (maxf >= 1)
	{
	  unsigned features;
	  cpuid (&data[0], &unused[0], &unused[1], &features, 1);
	  if (features & (1 << 18))
	    {
	      debug_printf ("processor has psn");
	      if (maxf >= 3)
		{
		  cpuid (&unused[0], &unused[1], &data[1], &data[2], 3);
		  debug_printf ("Processor PSN: %04x-%04x-%04x-%04x-%04x-%04x",
				data[0] >> 16, data[0] & 0xffff, data[2] >> 16, data[2] & 0xffff, data[1] >> 16, data[1] & 0xffff);
		}
	    }
	  else
	    debug_printf ("processor does not have psn");
	}
    }

  UUID Uuid;
  RPC_STATUS status = UuidCreateSequential (&Uuid);
  if (GetLastError () == ERROR_PROC_NOT_FOUND)
    status = UuidCreate (&Uuid);
  if (status == RPC_S_OK)
    {
      data[4] = *(unsigned *)&Uuid.Data4[2];
      data[5] = *(unsigned short *)&Uuid.Data4[6];
      // Unfortunately Windows will sometimes pick a virtual Ethernet card
      // e.g. VMWare Virtual Ethernet Adaptor
      debug_printf ("MAC address of first Ethernet card: %02x:%02x:%02x:%02x:%02x:%02x",
		    Uuid.Data4[2], Uuid.Data4[3], Uuid.Data4[4],
		    Uuid.Data4[5], Uuid.Data4[6], Uuid.Data4[7]);
    }
  else
    {
      debug_printf ("no Ethernet card installed");
    }

  reg_key key (HKEY_LOCAL_MACHINE, KEY_READ, "SOFTWARE", "Microsoft", "Windows", "CurrentVersion", NULL);
  key.get_string ("ProductId", (char *)&data[6], 24, "00000-000-0000000-00000");
  debug_printf ("Windows Product ID: %s", (char *)&data[6]);

  /* Contrary to MSDN, NT4 requires the second argument
     or a STATUS_ACCESS_VIOLATION is generated */
  ULARGE_INTEGER availb;
  GetDiskFreeSpaceEx ("C:\\", &availb, (PULARGE_INTEGER) &data[11], NULL);
  if (GetLastError () == ERROR_PROC_NOT_FOUND)
    GetDiskFreeSpace ("C:\\", NULL, NULL, NULL, (DWORD *)&data[11]);

  debug_printf ("hostid entropy: %08x %08x %08x %08x "
				"%08x %08x %08x %08x "
				"%08x %08x %08x %08x "
				"%08x",
				data[0], data[1],
				data[2], data[3],
				data[4], data[5],
				data[6], data[7],
				data[8], data[9],
				data[10], data[11],
				data[12]);

  long hostid = 0x40291372;
  // a random hashing algorithm
  // dependancy on md5 is probably too costly
  for (int i=0;i<13;i++)
    hostid ^= ((data[i] << (i << 2)) | (data[i] >> (32 - (i << 2))));

  if (opmask && !SetThreadAffinityMask (GetCurrentThread (), opmask))
    debug_printf ("SetThreadAffinityMask to %p failed, %E", opmask);

  debug_printf ("hostid: %08x", hostid);

  return hostid;
}

#define ETC_SHELLS "/etc/shells"
static int shell_index;
static struct __sFILE64 *shell_fp;

extern "C" char *
getusershell ()
{
  /* List of default shells if no /etc/shells exists, defined as on Linux.
     FIXME: SunOS has a far longer list, containing all shells which
     might be shipped with the OS.  Should we do the same for the Cygwin
     distro, adding bash, tcsh, ksh, pdksh and zsh?  */
  static NO_COPY const char *def_shells[] = {
    "/bin/sh",
    "/bin/csh",
    "/usr/bin/sh",
    "/usr/bin/csh",
    NULL
  };
  static char buf[CYG_MAX_PATH];
  int ch, buf_idx;

  if (!shell_fp && !(shell_fp = fopen64 (ETC_SHELLS, "rt")))
    {
      if (def_shells[shell_index])
	return strcpy (buf, def_shells[shell_index++]);
      return NULL;
    }
  /* Skip white space characters. */
  while ((ch = getc (shell_fp)) != EOF && isspace (ch))
    ;
  /* Get each non-whitespace character as part of the shell path as long as
     it fits in buf. */
  for (buf_idx = 0;
       ch != EOF && !isspace (ch) && buf_idx < CYG_MAX_PATH;
       buf_idx++, ch = getc (shell_fp))
    buf[buf_idx] = ch;
  /* Skip any trailing non-whitespace character not fitting in buf.  If the
     path is longer than CYG_MAX_PATH, it's invalid anyway. */
  while (ch != EOF && !isspace (ch))
    ch = getc (shell_fp);
  if (buf_idx)
    {
      buf[buf_idx] = '\0';
      return buf;
    }
  return NULL;
}

extern "C" void
setusershell ()
{
  if (shell_fp)
    fseek (shell_fp, 0L, SEEK_SET);
  shell_index = 0;
}

extern "C" void
endusershell ()
{
  if (shell_fp)
    fclose (shell_fp);
  shell_index = 0;
}
