/* syscalls.cc: syscalls

   Copyright 1996, 1997, 1998, 1999, 2000, 2001 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <sys/stat.h>
#include <sys/vfs.h> /* needed for statfs */
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <stdio.h>
#include <process.h>
#include <utmp.h>
#include <sys/uio.h>
#include <errno.h>
#include <limits.h>
#include <winnls.h>
#include <wininet.h>
#include <lmcons.h> /* for UNLEN */
#include <cygwin/version.h>
#include <sys/cygwin.h>
#include "cygerrno.h"
#include "perprocess.h"
#include "security.h"
#include "fhandler.h"
#include "path.h"
#include "dtable.h"
#include "sync.h"
#include "sigproc.h"
#include "pinfo.h"
#include <unistd.h>
#include "shared_info.h"
#include "cygheap.h"

extern int normalize_posix_path (const char *, char *);

SYSTEM_INFO system_info;

/* Close all files and process any queued deletions.
   Lots of unix style applications will open a tmp file, unlink it,
   but never call close.  This function is called by _exit to
   ensure we don't leave any such files lying around.  */

void __stdcall
close_all_files (void)
{
  SetResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "close_all_files");

  fhandler_base *fh;
  for (int i = 0; i < (int) cygheap->fdtab.size; i++)
    if ((fh = cygheap->fdtab[i]) != NULL)
      {
	fh->close ();
	cygheap->fdtab.release (i);
      }

  ReleaseResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "close_all_files");
  cygwin_shared->delqueue.process_queue ();
}

static BOOL __stdcall
check_ttys_fds (void)
{
  int res = FALSE;
  SetResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "close_all_files");
  fhandler_base *fh;
  for (int i = 0; i < (int) cygheap->fdtab.size; i++)
    if ((fh = cygheap->fdtab[i]) != NULL && fh->get_device() == FH_TTYS)
      {
	res = TRUE;
	break;
      }
  ReleaseResourceLock (LOCK_FD_LIST, WRITE_LOCK | READ_LOCK, "close_all_files");
  return res;
}

extern "C" int
_unlink (const char *ourname)
{
  int res = -1;
  sigframe thisframe (mainthread);

  path_conv win32_name (ourname, PC_SYM_NOFOLLOW | PC_FULL);

  if (win32_name.error)
    {
      set_errno (win32_name.error);
      goto done;
    }

  syscall_printf ("_unlink (%s)", win32_name.get_win32 ());

  DWORD atts;
  atts = win32_name.file_attributes ();
  if (atts == 0xffffffff)
    {
      syscall_printf ("unlinking a nonexistant file");
      set_errno (ENOENT);
      goto done;
    }

  if (atts & FILE_ATTRIBUTE_DIRECTORY)
    {
      syscall_printf ("unlinking a directory");
      set_errno (EPERM);
      goto done;
    }

  /* Windows won't check the directory mode, so we do that ourselves.  */
  if (!writable_directory (win32_name))
    {
      syscall_printf ("non-writable directory");
      goto done;
    }

  /* Check for shortcut as symlink condition. */
  if (atts & FILE_ATTRIBUTE_READONLY)
    {
      int len = strlen (win32_name);
      if (len > 4 && strcasematch (win32_name + len - 4, ".lnk"))
	SetFileAttributes (win32_name, atts & ~FILE_ATTRIBUTE_READONLY);
    }

  DWORD lasterr;
  lasterr = 0;
  for (int i = 0; i < 2; i++)
    {
      if (DeleteFile (win32_name))
	{
	  syscall_printf ("DeleteFile succeeded");
	  goto ok;
	}

      lasterr = GetLastError ();
      if (i || lasterr != ERROR_ACCESS_DENIED || win32_name.issymlink ())
	break;		/* Couldn't delete it. */

      /* if access denied, chmod to be writable, in case it is not,
	 and try again */
      (void) chmod (win32_name, 0777);
    }

  /* Windows 9x seems to report ERROR_ACCESS_DENIED rather than sharing
     violation.  So, set lasterr to ERROR_SHARING_VIOLATION in this case
     to simplify tests. */
  if (!iswinnt && lasterr == ERROR_ACCESS_DENIED
      && !win32_name.isremote ())
    lasterr = ERROR_SHARING_VIOLATION;

  /* Tried to delete file by normal DeleteFile and by resetting protection
     and then deleting.  That didn't work.

     There are two possible reasons for this:  1) The file may be opened and
     Windows is not allowing it to be deleted, or 2) We may not have permissions
     to delete the file.

     So, first assume that it may be 1) and try to remove the file using the
     Windows FILE_FLAG_DELETE_ON_CLOSE semantics.  This seems to work only
     spottily on Windows 9x/Me but it does seem to work reliably on NT as
     long as the file doesn't exist on a remote drive. */

  bool delete_on_close_ok;

  delete_on_close_ok  = !win32_name.isremote () && iswinnt;

  /* Attempt to use "delete on close" semantics to handle removing
     a file which may be open. */
  HANDLE h;
  h = CreateFile (win32_name, GENERIC_READ, FILE_SHARE_READ, &sec_none_nih,
		  OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, 0);
  if (h == INVALID_HANDLE_VALUE)
    {
      if (GetLastError () == ERROR_FILE_NOT_FOUND)
	goto ok;
    }
  else
    {
      CloseHandle (h);
      syscall_printf ("CreateFile/CloseHandle succeeded");
      /* Everything is fine if the file has disappeared or if we know that the
	 FILE_FLAG_DELETE_ON_CLOSE will eventually work. */
      if (GetFileAttributes (win32_name) == (DWORD) -1 || delete_on_close_ok)
	goto ok;	/* The file is either gone already or will eventually be
			   deleted by the OS. */
    }

  /* FILE_FLAGS_DELETE_ON_CLOSE was a bust.  If this is a sharing
     violation, then queue the file for deletion when the process
     exits.  Otherwise, punt. */
  if (lasterr != ERROR_SHARING_VIOLATION)
    goto err;

  syscall_printf ("couldn't delete file, err %d", lasterr);

  /* Add file to the "to be deleted" queue. */
  cygwin_shared->delqueue.queue_file (win32_name);

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
remove (const char *ourname)
{
  path_conv win32_name (ourname, PC_SYM_NOFOLLOW | PC_FULL);

  if (win32_name.error)
    {
      set_errno (win32_name.error);
      syscall_printf ("-1 = remove (%s)", ourname);
      return -1;
    }

  DWORD atts = win32_name.file_attributes ();
  if (atts != 0xffffffff && atts & FILE_ATTRIBUTE_DIRECTORY)
    return rmdir (ourname);

  return _unlink (ourname);
}

extern "C" pid_t
_getpid ()
{
  return myself->pid;
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
  if (myself->pgid != _getpid ())
    {
      if (myself->ctty == TTY_CONSOLE &&
	  !cygheap->fdtab.has_console_fds () &&
	  !check_ttys_fds ())
	FreeConsole ();
      myself->ctty = -1;
      myself->sid = _getpid ();
      myself->pgid = _getpid ();
      syscall_printf ("sid %d, pgid %d, ctty %d", myself->sid, myself->pgid, myself->ctty);
      return myself->sid;
    }
  set_errno (EPERM);
  return -1;
}

extern "C" ssize_t
_read (int fd, void *ptr, size_t len)
{
  int res;
  fhandler_base *fh;
  extern int sigcatchers;
  int e = get_errno ();

  while (1)
    {
      sigframe thisframe (mainthread);

      if (cygheap->fdtab.not_open (fd))
	{
	  set_errno (EBADF);
	  return -1;
	}

      // set_sig_errno (0);
      fh = cygheap->fdtab[fd];
      DWORD wait = fh->is_nonblocking () ? 0 : INFINITE;

      /* Could block, so let user know we at least got here.  */
      syscall_printf ("read (%d, %p, %d) %sblocking, sigcatchers %d", fd, ptr, len, wait ? "" : "non", sigcatchers);

      if (wait && (!sigcatchers || !fh->is_slow () || fh->get_r_no_interrupt ()))
	debug_printf ("non-interruptible read\n");
      else if (!fh->ready_for_read (fd, wait, 0))
	{
	  if (!wait)
	    set_sig_errno (EAGAIN);	/* Don't really need 'set_sig_errno' here, but... */
	  else
	    set_sig_errno (EINTR);
	  res = -1;
	  goto out;
	}

      /* Check to see if this is a background read from a "tty",
	 sending a SIGTTIN, if appropriate */
      res = fh->bg_check (SIGTTIN);
      if (res > bg_eof)
	{
	  myself->process_state |= PID_TTYIN;
	  res = fh->read (ptr, len);
	  myself->process_state &= ~PID_TTYIN;
	}

    out:
      if (res >= 0 || get_errno () != EINTR || !thisframe.call_signal_handler ())
	break;
      set_errno (e);
    }

  syscall_printf ("%d = read (%d<%s>, %p, %d), bin %d, errno %d", res, fd, fh->get_name (),
		  ptr, len, fh->get_r_binary (), get_errno ());
  MALLOC_CHECK;
  return res;
}

extern "C" ssize_t
_write (int fd, const void *ptr, size_t len)
{
  int res = -1;
  sigframe thisframe (mainthread);

  if (cygheap->fdtab.not_open (fd))
    {
      set_errno (EBADF);
      goto done;
    }

  /* Could block, so let user know we at least got here.  */
  if (fd == 1 || fd == 2)
    paranoid_printf ("write (%d, %p, %d)", fd, ptr, len);
  else
    syscall_printf  ("write (%d, %p, %d)", fd, ptr, len);

  fhandler_base *fh;
  fh = cygheap->fdtab[fd];

  res = fh->bg_check (SIGTTOU);

  if (res > bg_eof)
    {
      myself->process_state |= PID_TTYOU;
      res = fh->write (ptr, len);
      myself->process_state &= ~PID_TTYOU;
    }

done:
  if (fd == 1 || fd == 2)
    paranoid_printf ("%d = write (%d, %p, %d)", res, fd, ptr, len);
  else
    syscall_printf ("%d = write (%d, %p, %d)", res, fd, ptr, len);

  MALLOC_CHECK;
  return (ssize_t)res;
}

/*
 * FIXME - should really move this interface into fhandler, and implement
 * write in terms of it. There are devices in Win32 that could do this with
 * overlapped I/O much more efficiently - we should eventually use
 * these.
 */

extern "C" ssize_t
writev (int fd, const struct iovec *iov, int iovcnt)
{
  int i;
  ssize_t len, total;
  char *base;

  if (iovcnt < 1 || iovcnt > IOV_MAX)
    {
      set_errno (EINVAL);
      return -1;
    }

  /* Ensure that the sum of the iov_len values is less than
     SSIZE_MAX (per spec), if so, we must fail with no output (per spec).
  */
  total = 0;
  for (i = 0; i < iovcnt; ++i)
    {
    total += iov[i].iov_len;
    if (total > SSIZE_MAX)
      {
      set_errno (EINVAL);
      return -1;
      }
    }
  /* Now write the data */
  for (i = 0, total = 0; i < iovcnt; i++, iov++)
    {
      len = iov->iov_len;
      base = iov->iov_base;
      while (len > 0)
	{
	  register int nbytes;
	  nbytes = write (fd, base, len);
	  if (nbytes < 0 && total == 0)
	    return -1;
	  if (nbytes <= 0)
	    return total;
	  len -= nbytes;
	  total += nbytes;
	  base += nbytes;
	}
    }
  return total;
}

/*
 * FIXME - should really move this interface into fhandler, and implement
 * read in terms of it. There are devices in Win32 that could do this with
 * overlapped I/O much more efficiently - we should eventually use
 * these.
 */

extern "C" ssize_t
readv (int fd, const struct iovec *iov, int iovcnt)
{
  int i;
  ssize_t len, total;
  char *base;

  for (i = 0, total = 0; i < iovcnt; i++, iov++)
    {
      len = iov->iov_len;
      base = iov->iov_base;
      while (len > 0)
	{
	  register int nbytes;
	  nbytes = read (fd, base, len);
	  if (nbytes < 0 && total == 0)
	    return -1;
	  if (nbytes <= 0)
	    return total;
	  len -= nbytes;
	  total += nbytes;
	  base += nbytes;
	}
    }
  return total;
}

/* _open */
/* newlib's fcntl.h defines _open as taking variable args so we must
   correspond.  The third arg if it exists is: mode_t mode. */
extern "C" int
_open (const char *unix_path, int flags, ...)
{
  int fd;
  int res = -1;
  va_list ap;
  mode_t mode = 0;
  fhandler_base *fh;
  sigframe thisframe (mainthread);

  syscall_printf ("open (%s, %p)", unix_path, flags);
  if (!check_null_empty_str_errno (unix_path))
    {
      SetResourceLock (LOCK_FD_LIST, WRITE_LOCK|READ_LOCK, " open ");

      /* check for optional mode argument */
      va_start (ap, flags);
      mode = va_arg (ap, mode_t);
      va_end (ap);

      fd = cygheap->fdtab.find_unused_handle ();

      if (fd < 0)
	set_errno (ENMFILE);
      else if ((fh = cygheap->fdtab.build_fhandler (fd, unix_path, NULL)) == NULL)
	res = -1;		// errno already set
      else if (!fh->open (unix_path, flags, (mode & 07777) & ~cygheap->umask))
	{
	  cygheap->fdtab.release (fd);
	  res = -1;
	}
      else if ((res = fd) <= 2)
	set_std_handle (res);
      ReleaseResourceLock (LOCK_FD_LIST,WRITE_LOCK|READ_LOCK," open");
    }

  syscall_printf ("%d = open (%s, %p)", res, unix_path, flags);
  return res;
}

extern "C" off_t
_lseek (int fd, off_t pos, int dir)
{
  off_t res;
  sigframe thisframe (mainthread);

  if (dir != SEEK_SET && dir != SEEK_CUR && dir != SEEK_END)
    {
      set_errno (EINVAL);
      res = -1;
    }
  else if (cygheap->fdtab.not_open (fd))
    {
      set_errno (EBADF);
      res = -1;
    }
  else
    {
      res = cygheap->fdtab[fd]->lseek (pos, dir);
    }
  syscall_printf ("%d = lseek (%d, %d, %d)", res, fd, pos, dir);

  return res;
}

extern "C" int
_close (int fd)
{
  int res;
  sigframe thisframe (mainthread);

  syscall_printf ("close (%d)", fd);

  MALLOC_CHECK;
  if (cygheap->fdtab.not_open (fd))
    {
      debug_printf ("handle %d not open", fd);
      set_errno (EBADF);
      res = -1;
    }
  else
    {
      SetResourceLock (LOCK_FD_LIST,WRITE_LOCK|READ_LOCK," close");
      res = cygheap->fdtab[fd]->close ();
      cygheap->fdtab.release (fd);
      ReleaseResourceLock (LOCK_FD_LIST,WRITE_LOCK|READ_LOCK," close");
    }

  syscall_printf ("%d = close (%d)", res, fd);
  MALLOC_CHECK;
  return res;
}

extern "C" int
isatty (int fd)
{
  int res;
  sigframe thisframe (mainthread);

  if (cygheap->fdtab.not_open (fd))
    {
      syscall_printf ("0 = isatty (%d)", fd);
      return 0;
    }

  res = cygheap->fdtab[fd]->is_tty ();
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
_link (const char *a, const char *b)
{
  int res = -1;
  sigframe thisframe (mainthread);
  path_conv real_a (a, PC_SYM_NOFOLLOW | PC_FULL);
  path_conv real_b (b, PC_SYM_NOFOLLOW | PC_FULL);

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

  if (real_b.file_attributes () != (DWORD)-1)
    {
      syscall_printf ("file '%s' exists?", (char *)real_b);
      set_errno (EEXIST);
      goto done;
    }
  if (real_b.get_win32 ()[strlen (real_b.get_win32 ()) - 1] == '.')
    {
      syscall_printf ("trailing dot, bailing out");
      set_errno (EINVAL);
      goto done;
    }

  /* Try to make hard link first on Windows NT */
  if (iswinnt)
    {
      HANDLE hFileSource;

      WIN32_STREAM_ID StreamId;
      DWORD dwBytesWritten;
      LPVOID lpContext;
      DWORD cbPathLen;
      DWORD StreamSize;
      WCHAR wbuf[MAX_PATH];

      BOOL bSuccess;

      hFileSource = CreateFile (
	real_a.get_win32 (),
	FILE_WRITE_ATTRIBUTES,
	FILE_SHARE_READ | FILE_SHARE_WRITE /*| FILE_SHARE_DELETE*/,
	&sec_none_nih, // sa
	OPEN_EXISTING,
	0,
	NULL
	);

      if (hFileSource == INVALID_HANDLE_VALUE)
	{
	  syscall_printf ("cannot open source, %E");
	  goto docopy;
	}

      lpContext = NULL;
      cbPathLen = sys_mbstowcs (wbuf, real_b.get_win32 (), MAX_PATH) * sizeof (WCHAR);

      StreamId.dwStreamId = BACKUP_LINK;
      StreamId.dwStreamAttributes = 0;
      StreamId.dwStreamNameSize = 0;
      StreamId.Size.HighPart = 0;
      StreamId.Size.LowPart = cbPathLen;

      StreamSize = sizeof (WIN32_STREAM_ID) - sizeof (WCHAR**) +
					    StreamId.dwStreamNameSize;

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

      res = 0;
      goto done;
    }
docopy:
  /* do this with a copy */
  if (CopyFileA (real_a.get_win32 (), real_b.get_win32 (), 1))
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
chown_worker (const char *name, unsigned fmode, uid_t uid, gid_t gid)
{
  int res;
  uid_t old_uid;
  gid_t old_gid;

  if (check_null_empty_str_errno (name))
    return -1;

  if (!iswinnt)    // real chown only works on NT
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
      if (win32_path.is_device ())
	{
	  res = 0;
	  goto done;
	}

      DWORD attrib = 0;
      if (win32_path.file_attributes () & FILE_ATTRIBUTE_DIRECTORY)
	attrib |= S_IFDIR;
      res = get_file_attribute (win32_path.has_acls (),
				win32_path.get_win32 (),
				(int *) &attrib,
				&old_uid,
				&old_gid);
      if (!res)
	{
	  if (uid == (uid_t) -1)
	    uid = old_uid;
	  if (gid == (gid_t) -1)
	    gid = old_gid;
	  if (win32_path.file_attributes () & FILE_ATTRIBUTE_DIRECTORY)
	    attrib |= S_IFDIR;
	  res = set_file_attribute (win32_path.has_acls (),
				    win32_path.get_win32 (),
				    uid, gid, attrib,
				    cygheap->user.logsrv ());
	}
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
chown (const char * name, uid_t uid, gid_t gid)
{
  sigframe thisframe (mainthread);
  return chown_worker (name, PC_SYM_FOLLOW, uid, gid);
}

extern "C" int
lchown (const char * name, uid_t uid, gid_t gid)
{
  sigframe thisframe (mainthread);
  return chown_worker (name, PC_SYM_NOFOLLOW, uid, gid);
}

extern "C" int
fchown (int fd, uid_t uid, gid_t gid)
{
  sigframe thisframe (mainthread);
  if (cygheap->fdtab.not_open (fd))
    {
      syscall_printf ("-1 = fchown (%d,...)", fd);
      set_errno (EBADF);
      return -1;
    }

  const char *path = cygheap->fdtab[fd]->get_name ();

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

/* umask: POSIX 5.3.3.1 */
extern "C" mode_t
umask (mode_t mask)
{
  mode_t oldmask;

  oldmask = cygheap->umask;
  cygheap->umask = mask & 0777;
  return oldmask;
}

/* chmod: POSIX 5.6.4.1 */
extern "C" int
chmod (const char *path, mode_t mode)
{
  int res = -1;
  sigframe thisframe (mainthread);

  path_conv win32_path (path);

  if (win32_path.error)
    {
      set_errno (win32_path.error);
      goto done;
    }

  /* FIXME: This makes chmod on a device succeed always.  Someday we'll want
     to actually allow chmod to work properly on devices. */
  if (win32_path.is_device ())
    {
      res = 0;
      goto done;
    }

  if (win32_path.file_attributes () == (DWORD)-1)
    __seterrno ();
  else
    {
      DWORD attr = win32_path.file_attributes ();
      /* temporary erase read only bit, to be able to set file security */
      SetFileAttributesA (win32_path.get_win32 (),
			  attr & ~FILE_ATTRIBUTE_READONLY);

      uid_t uid;
      gid_t gid;

      if (win32_path.file_attributes () & FILE_ATTRIBUTE_DIRECTORY)
	mode |= S_IFDIR;
      get_file_attribute (win32_path.has_acls (),
			  win32_path.get_win32 (),
			  NULL, &uid, &gid);
      if (win32_path.file_attributes () & FILE_ATTRIBUTE_DIRECTORY)
	mode |= S_IFDIR;
      if (!set_file_attribute (win32_path.has_acls (),
				win32_path.get_win32 (),
				uid, gid,
				mode, cygheap->user.logsrv ())
	  && allow_ntsec)
	res = 0;

      /* if the mode we want has any write bits set, we can't
	 be read only. */
      if (mode & (S_IWUSR | S_IWGRP | S_IWOTH))
	attr &= ~FILE_ATTRIBUTE_READONLY;
      else
	attr |= FILE_ATTRIBUTE_READONLY;

      if (S_ISLNK (mode) || S_ISSOCK (mode))
	attr |= FILE_ATTRIBUTE_SYSTEM;

      if (!SetFileAttributesA (win32_path.get_win32 (), attr))
	__seterrno ();
      else
	{
	  /* Correct NTFS security attributes have higher priority */
	  if (res == 0 || !allow_ntsec)
	    res = 0;
	}
    }

done:
  syscall_printf ("%d = chmod (%s, %p)", res, path, mode);
  return res;
}

/* fchmod: P96 5.6.4.1 */

extern "C" int
fchmod (int fd, mode_t mode)
{
  sigframe thisframe (mainthread);
  if (cygheap->fdtab.not_open (fd))
    {
      syscall_printf ("-1 = fchmod (%d, 0%o)", fd, mode);
      set_errno (EBADF);
      return -1;
    }

  const char *path = cygheap->fdtab[fd]->get_name ();

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

/* Cygwin internal */
static int
num_entries (const char *win32_name)
{
  WIN32_FIND_DATA buf;
  HANDLE handle;
  char buf1[MAX_PATH];
  int count = 0;

  strcpy (buf1, win32_name);
  int len = strlen (buf1);
  if (len == 0 || isdirsep (buf1[len - 1]))
    strcat (buf1, "*");
  else
    strcat (buf1, "/*");	/* */

  handle = FindFirstFileA (buf1, &buf);

  if (handle == INVALID_HANDLE_VALUE)
    return 0;
  count ++;
  while (FindNextFileA (handle, &buf))
    {
      if ((buf.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
	count ++;
    }
  FindClose (handle);
  return count;
}

extern "C" int
_fstat (int fd, struct stat *buf)
{
  int r;
  sigframe thisframe (mainthread);

  if (cygheap->fdtab.not_open (fd))
    {
      syscall_printf ("-1 = fstat (%d, %p)", fd, buf);
      set_errno (EBADF);
      r = -1;
    }
  else
    {
      memset (buf, 0, sizeof (struct stat));
      r = cygheap->fdtab[fd]->fstat (buf);
      syscall_printf ("%d = fstat (%d, %x)", r, fd, buf);
    }

  return r;
}

/* fsync: P96 6.6.1.1 */
extern "C" int
fsync (int fd)
{
  sigframe thisframe (mainthread);
  if (cygheap->fdtab.not_open (fd))
    {
      syscall_printf ("-1 = fsync (%d)", fd);
      set_errno (EBADF);
      return -1;
    }

  HANDLE h = cygheap->fdtab[fd]->get_handle ();

  if (FlushFileBuffers (h) == 0)
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

int __stdcall
stat_dev (DWORD devn, int unit, unsigned long ino, struct stat *buf)
{
  sigframe thisframe (mainthread);
  switch (devn)
    {
    case FH_PIPEW:
      buf->st_mode = STD_WBITS | S_IWGRP | S_IWOTH;
      break;
    case FH_PIPER:
      buf->st_mode = STD_RBITS;
      break;
    default:
      buf->st_mode = STD_RBITS | STD_WBITS | S_IWGRP | S_IWOTH;
      break;
    }

  buf->st_mode |= S_IFCHR;
  buf->st_blksize = S_BLKSIZE;
  buf->st_nlink = 1;
  buf->st_dev = buf->st_rdev = FHDEVN (devn) << 8 | (unit & 0xff);
  buf->st_ino = ino;
  buf->st_atime = buf->st_mtime = buf->st_ctime = time (NULL);
  return 0;
}

suffix_info stat_suffixes[] =
{
  suffix_info ("", 1),
  suffix_info (".exe", 1),
  suffix_info (NULL)
};

/* Cygwin internal */
static int
stat_worker (const char *caller, const char *name, struct stat *buf,
	     int nofollow)
{
  int res = -1;
  int oret = 1;
  int atts;

  int attribute = 0;
  uid_t uid;
  gid_t gid;

  UINT dtype;
  fhandler_disk_file fh (NULL);

  MALLOC_CHECK;

  debug_printf ("%s (%s, %p)", caller, name, buf);

  path_conv real_path (name, (nofollow ? PC_SYM_NOFOLLOW : PC_SYM_FOLLOW) |
					 PC_FULL, stat_suffixes);

  if (real_path.error)
    {
      set_errno (real_path.error);
      goto done;
    }

  if (check_null_invalid_struct_errno (buf))
    goto done;

  memset (buf, 0, sizeof (struct stat));

  if (real_path.is_device ())
    return stat_dev (real_path.get_devn (), real_path.get_unitn (),
		     hash_path_name (0, real_path.get_win32 ()), buf);

  atts = real_path.file_attributes ();

  debug_printf ("%d = file_attributes for '%s'", atts, real_path.get_win32 ());

  dtype = real_path.get_drive_type ();

  if ((atts == -1 || ! (atts & FILE_ATTRIBUTE_DIRECTORY) ||
       (iswinnt
	&& dtype != DRIVE_NO_ROOT_DIR
	&& dtype != DRIVE_UNKNOWN)))
    {
      oret = fh.open (real_path, O_RDONLY | O_BINARY | O_DIROPEN |
				 (nofollow ? O_NOSYMLINK : 0), 0);
      /* If we couldn't open the file, try a "query open" with no permissions.
	 This will allow us to determine *some* things about the file, at least. */
      if (!oret)
	{
	  fh.set_query_open (TRUE);
	  oret = fh.open (real_path, O_RDONLY | O_BINARY | O_DIROPEN |
				     (nofollow ? O_NOSYMLINK : 0), 0);
	}
      /* Check a special case here. If ntsec is ON it happens
	 that a process creates a file using mode 000 to disallow
	 other processes access. In contrast to UNIX, this results
	 in a failing open call in the same process. Check that
	 case. */
      if (!oret && allow_ntsec && get_errno () == EACCES
	  && !get_file_attribute (TRUE, real_path, &attribute, &uid, &gid)
	  && !attribute && uid == myself->uid && gid == myself->gid)
	{
	  set_file_attribute (TRUE, real_path, 0400);
	  oret = fh.open (real_path, O_RDONLY | O_BINARY | O_DIROPEN |
				     (nofollow ? O_NOSYMLINK : 0), 0);
	  set_file_attribute (TRUE, real_path.get_win32 (), 0);
	}
      if (oret)
	{
	  res = fh.fstat (buf);
	  fh.close ();
	  /* The number of links to a directory includes the
	     number of subdirectories in the directory, since all
	     those subdirectories point to it.
	     This is too slow on remote drives, so we do without it and
	     set the number of links to 2. */
	  /* Unfortunately the count of 2 confuses `find (1)' command. So
	     let's try it with `1' as link count. */
	  if (atts != -1 && (atts & FILE_ATTRIBUTE_DIRECTORY))
	    buf->st_nlink = (dtype == DRIVE_REMOTE
			     ? 1
			     : num_entries (real_path.get_win32 ()));
	  goto done;
	}
    }
  if (atts != -1 && (oret || (!oret && get_errno () != ENOENT
				    && get_errno () != ENOSHARE)))
    {
      /* Unfortunately, the above open may fail if the file exists, though.
	 So we have to care for this case here, too. */
      WIN32_FIND_DATA wfd;
      HANDLE handle;
      buf->st_nlink = 1;
      if (atts != -1
	  && (atts & FILE_ATTRIBUTE_DIRECTORY)
	  && dtype != DRIVE_REMOTE)
	buf->st_nlink = num_entries (real_path.get_win32 ());
      buf->st_dev = FHDEVN (FH_DISK) << 8;
      buf->st_ino = hash_path_name (0, real_path.get_win32 ());
      if (atts != -1 && (atts & FILE_ATTRIBUTE_DIRECTORY))
	buf->st_mode = S_IFDIR;
      else if (real_path.issymlink ())
	buf->st_mode = S_IFLNK;
      else if (real_path.issocket ())
	buf->st_mode = S_IFSOCK;
      else
	buf->st_mode = S_IFREG;
      if (!real_path.has_acls ()
	  || get_file_attribute (TRUE, real_path.get_win32 (),
				 &buf->st_mode,
				 &buf->st_uid, &buf->st_gid))
	{
	  buf->st_mode |= STD_RBITS | STD_XBITS;
	  if ((atts & FILE_ATTRIBUTE_READONLY) == 0)
	    buf->st_mode |= STD_WBITS;
	  if (real_path.issymlink ())
	    buf->st_mode |= S_IRWXU | S_IRWXG | S_IRWXO;
	  get_file_attribute (FALSE, real_path.get_win32 (),
			      NULL, &buf->st_uid, &buf->st_gid);
	}
      if ((handle = FindFirstFile (real_path.get_win32 (), &wfd))
	  != INVALID_HANDLE_VALUE)
	{
	  buf->st_atime   = to_time_t (&wfd.ftLastAccessTime);
	  buf->st_mtime   = to_time_t (&wfd.ftLastWriteTime);
	  buf->st_ctime   = to_time_t (&wfd.ftCreationTime);
	  buf->st_size    = wfd.nFileSizeLow;
	  buf->st_blksize = S_BLKSIZE;
	  buf->st_blocks  = ((unsigned long) buf->st_size +
			    S_BLKSIZE-1) / S_BLKSIZE;
	  FindClose (handle);
	}
      res = 0;
    }

 done:
  MALLOC_CHECK;
  syscall_printf ("%d = %s (%s, %p)", res, caller, name, buf);
  return res;
}

extern "C" int
_stat (const char *name, struct stat *buf)
{
  sigframe thisframe (mainthread);
  return stat_worker ("stat", name, buf, 0);
}

/* lstat: Provided by SVR4 and 4.3+BSD, POSIX? */
extern "C" int
lstat (const char *name, struct stat *buf)
{
  sigframe thisframe (mainthread);
  return stat_worker ("lstat", name, buf, 1);
}

extern int acl_access (const char *, int);

extern "C" int
access (const char *fn, int flags)
{
  sigframe thisframe (mainthread);
  // flags were incorrectly specified
  if (flags & ~ (F_OK|R_OK|W_OK|X_OK))
    {
      set_errno (EINVAL);
      return -1;
    }

  if (allow_ntsec)
    return acl_access (fn, flags);

  struct stat st;
  int r = stat (fn, &st);
  if (r)
    return -1;
  r = -1;
  if (flags & R_OK)
    {
      if (st.st_uid == myself->uid)
	{
	  if (! (st.st_mode & S_IRUSR))
	    goto done;
	}
      else if (st.st_gid == myself->gid)
	{
	  if (! (st.st_mode & S_IRGRP))
	    goto done;
	}
      else if (! (st.st_mode & S_IROTH))
	goto done;
    }
  if (flags & W_OK)
    {
      if (st.st_uid == myself->uid)
	{
	  if (! (st.st_mode & S_IWUSR))
	    goto done;
	}
      else if (st.st_gid == myself->gid)
	{
	  if (! (st.st_mode & S_IWGRP))
	    goto done;
	}
      else if (! (st.st_mode & S_IWOTH))
	goto done;
    }
  if (flags & X_OK)
    {
      if (st.st_uid == myself->uid)
	{
	  if (! (st.st_mode & S_IXUSR))
	    goto done;
	}
      else if (st.st_gid == myself->gid)
	{
	  if (! (st.st_mode & S_IXGRP))
	    goto done;
	}
      else if (! (st.st_mode & S_IXOTH))
	goto done;
    }
  r = 0;
done:
  if (r)
    set_errno (EACCES);
  return r;
}

extern "C" int
_rename (const char *oldpath, const char *newpath)
{
  sigframe thisframe (mainthread);
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
  char new_lnk_buf[MAX_PATH + 5];
  if (real_old.issymlink () && !real_new.error && !real_new.case_clash)
    {
      int len_old = strlen (real_old.get_win32 ());
      if (strcasematch (real_old.get_win32 () + len_old - 4, ".lnk"))
	{
	  strcpy (new_lnk_buf, newpath);
	  strcat (new_lnk_buf, ".lnk");
	  newpath = new_lnk_buf;
	  real_new.check (newpath, PC_SYM_NOFOLLOW);
	}
    }

  if (real_new.error || real_new.case_clash)
    {
      syscall_printf ("-1 = rename (%s, %s)", oldpath, newpath);
      set_errno (real_new.case_clash ? ECASECLASH : real_new.error);
      return -1;
    }

  if (!writable_directory (real_old.get_win32 ())
      || !writable_directory (real_new.get_win32 ()))
    {
      syscall_printf ("-1 = rename (%s, %s)", oldpath, newpath);
      set_errno (EACCES);
      return -1;
    }

  if (real_old.file_attributes () == (DWORD) -1) /* file to move doesn't exist */
    {
       syscall_printf ("file to move doesn't exist");
       set_errno (ENOENT);
       return (-1);
    }

  /* Destination file exists and is read only, change that or else
     the rename won't work. */
  if (real_new.file_attributes () != (DWORD) -1 &&
      real_new.file_attributes () & FILE_ATTRIBUTE_READONLY)
    SetFileAttributesA (real_new.get_win32 (),
			real_new.file_attributes () & ~FILE_ATTRIBUTE_READONLY);

  /* Shortcut hack No. 2, part 1 */
  if (!real_old.issymlink () && !real_new.error && real_new.issymlink () &&
      real_new.known_suffix && strcasematch (real_new.known_suffix, ".lnk") &&
      (lnk_suffix = strrchr (real_new.get_win32 (), '.')))
     *lnk_suffix = '\0';

  if (!MoveFile (real_old.get_win32 (), real_new.get_win32 ()))
    res = -1;

  if (res == 0 || (GetLastError () != ERROR_ALREADY_EXISTS
		   && GetLastError () != ERROR_FILE_EXISTS))
    goto done;

  if (iswinnt)
    {
      if (MoveFileEx (real_old.get_win32 (), real_new.get_win32 (),
		      MOVEFILE_REPLACE_EXISTING))
	res = 0;
    }
  else
    {
      syscall_printf ("try win95 hack");
      for (;;)
	{
	  if (!DeleteFileA (real_new.get_win32 ()) &&
	      GetLastError () != ERROR_FILE_NOT_FOUND)
	    {
	      syscall_printf ("deleting %s to be paranoid",
			      real_new.get_win32 ());
	      break;
	    }
	  else
	    {
	      if (MoveFile (real_old.get_win32 (), real_new.get_win32 ()))
		{
		  res = 0;
		  break;
		}
	    }
	}
    }

done:
  if (res)
    {
      __seterrno ();
      /* Reset R/O attributes if neccessary. */
      if (real_new.file_attributes () != (DWORD) -1 &&
	  real_new.file_attributes () & FILE_ATTRIBUTE_READONLY)
	SetFileAttributesA (real_new.get_win32 (), real_new.file_attributes ());
    }
  else
    {
      /* make the new file have the permissions of the old one */
      SetFileAttributesA (real_new.get_win32 (), real_old.file_attributes ());

      /* Shortcut hack, No. 2, part 2 */
      /* if the new filename was an existing shortcut, remove it now if the
	 new filename is equal to the shortcut name without .lnk suffix. */
      if (lnk_suffix)
	{
	  *lnk_suffix = '.';
	  DeleteFile (real_new.get_win32 ());
	}
    }

  syscall_printf ("%d = rename (%s, %s)", res, real_old.get_win32 (),
		  real_new.get_win32 ());

  return res;
}

extern "C" int
system (const char *cmdstring)
{
  sigframe thisframe (mainthread);
  int res;
  const char* command[4];
  _sig_func_ptr oldint, oldquit;
  sigset_t child_block, old_mask;

  if (cmdstring == (const char *) NULL)
	return 1;

  oldint = signal (SIGINT, SIG_IGN);
  oldquit = signal (SIGQUIT, SIG_IGN);
  sigemptyset (&child_block);
  sigaddset (&child_block, SIGCHLD);
  (void) sigprocmask (SIG_BLOCK, &child_block, &old_mask);

  command[0] = "sh";
  command[1] = "-c";
  command[2] = cmdstring;
  command[3] = (const char *) NULL;

  if ((res = spawnvp (_P_WAIT, "sh", command)) == -1)
    {
      // when exec fails, return value should be as if shell
      // executed exit (127)
      res = 127;
    }

  signal (SIGINT, oldint);
  signal (SIGQUIT, oldquit);
  (void) sigprocmask (SIG_SETMASK, &old_mask, 0);
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

static int
check_posix_perm (const char *fname, int v)
{
  extern int allow_ntea, allow_ntsec, allow_smbntsec;

  /* Windows 95/98/ME don't support file system security at all. */
  if (!iswinnt)
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
  if (cygheap->fdtab.not_open (fd))
    {
      set_errno (EBADF);
      return -1;
    }
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
      if (isatty (fd))
	return -1;
      else
	{
	  set_errno (EBADF);
	  return -1;
	}
    case _PC_POSIX_PERMISSIONS:
    case _PC_POSIX_SECURITY:
      {
	fhandler_base *fh = cygheap->fdtab[fd];
	if (fh->get_device () == FH_DISK)
	  return check_posix_perm (fh->get_win32_name (), v);
	set_errno (EINVAL);
	return -1;
      }
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
	if (full_path.is_device ())
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
  if (cygheap->fdtab.not_open (fd) || !cygheap->fdtab[fd]->is_tty ())
    {
      return 0;
    }
  return (char *) (cygheap->fdtab[fd]->ttyname ());
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
  syscall_printf ("_cygwin_istext_for_stdio (%d)\n", fd);
  if (CYGWIN_VERSION_OLD_STDIO_CRLF_HANDLING)
    {
      syscall_printf (" _cifs: old API\n");
      return 0; /* we do it for old apps, due to getc/putc macros */
    }

  if (cygheap->fdtab.not_open (fd))
    {
      syscall_printf (" _cifs: fd not open\n");
      return 0;
    }

  fhandler_base *p = cygheap->fdtab[fd];

  if (p->get_device () != FH_DISK)
    {
      syscall_printf (" _cifs: fd not disk file\n");
      return 0;
    }

  if (p->get_w_binary () || p->get_r_binary ())
    {
      syscall_printf (" _cifs: get_*_binary\n");
      return 0;
    }

  syscall_printf ("_cygwin_istext_for_stdio says yes\n");
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
    return 0;
  syscall_printf ("setmode: file was %s now %s\n",
		 f->_flags & __SCLE ? "cle" : "raw",
		 setmode_mode & O_TEXT ? "cle" : "raw");
  if (setmode_mode & O_TEXT)
    f->_flags |= __SCLE;
  else
    f->_flags &= ~__SCLE;
  return 0;
}

extern "C" int
getmode (int fd)
{
  if (cygheap->fdtab.not_open (fd))
    {
      set_errno (EBADF);
      return -1;
    }

  return cygheap->fdtab[fd]->get_flags () & (O_BINARY | O_TEXT);
}

/* Set a file descriptor into text or binary mode, returning the
   previous mode.  */

extern "C" int
setmode (int fd, int mode)
{
  if (cygheap->fdtab.not_open (fd))
    {
      set_errno (EBADF);
      return -1;
    }
  if (mode != O_BINARY  && mode != O_TEXT && mode != 0)
    {
      set_errno (EINVAL);
      return -1;
    }

  fhandler_base *p = cygheap->fdtab[fd];

  /* Note that we have no way to indicate the case that writes are
     binary but not reads, or vice-versa.  These cases can arise when
     using the tty or console interface.  People using those
     interfaces should not use setmode.  */

  int res;
  if (p->get_w_binary () && p->get_r_binary ())
    res = O_BINARY;
  else if (p->get_w_binset () && p->get_r_binset ())
    res = O_TEXT;	/* Specifically set O_TEXT */
  else
    res = 0;

  if (!mode)
    p->reset_to_open_binmode ();
  else if (mode & O_BINARY)
    {
      p->set_w_binary (1);
      p->set_r_binary (1);
    }
  else
    {
      p->set_w_binary (0);
      p->set_r_binary (0);
    }

  if (_cygwin_istext_for_stdio (fd))
    setmode_mode = O_TEXT;
  else
    setmode_mode = O_BINARY;
  setmode_file = fd;
  _fwalk (_REENT, setmode_helper);

  syscall_printf ("setmode (%d<%s>, %s) returns %s\n", fd, p->get_name (),
		  mode & O_TEXT ? "text" : "binary",
		  res & O_TEXT ? "text" : "binary");
  return res;
}

/* ftruncate: P96 5.6.7.1 */
extern "C" int
ftruncate (int fd, off_t length)
{
  sigframe thisframe (mainthread);
  int res = -1;

  if (cygheap->fdtab.not_open (fd))
    {
      set_errno (EBADF);
    }
  else
    {
      HANDLE h = cygheap->fdtab[fd]->get_handle ();
      off_t prev_loc;

      if (h)
	{
	  /* remember curr file pointer location */
	  prev_loc = cygheap->fdtab[fd]->lseek (0, SEEK_CUR);

	  cygheap->fdtab[fd]->lseek (length, SEEK_SET);
	  if (!SetEndOfFile (h))
	    {
	      __seterrno ();
	    }
	  else
	    res = 0;

	  /* restore original file pointer location */
	  cygheap->fdtab[fd]->lseek (prev_loc, 0);
	}
    }
  syscall_printf ("%d = ftruncate (%d, %d)", res, fd, length);

  return res;
}

/* truncate: Provided by SVR4 and 4.3+BSD.  Not part of POSIX.1 or XPG3 */
extern "C" int
truncate (const char *pathname, off_t length)
{
  sigframe thisframe (mainthread);
  int fd;
  int res = -1;

  fd = open (pathname, O_RDWR);

  if (fd == -1)
    set_errno (EBADF);
  else
    {
      res = ftruncate (fd, length);
      close (fd);
    }
  syscall_printf ("%d = truncate (%s, %d)", res, pathname, length);

  return res;
}

extern "C" long
get_osfhandle (int fd)
{
  long res = -1;

  if (cygheap->fdtab.not_open (fd))
    set_errno (EBADF);
  else
    res = (long) cygheap->fdtab[fd]->get_handle ();

  syscall_printf ("%d = get_osfhandle (%d)", res, fd);
  return res;
}

extern "C" int
statfs (const char *fname, struct statfs *sfs)
{
  sigframe thisframe (mainthread);
  if (!sfs)
    {
      set_errno (EFAULT);
      return -1;
    }

  path_conv full_path (fname, PC_SYM_FOLLOW | PC_FULL);
  char *root = rootdir (full_path);

  syscall_printf ("statfs %s", root);

  DWORD spc, bps, freec, totalc;

  if (!GetDiskFreeSpace (root, &spc, &bps, &freec, &totalc))
    {
      __seterrno ();
      return -1;
    }

  DWORD vsn, maxlen, flags;

  if (!GetVolumeInformation (root, NULL, 0, &vsn, &maxlen, &flags, NULL, 0))
    {
      __seterrno ();
      return -1;
    }
  sfs->f_type = flags;
  sfs->f_bsize = spc*bps;
  sfs->f_blocks = totalc;
  sfs->f_bfree = sfs->f_bavail = freec;
  sfs->f_files = -1;
  sfs->f_ffree = -1;
  sfs->f_fsid = vsn;
  sfs->f_namelen = maxlen;
  return 0;
}

extern "C" int
fstatfs (int fd, struct statfs *sfs)
{
  sigframe thisframe (mainthread);
  if (cygheap->fdtab.not_open (fd))
    {
      set_errno (EBADF);
      return -1;
    }
  fhandler_disk_file *f = (fhandler_disk_file *) cygheap->fdtab[fd];
  return statfs (f->get_name (), sfs);
}

/* setpgid: POSIX 4.3.3.1 */
extern "C" int
setpgid (pid_t pid, pid_t pgid)
{
  sigframe thisframe (mainthread);
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
      pinfo p (pid);
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
  sigframe thisframe (mainthread);
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
  sigframe thisframe (mainthread);
  return setpgid (0, 0);
}

extern "C" pid_t
getpgrp (void)
{
  sigframe thisframe (mainthread);
  return getpgid (0);
}

extern "C" char *
ptsname (int fd)
{
  sigframe thisframe (mainthread);
  if (cygheap->fdtab.not_open (fd))
    {
      set_errno (EBADF);
      return 0;
    }
  return (char *) (cygheap->fdtab[fd]->ptsname ());
}

/* FIXME: what is this? */
extern "C" int
regfree ()
{
  return 0;
}

/* mknod was the call to create directories before the introduction
   of mkdir in 4.2BSD and SVR3.  Use of mknod required superuser privs
   so the mkdir command had to be setuid root.
   Although mknod hasn't been implemented yet, some GNU tools (e.g. the
   fileutils) assume its existence so we must provide a stub that always
   fails. */
extern "C" int
mknod (const char *_path, mode_t mode, dev_t dev)
{
  set_errno (ENOSYS);
  return -1;
}

extern "C" int
mkfifo (const char *_path, mode_t mode)
{
  set_errno (ENOSYS);
  return -1;
}

/* setgid: POSIX 4.2.2.1 */
extern "C" int
setgid (gid_t gid)
{
  int ret = setegid (gid);
  if (!ret)
    cygheap->user.real_gid = myself->gid;
  return ret;
}

/* setuid: POSIX 4.2.2.1 */
extern "C" int
setuid (uid_t uid)
{
  int ret = seteuid (uid);
  if (!ret)
    cygheap->user.real_uid = myself->uid;
  debug_printf ("real: %d, effective: %d", cygheap->user.real_uid, myself->uid);
  return ret;
}

extern struct passwd *internal_getlogin (cygheap_user &user);

/* seteuid: standards? */
extern "C" int
seteuid (uid_t uid)
{
  sigframe thisframe (mainthread);
  if (iswinnt)
    {
      char orig_username[UNLEN + 1];
      char orig_domain[INTERNET_MAX_HOST_NAME_LENGTH + 1];
      char username[UNLEN + 1];
      DWORD ulen = UNLEN + 1;
      char domain[INTERNET_MAX_HOST_NAME_LENGTH + 1];
      DWORD dlen = INTERNET_MAX_HOST_NAME_LENGTH + 1;
      SID_NAME_USE use;

      if (uid == (uid_t) -1 || uid == myself->uid)
	{
	  debug_printf ("new euid == current euid, nothing happens");
	  return 0;
	}
      struct passwd *pw_new = getpwuid (uid);
      if (!pw_new)
	{
	  set_errno (EINVAL);
	  return -1;
	}

      cygsid tok_usersid;
      DWORD siz;

      char *env;
      orig_username[0] = orig_domain[0] = '\0';
      if ((env = getenv ("USERNAME")))
	strncat (orig_username, env, UNLEN + 1);
      if ((env = getenv ("USERDOMAIN")))
	strncat (orig_domain, env, INTERNET_MAX_HOST_NAME_LENGTH + 1);
      if (uid == cygheap->user.orig_uid)
	{

	  debug_printf ("RevertToSelf () (uid == orig_uid, token=%d)",
			cygheap->user.token);
	  RevertToSelf ();
	  if (cygheap->user.token != INVALID_HANDLE_VALUE)
	    cygheap->user.impersonated = FALSE;

	  HANDLE ptok = INVALID_HANDLE_VALUE;
	  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &ptok))
	    debug_printf ("OpenProcessToken(): %E\n");
	  else if (!GetTokenInformation (ptok, TokenUser, &tok_usersid,
					 sizeof tok_usersid, &siz))
	    debug_printf ("GetTokenInformation(): %E");
	  else if (!LookupAccountSid (NULL, tok_usersid, username, &ulen,
				      domain, &dlen, &use))
	    debug_printf ("LookupAccountSid(): %E");
	  else
	    {
	      setenv ("USERNAME", username, 1);
	      setenv ("USERDOMAIN", domain, 1);
	    }
	  if (ptok != INVALID_HANDLE_VALUE)
	    CloseHandle (ptok);
	}
      else
	{
	  cygsid usersid, pgrpsid, tok_pgrpsid;
	  HANDLE sav_token = INVALID_HANDLE_VALUE;
	  BOOL sav_impersonation;
	  BOOL current_token_is_internal_token = FALSE;
	  BOOL explicitely_created_token = FALSE;

	  struct group *gr = getgrgid (myself->gid);
	  debug_printf ("myself->gid: %d, gr: %d", myself->gid, gr);

	  usersid.getfrompw (pw_new);
	  pgrpsid.getfromgr (gr);

	  /* Only when ntsec is ON! */
	  /* Check if new user == user of impersonation token and
	     - if reasonable - new pgrp == pgrp of impersonation token. */
	  if (allow_ntsec && cygheap->user.token != INVALID_HANDLE_VALUE)
	    {
	      if (!GetTokenInformation (cygheap->user.token, TokenUser,
					&tok_usersid, sizeof tok_usersid, &siz))
		{
		  debug_printf ("GetTokenInformation(): %E");
		  tok_usersid = NO_SID;
		}
	      if (!GetTokenInformation (cygheap->user.token, TokenPrimaryGroup,
					&tok_pgrpsid, sizeof tok_pgrpsid, &siz))
		{
		  debug_printf ("GetTokenInformation(): %E");
		  tok_pgrpsid = NO_SID;
		}
	      /* Check if the current user token was internally created. */
	      TOKEN_SOURCE ts;
	      if (!GetTokenInformation (cygheap->user.token, TokenSource,
					&ts, sizeof ts, &siz))
		debug_printf ("GetTokenInformation(): %E");
	      else if (!memcmp (ts.SourceName, "Cygwin.1", 8))
		current_token_is_internal_token = TRUE;
	      if ((usersid && tok_usersid && usersid != tok_usersid) ||
		  /* Check for pgrp only if current token is an internal
		     token. Otherwise the external provided token is
		     very likely overwritten here. */
		  (current_token_is_internal_token &&
		   pgrpsid && tok_pgrpsid && pgrpsid != tok_pgrpsid))
		{
		  /* If not, RevertToSelf and close old token. */
		  debug_printf ("tsid != usersid");
		  RevertToSelf ();
		  sav_token = cygheap->user.token;
		  sav_impersonation = cygheap->user.impersonated;
		  cygheap->user.token = INVALID_HANDLE_VALUE;
		  cygheap->user.impersonated = FALSE;
		}
	    }

	  /* Only when ntsec is ON! */
	  /* If no impersonation token is available, try to
	     authenticate using NtCreateToken() or subauthentication. */
	  if (allow_ntsec && cygheap->user.token == INVALID_HANDLE_VALUE)
	    {
	      HANDLE ptok = INVALID_HANDLE_VALUE;

	      ptok = create_token (usersid, pgrpsid);
	      if (ptok != INVALID_HANDLE_VALUE)
		explicitely_created_token = TRUE;
	      else
		{
		  /* create_token failed. Try subauthentication. */
		  debug_printf ("create token failed, try subauthentication.");
		  ptok = subauth (pw_new);
		}
	      if (ptok != INVALID_HANDLE_VALUE)
		{
		  cygwin_set_impersonation_token (ptok);
		  /* If sav_token was internally created, destroy it. */
		  if (sav_token != INVALID_HANDLE_VALUE &&
		      current_token_is_internal_token)
		    CloseHandle (sav_token);
		}
	      else if (sav_token != INVALID_HANDLE_VALUE)
		cygheap->user.token = sav_token;
	    }
	  /* If no impersonation is active but an impersonation
	     token is available, try to impersonate. */
	  if (cygheap->user.token != INVALID_HANDLE_VALUE &&
	      !cygheap->user.impersonated)
	    {
	      debug_printf ("Impersonate (uid == %d)", uid);
	      RevertToSelf ();

	      /* If the token was explicitely created, all information has
		 already been set correctly. */
	      if (!explicitely_created_token)
		{
		  /* Try setting owner to same value as user. */
		  if (usersid &&
		      !SetTokenInformation (cygheap->user.token, TokenOwner,
					    &usersid, sizeof usersid))
		    debug_printf ("SetTokenInformation(user.token, "
				  "TokenOwner): %E");
		  /* Try setting primary group in token to current group
		     if token not explicitely created. */
		  if (pgrpsid &&
		      !SetTokenInformation (cygheap->user.token,
					    TokenPrimaryGroup,
					    &pgrpsid, sizeof pgrpsid))
		    debug_printf ("SetTokenInformation(user.token, "
				  "TokenPrimaryGroup): %E");

		}

	      /* Now try to impersonate. */
	      if (!LookupAccountSid (NULL, usersid, username, &ulen,
				     domain, &dlen, &use))
		debug_printf ("LookupAccountSid (): %E");
	      else if (!ImpersonateLoggedOnUser (cygheap->user.token))
		system_printf ("Impersonating (%d) in set(e)uid failed: %E",
			       cygheap->user.token);
	      else
		{
		  cygheap->user.impersonated = TRUE;
		  setenv ("USERNAME", username, 1);
		  setenv ("USERDOMAIN", domain, 1);
		}
	    }
	}

      cygheap_user user;
      /* user.token is used in internal_getlogin () to determine if
	 impersonation is active. If so, the token is used for
	 retrieving user's SID. */
      user.token = cygheap->user.impersonated ? cygheap->user.token
					      : INVALID_HANDLE_VALUE;
      struct passwd *pw_cur = internal_getlogin (user);
      if (pw_cur != pw_new)
	{
	  debug_printf ("Diffs!!! token: %d, cur: %d, new: %d, orig: %d",
			cygheap->user.token, pw_cur->pw_uid,
			pw_new->pw_uid, cygheap->user.orig_uid);
	  setenv ("USERNAME", orig_username, 1);
	  setenv ("USERDOMAIN", orig_domain, 1);
	  set_errno (EPERM);
	  return -1;
	}
      myself->uid = uid;
      cygheap->user = user;
    }
  else
    set_errno (ENOSYS);
  debug_printf ("real: %d, effective: %d", cygheap->user.real_uid, myself->uid);
  return 0;
}

/* setegid: from System V.  */
extern "C" int
setegid (gid_t gid)
{
  sigframe thisframe (mainthread);
  if (iswinnt)
    {
      if (gid != (gid_t) -1)
	{
	  struct group *gr;

	  if (!(gr = getgrgid (gid)))
	    {
	      set_errno (EINVAL);
	      return -1;
	    }
	  myself->gid = gid;
	  if (allow_ntsec)
	    {
	      cygsid gsid;
	      HANDLE ptok;

	      if (gsid.getfromgr (gr))
		{
		  if (!OpenProcessToken (GetCurrentProcess (),
					 TOKEN_ADJUST_DEFAULT,
					 &ptok))
		    debug_printf ("OpenProcessToken(): %E\n");
		  else
		    {
		      if (!SetTokenInformation (ptok, TokenPrimaryGroup,
						&gsid, sizeof gsid))
			debug_printf ("SetTokenInformation(myself, "
				      "TokenPrimaryGroup): %E");
		      CloseHandle (ptok);
		    }
		}
	    }
	}
    }
  else
    set_errno (ENOSYS);
  return 0;
}

/* chroot: privileged Unix system call.  */
/* FIXME: Not privileged here. How should this be done? */
extern "C" int
chroot (const char *newroot)
{
  sigframe thisframe (mainthread);
  int ret = -1;
  path_conv path (newroot, PC_SYM_FOLLOW | PC_FULL);

  if (path.error)
    goto done;
  if (path.file_attributes () == (DWORD)-1)
    {
      set_errno (ENOENT);
      goto done;
    }
  if (!(path.file_attributes () & FILE_ATTRIBUTE_DIRECTORY))
    {
      set_errno (ENOTDIR);
      goto done;
    }
  char buf[MAX_PATH];
  normalize_posix_path (newroot, buf);
  cygheap->root.set (buf, path);
  ret = 0;

done:
  syscall_printf ("%d = chroot (%s)", ret ? get_errno () : 0,
				      newroot ? newroot : "NULL");
  return ret;
}

extern "C" int
creat (const char *path, mode_t mode)
{
  sigframe thisframe (mainthread);
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
  sigframe thisframe (mainthread);
  int w, ret;
  ret = fread (&w, sizeof (int), 1, fp);
  return ret != 1 ? EOF : w;
}

extern "C" int
putw (int w, FILE *fp)
{
  sigframe thisframe (mainthread);
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
  sigframe thisframe (mainthread);
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

extern "C" void
login (struct utmp *ut)
{
  sigframe thisframe (mainthread);
  register int fd;
  int currtty = ttyslot ();

  if (currtty >= 0 && (fd = open (_PATH_UTMP, O_WRONLY | O_CREAT | O_BINARY,
					 0644)) >= 0)
    {
      (void) lseek (fd, (long) (currtty * sizeof (struct utmp)), SEEK_SET);
      (void) write (fd, (char *) ut, sizeof (struct utmp));
      (void) close (fd);
    }
  if ((fd = open (_PATH_WTMP, O_WRONLY | O_APPEND | O_BINARY, 0)) >= 0)
    {
      (void) write (fd, (char *) ut, sizeof (struct utmp));
      (void) close (fd);
    }
}

/* It isn't possible to use unix-style I/O function in logout code because
cygwin's I/O subsystem may be inaccessible at logout () call time.
FIXME (cgf): huh?
*/
extern "C" int
logout (char *line)
{
  sigframe thisframe (mainthread);
  int res = 0;
  HANDLE ut_fd;
  static const char path_utmp[] = _PATH_UTMP;

  path_conv win32_path (path_utmp);
  if (win32_path.error)
    return 0;

  ut_fd = CreateFile (win32_path.get_win32 (),
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			&sec_none_nih,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
  if (ut_fd != INVALID_HANDLE_VALUE)
    {
      struct utmp *ut;
      struct utmp ut_buf[100];
      off_t pos = 0;		/* Position in file */
      DWORD rd;

      while (!res && ReadFile (ut_fd, ut_buf, sizeof ut_buf, &rd, NULL)
	     && rd != 0)
	{
	  struct utmp *ut_end = (struct utmp *) ((char *) ut_buf + rd);

	  for (ut = ut_buf; ut < ut_end; ut++, pos += sizeof (*ut))
	    if (ut->ut_name[0]
		&& strncmp (ut->ut_line, line, sizeof (ut->ut_line)) == 0)
	      /* Found the entry for LINE; mark it as logged out.  */
	      {
		/* Zero out entries describing who's logged in.  */
		bzero (ut->ut_name, sizeof (ut->ut_name));
		bzero (ut->ut_host, sizeof (ut->ut_host));
		time (&ut->ut_time);

		/* Now seek back to the position in utmp at which UT occured,
		   and write the new version of UT there.  */
		if ((SetFilePointer (ut_fd, pos, 0, FILE_BEGIN) != 0xFFFFFFFF)
		    && (WriteFile (ut_fd, (char *) ut, sizeof (*ut),
				   &rd, NULL)))
		  {
		    res = 1;
		    break;
		  }
	      }
	}

      CloseHandle (ut_fd);
    }

  return res;
}
