/* fhandler.cc.  See console.cc for fhandler_console functions.

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <unistd.h>
#include <stdlib.h>
#include <sys/cygwin.h>
#include <sys/uio.h>
#include <signal.h>
#include "cygerrno.h"
#include "perprocess.h"
#include "security.h"
#include "cygwin/version.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "shared_info.h"
#include "pinfo.h"
#include <assert.h>
#include <limits.h>
#include <winioctl.h>

static NO_COPY const int CHUNK_SIZE = 1024; /* Used for crlf conversions */

struct __cygwin_perfile *perfile_table;

DWORD binmode;

inline fhandler_base&
fhandler_base::operator =(fhandler_base& x)
{
  memcpy (this, &x, sizeof *this);
  pc.set_normalized_path (x.pc.normalized_path);
  rabuf = NULL;
  ralen = 0;
  raixget = 0;
  raixput = 0;
  rabuflen = 0;
  return *this;
}

int
fhandler_base::puts_readahead (const char *s, size_t len)
{
  int success = 1;
  while ((*s || (len != (size_t) -1 && len--))
	 && (success = put_readahead (*s++) > 0))
    continue;
  return success;
}

int
fhandler_base::put_readahead (char value)
{
  char *newrabuf;
  if (raixput < rabuflen)
    /* Nothing to do */;
  else if ((newrabuf = (char *) realloc (rabuf, rabuflen += 32)))
    rabuf = newrabuf;
  else
    return 0;

  rabuf[raixput++] = value;
  ralen++;
  return 1;
}

int
fhandler_base::get_readahead ()
{
  int chret = -1;
  if (raixget < ralen)
    chret = ((unsigned char) rabuf[raixget++]) & 0xff;
  /* FIXME - not thread safe */
  if (raixget >= ralen)
    raixget = raixput = ralen = 0;
  return chret;
}

int
fhandler_base::peek_readahead (int queryput)
{
  int chret = -1;
  if (!queryput && raixget < ralen)
    chret = ((unsigned char) rabuf[raixget]) & 0xff;
  else if (queryput && raixput > 0)
    chret = ((unsigned char) rabuf[raixput - 1]) & 0xff;
  return chret;
}

void
fhandler_base::set_readahead_valid (int val, int ch)
{
  if (!val)
    ralen = raixget = raixput = 0;
  if (ch != -1)
    put_readahead (ch);
}

int
fhandler_base::eat_readahead (int n)
{
  int oralen = ralen;
  if (n < 0)
    n = ralen;
  if (n > 0 && ralen)
    {
      if ((int) (ralen -= n) < 0)
	ralen = 0;

      if (raixget >= ralen)
	raixget = raixput = ralen = 0;
      else if (raixput > ralen)
	raixput = ralen;
    }

  return oralen;
}

int
fhandler_base::get_readahead_into_buffer (char *buf, size_t buflen)
{
  int ch;
  int copied_chars = 0;

  while (buflen)
    if ((ch = get_readahead ()) < 0)
      break;
    else
      {
	buf[copied_chars++] = (unsigned char)(ch & 0xff);
	buflen--;
      }

  return copied_chars;
}

/* Record the file name. and name hash */
void
fhandler_base::set_name (path_conv &in_pc)
{
  memcpy (&pc, &in_pc, in_pc.size ());
  pc.set_normalized_path (in_pc.normalized_path);
  namehash = hash_path_name (0, get_win32_name ());
}

/* Detect if we are sitting at EOF for conditions where Windows
   returns an error but UNIX doesn't.  */
static int __stdcall
is_at_eof (HANDLE h, DWORD err)
{
  DWORD size, upper1, curr;

  size = GetFileSize (h, &upper1);
  if (size != INVALID_FILE_SIZE || GetLastError () == NO_ERROR)
    {
      LONG upper2 = 0;
      curr = SetFilePointer (h, 0, &upper2, FILE_CURRENT);
      if (curr == size && upper1 == (DWORD) upper2)
	return 1;
    }

  SetLastError (err);
  return 0;
}

void
fhandler_base::set_flags (int flags, int supplied_bin)
{
  int bin;
  int fmode;
  debug_printf ("flags %p, supplied_bin %p", flags, supplied_bin);
  if ((bin = flags & (O_BINARY | O_TEXT)))
    debug_printf ("O_TEXT/O_BINARY set in flags %p", bin);
  else if (get_r_binset () && get_w_binset ())
    bin = get_r_binary () ? O_BINARY : O_TEXT;	// FIXME: Not quite right
  else if ((fmode = get_default_fmode (flags)) & O_BINARY)
    bin = O_BINARY;
  else if (fmode & O_TEXT)
    bin = O_TEXT;
  else if (supplied_bin)
    bin = supplied_bin;
  else
    bin = get_w_binary () || get_r_binary () || (binmode != O_TEXT)
	  ? O_BINARY : O_TEXT;

  openflags = flags | bin;

  bin &= O_BINARY;
  set_r_binary (bin);
  set_w_binary (bin);
  syscall_printf ("filemode set to %s", bin ? "binary" : "text");
}

/* Normal file i/o handlers.  */

/* Cover function to ReadFile to achieve (as much as possible) Posix style
   semantics and use of errno.  */
void
fhandler_base::raw_read (void *ptr, size_t& ulen)
{
#define bytes_read ulen

  HANDLE h = NULL;	/* grumble */
  int prio = 0;		/* ditto */
  DWORD len = ulen;

  ulen = (size_t) -1;
  if (read_state)
    {
      h = GetCurrentThread ();
      prio = GetThreadPriority (h);
      (void) SetThreadPriority (h, THREAD_PRIORITY_TIME_CRITICAL);
      SetEvent (read_state);
    }
  BOOL res = ReadFile (get_handle (), ptr, len, (DWORD *) &ulen, 0);
  if (read_state)
    {
      SetEvent (read_state);
      (void) SetThreadPriority (h, prio);
    }
  if (!res)
    {
      /* Some errors are not really errors.  Detect such cases here.  */

      DWORD  errcode = GetLastError ();
      switch (errcode)
	{
	case ERROR_BROKEN_PIPE:
	  /* This is really EOF.  */
	  bytes_read = 0;
	  break;
	case ERROR_MORE_DATA:
	  /* `bytes_read' is supposedly valid.  */
	  break;
	case ERROR_NOACCESS:
	  if (is_at_eof (get_handle (), errcode))
	    {
	      bytes_read = 0;
	      break;
	    }
	case ERROR_INVALID_FUNCTION:
	case ERROR_INVALID_PARAMETER:
	case ERROR_INVALID_HANDLE:
	  if (openflags & O_DIROPEN)
	    {
	      set_errno (EISDIR);
	      bytes_read = (size_t) -1;
	      break;
	    }
	default:
	  syscall_printf ("ReadFile %s failed, %E", get_name ());
	  __seterrno_from_win_error (errcode);
	  bytes_read = (size_t) -1;
	  break;
	}
    }
#undef bytes_read
}

/* Cover function to WriteFile to provide Posix interface and semantics
   (as much as possible).  */
int
fhandler_base::raw_write (const void *ptr, size_t len)
{
  DWORD bytes_written;

  if (!WriteFile (get_output_handle (), ptr, len, &bytes_written, 0))
    {
      if (GetLastError () == ERROR_DISK_FULL && bytes_written > 0)
	return bytes_written;
      __seterrno ();
      if (get_errno () == EPIPE)
	raise (SIGPIPE);
      return -1;
    }
  return bytes_written;
}

#define ACCFLAGS(x) (x & (O_RDONLY | O_WRONLY | O_RDWR))
int
fhandler_base::get_default_fmode (int flags)
{
  int fmode = __fmode;
  if (perfile_table)
    {
      size_t nlen = strlen (get_name ());
      unsigned accflags = ACCFLAGS (flags);
      for (__cygwin_perfile *pf = perfile_table; pf->name; pf++)
	if (!*pf->name && ACCFLAGS (pf->flags) == accflags)
	  {
	    fmode = pf->flags & ~(O_RDONLY | O_WRONLY | O_RDWR);
	    break;
	  }
	else
	  {
	    size_t pflen = strlen (pf->name);
	    const char *stem = get_name () + nlen - pflen;
	    if (pflen > nlen || (stem != get_name () && !isdirsep (stem[-1])))
	      continue;
	    else if (ACCFLAGS (pf->flags) == accflags && strcasematch (stem, pf->name))
	      {
		fmode = pf->flags & ~(O_RDONLY | O_WRONLY | O_RDWR);
		break;
	      }
	  }
    }
  return fmode;
}

bool
fhandler_base::device_access_denied (int flags)
{
  int mode = 0;

  if (flags & O_RDWR)
    mode |= R_OK | W_OK;
  if (flags & (O_WRONLY | O_APPEND))
    mode |= W_OK;
  if (!mode)
    mode |= R_OK;

  return fhaccess (mode);
}

int
fhandler_base::fhaccess (int flags)
{
  int res = -1;
  if (error ())
    {
      set_errno (error ());
      goto done;
    }

  if (!exists ())
    {
      set_errno (ENOENT);
      goto done;
    }

  if (!(flags & (R_OK | W_OK | X_OK)))
    return 0;

  if (is_fs_special ())
    /* short circuit */;
  else if (has_attribute (FILE_ATTRIBUTE_READONLY) && (flags & W_OK))
    goto eaccess_done;
  else if (has_acls () && allow_ntsec)
    {
      res = check_file_access (get_win32_name (), flags);
      goto done;
    }

  struct __stat64 st;
  if (fstat (&st))
    goto done;

  if (flags & R_OK)
    {
      if (st.st_uid == myself->uid)
	{
	  if (!(st.st_mode & S_IRUSR))
	    goto eaccess_done;
	}
      else if (st.st_gid == myself->gid)
	{
	  if (!(st.st_mode & S_IRGRP))
	    goto eaccess_done;
	}
      else if (!(st.st_mode & S_IROTH))
	goto eaccess_done;
    }

  if (flags & W_OK)
    {
      if (st.st_uid == myself->uid)
	{
	  if (!(st.st_mode & S_IWUSR))
	    goto eaccess_done;
	}
      else if (st.st_gid == myself->gid)
	{
	  if (!(st.st_mode & S_IWGRP))
	    goto eaccess_done;
	}
      else if (!(st.st_mode & S_IWOTH))
	goto eaccess_done;
    }

  if (flags & X_OK)
    {
      if (st.st_uid == myself->uid)
	{
	  if (!(st.st_mode & S_IXUSR))
	    goto eaccess_done;
	}
      else if (st.st_gid == myself->gid)
	{
	  if (!(st.st_mode & S_IXGRP))
	    goto eaccess_done;
	}
      else if (!(st.st_mode & S_IXOTH))
	goto eaccess_done;
    }

  res = 0;
  goto done;

eaccess_done:
  set_errno (EACCES);
done:
  debug_printf ("returning %d", res);
  return res;
}

/* Open system call handler function. */
int
fhandler_base::open (int flags, mode_t mode)
{
  int res = 0;
  HANDLE x;
  int file_attributes;
  int shared;
  int creation_distribution;
  SECURITY_ATTRIBUTES sa = sec_none;
  security_descriptor sd;

  syscall_printf ("(%s, %p) query_open %d", get_win32_name (), flags, get_query_open ());

  if (get_win32_name () == NULL)
    {
      set_errno (ENOENT);
      goto done;
    }

  if (get_query_open ())
    access = get_query_open () == query_read_control ? READ_CONTROL : 0;
  else if (get_major () == DEV_TAPE_MAJOR)
    access = GENERIC_READ | GENERIC_WRITE;
  else if ((flags & (O_RDONLY | O_WRONLY | O_RDWR)) == O_RDONLY)
    access = GENERIC_READ;
  else if ((flags & (O_RDONLY | O_WRONLY | O_RDWR)) == O_WRONLY)
    access = GENERIC_WRITE;
  else
    access = GENERIC_READ | GENERIC_WRITE;

  /* Allow reliable lseek on disk devices. */
  if (get_major () == DEV_FLOPPY_MAJOR)
    access |= GENERIC_READ;

  /* FIXME: O_EXCL handling?  */

  if ((flags & O_TRUNC) && ((flags & O_ACCMODE) != O_RDONLY))
    {
      if (flags & O_CREAT)
	creation_distribution = CREATE_ALWAYS;
      else
	creation_distribution = TRUNCATE_EXISTING;
    }
  else if (flags & O_CREAT)
    creation_distribution = OPEN_ALWAYS;
  else
    creation_distribution = OPEN_EXISTING;

  if ((flags & O_EXCL) && (flags & O_CREAT))
    creation_distribution = CREATE_NEW;

  if (flags & O_APPEND)
    set_append_p ();

  /* These flags are host dependent. */
  shared = wincap.shared ();

  file_attributes = FILE_ATTRIBUTE_NORMAL;
  if (flags & O_DIROPEN)
    file_attributes |= FILE_FLAG_BACKUP_SEMANTICS;
  if (get_major () == DEV_SERIAL_MAJOR)
    file_attributes |= FILE_FLAG_OVERLAPPED;

#ifdef HIDDEN_DOT_FILES
  if (flags & O_CREAT && get_device () == FH_FS)
    {
      char *c = strrchr (get_win32_name (), '\\');
      if ((c && c[1] == '.') || *get_win32_name () == '.')
	file_attributes |= FILE_ATTRIBUTE_HIDDEN;
    }
#endif

  /* CreateFile() with dwDesiredAccess == 0 when called on remote
     share returns some handle, even if file doesn't exist. This code
     works around this bug. */
  if (get_query_open () && isremote () &&
      creation_distribution == OPEN_EXISTING && !pc.exists ())
    {
      set_errno (ENOENT);
      goto done;
    }

  /* If mode has no write bits set, we set the R/O attribute. */
  if (!(mode & (S_IWUSR | S_IWGRP | S_IWOTH)))
    file_attributes |= FILE_ATTRIBUTE_READONLY;

  /* If the file should actually be created and ntsec is on,
     set files attributes. */
  if (flags & O_CREAT && get_device () == FH_FS && allow_ntsec && has_acls ())
    set_security_attribute (mode, &sa, sd);

  x = CreateFile (get_win32_name (), access, shared, &sa, creation_distribution,
		  file_attributes, 0);

  if (x == INVALID_HANDLE_VALUE)
    {
      if (!wincap.can_open_directories () && pc.isdir ())
	{
	  if (flags & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL))
	    set_errno (EEXIST);
	  else if (flags & (O_WRONLY | O_RDWR))
	    set_errno (EISDIR);
	  else
	    set_nohandle (true);
	}
      else if (GetLastError () == ERROR_INVALID_HANDLE)
	set_errno (ENOENT);
      else
	__seterrno ();
      if (!get_nohandle ())
	goto done;
   }

  syscall_printf ("%p = CreateFile (%s, %p, %p, %p, %p, %p, 0)",
		  x, get_win32_name (), access, shared, &sa,
		  creation_distribution, file_attributes);

  set_io_handle (x);
  set_flags (flags, pc.binmode ());

  res = 1;
  set_open_status ();
done:
  syscall_printf ("%d = fhandler_base::open (%s, %p)", res, get_win32_name (),
		  flags);
  return res;
}

/* states:
   open buffer in binary mode?  Just do the read.

   open buffer in text mode?  Scan buffer for control zs and handle
   the first one found.  Then scan buffer, converting every \r\n into
   an \n.  If last char is an \r, look ahead one more char, if \n then
   modify \r, if not, remember char.
*/
void
fhandler_base::read (void *in_ptr, size_t& len)
{
  char *ptr = (char *) in_ptr;
  ssize_t copied_chars = 0;
  bool need_signal = !!read_state;
  int c;

  while (len)
    if ((c = get_readahead ()) < 0)
      break;
    else
      {
	ptr[copied_chars++] = (unsigned char) (c & 0xff);
	len--;
      }

  if (copied_chars && is_slow ())
    {
      len = (size_t) copied_chars;
      goto out;
    }

  if (!len)
    {
      len = (size_t) copied_chars;
      goto out;
    }

  raw_read (ptr + copied_chars, len);
  need_signal = false;
  if (!copied_chars)
    /* nothing */;
  else if ((ssize_t) len > 0)
    len += copied_chars;
  else
    len = copied_chars;

  if (get_r_binary () || len <= 0)
    goto out;

  /* Scan buffer and turn \r\n into \n */
  char *src, *dst, *end;
  src = (char *) ptr;
  dst = (char *) ptr;
  end = src + len - 1;

  /* Read up to the last but one char - the last char needs special handling */
  while (src < end)
    {
      if (*src == '\r' && src[1] == '\n')
	src++;
      *dst++ = *src++;
    }

  /* If not beyond end and last char is a '\r' then read one more
     to see if we should translate this one too */
  if (src > end)
    /* nothing */;
  else if (*src != '\r')
    *dst++ = *src;
  else
    {
      char c1;
      size_t c1len = 1;
      raw_read (&c1, c1len);
      if (c1len <= 0)
	/* nothing */;
      else if (c1 == '\n')
	*dst++ = '\n';
      else
	{
	  set_readahead_valid (1, c1);
	  *dst++ = *src;
	}
    }

  len = dst - (char *) ptr;

#ifndef NOSTRACE
  if (strace.active)
    {
      char buf[16 * 6 + 1];
      char *p = buf;

      for (int i = 0; i < copied_chars && i < 16; ++i)
	{
	  unsigned char c = ((unsigned char *) ptr)[i];
	  /* >= 33 so space prints in hex */
	  __small_sprintf (p, c >= 33 && c <= 127 ? " %c" : " %p", c);
	  p += strlen (p);
	}
      debug_printf ("read %d bytes (%s%s)", copied_chars, buf,
		    copied_chars > 16 ? " ..." : "");
    }
#endif

out:
  if (need_signal)
    SetEvent (read_state);

  debug_printf ("returning %d, %s mode", len,
		get_r_binary () ? "binary" : "text");
  return;
}

int
fhandler_base::write (const void *ptr, size_t len)
{
  int res;

  if (get_append_p ())
    SetFilePointer (get_output_handle (), 0, 0, FILE_END);
  else if (get_did_lseek ())
    {
      _off64_t actual_length, current_position;
      DWORD size_high = 0;
      LONG pos_high = 0;

      set_did_lseek (false); /* don't do it again */

      actual_length = GetFileSize (get_output_handle (), &size_high);
      actual_length += ((_off64_t) size_high) << 32;

      current_position = SetFilePointer (get_output_handle (), 0, &pos_high,
					 FILE_CURRENT);
      current_position += ((_off64_t) pos_high) << 32;

      if (current_position > actual_length)
	{
	  if ((get_fs_flags (FILE_SUPPORTS_SPARSE_FILES))
	      && current_position >= actual_length + (128 * 1024))
	    {
	      /* If the file systemn supports sparse files and the application
	         is writing after a long seek beyond EOF, convert the file to
		 a sparse file. */
	      DWORD dw;
	      HANDLE h = get_output_handle ();
	      BOOL r = DeviceIoControl (h, FSCTL_SET_SPARSE, NULL, 0, NULL,
	      				0, &dw, NULL);
	      syscall_printf ("%d = DeviceIoControl(%p, FSCTL_SET_SPARSE, "
			      "NULL, 0, NULL, 0, &dw, NULL)", r, h);
	    }
	  else if (wincap.has_lseek_bug ())
	    {
	      /* Oops, this is the bug case - Win95 uses whatever is on the
	         disk instead of some known (safe) value, so we must seek
		 back and fill in the gap with zeros. - DJ
	         Note: this bug doesn't happen on NT4, even though the
	         documentation for WriteFile() says that it *may* happen
		 on any OS. */
	      char zeros[512];
	      int number_of_zeros_to_write = current_position - actual_length;
	      memset (zeros, 0, 512);
	      SetFilePointer (get_output_handle (), 0, NULL, FILE_END);
	      while (number_of_zeros_to_write > 0)
		{
		  DWORD zeros_this_time = (number_of_zeros_to_write > 512
					 ? 512 : number_of_zeros_to_write);
		  DWORD written;
		  if (!WriteFile (get_output_handle (), zeros, zeros_this_time,
				  &written, NULL))
		    {
		      __seterrno ();
		      if (get_errno () == EPIPE)
			raise (SIGPIPE);
		      /* This might fail, but it's the best we can hope for */
		      SetFilePointer (get_output_handle (), current_position, NULL,
				      FILE_BEGIN);
		      return -1;

		    }
		  if (written < zeros_this_time) /* just in case */
		    {
		      set_errno (ENOSPC);
		      /* This might fail, but it's the best we can hope for */
		      SetFilePointer (get_output_handle (), current_position, NULL,
				      FILE_BEGIN);
		      return -1;
		    }
		  number_of_zeros_to_write -= written;
		}
	    }
	}
    }

  if (get_w_binary ())
    {
      debug_printf ("binary write");
      res = raw_write (ptr, len);
    }
  else
    {
      debug_printf ("text write");
      /* This is the Microsoft/DJGPP way.  Still not ideal, but it's
	 compatible.
	 Modified slightly by CGF 2000-10-07 */

      int left_in_data = len;
      char *data = (char *)ptr;
      res = 0;

      while (left_in_data > 0)
	{
	  char buf[CHUNK_SIZE + 1], *buf_ptr = buf;
	  int left_in_buf = CHUNK_SIZE;

	  while (left_in_buf > 0 && left_in_data > 0)
	    {
	      char ch = *data++;
	      if (ch == '\n')
		{
		  *buf_ptr++ = '\r';
		  left_in_buf--;
		}
	      *buf_ptr++ = ch;
	      left_in_buf--;
	      left_in_data--;
	      if (left_in_data > 0 && ch == '\r' && *data == '\n')
		{
		  *buf_ptr++ = *data++;
		  left_in_buf--;
		  left_in_data--;
		}
	    }

	  /* We've got a buffer-full, or we're out of data.  Write it out */
	  int nbytes;
	  int want = buf_ptr - buf;
	  if ((nbytes = raw_write (buf, want)) == want)
	    {
	      /* Keep track of how much written not counting additional \r's */
	      res = data - (char *)ptr;
	      continue;
	    }

	  if (nbytes == -1)
	    res = -1;		/* Error */
	  else
	    res += nbytes;	/* Partial write.  Return total bytes written. */
	  break;		/* All done */
	}
    }

  debug_printf ("%d = write (%p, %d)", res, ptr, len);
  return res;
}

ssize_t
fhandler_base::readv (const struct iovec *const iov, const int iovcnt,
		      ssize_t tot)
{
  assert (iov);
  assert (iovcnt >= 1);

  size_t len = tot;
  if (iovcnt == 1)
    {
      len = iov->iov_len;
      read (iov->iov_base, len);
      return len;
    }

  if (tot == -1)		// i.e. if not pre-calculated by the caller.
    {
      len = 0;
      const struct iovec *iovptr = iov + iovcnt;
      do
	{
	  iovptr -= 1;
	  len += iovptr->iov_len;
	}
      while (iovptr != iov);
    }

  assert (tot >= 0);

  if (!len)
    return 0;

  char *buf = (char *) alloca (tot);

  if (!buf)
    {
      set_errno (ENOMEM);
      return -1;
    }

  read (buf, len);
  ssize_t nbytes = (ssize_t) len;

  const struct iovec *iovptr = iov;

  while (nbytes > 0)
    {
      const int frag = min (nbytes, (ssize_t) iovptr->iov_len);
      memcpy (iovptr->iov_base, buf, frag);
      buf += frag;
      iovptr += 1;
      nbytes -= frag;
    }

  return len;
}

ssize_t
fhandler_base::writev (const struct iovec *const iov, const int iovcnt,
		       ssize_t tot)
{
  assert (iov);
  assert (iovcnt >= 1);

  if (iovcnt == 1)
    return write (iov->iov_base, iov->iov_len);

  if (tot == -1)		// i.e. if not pre-calculated by the caller.
    {
      tot = 0;
      const struct iovec *iovptr = iov + iovcnt;
      do
	{
	  iovptr -= 1;
	  tot += iovptr->iov_len;
	}
      while (iovptr != iov);
    }

  assert (tot >= 0);

  if (tot == 0)
    return 0;

  char *const buf = (char *) alloca (tot);

  if (!buf)
    {
      set_errno (ENOMEM);
      return -1;
    }

  char *bufptr = buf;
  const struct iovec *iovptr = iov;
  int nbytes = tot;

  while (nbytes != 0)
    {
      const int frag = min (nbytes, (ssize_t) iovptr->iov_len);
      memcpy (bufptr, iovptr->iov_base, frag);
      bufptr += frag;
      iovptr += 1;
      nbytes -= frag;
    }

  return write (buf, tot);
}

_off64_t
fhandler_base::lseek (_off64_t offset, int whence)
{
  _off64_t res;

  /* 9x/Me doesn't support 64bit offsets.  We trap that here and return
     EINVAL.  It doesn't make sense to simulate bigger offsets by a
     SetFilePointer sequence since FAT and FAT32 don't support file
     size >= 4GB anyway. */
  if (!wincap.has_64bit_file_access ()
      && (offset < LONG_MIN || offset > LONG_MAX))
    {
      debug_printf ("Win9x, offset not 32 bit.");
      set_errno (EINVAL);
      return (_off64_t)-1;
    }

  /* Seeks on text files is tough, we rewind and read till we get to the
     right place.  */

  if (whence != SEEK_CUR || offset != 0)
    {
      if (whence == SEEK_CUR)
	offset -= ralen - raixget;
      set_readahead_valid (0);
    }

  debug_printf ("lseek (%s, %D, %d)", get_name (), offset, whence);

  DWORD win32_whence = whence == SEEK_SET ? FILE_BEGIN
		       : (whence == SEEK_CUR ? FILE_CURRENT : FILE_END);

  LONG off_low = ((__uint64_t) offset) & UINT32_MAX;
  LONG *poff_high, off_high;
  if (!wincap.has_64bit_file_access ())
    poff_high = NULL;
  else
    {
      off_high =  ((__uint64_t) offset) >> 32LL;
      poff_high = &off_high;
    }

  debug_printf ("setting file pointer to %u (high), %u (low)", off_high, off_low);
  res = SetFilePointer (get_handle (), off_low, poff_high, win32_whence);
  if (res == INVALID_SET_FILE_POINTER && GetLastError ())
    {
      __seterrno ();
    }
  else
    {
      if (poff_high)
        res += (_off64_t) *poff_high << 32;

      /* When next we write(), we will check to see if *this* seek went beyond
	 the end of the file, and back-seek and fill with zeros if so - DJ */
      set_did_lseek (true);

      /* If this was a SEEK_CUR with offset 0, we still might have
	 readahead that we have to take into account when calculating
	 the actual position for the application.  */
      if (whence == SEEK_CUR)
	res -= ralen - raixget;
    }

  return res;
}

int
fhandler_base::close ()
{
  int res = -1;

  syscall_printf ("closing '%s' handle %p", get_name (), get_handle ());
  if (get_nohandle () || CloseHandle (get_handle ()))
    res = 0;
  else
    {
      paranoid_printf ("CloseHandle (%d <%s>) failed", get_handle (),
		       get_name ());

      __seterrno ();
    }
  return res;
}

int
fhandler_base::ioctl (unsigned int cmd, void *buf)
{
  int res;

  switch (cmd)
    {
    case FIONBIO:
      set_nonblocking (*(int *) buf);
      res = 0;
      break;
    default:
      set_errno (EINVAL);
      res = -1;
      break;
    }

  syscall_printf ("%d = ioctl (%x, %p)", res, cmd, buf);
  return res;
}

int
fhandler_base::lock (int, struct __flock64 *)
{
  set_errno (EINVAL);
  return -1;
}

extern "C" char * __stdcall
rootdir (char *full_path)
{
  /* Possible choices:
   * d:... -> d:/
   * \\server\share... -> \\server\share\
   * else current drive.
   */
  char *root = full_path;

  if (full_path[1] == ':')
    strcpy (full_path + 2, "\\");
  else if (full_path[0] == '\\' && full_path[1] == '\\')
    {
      char *cp = full_path + 2;
      while (*cp && *cp != '\\')
	cp++;
      if (!*cp)
	{
	  set_errno (ENOTDIR);
	  return NULL;
	}
      cp++;
      while (*cp && *cp != '\\')
	cp++;
      strcpy (cp, "\\");
    }
  else
    root = NULL;

  return root;
}

int __stdcall
fhandler_base::fstat (struct __stat64 *buf)
{
  debug_printf ("here");

  if (is_fs_special ())
    return fstat_fs (buf);

  switch (get_device ())
    {
    case FH_PIPE:
      buf->st_mode = S_IFIFO | STD_RBITS | STD_WBITS | S_IWGRP | S_IWOTH;
      break;
    case FH_PIPEW:
      buf->st_mode = S_IFIFO | STD_WBITS | S_IWGRP | S_IWOTH;
      break;
    case FH_PIPER:
      buf->st_mode = S_IFIFO | STD_RBITS;
      break;
    default:
      buf->st_mode = S_IFCHR | STD_RBITS | STD_WBITS | S_IWGRP | S_IWOTH;
      break;
    }

  buf->st_uid = geteuid32 ();
  buf->st_gid = getegid32 ();
  buf->st_nlink = 1;
  buf->st_blksize = S_BLKSIZE;
  time_as_timestruc_t (&buf->st_ctim);
  buf->st_atim = buf->st_mtim = buf->st_ctim;
  return 0;
}

void
fhandler_base::init (HANDLE f, DWORD a, mode_t bin)
{
  set_io_handle (f);
  access = a;
  a &= GENERIC_READ | GENERIC_WRITE;
  int flags = 0;
  if (a == GENERIC_READ)
    flags = O_RDONLY;
  else if (a == GENERIC_WRITE)
    flags = O_WRONLY;
  else if (a == (GENERIC_READ | GENERIC_WRITE))
    flags = O_RDWR;
  set_flags (flags | bin);
  set_open_status ();
  debug_printf ("created new fhandler_base for handle %p, bin %d", f, get_r_binary ());
}

void
fhandler_base::dump (void)
{
  paranoid_printf ("here");
}

int
fhandler_base::dup (fhandler_base *child)
{
  debug_printf ("in fhandler_base dup");

  HANDLE nh;
  if (!get_nohandle ())
    {
      if (!DuplicateHandle (hMainProc, get_handle (), hMainProc, &nh, 0, TRUE,
			    DUPLICATE_SAME_ACCESS))
	{
	  system_printf ("dup(%s) failed, handle %x, %E",
			 get_name (), get_handle ());
	  __seterrno ();
	  return -1;
	}

      VerifyHandle (nh);
      child->set_io_handle (nh);
    }
  return 0;
}

int fhandler_base::fcntl (int cmd, void *arg)
{
  int res;

  switch (cmd)
    {
    case F_GETFD:
      res = get_close_on_exec () ? FD_CLOEXEC : 0;
      break;
    case F_SETFD:
      set_close_on_exec ((int) arg);
      res = 0;
      break;
    case F_GETFL:
      res = get_flags ();
      debug_printf ("GETFL: %d", res);
      break;
    case F_SETFL:
      {
	/*
	 * Only O_APPEND, O_ASYNC and O_NONBLOCK/O_NDELAY are allowed.
	 * Each other flag will be ignored.
	 * Since O_ASYNC isn't defined in fcntl.h it's currently
	 * ignored as well.
	 */
	const int allowed_flags = O_APPEND | O_NONBLOCK_MASK;
	int new_flags = (int) arg & allowed_flags;
	/* Carefully test for the O_NONBLOCK or deprecated OLD_O_NDELAY flag.
	   Set only the flag that has been passed in.  If both are set, just
	   record O_NONBLOCK.   */
	if ((new_flags & OLD_O_NDELAY) && (new_flags & O_NONBLOCK))
	  new_flags &= ~OLD_O_NDELAY;
	set_flags ((get_flags () & ~allowed_flags) | new_flags);
      }
      res = 0;
      break;
    case F_GETLK:
    case F_SETLK:
    case F_SETLKW:
      res = lock (cmd, (struct __flock64 *) arg);
      break;
    default:
      set_errno (EINVAL);
      res = -1;
      break;
    }
  return res;
}

/* Base terminal handlers.  These just return errors.  */

int
fhandler_base::tcflush (int)
{
  set_errno (ENOTTY);
  return -1;
}

int
fhandler_base::tcsendbreak (int)
{
  set_errno (ENOTTY);
  return -1;
}

int
fhandler_base::tcdrain (void)
{
  set_errno (ENOTTY);
  return -1;
}

int
fhandler_base::tcflow (int)
{
  set_errno (ENOTTY);
  return -1;
}

int
fhandler_base::tcsetattr (int, const struct termios *)
{
  set_errno (ENOTTY);
  return -1;
}

int
fhandler_base::tcgetattr (struct termios *)
{
  set_errno (ENOTTY);
  return -1;
}

int
fhandler_base::tcsetpgrp (const pid_t)
{
  set_errno (ENOTTY);
  return -1;
}

int
fhandler_base::tcgetpgrp (void)
{
  set_errno (ENOTTY);
  return -1;
}

void
fhandler_base::operator delete (void *p)
{
  cfree (p);
  return;
}

/* Normal I/O constructor */
fhandler_base::fhandler_base () :
  status (),
  open_status (),
  access (0),
  io_handle (NULL),
  namehash (0),
  openflags (0),
  rabuf (NULL),
  ralen (0),
  raixget (0),
  raixput (0),
  rabuflen (0),
  fs_flags (0),
  read_state (NULL),
  archetype (NULL),
  usecount (0)
{
}

/* Normal I/O destructor */
fhandler_base::~fhandler_base (void)
{
  if (rabuf)
    free (rabuf);
}

/**********************************************************************/
/* /dev/null */

fhandler_dev_null::fhandler_dev_null () :
	fhandler_base ()
{
}

void
fhandler_dev_null::dump (void)
{
  paranoid_printf ("here");
}

void
fhandler_base::set_no_inheritance (HANDLE &h, int not_inheriting)
{
  HANDLE oh = h;
  /* Note that we could use SetHandleInformation here but it is not available
     on all platforms.  Test cases seem to indicate that using DuplicateHandle
     in this fashion does not actually close the original handle, which is
     what we want.  If this changes in the future, we may be forced to use
     SetHandleInformation on newer OS's */
  if (!DuplicateHandle (hMainProc, oh, hMainProc, &h, 0, !not_inheriting,
			     DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE))
    debug_printf ("DuplicateHandle failed, %E");
  if (oh != h)
    VerifyHandle (h);
#ifdef DEBUGGING_AND_FDS_PROTECTED
  if (h)
    setclexec (oh, h, not_inheriting);
#endif
}

void
fhandler_base::fork_fixup (HANDLE parent, HANDLE &h, const char *name)
{
  HANDLE oh = h;
  if (/* !is_socket () && */ !get_close_on_exec ())
    debug_printf ("handle %p already opened", h);
  else if (!DuplicateHandle (parent, h, hMainProc, &h, 0, !get_close_on_exec (),
			     DUPLICATE_SAME_ACCESS))
    system_printf ("%s - %E, handle %s<%p>", get_name (), name, h);
  else if (oh != h)
    VerifyHandle (h);
}

void
fhandler_base::set_close_on_exec (int val)
{
  if (!get_nohandle ())
    set_no_inheritance (io_handle, val);
  set_close_on_exec_flag (val);
  debug_printf ("set close_on_exec for %s to %d", get_name (), val);
}

void
fhandler_base::fixup_after_fork (HANDLE parent)
{
  debug_printf ("inheriting '%s' from parent", get_name ());
  if (!get_nohandle ())
    fork_fixup (parent, io_handle, "io_handle");
}

bool
fhandler_base::is_nonblocking ()
{
  return (openflags & O_NONBLOCK_MASK) != 0;
}

void
fhandler_base::set_nonblocking (int yes)
{
  int current = openflags & O_NONBLOCK_MASK;
  int new_flags = yes ? (!current ? O_NONBLOCK : current) : 0;
  openflags = (openflags & ~O_NONBLOCK_MASK) | new_flags;
}

DIR *
fhandler_base::opendir ()
{
  set_errno (ENOTDIR);
  return NULL;
}

struct dirent *
fhandler_base::readdir (DIR *)
{
  set_errno (ENOTDIR);
  return NULL;
}

_off64_t
fhandler_base::telldir (DIR *)
{
  set_errno (ENOTDIR);
  return -1;
}

void
fhandler_base::seekdir (DIR *, _off64_t)
{
  set_errno (ENOTDIR);
  return;
}

void
fhandler_base::rewinddir (DIR *)
{
  set_errno (ENOTDIR);
  return;
}

int
fhandler_base::closedir (DIR *)
{
  set_errno (ENOTDIR);
  return -1;
}
