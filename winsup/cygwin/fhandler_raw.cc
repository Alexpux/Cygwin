/* fhandler_raw.cc.  See fhandler.h for a description of the fhandler classes.

   Copyright 1999, 2000, 2001, 2002, 2003, 2004, 2005 Red Hat, Inc.

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

#include "winsup.h"
#include <sys/termios.h>
#include <unistd.h>

#include <cygwin/rdevio.h>
#include <sys/mtio.h>
#include <ntdef.h>
#include "cygerrno.h"
#include "perprocess.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "ntdll.h"

/**********************************************************************/
/* fhandler_dev_raw */

int
fhandler_dev_raw::is_eom (int win_error)
{
  return 0;
}

int
fhandler_dev_raw::is_eof (int)
{
  return 0;
}


/* Wrapper functions to simplify error handling. */

BOOL
fhandler_dev_raw::write_file (const void *buf, DWORD to_write,
			      DWORD *written, int *err)
{
  BOOL ret;

  *err = 0;
  if (!(ret = WriteFile (get_handle (), buf, to_write, written, 0)))
    *err = GetLastError ();
  syscall_printf ("%d (err %d) = WriteFile (%d, %d, write %d, written %d, 0)",
		  ret, *err, get_handle (), buf, to_write, *written);
  return ret;
}

BOOL
fhandler_dev_raw::read_file (void *buf, DWORD to_read, DWORD *read, int *err)
{
  BOOL ret;

  *err = 0;
  if (!(ret = ReadFile (get_handle (), buf, to_read, read, 0)))
    *err = GetLastError ();
  syscall_printf ("%d (err %d) = ReadFile (%d, %d, to_read %d, read %d, 0)",
		  ret, *err, get_handle (), buf, to_read, *read);
  return ret;
}

fhandler_dev_raw::fhandler_dev_raw ()
  : fhandler_base (), status ()
{
  need_fork_fixup (true);
}

fhandler_dev_raw::~fhandler_dev_raw (void)
{
  if (devbufsiz > 1L)
    delete [] devbuf;
}

int __stdcall
fhandler_dev_raw::fstat (struct __stat64 *buf)
{
  debug_printf ("here");

  fhandler_base::fstat (buf);
  if (is_auto_device ())
    {
      if (get_major () == DEV_TAPE_MAJOR)
	buf->st_mode = S_IFCHR | STD_RBITS | STD_WBITS | S_IWGRP | S_IWOTH;
      else
	buf->st_mode = S_IFBLK | STD_RBITS | STD_WBITS | S_IWGRP | S_IWOTH;

      buf->st_uid = geteuid32 ();
      buf->st_gid = getegid32 ();
      buf->st_nlink = 1;
      buf->st_blksize = S_BLKSIZE;
      time_as_timestruc_t (&buf->st_ctim);
      buf->st_atim = buf->st_mtim = buf->st_ctim;
    }
  return 0;
}

int
fhandler_dev_raw::open (int flags, mode_t)
{
  if (!wincap.has_raw_devices ())
    {
      set_errno (ENOENT);
      debug_printf ("%s is accessible under NT/W2K only", get_win32_name ());
      return 0;
    }

  /* Check for illegal flags. */
  if (get_major () != DEV_TAPE_MAJOR && (flags & (O_APPEND | O_EXCL)))
    {
      set_errno (EINVAL);
      return 0;
    }

  /* Always open a raw device existing and binary. */
  flags &= ~(O_CREAT | O_TRUNC);
  flags |= O_BINARY;

  /* Write-only doesn't work well with raw devices */
  if ((flags & (O_RDONLY | O_WRONLY | O_RDWR)) == O_WRONLY)
    flags = ((flags & ~O_WRONLY) | O_RDWR);

  int res = fhandler_base::open (flags, 0);
  if (res && devbufsiz > 1L)
    devbuf = new char [devbufsiz];

  return res;
}

int
fhandler_dev_raw::close (void)
{
  return fhandler_base::close ();
}

void
fhandler_dev_raw::raw_read (void *ptr, size_t& ulen)
{
  DWORD bytes_read = 0;
  DWORD read2;
  DWORD bytes_to_read;
  int ret;
  size_t len = ulen;
  char *tgt;
  char *p = (char *) ptr;

  /* Checking a previous end of file */
  if (eof_detected () && !lastblk_to_read ())
    {
      eof_detected (false);
      ulen = 0;
      return;
    }

  /* Checking a previous end of media */
  if (eom_detected () && !lastblk_to_read ())
    {
      set_errno (ENOSPC);
      goto err;
    }

  if (devbuf)
    {
      while (len > 0)
	{
	  if (devbufstart < devbufend)
	    {
	      bytes_to_read = min (len, devbufend - devbufstart);
	      debug_printf ("read %d bytes from buffer (rest %d)",
			    bytes_to_read,
			    devbufend - devbufstart - bytes_to_read);
	      memcpy (p, devbuf + devbufstart, bytes_to_read);
	      len -= bytes_to_read;
	      p += bytes_to_read;
	      bytes_read += bytes_to_read;
	      devbufstart += bytes_to_read;

	      if (lastblk_to_read ())
		{
		  lastblk_to_read (false);
		  break;
		}
	    }
	  if (len > 0)
	    {
	      if (len >= devbufsiz)
		{
		  bytes_to_read = (len / 512) * 512;
		  tgt = p;
		  debug_printf ("read %d bytes direct from file",bytes_to_read);
		}
	      else
		{
		  tgt = devbuf;
		  bytes_to_read = devbufsiz;
		  debug_printf ("read %d bytes from file into buffer",
				bytes_to_read);
		}
	      if (!read_file (tgt, bytes_to_read, &read2, &ret))
		{
		  if (!is_eof (ret) && !is_eom (ret))
		    {
		      __seterrno ();
		      goto err;
		    }

		  if (is_eof (ret))
		    eof_detected (true);
		  else
		    eom_detected (true);

		  if (!read2)
		    {
		      if (!bytes_read && is_eom (ret))
			{
			  debug_printf ("return -1, set errno to ENOSPC");
			  set_errno (ENOSPC);
			  goto err;
			}
		      break;
		    }
		  lastblk_to_read (true);
		}
	      if (!read2)
	       break;
	      if (tgt == devbuf)
		{
		  devbufstart = 0;
		  devbufend = read2;
		}
	      else
		{
		  len -= read2;
		  p += read2;
		  bytes_read += read2;
		}
	    }
	}
    }
  else if (!read_file (p, len, &bytes_read, &ret))
    {
      if (!is_eof (ret) && !is_eom (ret))
	{
	  __seterrno ();
	  goto err;
	}
      if (bytes_read)
	{
	  if (is_eof (ret))
	    eof_detected (true);
	  else
	    eom_detected (true);
	}
      else if (is_eom (ret))
	{
	  debug_printf ("return -1, set errno to ENOSPC");
	  set_errno (ENOSPC);
	  goto err;
	}
    }

  ulen = (size_t) bytes_read;
  return;

err:
  ulen = (size_t) -1;
  return;
}

int
fhandler_dev_raw::raw_write (const void *ptr, size_t len)
{
  DWORD bytes_written = 0;
  char *p = (char *) ptr;
  int ret;

  /* Checking a previous end of media on tape */
  if (eom_detected ())
    {
      set_errno (ENOSPC);
      return -1;
    }

  /* Invalidate buffer. */
  devbufstart = devbufend = 0;

  if (len > 0)
    {
      if (!write_file (p, len, &bytes_written, &ret))
	{
	  if (!is_eom (ret))
	    {
	      __seterrno ();
	      return -1;
	    }
	  eom_detected (true);
	  if (!bytes_written)
	    {
	      set_errno (ENOSPC);
	      return -1;
	    }
	}
    }
  return bytes_written;
}

int
fhandler_dev_raw::dup (fhandler_base *child)
{
  int ret = fhandler_base::dup (child);

  if (! ret)
    {
      fhandler_dev_raw *fhc = (fhandler_dev_raw *) child;

      fhc->devbufsiz = devbufsiz;
      if (devbufsiz > 1L)
	fhc->devbuf = new char [devbufsiz];
      fhc->devbufstart = 0;
      fhc->devbufend = 0;
      fhc->eom_detected (eom_detected ());
      fhc->eof_detected (eof_detected ());
      fhc->lastblk_to_read (false);
    }
  return ret;
}

void
fhandler_dev_raw::fixup_after_fork (HANDLE)
{
  devbufstart = 0;
  devbufend = 0;
  lastblk_to_read (false);
}

void
fhandler_dev_raw::fixup_after_exec ()
{
  if (devbufsiz > 1L)
    devbuf = new char [devbufsiz];
  devbufstart = 0;
  devbufend = 0;
  lastblk_to_read (false);
}

int
fhandler_dev_raw::ioctl (unsigned int cmd, void *buf)
{
  int ret = NO_ERROR;

  if (cmd == RDIOCDOP)
    {
      struct rdop *op = (struct rdop *) buf;

      if (!op)
	ret = ERROR_INVALID_PARAMETER;
      else
	switch (op->rd_op)
	  {
	  case RDSETBLK:
	    if (get_major () == DEV_TAPE_MAJOR)
	      {
		struct mtop mop;

		mop.mt_op = MTSETBLK;
		mop.mt_count = op->rd_parm;
		ret = ioctl (MTIOCTOP, &mop);
	      }
	    else if (op->rd_parm % 512)
	      ret = ERROR_INVALID_PARAMETER;
	    else if (devbuf && op->rd_parm < devbufend - devbufstart)
	      ret = ERROR_INVALID_PARAMETER;
	    else if (!devbuf || op->rd_parm != devbufsiz)
	      {
		char *buf = new char [op->rd_parm];
		if (devbufsiz > 1L)
		  {
		    memcpy (buf, devbuf + devbufstart, devbufend - devbufstart);
		    devbufend -= devbufstart;
		    delete [] devbuf;
		  }
		else
		  devbufend = 0;

		devbufstart = 0;
		devbuf = buf;
		devbufsiz = op->rd_parm;
	      }
	    break;
	  default:
	    break;
	  }
    }
  else if (cmd == RDIOCGET)
    {
      struct rdget *get = (struct rdget *) buf;

      if (!get)
	ret = ERROR_INVALID_PARAMETER;
      else
	get->bufsiz = devbufsiz ? devbufsiz : 1L;
    }
  else
    return fhandler_base::ioctl (cmd, buf);

  if (ret != NO_ERROR)
    {
      SetLastError (ret);
      __seterrno ();
      return -1;
    }
  return 0;
}
