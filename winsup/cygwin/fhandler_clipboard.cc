/* fhandler_dev_clipboard: code to access /dev/clipboard

   Copyright 2000, 2001, 2002, 2003, 2004, 2005 Red Hat, Inc

   Written by Charles Wilson (cwilson@ece.gatech.edu)

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <windows.h>
#include <wingdi.h>
#include <winuser.h>
#include "cygerrno.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"

/*
 * Robert Collins:
 * FIXME: should we use GetClipboardSequenceNumber to tell if the clipboard has
 * changed? How does /dev/clipboard operate under (say) linux?
 */

static const NO_COPY char *CYGWIN_NATIVE = "CYGWIN_NATIVE_CLIPBOARD";
/* this is MT safe because windows format id's are atomic */
static int cygnativeformat;

fhandler_dev_clipboard::fhandler_dev_clipboard ()
  : fhandler_base (), pos (0), membuffer (NULL), msize (0),
  eof (true)
{
  /* FIXME: check for errors and loop until we can open the clipboard */
  OpenClipboard (NULL);
  cygnativeformat = RegisterClipboardFormat (CYGWIN_NATIVE);
  CloseClipboard ();
}

/*
 * Special clipboard dup to duplicate input and output
 * handles.
 */

int
fhandler_dev_clipboard::dup (fhandler_base * child, HANDLE from_proc)
{
  fhandler_dev_clipboard *fhc = (fhandler_dev_clipboard *) child;

  if (!fhc->open (get_flags (), 0))
    system_printf ("error opening clipboard, %E");

  fhc->membuffer = membuffer;
  fhc->pos = pos;
  fhc->msize = msize;

  return 0;
}

int
fhandler_dev_clipboard::open (int flags, mode_t)
{
  set_flags (flags | O_TEXT);
  eof = false;
  pos = 0;
  if (membuffer)
    free (membuffer);
  membuffer = NULL;
  if (!cygnativeformat)
    cygnativeformat = RegisterClipboardFormat (CYGWIN_NATIVE);
  nohandle (true);
  set_open_status ();
  return 1;
}

static int
set_clipboard (const void *buf, size_t len)
{
  HGLOBAL hmem;
  unsigned char *clipbuf;
  /* Native CYGWIN format */
  OpenClipboard (0);
  hmem = GlobalAlloc (GMEM_MOVEABLE, len + sizeof (size_t));
  if (!hmem)
    {
      system_printf ("Couldn't allocate global buffer for write");
      return -1;
    }
  clipbuf = (unsigned char *) GlobalLock (hmem);
  memcpy (clipbuf + sizeof (size_t), buf, len);
  *(size_t *) (clipbuf) = len;
  GlobalUnlock (hmem);
  EmptyClipboard ();
  if (!cygnativeformat)
    cygnativeformat = RegisterClipboardFormat (CYGWIN_NATIVE);
  if (!SetClipboardData (cygnativeformat, hmem))
    {
      system_printf
	("Couldn't write native format to the clipboard %04x %x",
	 cygnativeformat, hmem);
/* FIXME: return an appriate error code &| set_errno(); */
      return -1;
    }
  CloseClipboard ();
  if (GlobalFree (hmem))
    {
      system_printf
	("Couldn't free global buffer after write to the clipboard");
/* FIXME: return an appriate error code &| set_errno(); */
      return 0;
    }

  /* CF_TEXT/CF_OEMTEXT for copying to wordpad and the like */

  OpenClipboard (0);
  hmem = GlobalAlloc (GMEM_MOVEABLE, len + 2);
  if (!hmem)
    {
      system_printf ("Couldn't allocate global buffer for write");
      return -1;
    }
  clipbuf = (unsigned char *) GlobalLock (hmem);
  memcpy (clipbuf, buf, len);
  *(clipbuf + len) = '\0';
  *(clipbuf + len + 1) = '\0';
  GlobalUnlock (hmem);
  if (!SetClipboardData
      ((current_codepage == ansi_cp ? CF_TEXT : CF_OEMTEXT), hmem))
    {
      system_printf ("Couldn't write to the clipboard");
/* FIXME: return an appriate error code &| set_errno(); */
      return -1;
    }
  CloseClipboard ();
  if (GlobalFree (hmem))
    {
      system_printf
	("Couldn't free global buffer after write to the clipboard");
/* FIXME: return an appriate error code &| set_errno(); */
    }
  return 0;
}

/* FIXME: arbitrary seeking is not handled */
int
fhandler_dev_clipboard::write (const void *buf, size_t len)
{
  if (!eof)
    {
      /* write to our membuffer */
      size_t cursize = msize;
      void *tempbuffer = realloc (membuffer, cursize + len);
      if (!tempbuffer)
	{
	  system_printf ("Couldn't realloc() clipboard buffer for write");
	  return -1;
	}
      membuffer = tempbuffer;
      msize = cursize + len;
      memcpy ((unsigned char *) membuffer + cursize, buf, len);

      /* now pass to windows */
      if (set_clipboard (membuffer, msize))
	{
	  /* FIXME: membuffer is now out of sync with pos, but msize is used above */
	  set_errno (ENOSPC);
	  return -1;
	}

      pos = msize;

      eof = false;
      return len;
    }
  else
    {
      /* FIXME: return 0 bytes written, file not open */
      return 0;
    }
}

void __stdcall
fhandler_dev_clipboard::read (void *ptr, size_t& len)
{
  HGLOBAL hglb;
  size_t ret;
  UINT formatlist[2];
  int format;
  if (eof)
    len = 0;
  else
    {
      formatlist[0] = cygnativeformat;
      formatlist[1] = current_codepage == ansi_cp ? CF_TEXT : CF_OEMTEXT;
      OpenClipboard (0);
      if ((format = GetPriorityClipboardFormat (formatlist, 2)) <= 0)
	{
	  CloseClipboard ();
#if 0
	  system_printf ("a non-accepted format! %d", format);
#endif
	  len = 0;
	}
      else
	{
	  hglb = GetClipboardData (format);
	  if (format == cygnativeformat)
	    {
	      unsigned char *buf = (unsigned char *) GlobalLock (hglb);
	      size_t buflen = (*(size_t *) buf);
	      ret = ((len > (buflen - pos)) ? (buflen - pos) : len);
	      memcpy (ptr, buf + sizeof (size_t)+ pos , ret);
	      pos += ret;
	      if (pos + len - ret >= buflen)
		eof = true;
	      GlobalUnlock (hglb);
	    }
	  else
	    {
	      LPSTR lpstr;
	      lpstr = (LPSTR) GlobalLock (hglb);

	      ret = ((len > (strlen (lpstr) - pos)) ? (strlen (lpstr) - pos)
		     : len);

	      memcpy (ptr, lpstr + pos, ret);
	      //ret = snprintf((char *) ptr, len, "%s", lpstr);//+pos);
	      pos += ret;
	      if (pos + len - ret >= strlen (lpstr))
		eof = true;
	      GlobalUnlock (hglb);
	    }
	  CloseClipboard ();
	  len = ret;
	}
    }
}

_off64_t
fhandler_dev_clipboard::lseek (_off64_t offset, int whence)
{
  /* On reads we check this at read time, not seek time.
   * On writes we use this to decide how to write - empty and write, or open, copy, empty
   * and write
   */
  pos = offset;
  /* treat seek like rewind */
  if (membuffer)
    free (membuffer);
  msize = 0;
  return 0;
}

int
fhandler_dev_clipboard::close ()
{
  if (!hExeced)
    {
      eof = true;
      pos = 0;
      if (membuffer)
	{
	  free (membuffer);
	  membuffer = NULL;
	}
      msize = 0;
    }
  return 0;
}

void
fhandler_dev_clipboard::fixup_after_exec ()
{
  eof = false;
  pos = msize = 0;
  membuffer = NULL;
}
