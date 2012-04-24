/* fhandler_console.cc

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
   2006, 2008, 2009, 2010, 2011, 2012 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include "miscfuncs.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <wingdi.h>
#include <winuser.h>
#include <winnls.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/cygwin.h>
#include <cygwin/kd.h>
#include "cygerrno.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "sigproc.h"
#include "pinfo.h"
#include "shared_info.h"
#include "cygtls.h"
#include "tls_pbuf.h"
#include "registry.h"
#include <asm/socket.h>
#include "sync.h"
#include "child_info.h"

/* Don't make this bigger than NT_MAX_PATH as long as the temporary buffer
   is allocated using tmp_pathbuf!!! */
#define CONVERT_LIMIT NT_MAX_PATH

#define ALT_PRESSED (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED)
#define CTRL_PRESSED (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)

/*
 * Scroll the screen context.
 * x1, y1 - ul corner
 * x2, y2 - dr corner
 * xn, yn - new ul corner
 * Negative values represents current screen dimensions
 */

#define dev_state (shared_console_info->dev_state)
#define srTop (dev_state.info.winTop + dev_state.scroll_region.Top)
#define srBottom ((dev_state.scroll_region.Bottom < 0) ? dev_state.info.winBottom : dev_state.info.winTop + dev_state.scroll_region.Bottom)

const char *get_nonascii_key (INPUT_RECORD&, char *);

const unsigned fhandler_console::MAX_WRITE_CHARS = 16384;

fhandler_console::console_state NO_COPY *fhandler_console::shared_console_info;

bool NO_COPY fhandler_console::invisible_console;

static void
beep ()
{
  const WCHAR ding[] = L"\\media\\ding.wav";
  reg_key r (HKEY_CURRENT_USER, KEY_ALL_ACCESS, L"AppEvents", L"Schemes",
	     L"Apps", L".Default", L".Default", L".Current", NULL);
  if (r.created ())
    {
      PWCHAR buf = NULL;
      UINT len = GetSystemWindowsDirectoryW (buf, 0) * sizeof (WCHAR);
      buf = (PWCHAR) alloca (len += sizeof (ding));
      UINT res = GetSystemWindowsDirectoryW (buf, len);
      if (res && res <= len)
	r.set_string (L"", wcscat (buf, ding));
    }
  MessageBeep (MB_OK);
}

fhandler_console::console_state *
fhandler_console::open_shared_console (HWND hw, HANDLE& h, bool& create)
{
  wchar_t namebuf[(sizeof "XXXXXXXXXXXXXXXXXX-consNNNNNNNNNN")];
  __small_swprintf (namebuf, L"%S-cons%p", &cygheap->installation_key, hw);

  shared_locations m = create ? SH_SHARED_CONSOLE : SH_JUSTOPEN;
  console_state *res = (console_state *)
    open_shared (namebuf, 0, h, sizeof (*shared_console_info), &m);
  create = m != SH_JUSTOPEN;
  return res;
}
class console_unit
{
  int n;
  unsigned long bitmask;
  HWND me;

public:
  operator int () const {return n;}
  console_unit (HWND);
  friend BOOL CALLBACK enum_windows (HWND, LPARAM);
};

BOOL CALLBACK
enum_windows (HWND hw, LPARAM lp)
{
  console_unit *this1 = (console_unit *) lp;
  if (hw == this1->me)
    return TRUE;
  HANDLE h = NULL;
  fhandler_console::console_state *cs;
  if ((cs = fhandler_console::open_shared_console (hw, h)))
    {
      this1->bitmask ^= 1 << cs->tty_min_state.getntty ();
      UnmapViewOfFile ((void *) cs);
      CloseHandle (h);
    }
  return TRUE;
}

console_unit::console_unit (HWND me0):
  bitmask (0xffffffff), me (me0)
{
  EnumWindows (enum_windows, (LPARAM) this);
  n = (_minor_t) ffs (bitmask) - 1;
  if (n < 0)
    api_fatal ("console device allocation failure - too many consoles in use, max consoles is 32");
}

bool
fhandler_console::set_unit ()
{
  bool created;
  fh_devices devset;
  lock_ttys here;
  HWND me;
  fh_devices this_unit = dev ();
  bool generic_console = this_unit == FH_CONIN || this_unit == FH_CONOUT;
  if (shared_console_info)
    {
      fh_devices shared_unit =
	(fh_devices) shared_console_info->tty_min_state.getntty ();
      devset = (shared_unit == this_unit || this_unit == FH_CONSOLE
		|| generic_console
		|| this_unit == FH_TTY) ?
		shared_unit : FH_ERROR;
      created = false;
    }
  else if ((!generic_console && (myself->ctty != -1 && !iscons_dev (myself->ctty)))
	   || !(me = GetConsoleWindow ()))
    devset = FH_ERROR;
  else
    {
      created = true;
      shared_console_info = open_shared_console (me, cygheap->console_h, created);
      ProtectHandleINH (cygheap->console_h);
      if (created)
	shared_console_info->tty_min_state.setntty (DEV_CONS_MAJOR, console_unit (me));
      devset = (fh_devices) shared_console_info->tty_min_state.getntty ();
    }

  dev ().parse (devset);
  if (devset != FH_ERROR)
    pc.file_attributes (FILE_ATTRIBUTE_NORMAL);
  else
    {
      set_io_handle (NULL);
      set_output_handle (NULL);
      created = false;
    }
  return created;
}

/* Allocate and initialize the shared record for the current console. */
void
fhandler_console::setup ()
{
  if (set_unit ())
      {

	dev_state.scroll_region.Bottom = -1;
	dev_state.dwLastCursorPosition.X = -1;
	dev_state.dwLastCursorPosition.Y = -1;
	dev_state.dwLastMousePosition.X = -1;
	dev_state.dwLastMousePosition.Y = -1;
	dev_state.dwLastButtonState = 0;	/* none pressed */
	dev_state.last_button_code = 3;	/* released */
	dev_state.underline_color = FOREGROUND_GREEN | FOREGROUND_BLUE;
	dev_state.dim_color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
	dev_state.meta_mask = LEFT_ALT_PRESSED;
	/* Set the mask that determines if an input keystroke is modified by
	   META.  We set this based on the keyboard layout language loaded
	   for the current thread.  The left <ALT> key always generates
	   META, but the right <ALT> key only generates META if we are using
	   an English keyboard because many "international" keyboards
	   replace common shell symbols ('[', '{', etc.) with accented
	   language-specific characters (umlaut, accent grave, etc.).  On
	   these keyboards right <ALT> (called AltGr) is used to produce the
	   shell symbols and should not be interpreted as META. */
	if (PRIMARYLANGID (LOWORD (GetKeyboardLayout (0))) == LANG_ENGLISH)
	  dev_state.meta_mask |= RIGHT_ALT_PRESSED;
	dev_state.set_default_attr ();
	dev_state.backspace_keycode = CERASE;
	shared_console_info->tty_min_state.is_console = true;
      }
}

/* Return the tty structure associated with a given tty number.  If the
   tty number is < 0, just return a dummy record. */
tty_min *
tty_list::get_cttyp ()
{
  _dev_t n = myself->ctty;
  if (iscons_dev (n))
    return fhandler_console::shared_console_info ?
      &fhandler_console::shared_console_info->tty_min_state : NULL;
  else if (istty_slave_dev (n))
    return &ttys[device::minor (n)];
  else
    return NULL;
}

inline DWORD
dev_console::con_to_str (char *d, int dlen, WCHAR w)
{
  return sys_cp_wcstombs (cygheap->locale.wctomb, cygheap->locale.charset,
			  d, dlen, &w, 1);
}

inline UINT
dev_console::get_console_cp ()
{
  /* The alternate charset is always 437, just as in the Linux console. */
  return alternate_charset_active ? 437 : 0;
}

inline DWORD
dev_console::str_to_con (mbtowc_p f_mbtowc, const char *charset,
			 PWCHAR d, const char *s, DWORD sz)
{
  return sys_cp_mbstowcs (f_mbtowc, charset, d, CONVERT_LIMIT, s, sz);
}

bool
fhandler_console::set_raw_win32_keyboard_mode (bool new_mode)
{
  bool old_mode = dev_state.raw_win32_keyboard_mode;
  dev_state.raw_win32_keyboard_mode = new_mode;
  syscall_printf ("raw keyboard mode %sabled", dev_state.raw_win32_keyboard_mode ? "en" : "dis");
  return old_mode;
};

void
fhandler_console::set_cursor_maybe ()
{
  CONSOLE_SCREEN_BUFFER_INFO now;

  if (!GetConsoleScreenBufferInfo (get_output_handle (), &now))
    return;

  if (dev_state.dwLastCursorPosition.X != now.dwCursorPosition.X ||
      dev_state.dwLastCursorPosition.Y != now.dwCursorPosition.Y)
    {
      SetConsoleCursorPosition (get_output_handle (), now.dwCursorPosition);
      dev_state.dwLastCursorPosition = now.dwCursorPosition;
    }
}

void
fhandler_console::send_winch_maybe ()
{
  SHORT y = dev_state.info.dwWinSize.Y;
  SHORT x = dev_state.info.dwWinSize.X;
  dev_state.fillin_info (get_output_handle ());

  if (y != dev_state.info.dwWinSize.Y || x != dev_state.info.dwWinSize.X)
    {
      dev_state.scroll_region.Top = 0;
      dev_state.scroll_region.Bottom = -1;
      get_ttyp ()->kill_pgrp (SIGWINCH);
    }
}

/* Check whether a mouse event is to be reported as an escape sequence */
bool
fhandler_console::mouse_aware (MOUSE_EVENT_RECORD& mouse_event)
{
  if (!dev_state.use_mouse)
    return 0;

  /* Adjust mouse position by window scroll buffer offset
     and remember adjusted position in state for use by read() */
  CONSOLE_SCREEN_BUFFER_INFO now;
  if (GetConsoleScreenBufferInfo (get_output_handle (), &now))
    {
      dev_state.dwMousePosition.X = mouse_event.dwMousePosition.X - now.srWindow.Left;
      dev_state.dwMousePosition.Y = mouse_event.dwMousePosition.Y - now.srWindow.Top;
    }
  else
    {
      /* Cannot adjust position by window scroll buffer offset */
      return 0;
    }

  /* Check whether adjusted mouse position can be reported */
  if (dev_state.dwMousePosition.X > 0xFF - ' ' - 1
      || dev_state.dwMousePosition.Y > 0xFF - ' ' - 1)
    {
      /* Mouse position out of reporting range */
      return 0;
    }

  return ((mouse_event.dwEventFlags == 0 || mouse_event.dwEventFlags == DOUBLE_CLICK)
	  && mouse_event.dwButtonState != dev_state.dwLastButtonState)
	 || mouse_event.dwEventFlags == MOUSE_WHEELED
	 || (mouse_event.dwEventFlags == MOUSE_MOVED
	     && (dev_state.dwMousePosition.X != dev_state.dwLastMousePosition.X
		 || dev_state.dwMousePosition.Y != dev_state.dwLastMousePosition.Y)
	     && ((dev_state.use_mouse >= 2 && mouse_event.dwButtonState)
		 || dev_state.use_mouse >= 3));
}

void __stdcall
fhandler_console::read (void *pv, size_t& buflen)
{
  push_process_state process_state (PID_TTYIN);

  HANDLE h = get_io_handle ();

#define buf ((char *) pv)

  int ch;
  set_input_state ();

  int copied_chars = get_readahead_into_buffer (buf, buflen);

  if (copied_chars)
    {
      buflen = copied_chars;
      return;
    }

  DWORD timeout = is_nonblocking () ? 0 : INFINITE;
  char tmp[60];

  termios ti = get_ttyp ()->ti;
  for (;;)
    {
      int bgres;
      if ((bgres = bg_check (SIGTTIN)) <= bg_eof)
	{
	  buflen = bgres;
	  return;
	}

      set_cursor_maybe ();	/* to make cursor appear on the screen immediately */
      switch (cygwait (h, timeout))
	{
	case WAIT_OBJECT_0:
	  break;
	case WAIT_OBJECT_0 + 1:
	  goto sig_exit;
	case WAIT_OBJECT_0 + 2:
	  process_state.pop ();
	  pthread::static_cancel_self ();
	  /*NOTREACHED*/
	case WAIT_TIMEOUT:
	  set_sig_errno (EAGAIN);
	  buflen = (size_t) -1;
	  return;
	default:
	  goto err;
	}

      DWORD nread;
      INPUT_RECORD input_rec;
      const char *toadd = NULL;

      if (!ReadConsoleInputW (h, &input_rec, 1, &nread))
	{
	  syscall_printf ("ReadConsoleInput failed, %E");
	  goto err;		/* seems to be failure */
	}

      /* check the event that occurred */
      switch (input_rec.EventType)
	{
	case KEY_EVENT:
#define virtual_key_code (input_rec.Event.KeyEvent.wVirtualKeyCode)
#define control_key_state (input_rec.Event.KeyEvent.dwControlKeyState)

	  dev_state.nModifiers = 0;

#ifdef DEBUGGING
	  /* allow manual switching to/from raw mode via ctrl-alt-scrolllock */
	  if (input_rec.Event.KeyEvent.bKeyDown &&
	      virtual_key_code == VK_SCROLL &&
	      ((control_key_state & (LEFT_ALT_PRESSED | LEFT_CTRL_PRESSED)) == (LEFT_ALT_PRESSED | LEFT_CTRL_PRESSED))
	    )
	    {
	      set_raw_win32_keyboard_mode (!dev_state.raw_win32_keyboard_mode);
	      continue;
	    }
#endif

	  if (dev_state.raw_win32_keyboard_mode)
	    {
	      __small_sprintf (tmp, "\033{%u;%u;%u;%u;%u;%luK",
				    input_rec.Event.KeyEvent.bKeyDown,
				    input_rec.Event.KeyEvent.wRepeatCount,
				    input_rec.Event.KeyEvent.wVirtualKeyCode,
				    input_rec.Event.KeyEvent.wVirtualScanCode,
				    input_rec.Event.KeyEvent.uChar.UnicodeChar,
				    input_rec.Event.KeyEvent.dwControlKeyState);
	      toadd = tmp;
	      nread = strlen (toadd);
	      break;
	    }

#define ich (input_rec.Event.KeyEvent.uChar.AsciiChar)
#define wch (input_rec.Event.KeyEvent.uChar.UnicodeChar)

	  /* Ignore key up events, except for left alt events with non-zero character
	   */
	  if (!input_rec.Event.KeyEvent.bKeyDown &&
	      /*
		Event for left alt, with a non-zero character, comes from
		"alt + numerics" key sequence.
		e.g. <left-alt> 0233 => &eacute;
	      */
	      !(wch != 0
		// ?? experimentally determined on an XP system
		&& virtual_key_code == VK_MENU
		// left alt -- see http://www.microsoft.com/hwdev/tech/input/Scancode.asp
		&& input_rec.Event.KeyEvent.wVirtualScanCode == 0x38))
	    continue;

	  if (control_key_state & SHIFT_PRESSED)
	    dev_state.nModifiers |= 1;
	  if (control_key_state & RIGHT_ALT_PRESSED)
	    dev_state.nModifiers |= 2;
	  if (control_key_state & CTRL_PRESSED)
	    dev_state.nModifiers |= 4;
	  if (control_key_state & LEFT_ALT_PRESSED)
	    dev_state.nModifiers |= 8;

	  /* Allow Backspace to emit ^? and escape sequences. */
	  if (input_rec.Event.KeyEvent.wVirtualKeyCode == VK_BACK)
	    {
	      char c = dev_state.backspace_keycode;
	      nread = 0;
	      if (control_key_state & ALT_PRESSED)
		{
		  if (dev_state.metabit)
		    c |= 0x80;
		  else
		    tmp[nread++] = '\e';
		}
	      tmp[nread++] = c;
	      tmp[nread] = 0;
	      toadd = tmp;
	    }
	  /* Allow Ctrl-Space to emit ^@ */
	  else if (input_rec.Event.KeyEvent.wVirtualKeyCode == VK_SPACE
		   && (control_key_state & CTRL_PRESSED)
		   && !(control_key_state & ALT_PRESSED))
	    toadd = "";
	  else if (wch == 0
	      /* arrow/function keys */
	      || (input_rec.Event.KeyEvent.dwControlKeyState & ENHANCED_KEY))
	    {
	      toadd = get_nonascii_key (input_rec, tmp);
	      if (!toadd)
		{
		  dev_state.nModifiers = 0;
		  continue;
		}
	      nread = strlen (toadd);
	    }
	  else
	    {
	      nread = dev_state.con_to_str (tmp + 1, 59, wch);
	      /* Determine if the keystroke is modified by META.  The tricky
		 part is to distinguish whether the right Alt key should be
		 recognized as Alt, or as AltGr. */
	      bool meta =
		     /* Alt but not AltGr (= left ctrl + right alt)? */
		     (control_key_state & ALT_PRESSED) != 0
		     && ((control_key_state & CTRL_PRESSED) == 0
			    /* but also allow Alt-AltGr: */
			 || (control_key_state & ALT_PRESSED) == ALT_PRESSED
			 || (wch <= 0x1f || wch == 0x7f));
	      if (!meta)
		{
		  /* Determine if the character is in the current multibyte
		     charset.  The test is easy.  If the multibyte sequence
		     is > 1 and the first byte is ASCII CAN, the character
		     has been translated into the ASCII CAN + UTF-8 replacement
		     sequence.  If so, just ignore the keypress.
		     FIXME: Is there a better solution? */
		  if (nread > 1 && tmp[1] == 0x18)
		    beep ();
		  else
		    toadd = tmp + 1;
		}
	      else if (dev_state.metabit)
		{
		  tmp[1] |= 0x80;
		  toadd = tmp + 1;
		}
	      else
		{
		  tmp[0] = '\033';
		  tmp[1] = cyg_tolower (tmp[1]);
		  toadd = tmp;
		  nread++;
		  dev_state.nModifiers &= ~4;
		}
	    }
#undef ich
#undef wch
	  break;

	case MOUSE_EVENT:
	  send_winch_maybe ();
	  {
	    MOUSE_EVENT_RECORD& mouse_event = input_rec.Event.MouseEvent;
	    /* As a unique guard for mouse report generation,
	       call mouse_aware() which is common with select(), so the result
	       of select() and the actual read() will be consistent on the
	       issue of whether input (i.e. a mouse escape sequence) will
	       be available or not */
	    if (mouse_aware (mouse_event))
	      {
		/* Note: Reported mouse position was already retrieved by
		   mouse_aware() and adjusted by window scroll buffer offset */

		/* Treat the double-click event like a regular button press */
		if (mouse_event.dwEventFlags == DOUBLE_CLICK)
		  {
		    syscall_printf ("mouse: double-click -> click");
		    mouse_event.dwEventFlags = 0;
		  }

		/* This code assumes Windows never reports multiple button
		   events at the same time. */
		int b = 0;
		char sz[32];
		char mode6_term = 'M';

		if (mouse_event.dwEventFlags == MOUSE_WHEELED)
		  {
		    if (mouse_event.dwButtonState & 0xFF800000)
		      {
			b = 0x41;
			strcpy (sz, "wheel down");
		      }
		    else
		      {
			b = 0x40;
			strcpy (sz, "wheel up");
		      }
		  }
		else
		  {
		    /* Ignore unimportant mouse buttons */
		    mouse_event.dwButtonState &= 0x7;

		    if (mouse_event.dwEventFlags == MOUSE_MOVED)
		      {
			b = dev_state.last_button_code;
		      }
		    else if (mouse_event.dwButtonState < dev_state.dwLastButtonState && !dev_state.ext_mouse_mode6)
		      {
			b = 3;
			strcpy (sz, "btn up");
		      }
		    else if ((mouse_event.dwButtonState & 1) != (dev_state.dwLastButtonState & 1))
		      {
			b = 0;
			strcpy (sz, "btn1 down");
		      }
		    else if ((mouse_event.dwButtonState & 2) != (dev_state.dwLastButtonState & 2))
		      {
			b = 2;
			strcpy (sz, "btn2 down");
		      }
		    else if ((mouse_event.dwButtonState & 4) != (dev_state.dwLastButtonState & 4))
		      {
			b = 1;
			strcpy (sz, "btn3 down");
		      }

		    if (dev_state.ext_mouse_mode6 /* distinguish release */
			&& mouse_event.dwButtonState < dev_state.dwLastButtonState)
		        mode6_term = 'm';

		    dev_state.last_button_code = b;

		    if (mouse_event.dwEventFlags == MOUSE_MOVED)
		      {
			b += 32;
			strcpy (sz, "move");
		      }
		    else
		      {
			/* Remember the modified button state */
			dev_state.dwLastButtonState = mouse_event.dwButtonState;
		      }
		  }

		/* Remember mouse position */
		dev_state.dwLastMousePosition.X = dev_state.dwMousePosition.X;
		dev_state.dwLastMousePosition.Y = dev_state.dwMousePosition.Y;

		/* Remember the modifiers */
		dev_state.nModifiers = 0;
		if (mouse_event.dwControlKeyState & SHIFT_PRESSED)
		    dev_state.nModifiers |= 0x4;
		if (mouse_event.dwControlKeyState & ALT_PRESSED)
		    dev_state.nModifiers |= 0x8;
		if (mouse_event.dwControlKeyState & CTRL_PRESSED)
		    dev_state.nModifiers |= 0x10;

		/* Indicate the modifiers */
		b |= dev_state.nModifiers;

		/* We can now create the code. */
		if (dev_state.ext_mouse_mode6)
		  {
		    __small_sprintf (tmp, "\033[<%d;%d;%d%c", b,
				     dev_state.dwMousePosition.X + 1,
				     dev_state.dwMousePosition.Y + 1,
				     mode6_term);
		    nread = strlen (tmp);
		  }
		else if (dev_state.ext_mouse_mode15)
		  {
		    __small_sprintf (tmp, "\033[%d;%d;%dM", b + 32,
				     dev_state.dwMousePosition.X + 1,
				     dev_state.dwMousePosition.Y + 1);
		    nread = strlen (tmp);
		  }
		/* else if (dev_state.ext_mouse_mode5) not implemented */
		else
		  {
		    unsigned int xcode = dev_state.dwMousePosition.X + ' ' + 1;
		    unsigned int ycode = dev_state.dwMousePosition.Y + ' ' + 1;
		    if (xcode >= 256)
		      xcode = 0;
		    if (ycode >= 256)
		      ycode = 0;
		    __small_sprintf (tmp, "\033[M%c%c%c", b + ' ',
				     xcode, ycode);
		    nread = 6;	/* tmp may contain NUL bytes */
		  }
		syscall_printf ("mouse: %s at (%d,%d)", sz,
				dev_state.dwMousePosition.X,
				dev_state.dwMousePosition.Y);

		toadd = tmp;
	      }
	  }
	  break;

	case FOCUS_EVENT:
	  if (dev_state.use_focus)
	    {
	      if (input_rec.Event.FocusEvent.bSetFocus)
	        __small_sprintf (tmp, "\033[I");
	      else
	        __small_sprintf (tmp, "\033[O");

	      toadd = tmp;
	      nread = 3;
	    }
	  break;

	case WINDOW_BUFFER_SIZE_EVENT:
	  send_winch_maybe ();
	  /* fall through */
	default:
	  continue;
	}

      if (toadd)
	{
	  line_edit_status res = line_edit (toadd, nread, ti);
	  if (res == line_edit_signalled)
	    goto sig_exit;
	  else if (res == line_edit_input_done)
	    break;
	}
    }

  while (buflen)
    if ((ch = get_readahead ()) < 0)
      break;
    else
      {
	buf[copied_chars++] = (unsigned char)(ch & 0xff);
	buflen--;
      }
#undef buf

  buflen = copied_chars;
  return;

err:
  __seterrno ();
  buflen = (size_t) -1;
  return;

sig_exit:
  set_sig_errno (EINTR);
  buflen = (size_t) -1;
}

void
fhandler_console::set_input_state ()
{
  if (get_ttyp ()->rstcons ())
    input_tcsetattr (0, &get_ttyp ()->ti);
}

bool
dev_console::fillin_info (HANDLE h)
{
  bool ret;
  CONSOLE_SCREEN_BUFFER_INFO linfo;

  if ((ret = GetConsoleScreenBufferInfo (h, &linfo)))
    {
      info.winTop = linfo.srWindow.Top;
      info.winBottom = linfo.srWindow.Bottom;
      info.dwWinSize.Y = 1 + linfo.srWindow.Bottom - linfo.srWindow.Top;
      info.dwWinSize.X = 1 + linfo.srWindow.Right - linfo.srWindow.Left;
      info.dwBufferSize = linfo.dwSize;
      info.dwCursorPosition = linfo.dwCursorPosition;
      info.wAttributes = linfo.wAttributes;
    }
  else
    {
      memset (&info, 0, sizeof info);
      info.dwWinSize.Y = 25;
      info.dwWinSize.X = 80;
      info.winBottom = 24;
    }

  return ret;
}

void
fhandler_console::scroll_screen (int x1, int y1, int x2, int y2, int xn, int yn)
{
  SMALL_RECT sr1, sr2;
  CHAR_INFO fill;
  COORD dest;

  dev_state.fillin_info (get_output_handle ());
  sr1.Left = x1 >= 0 ? x1 : dev_state.info.dwWinSize.X - 1;
  if (y1 == 0)
    sr1.Top = dev_state.info.winTop;
  else
    sr1.Top = y1 > 0 ? y1 : dev_state.info.winBottom;
  sr1.Right = x2 >= 0 ? x2 : dev_state.info.dwWinSize.X - 1;
  if (y2 == 0)
    sr1.Bottom = dev_state.info.winTop;
  else
    sr1.Bottom = y2 > 0 ? y2 : dev_state.info.winBottom;
  sr2.Top = srTop;
  sr2.Left = 0;
  sr2.Bottom = srBottom;
  sr2.Right = dev_state.info.dwWinSize.X - 1;
  if (sr1.Bottom > sr2.Bottom && sr1.Top <= sr2.Bottom)
    sr1.Bottom = sr2.Bottom;
  dest.X = xn >= 0 ? xn : dev_state.info.dwWinSize.X - 1;
  if (yn == 0)
    dest.Y = dev_state.info.winTop;
  else
    dest.Y = yn > 0 ? yn : dev_state.info.winBottom;
  fill.Char.AsciiChar = ' ';
  fill.Attributes = dev_state.current_win32_attr;
  ScrollConsoleScreenBuffer (get_output_handle (), &sr1, &sr2, dest, &fill);

  /* ScrollConsoleScreenBuffer on Windows 95 is buggy - when scroll distance
   * is more than half of screen, filling doesn't work as expected */

  if (sr1.Top == sr1.Bottom)
    /* nothing to do */;
  else if (dest.Y <= sr1.Top)	/* forward scroll */
    clear_screen (0, 1 + dest.Y + sr1.Bottom - sr1.Top, sr2.Right, sr2.Bottom);
  else			/* reverse scroll */
    clear_screen (0, sr1.Top, sr2.Right, dest.Y - 1);
}

int
fhandler_console::dup (fhandler_base *child, int flags)
{
  /* See comments in fhandler_pty_slave::dup */
  if (myself->ctty != -2)
    myself->set_ctty (this, flags);
  return 0;
}

int
fhandler_console::open (int flags, mode_t)
{
  HANDLE h;

  if (dev () == FH_ERROR)
    {
      set_errno (EPERM);	/* constructor found an error */
      return 0;
    }

  tcinit (false);

  set_io_handle (NULL);
  set_output_handle (NULL);

  /* Open the input handle as handle_ */
  h = CreateFile ("CONIN$", GENERIC_READ | GENERIC_WRITE,
		  FILE_SHARE_READ | FILE_SHARE_WRITE, &sec_none,
		  OPEN_EXISTING, 0, 0);

  if (h == INVALID_HANDLE_VALUE)
    {
      __seterrno ();
      return 0;
    }
  set_io_handle (h);

  h = CreateFile ("CONOUT$", GENERIC_READ | GENERIC_WRITE,
		  FILE_SHARE_READ | FILE_SHARE_WRITE, &sec_none,
		  OPEN_EXISTING, 0, 0);

  if (h == INVALID_HANDLE_VALUE)
    {
      __seterrno ();
      return 0;
    }
  set_output_handle (h);

  if (dev_state.fillin_info (get_output_handle ()))
    {
      dev_state.current_win32_attr = dev_state.info.wAttributes;
      if (!dev_state.default_color)
	dev_state.default_color = dev_state.info.wAttributes;
      dev_state.set_default_attr ();
    }

  get_ttyp ()->rstcons (false);
  set_open_status ();

  DWORD cflags;
  if (GetConsoleMode (get_io_handle (), &cflags))
    SetConsoleMode (get_io_handle (),
		    ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT | cflags);

  debug_printf ("opened conin$ %p, conout$ %p", get_io_handle (),
		get_output_handle ());

  return 1;
}

void
fhandler_console::open_setup (int flags)
{
  set_flags ((flags & ~O_TEXT) | O_BINARY);
  if (myself->set_ctty (this, flags) && !myself->cygstarted)
    init_console_handler (true);
}

int
fhandler_console::close ()
{
  CloseHandle (get_io_handle ());
  CloseHandle (get_output_handle ());
  if (!have_execed)
    free_console ();
  return 0;
}

int
fhandler_console::ioctl (unsigned int cmd, void *arg)
{
  int res = fhandler_termios::ioctl (cmd, arg);
  if (res <= 0)
    return res;
  switch (cmd)
    {
      case TIOCGWINSZ:
	int st;

	st = dev_state.fillin_info (get_output_handle ());
	if (st)
	  {
	    /* *not* the buffer size, the actual screen size... */
	    /* based on Left Top Right Bottom of srWindow */
	    ((struct winsize *) arg)->ws_row = dev_state.info.dwWinSize.Y;
	    ((struct winsize *) arg)->ws_col = dev_state.info.dwWinSize.X;
	    syscall_printf ("WINSZ: (row=%d,col=%d)",
			   ((struct winsize *) arg)->ws_row,
			   ((struct winsize *) arg)->ws_col);
	    return 0;
	  }
	else
	  {
	    syscall_printf ("WINSZ failed");
	    __seterrno ();
	    return -1;
	  }
	return 0;
      case TIOCSWINSZ:
	bg_check (SIGTTOU);
	return 0;
      case KDGKBMETA:
	*(int *) arg = (dev_state.metabit) ? K_METABIT : K_ESCPREFIX;
	return 0;
      case KDSKBMETA:
	if ((int) arg == K_METABIT)
	  dev_state.metabit = TRUE;
	else if ((int) arg == K_ESCPREFIX)
	  dev_state.metabit = FALSE;
	else
	  {
	    set_errno (EINVAL);
	    return -1;
	  }
	return 0;
      case TIOCLINUX:
	if (*(unsigned char *) arg == 6)
	  {
	    *(unsigned char *) arg = (unsigned char) dev_state.nModifiers;
	    return 0;
	  }
	set_errno (EINVAL);
	return -1;
      case FIONREAD:
	{
	  /* Per MSDN, max size of buffer required is below 64K. */
#define	  INREC_SIZE	(65536 / sizeof (INPUT_RECORD))

	  DWORD n;
	  int ret = 0;
	  INPUT_RECORD inp[INREC_SIZE];
	  if (!PeekConsoleInputW (get_io_handle (), inp, INREC_SIZE, &n))
	    {
	      set_errno (EINVAL);
	      return -1;
	    }
	  while (n-- > 0)
	    if (inp[n].EventType == KEY_EVENT && inp[n].Event.KeyEvent.bKeyDown)
	      ++ret;
	  *(int *) arg = ret;
	  return 0;
	}
	break;
    }

  return fhandler_base::ioctl (cmd, arg);
}

int
fhandler_console::tcflush (int queue)
{
  int res = 0;
  if (queue == TCIFLUSH
      || queue == TCIOFLUSH)
    {
      if (!FlushConsoleInputBuffer (get_io_handle ()))
	{
	  __seterrno ();
	  res = -1;
	}
    }
  return res;
}

int
fhandler_console::output_tcsetattr (int, struct termios const *t)
{
  /* All the output bits we can ignore */

  DWORD flags = ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT;

  int res = SetConsoleMode (get_output_handle (), flags) ? 0 : -1;
  if (res)
    __seterrno_from_win_error (GetLastError ());
  syscall_printf ("%d = tcsetattr(,%x) (ENABLE FLAGS %x) (lflag %x oflag %x)",
		  res, t, flags, t->c_lflag, t->c_oflag);
  return res;
}

int
fhandler_console::input_tcsetattr (int, struct termios const *t)
{
  /* Ignore the optional_actions stuff, since all output is emitted
     instantly */

  DWORD oflags;

  if (!GetConsoleMode (get_io_handle (), &oflags))
    oflags = 0;
  DWORD flags = 0;

#if 0
  /* Enable/disable LF -> CRLF conversions */
  rbinary ((t->c_iflag & INLCR) ? false : true);
#endif

  /* There's some disparity between what we need and what's
     available.  We've got ECHO and ICANON, they've
     got ENABLE_ECHO_INPUT and ENABLE_LINE_INPUT. */

  termios_printf ("this %p, get_ttyp () %p, t %p", this, get_ttyp (), t);
  get_ttyp ()->ti = *t;

  if (t->c_lflag & ECHO)
    {
      flags |= ENABLE_ECHO_INPUT;
    }
  if (t->c_lflag & ICANON)
    {
      flags |= ENABLE_LINE_INPUT;
    }

  if (flags & ENABLE_ECHO_INPUT
      && !(flags & ENABLE_LINE_INPUT))
    {
      /* This is illegal, so turn off the echo here, and fake it
	 when we read the characters */

      flags &= ~ENABLE_ECHO_INPUT;
    }

  if ((t->c_lflag & ISIG) && !(t->c_iflag & IGNBRK))
    {
      flags |= ENABLE_PROCESSED_INPUT;
    }

  flags |= ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT;

  int res;
  if (flags == oflags)
    res = 0;
  else
    {
      res = SetConsoleMode (get_io_handle (), flags) ? 0 : -1;
      if (res < 0)
	__seterrno ();
      syscall_printf ("%d = tcsetattr(,%x) enable flags %p, c_lflag %p iflag %p",
		      res, t, flags, t->c_lflag, t->c_iflag);
    }

  get_ttyp ()->rstcons (false);
  return res;
}

int
fhandler_console::tcsetattr (int a, struct termios const *t)
{
  int res = output_tcsetattr (a, t);
  if (res != 0)
    return res;
  return input_tcsetattr (a, t);
}

int
fhandler_console::tcgetattr (struct termios *t)
{
  int res;
  *t = get_ttyp ()->ti;

  t->c_cflag |= CS8;

  DWORD flags;

  if (!GetConsoleMode (get_io_handle (), &flags))
    {
      __seterrno ();
      res = -1;
    }
  else
    {
      if (flags & ENABLE_ECHO_INPUT)
	t->c_lflag |= ECHO;

      if (flags & ENABLE_LINE_INPUT)
	t->c_lflag |= ICANON;

      if (flags & ENABLE_PROCESSED_INPUT)
	t->c_lflag |= ISIG;
      else
	t->c_iflag |= IGNBRK;

      /* What about ENABLE_WINDOW_INPUT
	 and ENABLE_MOUSE_INPUT   ? */

      /* All the output bits we can ignore */
      res = 0;
    }
  syscall_printf ("%d = tcgetattr(%p) enable flags %p, t->lflag %p, t->iflag %p",
		 res, t, flags, t->c_lflag, t->c_iflag);
  return res;
}

fhandler_console::fhandler_console (fh_devices unit) :
  fhandler_termios ()
{
  if (unit > 0)
    dev ().parse (unit);
  setup ();
  trunc_buf.len = 0;
  _tc = &(shared_console_info->tty_min_state);
}

void
dev_console::set_color (HANDLE h)
{
  WORD win_fg = fg;
  WORD win_bg = bg;
  if (reverse)
    {
      WORD save_fg = win_fg;
      win_fg = (win_bg & BACKGROUND_RED   ? FOREGROUND_RED   : 0) |
	       (win_bg & BACKGROUND_GREEN ? FOREGROUND_GREEN : 0) |
	       (win_bg & BACKGROUND_BLUE  ? FOREGROUND_BLUE  : 0) |
	       (win_bg & BACKGROUND_INTENSITY ? FOREGROUND_INTENSITY : 0);
      win_bg = (save_fg & FOREGROUND_RED   ? BACKGROUND_RED   : 0) |
	       (save_fg & FOREGROUND_GREEN ? BACKGROUND_GREEN : 0) |
	       (save_fg & FOREGROUND_BLUE  ? BACKGROUND_BLUE  : 0) |
	       (save_fg & FOREGROUND_INTENSITY ? BACKGROUND_INTENSITY : 0);
    }

  /* apply attributes */
  if (underline)
    win_fg = underline_color;
  /* emulate blink with bright background */
  if (blink)
    win_bg |= BACKGROUND_INTENSITY;
  if (intensity == INTENSITY_INVISIBLE)
    win_fg = win_bg;
  else if (intensity != INTENSITY_BOLD)
    /* nothing to do */;
    /* apply foreground intensity only in non-reverse mode! */
  else if (reverse)
    win_bg |= BACKGROUND_INTENSITY;
  else
    win_fg |= FOREGROUND_INTENSITY;

  current_win32_attr = win_fg | win_bg;
  if (h)
    SetConsoleTextAttribute (h, current_win32_attr);
}

#define FOREGROUND_ATTR_MASK (FOREGROUND_RED | FOREGROUND_GREEN | \
			      FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define BACKGROUND_ATTR_MASK (BACKGROUND_RED | BACKGROUND_GREEN | \
			      BACKGROUND_BLUE | BACKGROUND_INTENSITY)
void
dev_console::set_default_attr ()
{
  blink = underline = reverse = false;
  intensity = INTENSITY_NORMAL;
  fg = default_color & FOREGROUND_ATTR_MASK;
  bg = default_color & BACKGROUND_ATTR_MASK;
  set_color (NULL);
}

/*
 * Clear the screen context from x1/y1 to x2/y2 cell.
 * Negative values represents current screen dimensions
 */
void
fhandler_console::clear_screen (int x1, int y1, int x2, int y2)
{
  COORD tlc;
  DWORD done;
  int num;

  dev_state.fillin_info (get_output_handle ());

  if (x1 < 0)
    x1 = dev_state.info.dwWinSize.X - 1;
  if (y1 < 0)
    y1 = dev_state.info.winBottom;
  if (x2 < 0)
    x2 = dev_state.info.dwWinSize.X - 1;
  if (y2 < 0)
    y2 = dev_state.info.winBottom;

  num = abs (y1 - y2) * dev_state.info.dwBufferSize.X + abs (x1 - x2) + 1;

  if ((y2 * dev_state.info.dwBufferSize.X + x2) > (y1 * dev_state.info.dwBufferSize.X + x1))
    {
      tlc.X = x1;
      tlc.Y = y1;
    }
  else
    {
      tlc.X = x2;
      tlc.Y = y2;
    }
  FillConsoleOutputCharacterA (get_output_handle (), ' ',
			       num,
			       tlc,
			       &done);
  FillConsoleOutputAttribute (get_output_handle (),
			       dev_state.current_win32_attr,
			       num,
			       tlc,
			       &done);
}

void
fhandler_console::cursor_set (bool rel_to_top, int x, int y)
{
  COORD pos;

  dev_state.fillin_info (get_output_handle ());
#if 0
  /* Setting y to the current winBottom here is the reason that the window
     isn't scrolled back to the current cursor position like it's done in
     any other terminal.  Rather, the curser is forced to the bottom of the
     currently scrolled region.  This breaks the console buffer content if
     output is generated while the user had the window scrolled back.  This
     behaviour is very old, it has no matching ChangeLog entry.
     Just disable for now but keep the code in for future reference. */
  if (y > dev_state.info.winBottom)
    y = dev_state.info.winBottom;
  else
#endif
  if (y < 0)
    y = 0;
  else if (rel_to_top)
    y += dev_state.info.winTop;

  if (x > dev_state.info.dwWinSize.X)
    x = dev_state.info.dwWinSize.X - 1;
  else if (x < 0)
    x = 0;

  pos.X = x;
  pos.Y = y;
  SetConsoleCursorPosition (get_output_handle (), pos);
}

void
fhandler_console::cursor_rel (int x, int y)
{
  dev_state.fillin_info (get_output_handle ());
  x += dev_state.info.dwCursorPosition.X;
  y += dev_state.info.dwCursorPosition.Y;
  cursor_set (false, x, y);
}

void
fhandler_console::cursor_get (int *x, int *y)
{
  dev_state.fillin_info (get_output_handle ());
  *y = dev_state.info.dwCursorPosition.Y;
  *x = dev_state.info.dwCursorPosition.X;
}

/* VT100 line drawing graphics mode maps `abcdefghijklmnopqrstuvwxyz{|}~ to
   graphical characters */
static const wchar_t __vt100_conv[31] = {
	0x25C6, /* Black Diamond */
	0x2592, /* Medium Shade */
	0x2409, /* Symbol for Horizontal Tabulation */
	0x240C, /* Symbol for Form Feed */
	0x240D, /* Symbol for Carriage Return */
	0x240A, /* Symbol for Line Feed */
	0x00B0, /* Degree Sign */
	0x00B1, /* Plus-Minus Sign */
	0x2424, /* Symbol for Newline */
	0x240B, /* Symbol for Vertical Tabulation */
	0x2518, /* Box Drawings Light Up And Left */
	0x2510, /* Box Drawings Light Down And Left */
	0x250C, /* Box Drawings Light Down And Right */
	0x2514, /* Box Drawings Light Up And Right */
	0x253C, /* Box Drawings Light Vertical And Horizontal */
	0x23BA, /* Horizontal Scan Line-1 */
	0x23BB, /* Horizontal Scan Line-3 */
	0x2500, /* Box Drawings Light Horizontal */
	0x23BC, /* Horizontal Scan Line-7 */
	0x23BD, /* Horizontal Scan Line-9 */
	0x251C, /* Box Drawings Light Vertical And Right */
	0x2524, /* Box Drawings Light Vertical And Left */
	0x2534, /* Box Drawings Light Up And Horizontal */
	0x252C, /* Box Drawings Light Down And Horizontal */
	0x2502, /* Box Drawings Light Vertical */
	0x2264, /* Less-Than Or Equal To */
	0x2265, /* Greater-Than Or Equal To */
	0x03C0, /* Greek Small Letter Pi */
	0x2260, /* Not Equal To */
	0x00A3, /* Pound Sign */
	0x00B7, /* Middle Dot */
};

inline
bool fhandler_console::write_console (PWCHAR buf, DWORD len, DWORD& done)
{
  if (dev_state.iso_2022_G1
	? dev_state.vt100_graphics_mode_G1
	: dev_state.vt100_graphics_mode_G0)
    for (DWORD i = 0; i < len; i ++)
      if (buf[i] >= (unsigned char) '`' && buf[i] <= (unsigned char) '~')
	buf[i] = __vt100_conv[buf[i] - (unsigned char) '`'];

  while (len > 0)
    {
      DWORD nbytes = len > MAX_WRITE_CHARS ? MAX_WRITE_CHARS : len;
      if (!WriteConsoleW (get_output_handle (), buf, nbytes, &done, 0))
	{
	  __seterrno ();
	  return false;
	}
      len -= done;
      buf += done;
    }
  return true;
}

#define BAK 1
#define ESC 2
#define NOR 0
#define IGN 4
#if 1
#define ERR 5
#else
#define ERR NOR
#endif
#define DWN 6
#define BEL 7
#define TAB 8 /* We should't let the console deal with these */
#define CR 13
#define LF 10
#define SO 14
#define SI 15

static const char base_chars[256] =
{
/*00 01 02 03 04 05 06 07 */ IGN, ERR, ERR, NOR, NOR, NOR, NOR, BEL,
/*08 09 0A 0B 0C 0D 0E 0F */ BAK, TAB, DWN, ERR, ERR, CR,  SO,  SI,
/*10 11 12 13 14 15 16 17 */ NOR, NOR, ERR, ERR, ERR, ERR, ERR, ERR,
/*18 19 1A 1B 1C 1D 1E 1F */ NOR, NOR, ERR, ESC, ERR, ERR, ERR, ERR,
/*   !  "  #  $  %  &  '  */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*(  )  *  +  ,  -  .  /  */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*0  1  2  3  4  5  6  7  */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*8  9  :  ;  <  =  >  ?  */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*@  A  B  C  D  E  F  G  */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*H  I  J  K  L  M  N  O  */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*P  Q  R  S  T  U  V  W  */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*X  Y  Z  [  \  ]  ^  _  */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*`  a  b  c  d  e  f  g  */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*h  i  j  k  l  m  n  o  */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*p  q  r  s  t  u  v  w  */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*x  y  z  {  |  }  ~  7F */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*80 81 82 83 84 85 86 87 */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*88 89 8A 8B 8C 8D 8E 8F */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*90 91 92 93 94 95 96 97 */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*98 99 9A 9B 9C 9D 9E 9F */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*A0 A1 A2 A3 A4 A5 A6 A7 */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*A8 A9 AA AB AC AD AE AF */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*B0 B1 B2 B3 B4 B5 B6 B7 */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*B8 B9 BA BB BC BD BE BF */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*C0 C1 C2 C3 C4 C5 C6 C7 */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*C8 C9 CA CB CC CD CE CF */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*D0 D1 D2 D3 D4 D5 D6 D7 */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*D8 D9 DA DB DC DD DE DF */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*E0 E1 E2 E3 E4 E5 E6 E7 */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*E8 E9 EA EB EC ED EE EF */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*F0 F1 F2 F3 F4 F5 F6 F7 */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR,
/*F8 F9 FA FB FC FD FE FF */ NOR, NOR, NOR, NOR, NOR, NOR, NOR, NOR };

void
fhandler_console::char_command (char c)
{
  int x, y;
  char buf[40];

  switch (c)
    {
    case 'm':   /* Set Graphics Rendition */
       for (int i = 0; i <= dev_state.nargs_; i++)
	 switch (dev_state.args_[i])
	   {
	     case 0:    /* normal color */
	       dev_state.set_default_attr ();
	       break;
	     case 1:    /* bold */
	       dev_state.intensity = INTENSITY_BOLD;
	       break;
	     case 2:	/* dim */
	       dev_state.intensity = INTENSITY_DIM;
	       break;
	     case 4:	/* underlined */
	       dev_state.underline = 1;
	       break;
	     case 5:    /* blink mode */
	       dev_state.blink = true;
	       break;
	     case 7:    /* reverse */
	       dev_state.reverse = true;
	       break;
	     case 8:    /* invisible */
	       dev_state.intensity = INTENSITY_INVISIBLE;
	       break;
	     case 10:   /* end alternate charset */
	       dev_state.alternate_charset_active = false;
	       break;
	     case 11:   /* start alternate charset */
	       dev_state.alternate_charset_active = true;
	       break;
	     case 22:
	     case 28:
	       dev_state.intensity = INTENSITY_NORMAL;
	       break;
	     case 24:
	       dev_state.underline = false;
	       break;
	     case 25:
	       dev_state.blink = false;
	       break;
	     case 27:
	       dev_state.reverse = false;
	       break;
	     case 30:		/* BLACK foreground */
	       dev_state.fg = 0;
	       break;
	     case 31:		/* RED foreground */
	       dev_state.fg = FOREGROUND_RED;
	       break;
	     case 32:		/* GREEN foreground */
	       dev_state.fg = FOREGROUND_GREEN;
	       break;
	     case 33:		/* YELLOW foreground */
	       dev_state.fg = FOREGROUND_RED | FOREGROUND_GREEN;
	       break;
	     case 34:		/* BLUE foreground */
	       dev_state.fg = FOREGROUND_BLUE;
	       break;
	     case 35:		/* MAGENTA foreground */
	       dev_state.fg = FOREGROUND_RED | FOREGROUND_BLUE;
	       break;
	     case 36:		/* CYAN foreground */
	       dev_state.fg = FOREGROUND_BLUE | FOREGROUND_GREEN;
	       break;
	     case 37:		/* WHITE foreg */
	       dev_state.fg = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED;
	       break;
	     case 39:
	       dev_state.fg = dev_state.default_color & FOREGROUND_ATTR_MASK;
	       break;
	     case 40:		/* BLACK background */
	       dev_state.bg = 0;
	       break;
	     case 41:		/* RED background */
	       dev_state.bg = BACKGROUND_RED;
	       break;
	     case 42:		/* GREEN background */
	       dev_state.bg = BACKGROUND_GREEN;
	       break;
	     case 43:		/* YELLOW background */
	       dev_state.bg = BACKGROUND_RED | BACKGROUND_GREEN;
	       break;
	     case 44:		/* BLUE background */
	       dev_state.bg = BACKGROUND_BLUE;
	       break;
	     case 45:		/* MAGENTA background */
	       dev_state.bg = BACKGROUND_RED | BACKGROUND_BLUE;
	       break;
	     case 46:		/* CYAN background */
	       dev_state.bg = BACKGROUND_BLUE | BACKGROUND_GREEN;
	       break;
	     case 47:    /* WHITE background */
	       dev_state.bg = BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED;
	       break;
	     case 49:
	       dev_state.bg = dev_state.default_color & BACKGROUND_ATTR_MASK;
	       break;
	   }
       dev_state.set_color (get_output_handle ());
      break;
    case 'h':
    case 'l':
      if (!dev_state.saw_question_mark)
	{
	  switch (dev_state.args_[0])
	    {
	    case 4:    /* Insert mode */
	      dev_state.insert_mode = (c == 'h') ? true : false;
	      syscall_printf ("insert mode %sabled", dev_state.insert_mode ? "en" : "dis");
	      break;
	    }
	  break;
	}
      switch (dev_state.args_[0])
	{
	case 47:   /* Save/Restore screen */
	  if (c == 'h') /* save */
	    {
	      CONSOLE_SCREEN_BUFFER_INFO now;
	      COORD cob = { 0, 0 };

	      if (!GetConsoleScreenBufferInfo (get_output_handle (), &now))
		break;

	      dev_state.savebufsiz.X = now.srWindow.Right - now.srWindow.Left + 1;
	      dev_state.savebufsiz.Y = now.srWindow.Bottom - now.srWindow.Top + 1;

	      if (dev_state.savebuf)
		cfree (dev_state.savebuf);
	      dev_state.savebuf = (PCHAR_INFO) cmalloc_abort (HEAP_1_BUF, sizeof (CHAR_INFO) *
					     dev_state.savebufsiz.X * dev_state.savebufsiz.Y);

	      ReadConsoleOutputW (get_output_handle (), dev_state.savebuf,
				  dev_state.savebufsiz, cob, &now.srWindow);
	    }
	  else		/* restore */
	    {
	      CONSOLE_SCREEN_BUFFER_INFO now;
	      COORD cob = { 0, 0 };

	      if (!GetConsoleScreenBufferInfo (get_output_handle (), &now))
		break;

	      if (!dev_state.savebuf)
		break;

	      WriteConsoleOutputW (get_output_handle (), dev_state.savebuf,
				   dev_state.savebufsiz, cob, &now.srWindow);

	      cfree (dev_state.savebuf);
	      dev_state.savebuf = NULL;
	      dev_state.savebufsiz.X = dev_state.savebufsiz.Y = 0;
	    }
	  break;

	case 67: /* DECBKM ("DEC Backarrow Key Mode") */
	  dev_state.backspace_keycode = (c == 'h' ? CTRL('H') : CERASE);
	  break;

	case 1000: /* Mouse tracking */
	  dev_state.use_mouse = (c == 'h') ? 1 : 0;
	  break;

	case 1002: /* Mouse button event tracking */
	  dev_state.use_mouse = (c == 'h') ? 2 : 0;
	  break;

	case 1003: /* Mouse any event tracking */
	  dev_state.use_mouse = (c == 'h') ? 3 : 0;
	  break;

	case 1004: /* Focus in/out event reporting */
	  dev_state.use_focus = (c == 'h') ? true : false;
	  break;

	case 1005: /* Extended mouse mode */
	  syscall_printf ("ignored h/l command for extended mouse mode");
	  break;

	case 1006: /* SGR extended mouse mode */
	  dev_state.ext_mouse_mode6 = c == 'h';
	  break;

	case 1015: /* Urxvt extended mouse mode */
	  dev_state.ext_mouse_mode15 = c == 'h';
	  break;

	case 2000: /* Raw keyboard mode */
	  set_raw_win32_keyboard_mode ((c == 'h') ? true : false);
	  break;

	default: /* Ignore */
	  syscall_printf ("unknown h/l command: %d", dev_state.args_[0]);
	  break;
	}
      break;
    case 'J':
      switch (dev_state.args_[0])
	{
	case 0:			/* Clear to end of screen */
	  cursor_get (&x, &y);
	  clear_screen (x, y, -1, -1);
	  break;
	case 1:			/* Clear from beginning of screen to cursor */
	  cursor_get (&x, &y);
	  clear_screen (0, 0, x, y);
	  break;
	case 2:			/* Clear screen */
	  clear_screen (0, 0, -1, -1);
	  cursor_set (true, 0,0);
	  break;
	default:
	  goto bad_escape;
	}
      break;

    case 'A':
      cursor_rel (0, -(dev_state.args_[0] ? dev_state.args_[0] : 1));
      break;
    case 'B':
      cursor_rel (0, dev_state.args_[0] ? dev_state.args_[0] : 1);
      break;
    case 'C':
      cursor_rel (dev_state.args_[0] ? dev_state.args_[0] : 1, 0);
      break;
    case 'D':
      cursor_rel (-(dev_state.args_[0] ? dev_state.args_[0] : 1),0);
      break;
    case 'K':
      switch (dev_state.args_[0])
	{
	  case 0:		/* Clear to end of line */
	    cursor_get (&x, &y);
	    clear_screen (x, y, -1, y);
	    break;
	  case 2:		/* Clear line */
	    cursor_get (&x, &y);
	    clear_screen (0, y, -1, y);
	    break;
	  case 1:		/* Clear from bol to cursor */
	    cursor_get (&x, &y);
	    clear_screen (0, y, x, y);
	    break;
	  default:
	    goto bad_escape;
	}
      break;
    case 'H':
    case 'f':
      cursor_set (true, (dev_state.args_[1] ? dev_state.args_[1] : 1) - 1,
			(dev_state.args_[0] ? dev_state.args_[0] : 1) - 1);
      break;
    case 'G':   /* hpa - position cursor at column n - 1 */
      cursor_get (&x, &y);
      cursor_set (false, (dev_state.args_[0] ? dev_state.args_[0] - 1 : 0), y);
      break;
    case 'd':   /* vpa - position cursor at line n */
      cursor_get (&x, &y);
      cursor_set (true, x, (dev_state.args_[0] ? dev_state.args_[0] - 1 : 0));
      break;
    case 's':   /* Save cursor position */
      cursor_get (&dev_state.savex, &dev_state.savey);
      dev_state.savey -= dev_state.info.winTop;
      break;
    case 'u':   /* Restore cursor position */
      cursor_set (true, dev_state.savex, dev_state.savey);
      break;
    case 'I':	/* TAB */
      cursor_get (&x, &y);
      cursor_set (false, 8 * (x / 8 + 1), y);
      break;
    case 'L':				/* AL - insert blank lines */
      dev_state.args_[0] = dev_state.args_[0] ? dev_state.args_[0] : 1;
      cursor_get (&x, &y);
      scroll_screen (0, y, -1, -1, 0, y + dev_state.args_[0]);
      break;
    case 'M':				/* DL - delete lines */
      dev_state.args_[0] = dev_state.args_[0] ? dev_state.args_[0] : 1;
      cursor_get (&x, &y);
      scroll_screen (0, y + dev_state.args_[0], -1, -1, 0, y);
      break;
    case '@':				/* IC - insert chars */
      dev_state.args_[0] = dev_state.args_[0] ? dev_state.args_[0] : 1;
      cursor_get (&x, &y);
      scroll_screen (x, y, -1, y, x + dev_state.args_[0], y);
      break;
    case 'P':				/* DC - delete chars */
      dev_state.args_[0] = dev_state.args_[0] ? dev_state.args_[0] : 1;
      cursor_get (&x, &y);
      scroll_screen (x + dev_state.args_[0], y, -1, y, x, y);
      break;
    case 'S':				/* SF - Scroll forward */
      dev_state.args_[0] = dev_state.args_[0] ? dev_state.args_[0] : 1;
      scroll_screen (0, dev_state.args_[0], -1, -1, 0, 0);
      break;
    case 'T':				/* SR - Scroll down */
      dev_state.fillin_info (get_output_handle ());
      dev_state.args_[0] = dev_state.args_[0] ? dev_state.args_[0] : 1;
      scroll_screen (0, 0, -1, -1, 0, dev_state.info.winTop + dev_state.args_[0]);
      break;
    case 'X':				/* ec - erase chars */
      dev_state.args_[0] = dev_state.args_[0] ? dev_state.args_[0] : 1;
      cursor_get (&x, &y);
      scroll_screen (x + dev_state.args_[0], y, -1, y, x, y);
      scroll_screen (x, y, -1, y, x + dev_state.args_[0], y);
      break;
    case 'Z':				/* Back tab */
      cursor_get (&x, &y);
      cursor_set (false, ((8 * (x / 8 + 1)) - 8), y);
      break;
    case 'b':				/* Repeat char #1 #2 times */
      if (dev_state.insert_mode)
	{
	  cursor_get (&x, &y);
	  scroll_screen (x, y, -1, y, x + dev_state.args_[1], y);
	}
      while (dev_state.args_[1]--)
	WriteFile (get_output_handle (), &dev_state.args_[0], 1, (DWORD *) &x, 0);
      break;
    case 'c':				/* u9 - Terminal enquire string */
      if (dev_state.saw_greater_than_sign)
	/* Generate Secondary Device Attribute report, using 67 = ASCII 'C'
	   to indicate Cygwin (convention used by Rxvt, Urxvt, Screen, Mintty),
	   and cygwin version for terminal version. */
	__small_sprintf (buf, "\033[>67;%d%02d;0c", CYGWIN_VERSION_DLL_MAJOR, CYGWIN_VERSION_DLL_MINOR);
      else
	strcpy (buf, "\033[?6c");
      /* The generated report needs to be injected for read-ahead into the
	 fhandler_console object associated with standard input.
	 The current call does not work. */
      puts_readahead (buf);
      break;
    case 'n':
      switch (dev_state.args_[0])
	{
	case 6:				/* u7 - Cursor position request */
	  cursor_get (&x, &y);
	  y -= dev_state.info.winTop;
	  /* x -= dev_state.info.winLeft;		// not available yet */
	  __small_sprintf (buf, "\033[%d;%dR", y + 1, x + 1);
	  puts_readahead (buf);
	  break;
    default:
	  goto bad_escape;
	}
      break;
    case 'r':				/* Set Scroll region */
      dev_state.scroll_region.Top = dev_state.args_[0] ? dev_state.args_[0] - 1 : 0;
      dev_state.scroll_region.Bottom = dev_state.args_[1] ? dev_state.args_[1] - 1 : -1;
      cursor_set (true, 0, 0);
      break;
    case 'g':				/* TAB set/clear */
      break;
    default:
bad_escape:
      break;
    }
}

/* This gets called when we found an invalid input character.  We just
   print a half filled square (UTF 0x2592).  We have no chance to figure
   out the "meaning" of the input char anyway. */
inline void
fhandler_console::write_replacement_char ()
{
  static const wchar_t replacement_char = 0x2592; /* Half filled square */
  DWORD done;
  WriteConsoleW (get_output_handle (), &replacement_char, 1, &done, 0);
}

const unsigned char *
fhandler_console::write_normal (const unsigned char *src,
				const unsigned char *end)
{
  /* Scan forward to see what a char which needs special treatment */
  DWORD done;
  DWORD buf_len;
  const unsigned char *found = src;
  size_t ret;
  mbstate_t ps;
  UINT cp = dev_state.get_console_cp ();
  const char *charset;
  mbtowc_p f_mbtowc;

  if (cp)
    {
      /* The alternate charset is always 437, just as in the Linux console. */
      f_mbtowc = __cp_mbtowc;
      charset = "CP437";
    }
  else
    {
      f_mbtowc = cygheap->locale.mbtowc;
      charset = cygheap->locale.charset;
    }

  /* First check if we have cached lead bytes of a former try to write
     a truncated multibyte sequence.  If so, process it. */
  if (trunc_buf.len)
    {
      const unsigned char *nfound;
      int cp_len = MIN (end - src, 4 - trunc_buf.len);
      memcpy (trunc_buf.buf + trunc_buf.len, src, cp_len);
      memset (&ps, 0, sizeof ps);
      switch (ret = f_mbtowc (_REENT, NULL, (const char *) trunc_buf.buf,
			       trunc_buf.len + cp_len, charset, &ps))
	{
	case -2:
	  /* Still truncated multibyte sequence?  Keep in trunc_buf. */
	  trunc_buf.len += cp_len;
	  return end;
	case -1:
	  /* Give up, print replacement chars for trunc_buf... */
	  for (int i = 0; i < trunc_buf.len; ++i)
	    write_replacement_char ();
	  /* ... mark trunc_buf as unused... */
	  trunc_buf.len = 0;
	  /* ... and proceed. */
	  nfound = NULL;
	  break;
	case 0:
	  nfound = trunc_buf.buf + 1;
	  break;
	default:
	  nfound = trunc_buf.buf + ret;
	  break;
	}
      /* Valid multibyte sequence?  Process. */
      if (nfound)
	{
	  buf_len = dev_state.str_to_con (f_mbtowc, charset, write_buf,
					   (const char *) trunc_buf.buf,
					   nfound - trunc_buf.buf);
	  if (!write_console (write_buf, buf_len, done))
	    {
	      debug_printf ("multibyte sequence write failed, handle %p", get_output_handle ());
	      return 0;
	    }
	  found = src + (nfound - trunc_buf.buf - trunc_buf.len);
	  trunc_buf.len = 0;
	  return found;
	}
    }

  /* Loop over src buffer as long as we have just simple characters.  Stop
     as soon as we reach the conversion limit, or if we encounter a control
     character or a truncated or invalid mutibyte sequence. */
  memset (&ps, 0, sizeof ps);
  while (found < end
	 && found - src < CONVERT_LIMIT
	 && base_chars[*found] == NOR)
    {
      switch (ret = f_mbtowc (_REENT, NULL, (const char *) found,
			       end - found, charset, &ps))
	{
	case -2: /* Truncated multibyte sequence.  Store for next write. */
	  trunc_buf.len = end - found;
	  memcpy (trunc_buf.buf, found, trunc_buf.len);
	  goto do_print;
	case -1: /* Invalid multibyte sequence. Handled below. */
	  goto do_print;
	case 0:
	  found++;
	  break;
	default:
	  found += ret;
	  break;
	}
    }

do_print:

  /* Print all the base characters out */
  if (found != src)
    {
      DWORD len = found - src;
      buf_len = dev_state.str_to_con (f_mbtowc, charset, write_buf,
				       (const char *) src, len);
      if (!buf_len)
	{
	  debug_printf ("conversion error, handle %p",
			get_output_handle ());
	  __seterrno ();
	  return 0;
	}

      if (dev_state.insert_mode)
	{
	  int x, y;
	  cursor_get (&x, &y);
	  scroll_screen (x, y, -1, y, x + buf_len, y);
	}

      if (!write_console (write_buf, buf_len, done))
	{
	  debug_printf ("write failed, handle %p", get_output_handle ());
	  return 0;
	}
      /* Stop here if we reached the conversion limit. */
      if (len >= CONVERT_LIMIT)
	return found + trunc_buf.len;
    }
  /* If there's still something in the src buffer, but it's not a truncated
     multibyte sequence, then we stumbled over a control character or an
     invalid multibyte sequence.  Print it. */
  if (found < end && trunc_buf.len == 0)
    {
      int x, y;
      switch (base_chars[*found])
	{
	case SO:	/* Shift Out: Invoke G1 character set (ISO 2022) */
	  dev_state.iso_2022_G1 = true;
	  break;
	case SI:	/* Shift In: Invoke G0 character set (ISO 2022) */
	  dev_state.iso_2022_G1 = false;
	  break;
	case BEL:
	  beep ();
	  break;
	case ESC:
	  dev_state.state_ = gotesc;
	  break;
	case DWN:
	  cursor_get (&x, &y);
	  if (y >= srBottom)
	    {
	      if (y >= dev_state.info.winBottom && !dev_state.scroll_region.Top)
		WriteConsoleW (get_output_handle (), L"\n", 1, &done, 0);
	      else
		{
		  scroll_screen (0, srTop + 1, -1, srBottom, 0, srTop);
		  y--;
		}
	    }
	  cursor_set (false, ((get_ttyp ()->ti.c_oflag & ONLCR) ? 0 : x), y + 1);
	  break;
	case BAK:
	  cursor_rel (-1, 0);
	  break;
	case IGN:
	  cursor_rel (1, 0);
	  break;
	case CR:
	  cursor_get (&x, &y);
	  cursor_set (false, 0, y);
	  break;
	case ERR:
	  /* Don't print chars marked as ERR chars, except for a ASCII CAN
	     sequence which is printed as singlebyte chars from the UTF
	     Basic Latin and Latin 1 Supplement plains. */
	  if (*found == 0x18)
	    {
	      write_replacement_char ();
	      if (found + 1 < end)
		{
		  ret = __utf8_mbtowc (_REENT, NULL, (const char *) found + 1,
				       end - found - 1, NULL, &ps);
		  if (ret != (size_t) -1)
		    while (ret-- > 0)
		      {
			WCHAR w = *(found + 1);
			WriteConsoleW (get_output_handle (), &w, 1, &done, 0);
			found++;
		      }
		}
	    }
	  break;
	case TAB:
	  cursor_get (&x, &y);
	  cursor_set (false, 8 * (x / 8 + 1), y);
	  break;
	case NOR:
	  write_replacement_char ();
	  break;
	}
      found++;
    }
  return found + trunc_buf.len;
}

ssize_t __stdcall
fhandler_console::write (const void *vsrc, size_t len)
{
  bg_check_types bg = bg_check (SIGTTOU);
  if (bg <= bg_eof)
    return (ssize_t) bg;

  push_process_state process_state (PID_TTYOU);

  /* Run and check for ansi sequences */
  unsigned const char *src = (unsigned char *) vsrc;
  unsigned const char *end = src + len;
  /* This might look a bit far fetched, but using the TLS path buffer allows
     to allocate a big buffer without using the stack too much.  Doing it here
     in write instead of in write_normal should be faster, too. */
  tmp_pathbuf tp;
  write_buf = tp.w_get ();

  debug_printf ("%x, %d", vsrc, len);

  while (src < end)
    {
      debug_printf ("at %d(%c) state is %d", *src, isprint (*src) ? *src : ' ',
		    dev_state.state_);
      switch (dev_state.state_)
	{
	case normal:
	  src = write_normal (src, end);
	  if (!src) /* write_normal failed */
	    return -1;
	  break;
	case gotesc:
	  if (*src == '[')		/* CSI Control Sequence Introducer */
	    {
	      dev_state.state_ = gotsquare;
	      dev_state.saw_question_mark = false;
	      dev_state.saw_greater_than_sign = false;
	      for (dev_state.nargs_ = 0; dev_state.nargs_ < MAXARGS; dev_state.nargs_++)
		dev_state.args_[dev_state.nargs_] = 0;
	      dev_state.nargs_ = 0;
	    }
	  else if (*src == ']')		/* OSC Operating System Command */
	    {
	      dev_state.rarg = 0;
	      dev_state.my_title_buf[0] = '\0';
	      dev_state.state_ = gotrsquare;
	    }
	  else if (*src == '(')		/* Designate G0 character set */
	    {
	      dev_state.state_ = gotparen;
	    }
	  else if (*src == ')')		/* Designate G1 character set */
	    {
	      dev_state.state_ = gotrparen;
	    }
	  else if (*src == 'M')		/* Reverse Index (scroll down) */
	    {
	      dev_state.fillin_info (get_output_handle ());
	      scroll_screen (0, 0, -1, -1, 0, dev_state.info.winTop + 1);
	      dev_state.state_ = normal;
	    }
	  else if (*src == 'c')		/* RIS Full Reset */
	    {
	      dev_state.set_default_attr ();
	      dev_state.vt100_graphics_mode_G0 = false;
	      dev_state.vt100_graphics_mode_G1 = false;
	      dev_state.iso_2022_G1 = false;
	      clear_screen (0, 0, -1, -1);
	      cursor_set (true, 0, 0);
	      dev_state.state_ = normal;
	    }
	  else if (*src == '8')		/* DECRC Restore cursor position */
	    {
	      cursor_set (true, dev_state.savex, dev_state.savey);
	      dev_state.state_ = normal;
	    }
	  else if (*src == '7')		/* DECSC Save cursor position */
	    {
	      cursor_get (&dev_state.savex, &dev_state.savey);
	      dev_state.savey -= dev_state.info.winTop;
	      dev_state.state_ = normal;
	    }
	  else if (*src == 'R')		/* ? */
	      dev_state.state_ = normal;
	  else
	    {
	      dev_state.state_ = normal;
	    }
	  src++;
	  break;
	case gotarg1:
	  if (isdigit (*src))
	    {
	      dev_state.args_[dev_state.nargs_] = dev_state.args_[dev_state.nargs_] * 10 + *src - '0';
	      src++;
	    }
	  else if (*src == ';')
	    {
	      src++;
	      dev_state.nargs_++;
	      if (dev_state.nargs_ >= MAXARGS)
		dev_state.nargs_--;
	    }
	  else
	    {
	      dev_state.state_ = gotcommand;
	    }
	  break;
	case gotcommand:
	  char_command (*src++);
	  dev_state.state_ = normal;
	  break;
	case gotrsquare:
	  if (isdigit (*src))
	    dev_state.rarg = dev_state.rarg * 10 + (*src - '0');
	  else if (*src == ';' && (dev_state.rarg == 2 || dev_state.rarg == 0))
	    dev_state.state_ = gettitle;
	  else
	    dev_state.state_ = eattitle;
	  src++;
	  break;
	case eattitle:
	case gettitle:
	  {
	    int n = strlen (dev_state.my_title_buf);
	    if (*src < ' ')
	      {
		if (*src == '\007' && dev_state.state_ == gettitle)
		  set_console_title (dev_state.my_title_buf);
		dev_state.state_ = normal;
	      }
	    else if (n < TITLESIZE)
	      {
		dev_state.my_title_buf[n++] = *src;
		dev_state.my_title_buf[n] = '\0';
	      }
	    src++;
	    break;
	  }
	case gotsquare:
	  if (*src == ';')
	    {
	      dev_state.state_ = gotarg1;
	      dev_state.nargs_++;
	      src++;
	    }
	  else if (isalpha (*src))
	    dev_state.state_ = gotcommand;
	  else if (*src != '@' && !isalpha (*src) && !isdigit (*src))
	    {
	      if (*src == '?')
		dev_state.saw_question_mark = true;
	      else if (*src == '>')
		dev_state.saw_greater_than_sign = true;
	      /* ignore any extra chars between [ and first arg or command */
	      src++;
	    }
	  else
	    dev_state.state_ = gotarg1;
	  break;
	case gotparen:	/* Designate G0 Character Set (ISO 2022) */
	  if (*src == '0')
	    dev_state.vt100_graphics_mode_G0 = true;
	  else
	    dev_state.vt100_graphics_mode_G0 = false;
	  dev_state.state_ = normal;
	  src++;
	  break;
	case gotrparen:	/* Designate G1 Character Set (ISO 2022) */
	  if (*src == '0')
	    dev_state.vt100_graphics_mode_G1 = true;
	  else
	    dev_state.vt100_graphics_mode_G1 = false;
	  dev_state.state_ = normal;
	  src++;
	  break;
	}
    }

  syscall_printf ("%d = fhandler_console::write(...)", len);

  return len;
}

static struct {
  int vk;
  const char *val[4];
} keytable[] NO_COPY = {
	       /* NORMAL */    /* SHIFT */     /* CTRL */     /* CTRL-SHIFT */
  /* Unmodified and Alt-modified keypad keys comply with linux console
     SHIFT, CTRL, CTRL-SHIFT modifiers comply with xterm modifier usage */
  {VK_NUMPAD5,	{"\033[G",	"\033[1;2G",	"\033[1;5G",	"\033[1;6G"}},
  {VK_CLEAR,	{"\033[G",	"\033[1;2G",	"\033[1;5G",	"\033[1;6G"}},
  {VK_LEFT,	{"\033[D",	"\033[1;2D",	"\033[1;5D",	"\033[1;6D"}},
  {VK_RIGHT,	{"\033[C",	"\033[1;2C",	"\033[1;5C",	"\033[1;6C"}},
  {VK_UP,	{"\033[A",	"\033[1;2A",	"\033[1;5A",	"\033[1;6A"}},
  {VK_DOWN,	{"\033[B",	"\033[1;2B",	"\033[1;5B",	"\033[1;6B"}},
  {VK_PRIOR,	{"\033[5~",	"\033[5;2~",	"\033[5;5~",	"\033[5;6~"}},
  {VK_NEXT,	{"\033[6~",	"\033[6;2~",	"\033[6;5~",	"\033[6;6~"}},
  {VK_HOME,	{"\033[1~",	"\033[1;2~",	"\033[1;5~",	"\033[1;6~"}},
  {VK_END,	{"\033[4~",	"\033[4;2~",	"\033[4;5~",	"\033[4;6~"}},
  {VK_INSERT,	{"\033[2~",	"\033[2;2~",	"\033[2;5~",	"\033[2;6~"}},
  {VK_DELETE,	{"\033[3~",	"\033[3;2~",	"\033[3;5~",	"\033[3;6~"}},
  /* F1...F12, SHIFT-F1...SHIFT-F10 comply with linux console
     F6...F12, and all modified F-keys comply with rxvt (compatible extension) */
  {VK_F1,	{"\033[[A",	"\033[23~",	"\033[11^",	"\033[23^"}},
  {VK_F2,	{"\033[[B",	"\033[24~",	"\033[12^",	"\033[24^"}},
  {VK_F3,	{"\033[[C",	"\033[25~",	"\033[13^",	"\033[25^"}},
  {VK_F4,	{"\033[[D",	"\033[26~",	"\033[14^",	"\033[26^"}},
  {VK_F5,	{"\033[[E",	"\033[28~",	"\033[15^",	"\033[28^"}},
  {VK_F6,	{"\033[17~",	"\033[29~",	"\033[17^",	"\033[29^"}},
  {VK_F7,	{"\033[18~",	"\033[31~",	"\033[18^",	"\033[31^"}},
  {VK_F8,	{"\033[19~",	"\033[32~",	"\033[19^",	"\033[32^"}},
  {VK_F9,	{"\033[20~",	"\033[33~",	"\033[20^",	"\033[33^"}},
  {VK_F10,	{"\033[21~",	"\033[34~",	"\033[21^",	"\033[34^"}},
  {VK_F11,	{"\033[23~",	"\033[23$",	"\033[23^",	"\033[23@"}},
  {VK_F12,	{"\033[24~",	"\033[24$",	"\033[24^",	"\033[24@"}},
  /* CTRL-6 complies with Windows cmd console but should be fixed */
  {'6',		{NULL,		NULL,		"\036",		NULL}},
  /* Table end marker */
  {0}
};

const char *
get_nonascii_key (INPUT_RECORD& input_rec, char *tmp)
{
#define NORMAL  0
#define SHIFT	1
#define CONTROL	2
/*#define CONTROLSHIFT	3*/

  int modifier_index = NORMAL;
  if (input_rec.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED)
    modifier_index = SHIFT;
  if (input_rec.Event.KeyEvent.dwControlKeyState & CTRL_PRESSED)
    modifier_index += CONTROL;

  for (int i = 0; keytable[i].vk; i++)
    if (input_rec.Event.KeyEvent.wVirtualKeyCode == keytable[i].vk)
      {
	if ((input_rec.Event.KeyEvent.dwControlKeyState & ALT_PRESSED)
	    && keytable[i].val[modifier_index] != NULL)
	  { /* Generic ESC prefixing if Alt is pressed */
	    tmp[0] = '\033';
	    strcpy (tmp + 1, keytable[i].val[modifier_index]);
	    return tmp;
	  }
	else
	  return keytable[i].val[modifier_index];
      }

  if (input_rec.Event.KeyEvent.uChar.AsciiChar)
    {
      tmp[0] = input_rec.Event.KeyEvent.uChar.AsciiChar;
      tmp[1] = '\0';
      return tmp;
    }
  return NULL;
}

int
fhandler_console::init (HANDLE h, DWORD a, mode_t bin)
{
  // this->fhandler_termios::init (h, mode, bin);
  /* Ensure both input and output console handles are open */
  int flags = 0;

  a &= GENERIC_READ | GENERIC_WRITE;
  if (a == GENERIC_READ)
    flags = O_RDONLY;
  if (a == GENERIC_WRITE)
    flags = O_WRONLY;
  if (a == (GENERIC_READ | GENERIC_WRITE))
    flags = O_RDWR;
  open_with_arch (flags | O_BINARY | (h ? 0 : O_NOCTTY));

  return !tcsetattr (0, &get_ttyp ()->ti);
}

int
fhandler_console::igncr_enabled ()
{
  return get_ttyp ()->ti.c_iflag & IGNCR;
}

void
fhandler_console::set_close_on_exec (bool val)
{
  close_on_exec (val);
}

void __stdcall
set_console_title (char *title)
{
  wchar_t buf[TITLESIZE + 1];
  sys_mbstowcs (buf, TITLESIZE + 1, title);
  lock_ttys here (15000);
  SetConsoleTitleW (buf);
  debug_printf ("title '%W'", buf);
}

void
fhandler_console::fixup_after_fork_exec (bool execing)
{
  set_unit ();
}

// #define WINSTA_ACCESS (WINSTA_READATTRIBUTES | STANDARD_RIGHTS_READ | STANDARD_RIGHTS_WRITE | WINSTA_CREATEDESKTOP | WINSTA_EXITWINDOWS)
#define WINSTA_ACCESS WINSTA_ALL_ACCESS

/* Create a console in an invisible window station.  This should work
   in all versions of Windows NT except Windows 7 (so far). */
bool
fhandler_console::create_invisible_console (HWINSTA horig)
{
  HWINSTA h = CreateWindowStationW (NULL, 0, WINSTA_ACCESS, NULL);
  termios_printf ("%p = CreateWindowStation(NULL), %E", h);
  BOOL b;
  if (h)
    {
      b = SetProcessWindowStation (h);
      termios_printf ("SetProcessWindowStation %d, %E", b);
    }
  b = AllocConsole ();	/* will cause flashing if CreateWindowStation
			   failed */
  if (!h)
    SetParent (GetConsoleWindow (), HWND_MESSAGE);
  if (horig && h && h != horig && SetProcessWindowStation (horig))
    CloseWindowStation (h);
  termios_printf ("%d = AllocConsole (), %E", b);
  invisible_console = true;
  return b;
}

/* Ugly workaround for Windows 7.

   First try to just attach to any console which may have started this
   app.  If that works use this as our "invisible console".

   This will fail if not started from the command prompt.  In that case, start
   a dummy console application in a hidden state so that we can use its console
   as our invisible console.  This probably works everywhere but process
   creation is slow and to be avoided if possible so the window station method
   is vastly preferred.

   FIXME: This is not completely thread-safe since it creates two inheritable
   handles which are known only to this function.  If another thread starts
   a process the new process will inherit these handles.  However, since this
   function is currently only called at startup and during exec, it shouldn't
   be a big deal.  */
bool
fhandler_console::create_invisible_console_workaround ()
{
  if (!AttachConsole (-1))
    {
      bool taskbar;
      DWORD err = GetLastError ();
      path_conv helper ("/bin/cygwin-console-helper.exe");
      HANDLE hello = NULL;
      HANDLE goodbye = NULL;
      /* If err == ERROR_PROC_FOUND then this method won't work.  But that's
	 ok.  The window station method should work ok when AttachConsole doesn't
	 work.

	 If the helper doesn't exist or we can't create event handles then we
	 can't use this method. */
      if (err == ERROR_PROC_NOT_FOUND || !helper.exists ()
	  || !(hello = CreateEvent (&sec_none, true, false, NULL))
	  || !(goodbye = CreateEvent (&sec_none, true, false, NULL)))
	{
	  AllocConsole ();	/* This is just sanity check code.  We should
				   never actually hit here unless we're running
				   in an environment which lacks the helper
				   app. */
	  taskbar = true;
	}
      else
	{
	  STARTUPINFOW si = {};
	  PROCESS_INFORMATION pi;
	  size_t len = helper.get_wide_win32_path_len ();
	  WCHAR cmd[len + (2 * strlen (" 0xffffffff")) + 1];
	  WCHAR title[] = L"invisible cygwin console";

	  helper.get_wide_win32_path (cmd);
	  __small_swprintf (cmd + len, L" %p %p", hello, goodbye);

	  si.cb = sizeof (si);
	  si.dwFlags = STARTF_USESHOWWINDOW;
	  si.wShowWindow = SW_HIDE;
	  si.lpTitle = title;

	  /* Create a new hidden process.  Use the two event handles as
	     argv[1] and argv[2]. */
	  BOOL x = CreateProcessW (NULL, cmd, &sec_none_nih, &sec_none_nih, true,
				   CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	  if (x)
	    {
	      CloseHandle (pi.hProcess);	/* Don't need */
	      CloseHandle (pi.hThread);		/*  these.    */
	    }
	  taskbar = false;
	  /* Wait for subprocess to indicate that it is live.  This may not
	     actually be needed but it's hard to say since it is possible that
	     there will be no console for a brief time after the process
	     returns and there is no easy way to determine if/when this happens
	     in Windows.  So play it safe. */
	  if (!x || (WaitForSingleObject (hello, 10000) != WAIT_OBJECT_0)
	      || !AttachConsole (pi.dwProcessId))
	    AllocConsole ();	/* Oh well.  Watch the flash. */
	}

      if (!taskbar)
	/* Setting the owner of the console window to HWND_MESSAGE seems to
	   hide it from the taskbar.  Don't know if this method is faster than
	   calling ShowWindowAsync but it should guarantee no taskbar presence
	   for the hidden console. */
	SetParent (GetConsoleWindow (), HWND_MESSAGE);
      if (hello)
	CloseHandle (hello);
      if (goodbye)
	{
	  SetEvent (goodbye);	/* Tell helper process it's ok to exit. */
	  CloseHandle (goodbye);
	}
    }
  return invisible_console = true;
}

void
fhandler_console::free_console ()
{
  BOOL res = FreeConsole ();
  debug_printf ("freed console, res %d", res);
  init_console_handler (false);
}

bool
fhandler_console::need_invisible ()
{
  BOOL b = false;
  if (exists ())
    invisible_console = false;
  else
    {
      HWINSTA h;
      /* The intent here is to allocate an "invisible" console if we have no
	 controlling tty or to reuse the existing console if we already have
	 a tty.  So, first get the old window station.  If there is no controlling
	 terminal, create a new window station and then set it as the current
	 window station.  The subsequent AllocConsole will then be allocated
	 invisibly.  But, after doing that we have to restore any existing windows
	 station or, strangely, characters will not be displayed in any windows
	 drawn on the current screen.  We only do this if we have changed to
	 a new window station and if we had an existing windows station previously.
	 We also close the previously opened window station even though AllocConsole
	 is now "using" it.  This doesn't seem to cause any problems.

	 Things to watch out for if you make changes in this code:

	 - Flashing, black consoles showing up when you start, e.g., ssh in
	   an xterm.
	 - Non-displaying of characters in rxvt or xemacs if you start a
	   process using setsid: bash -lc "setsid rxvt".  */

      h = GetProcessWindowStation ();

      USEROBJECTFLAGS oi;
      DWORD len;
      if (!h
	  || !GetUserObjectInformationW (h, UOI_FLAGS, &oi, sizeof (oi), &len)
	  || !(oi.dwFlags & WSF_VISIBLE))
	{
	  b = true;
	  debug_printf ("window station is not visible");
	  AllocConsole ();
	  invisible_console = true;
	}
      else if (wincap.has_broken_alloc_console ())
	b = create_invisible_console_workaround ();
      else
	b = create_invisible_console (h);
    }

  debug_printf ("invisible_console %d", invisible_console);
  return b;
}
