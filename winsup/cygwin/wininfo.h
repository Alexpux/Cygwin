/* wininfo.h: main Cygwin header file.

   Copyright 2004 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

class muto;
class wininfo
{
  HWND hwnd;
  static muto _lock;
public:
  operator HWND ();
  int __stdcall wininfo::process (HWND, UINT, WPARAM, LPARAM)
    __attribute__ ((regparm (3)));
  void lock ();
  void release ();
  DWORD WINAPI winthread () __attribute__ ((regparm (1)));
};

extern wininfo winmsg;
