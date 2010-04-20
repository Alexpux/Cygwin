/* cygerrno.h: main Cygwin header file.

   Copyright 2000, 2001, 2002, 2003, 2004, 2010 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _CYGERRNO_H
#define _CYGERRNO_H
#include <errno.h>

void __stdcall seterrno_from_win_error (const char *file, int line, DWORD code) __attribute__ ((regparm(3)));
#ifdef _NTDLL_H
void __stdcall seterrno_from_nt_status (const char *file, int line, NTSTATUS status) __attribute__ ((regparm(3)));
#endif
void __stdcall seterrno (const char *, int line) __attribute__ ((regparm(2)));
int __stdcall geterrno_from_win_error (DWORD code = GetLastError (), int deferrno = 13 /*EACCESS*/) __attribute__ ((regparm(2)));

#define __seterrno() seterrno (__FILE__, __LINE__)
#define __seterrno_from_win_error(val) seterrno_from_win_error (__FILE__, __LINE__, val)
#define __seterrno_from_nt_status(status) seterrno_from_nt_status (__FILE__, __LINE__, status)

inline int
__set_errno (const char *fn, int ln, int val)
{
  debug_printf ("%s:%d val %d", fn, ln, val);
  return errno = _impure_ptr->_errno = val;
}
#define set_errno(val) __set_errno (__PRETTY_FUNCTION__, __LINE__, (val))

#define get_errno()  (errno)
extern "C" void __stdcall set_sig_errno (int e);

class save_errno
  {
    int saved;
  public:
    save_errno () {saved = get_errno ();}
    save_errno (int what) {saved = get_errno (); set_errno (what); }
    void set (int what) {set_errno (what); saved = what;}
    void reset () {saved = get_errno ();}
    ~save_errno () {errno = _impure_ptr->_errno = saved;}
  };

extern const char *__sp_fn;
extern int __sp_ln;
#endif /*_CYGERRNO_H*/
