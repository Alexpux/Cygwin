/* external.cc: Interface to Cygwin internals from external programs.

   Copyright 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004 Red Hat, Inc.

   Written by Christopher Faylor <cgf@cygnus.com>

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include "security.h"
#include "sigproc.h"
#include "pinfo.h"
#include <exceptions.h>
#include "shared_info.h"
#include "cygwin_version.h"
#include "perprocess.h"
#include "cygerrno.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "wincap.h"
#include "heap.h"
#include "cygthread.h"
#include "pwdgrp.h"
#include "cygtls.h"

static external_pinfo *
fillout_pinfo (pid_t pid, int winpid)
{
  BOOL nextpid;
  static external_pinfo ep;

  if ((nextpid = !!(pid & CW_NEXTPID)))
    pid ^= CW_NEXTPID;

  static winpids pids (0);

  static unsigned int i;
  if (!pids.npids || !nextpid)
    {
      pids.set (winpid);
      i = 0;
    }

  if (!pid)
    i = 0;

  memset (&ep, 0, sizeof ep);
  while (i < pids.npids)
    {
      DWORD thispid = pids.winpid (i);
      _pinfo *p = pids[i];
      i++;

      if (!p)
	{
	  if (!nextpid && thispid != (DWORD) pid)
	    continue;
	  ep.pid = cygwin_pid (thispid);
	  ep.dwProcessId = thispid;
	  ep.process_state = PID_IN_USE;
	  ep.ctty = -1;
	  break;
	}
      else if (nextpid || p->pid == pid || (winpid && thispid == (DWORD) pid))
	{
	  ep.ctty = p->ctty;
	  ep.pid = p->pid;
	  ep.ppid = p->ppid;
	  ep.hProcess = p->hProcess;
	  ep.dwProcessId = p->dwProcessId;
	  ep.uid = p->uid;
	  ep.gid = p->gid;
	  ep.pgid = p->pgid;
	  ep.sid = p->sid;
	  ep.umask = 0;
	  ep.start_time = p->start_time;
	  ep.rusage_self = p->rusage_self;
	  ep.rusage_children = p->rusage_children;
	  strcpy (ep.progname, p->progname);
	  ep.strace_mask = 0;
	  ep.version = EXTERNAL_PINFO_VERSION;

	  ep.process_state = p->process_state;

	  ep.uid32 = p->uid;
	  ep.gid32 = p->gid;
	  break;
	}
    }

  if (!ep.pid)
    {
      i = 0;
      pids.reset ();
      return 0;
    }
  return &ep;
}

static DWORD
get_cygdrive_info (char *user, char *system, char *user_flags,
		   char *system_flags)
{
  int res = mount_table->get_cygdrive_info (user, system, user_flags,
					    system_flags);
  return (res == ERROR_SUCCESS) ? 1 : 0;
}

static DWORD
get_cygdrive_prefixes (char *user, char *system)
{
  char user_flags[CYG_MAX_PATH];
  char system_flags[CYG_MAX_PATH];
  DWORD res = get_cygdrive_info (user, system, user_flags, system_flags);
  return res;
}

static DWORD
check_ntsec (const char *filename)
{
  if (!filename)
    return wincap.has_security () && allow_ntsec;
  path_conv pc (filename);
  return wincap.has_security () && allow_ntsec && pc.has_acls ();
}

extern "C" unsigned long
cygwin_internal (cygwin_getinfo_types t, ...)
{
  va_list arg;
  va_start (arg, t);

  switch (t)
    {
      case CW_LOCK_PINFO:
	return 1;

      case CW_UNLOCK_PINFO:
	return 1;

      case CW_GETTHREADNAME:
	return (DWORD) cygthread::name (va_arg (arg, DWORD));

      case CW_SETTHREADNAME:
	{
	  set_errno (ENOSYS);
	  return 0;
	}

      case CW_GETPINFO:
	return (DWORD) fillout_pinfo (va_arg (arg, DWORD), 0);

      case CW_GETVERSIONINFO:
	return (DWORD) cygwin_version_strings;

      case CW_READ_V1_MOUNT_TABLES:
	set_errno (ENOSYS);
	return 1;

      case CW_USER_DATA:
	return (DWORD) &__cygwin_user_data;

      case CW_PERFILE:
	perfile_table = va_arg (arg, struct __cygwin_perfile *);
	return 0;

      case CW_GET_CYGDRIVE_PREFIXES:
	{
	  char *user = va_arg (arg, char *);
	  char *system = va_arg (arg, char *);
	  return get_cygdrive_prefixes (user, system);
	}

      case CW_GETPINFO_FULL:
	return (DWORD) fillout_pinfo (va_arg (arg, pid_t), 1);

      case CW_INIT_EXCEPTIONS:
	init_exceptions (va_arg (arg, exception_list *));
	return 0;

      case CW_GET_CYGDRIVE_INFO:
	{
	  char *user = va_arg (arg, char *);
	  char *system = va_arg (arg, char *);
	  char *user_flags = va_arg (arg, char *);
	  char *system_flags = va_arg (arg, char *);
	  return get_cygdrive_info (user, system, user_flags, system_flags);
	}

      case CW_SET_CYGWIN_REGISTRY_NAME:
	{
	  const char *cr = va_arg (arg, char *);
	  if (check_null_empty_str_errno (cr))
	    return (DWORD) NULL;
	  cygheap->cygwin_regname = (char *) crealloc (cygheap->cygwin_regname,
						       strlen (cr) + 1);
	  strcpy (cygheap->cygwin_regname, cr);
	}
      case CW_GET_CYGWIN_REGISTRY_NAME:
	  return (DWORD) cygheap->cygwin_regname;

      case CW_STRACE_TOGGLE:
	{
	  pid_t pid = va_arg (arg, pid_t);
	  pinfo p (pid);
	  if (p)
	    {
	      sig_send (p, __SIGSTRACE);
	      return 0;
	    }
	  else
	    {
	      set_errno (ESRCH);
	      return (DWORD) -1;
	    }
	}

      case CW_STRACE_ACTIVE:
	{
	  return strace.active;
	}

      case CW_CYGWIN_PID_TO_WINPID:
	{
	  pinfo p (va_arg (arg, pid_t));
	  return p ? p->dwProcessId : 0;
	}
      case CW_EXTRACT_DOMAIN_AND_USER:
	{
	  struct passwd *pw = va_arg (arg, struct passwd *);
	  char *domain = va_arg (arg, char *);
	  char *user = va_arg (arg, char *);
	  extract_nt_dom_user (pw, domain, user);
	  return 0;
	}
      case CW_CMDLINE:
	{
	  size_t n;
	  pid_t pid = va_arg (arg, pid_t);
	  pinfo p (pid);
	  return (DWORD) p->cmdline (n);
	}
      case CW_CHECK_NTSEC:
	{
	  char *filename = va_arg (arg, char *);
	  return check_ntsec (filename);
	}
      case CW_GET_ERRNO_FROM_WINERROR:
	{
	  int error = va_arg (arg, int);
	  int deferrno = va_arg (arg, int);
	  return geterrno_from_win_error (error, deferrno);
	}
      case CW_GET_POSIX_SECURITY_ATTRIBUTE:
	{
	  security_descriptor sd;
	  int attribute = va_arg (arg, int);
	  PSECURITY_ATTRIBUTES psa = va_arg (arg, PSECURITY_ATTRIBUTES);
	  void *sd_buf = va_arg (arg, void *);
	  DWORD sd_buf_size = va_arg (arg, DWORD);
	  set_security_attribute (attribute, psa, sd);
	  if (!psa->lpSecurityDescriptor || sd.size () > sd_buf_size)
	    return sd.size ();
	  memcpy (sd_buf, sd, sd.size ());
	  psa->lpSecurityDescriptor = sd_buf;
	  return 0;
	}
      case CW_GET_SHMLBA:
	{
	  return getshmlba ();
	}
      case CW_GET_UID_FROM_SID:
	{
	  PSID psid = va_arg (arg, PSID);
	  cygsid sid (psid);
	  struct passwd *pw = internal_getpwsid (sid);
	  return pw ? pw->pw_uid : (__uid32_t)-1;
	}
      case CW_GET_GID_FROM_SID:
	{
	  PSID psid = va_arg (arg, PSID);
	  cygsid sid (psid);
	  struct __group32 *gr = internal_getgrsid (sid);
	  return gr ? gr->gr_gid : (__gid32_t)-1;
	}
      case CW_GET_BINMODE:
	{
	  const char *path = va_arg (arg, const char *);
	  path_conv p (path, PC_SYM_FOLLOW | PC_FULL | PC_NULLEMPTY);
	  if (p.error)
	    {
	      set_errno (p.error);
	      return (unsigned long) -1;
	    }
	  return p.binmode ();
	}
      default:
	return (DWORD) -1;
    }
}
