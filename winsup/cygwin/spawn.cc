/* spawn.cc

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004,
   2005, 2006 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <process.h>
#include <sys/wait.h>
#include <limits.h>
#include <wingdi.h>
#include <winuser.h>
#include <ctype.h>
#include "cygerrno.h"
#include <sys/cygwin.h>
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "sigproc.h"
#include "cygheap.h"
#include "child_info.h"
#include "shared_info.h"
#include "pinfo.h"
#include "registry.h"
#include "environ.h"
#include "cygtls.h"

#define LINE_BUF_CHUNK (CYG_MAX_PATH * 2)
#define MAXWINCMDLEN 32767

static suffix_info exe_suffixes[] =
{
  suffix_info ("", 1),
  suffix_info (".exe", 1),
  suffix_info (".com"),
  suffix_info (NULL)
};

static suffix_info dll_suffixes[] =
{
  suffix_info (".dll"),
  suffix_info ("", 1),
  suffix_info (".exe", 1),
  suffix_info (NULL)
};

HANDLE hExeced;
DWORD dwExeced;

/* Add .exe to PROG if not already present and see if that exists.
   If not, return PROG (converted from posix to win32 rules if necessary).
   The result is always BUF.

   Returns (possibly NULL) suffix */

static const char *
perhaps_suffix (const char *prog, path_conv& buf, int& err, unsigned opt)
{
  char *ext;

  err = 0;
  debug_printf ("prog '%s'", prog);
  buf.check (prog, PC_SYM_FOLLOW | PC_NULLEMPTY,
	     (opt & FE_DLL) ? dll_suffixes : exe_suffixes);

  if (buf.isdir ())
    {
      err = EACCES;
      ext = NULL;
    }
  else if (!buf.exists ())
    {
      err = ENOENT;
      ext = NULL;
    }
  else if (buf.known_suffix)
    ext = (char *) buf + (buf.known_suffix - buf.get_win32 ());
  else
    ext = strchr (buf, '\0');

  debug_printf ("buf %s, suffix found '%s'", (char *) buf, ext);
  return ext;
}

/* Find an executable name, possibly by appending known executable
   suffixes to it.  The win32-translated name is placed in 'buf'.
   Any found suffix is returned in known_suffix.

   If the file is not found and !null_if_not_found then the win32 version
   of name is placed in buf and returned.  Otherwise the contents of buf
   is undefined and NULL is returned.  */

const char * __stdcall
find_exec (const char *name, path_conv& buf, const char *mywinenv,
	   unsigned opt, const char **known_suffix)
{
  const char *suffix = "";
  debug_printf ("find_exec (%s)", name);
  const char *retval = buf;
  char tmp[CYG_MAX_PATH];
  const char *posix = (opt & FE_NATIVE) ? NULL : name;
  bool has_slash = strchr (name, '/');
  int err;

  /* Check to see if file can be opened as is first.
     Win32 systems always check . first, but PATH may not be set up to
     do this. */
  if ((has_slash || opt & FE_CWD)
      && (suffix = perhaps_suffix (name, buf, err, opt)) != NULL)
    {
      if (posix && !has_slash)
	{
	  tmp[0] = '.';
	  tmp[1] = '/';
	  strcpy (tmp + 2, name);
	  posix = tmp;
	}
      goto out;
    }

  win_env *winpath;
  const char *path;
  const char *posix_path;

  posix = (opt & FE_NATIVE) ? NULL : tmp;

  if (strchr (mywinenv, '/'))
    {
      /* it's not really an environment variable at all */
      int n = cygwin_posix_to_win32_path_list_buf_size (mywinenv);
      char *s = (char *) alloca (n + 1);
      if (cygwin_posix_to_win32_path_list (mywinenv, s))
	goto errout;
      path = s;
      posix_path = mywinenv - 1;
    }
  else if (has_slash || strchr (name, '\\') || isdrive (name)
      || !(winpath = getwinenv (mywinenv))
      || !(path = winpath->get_native ()) || *path == '\0')
    /* Return the error condition if this is an absolute path or if there
       is no PATH to search. */
    goto errout;
  else
    posix_path = winpath->get_posix () - 1;

  debug_printf ("%s%s", mywinenv, path);
  /* Iterate over the specified path, looking for the file with and without
     executable extensions. */
  do
    {
      posix_path++;
      char *eotmp = strccpy (tmp, &path, ';');
      /* An empty path or '.' means the current directory, but we've
	 already tried that.  */
      if (opt & FE_CWD && (tmp[0] == '\0' || (tmp[0] == '.' && tmp[1] == '\0')))
	continue;

      *eotmp++ = '\\';
      strcpy (eotmp, name);

      debug_printf ("trying %s", tmp);

      if ((suffix = perhaps_suffix (tmp, buf, err, opt)) != NULL)
	{
	  if (buf.has_acls () && allow_ntsec && check_file_access (buf, X_OK))
	    continue;

	  if (posix == tmp)
	    {
	      eotmp = strccpy (tmp, &posix_path, ':');
	      if (eotmp == tmp)
		*eotmp++ = '.';
	      *eotmp++ = '/';
	      strcpy (eotmp, name);
	    }
	  goto out;
	}
    }
  while (*path && *++path && (posix_path = strchr (posix_path, ':')));

 errout:
  posix = NULL;
  /* Couldn't find anything in the given path.
     Take the appropriate action based on null_if_not_found. */
  if (opt & FE_NNF)
    retval = NULL;
  else if (opt & FE_NATIVE)
    buf.check (name);
  else
    retval = name;

 out:
  if (posix)
    buf.set_path (posix);
  debug_printf ("%s = find_exec (%s)", (char *) buf, name);
  if (known_suffix)
    *known_suffix = suffix ?: strchr (buf, '\0');
  if (!retval && err)
    set_errno (err);
  return retval;
}

/* Utility for spawn_guts.  */

static HANDLE
handle (int fd, int direction)
{
  HANDLE h;
  cygheap_fdget cfd (fd);

  if (cfd < 0)
    h = INVALID_HANDLE_VALUE;
  else if (cfd->close_on_exec ())
    h = INVALID_HANDLE_VALUE;
  else if (direction == 0)
    h = cfd->get_handle ();
  else
    h = cfd->get_output_handle ();
  return h;
}

int
iscmd (const char *argv0, const char *what)
{
  int n;
  n = strlen (argv0) - strlen (what);
  if (n >= 2 && argv0[1] != ':')
    return 0;
  return n >= 0 && strcasematch (argv0 + n, what) &&
	 (n == 0 || isdirsep (argv0[n - 1]));
}

class linebuf
{
 public:
  size_t ix;
  char *buf;
  size_t alloced;
  linebuf () : ix (0), buf (NULL), alloced (0) {}
  ~linebuf () {if (buf) free (buf);}
  void add (const char *what, int len) __attribute__ ((regparm (3)));
  void add (const char *what) {add (what, strlen (what));}
  void prepend (const char *what, int len);
  void finish (bool) __attribute__ ((regparm (2)));
};

void
linebuf::finish (bool cmdlenoverflow_ok)
{
  if (!ix)
    add ("", 1);
  else
    {
      if (ix-- > MAXWINCMDLEN && cmdlenoverflow_ok)
	ix = MAXWINCMDLEN - 1;
      buf[ix] = '\0';
    }
}

void
linebuf::add (const char *what, int len)
{
  size_t newix = ix + len;
  if (newix >= alloced || !buf)
    {
      alloced += LINE_BUF_CHUNK + newix;
      buf = (char *) realloc (buf, alloced + 1);
    }
  memcpy (buf + ix, what, len);
  ix = newix;
  buf[ix] = '\0';
}

void
linebuf::prepend (const char *what, int len)
{
  int buflen;
  size_t newix;
  if ((newix = ix + len) >= alloced)
    {
      alloced += LINE_BUF_CHUNK + newix;
      buf = (char *) realloc (buf, alloced + 1);
      buf[ix] = '\0';
    }
  if ((buflen = strlen (buf)))
      memmove (buf + len, buf, buflen + 1);
  else
      buf[newix] = '\0';
  memcpy (buf, what, len);
  ix = newix;
}

class av
{
  char **argv;
  int calloced;
 public:
  int argc;
  bool win16_exe;
  bool iscui;
  av (): argv (NULL), iscui (false) {}
  av (int ac_in, const char * const *av_in) : calloced (0), argc (ac_in), win16_exe (false), iscui (false)
  {
    argv = (char **) cmalloc (HEAP_1_ARGV, (argc + 5) * sizeof (char *));
    memcpy (argv, av_in, (argc + 1) * sizeof (char *));
  }
  void *operator new (size_t, void *p) __attribute__ ((nothrow)) {return p;}
  void set (int ac_in, const char * const *av_in) {new (this) av (ac_in, av_in);}
  ~av ()
  {
    if (argv)
      {
	for (int i = 0; i < calloced; i++)
	  if (argv[i])
	    cfree (argv[i]);
	cfree (argv);
      }
  }
  int unshift (const char *what, int conv = 0);
  operator char **() {return argv;}
  void all_calloced () {calloced = argc;}
  void replace0_maybe (const char *arg0)
  {
    /* Note: Assumes that argv array has not yet been "unshifted" */
    if (!calloced)
      {
	argv[0] = cstrdup1 (arg0);
	calloced = true;
      }
  }
  void dup_maybe (int i)
  {
    if (i >= calloced)
      argv[i] = cstrdup1 (argv[i]);
  }
  void dup_all ()
  {
    for (int i = calloced; i < argc; i++)
      argv[i] = cstrdup1 (argv[i]);
  }
  int fixup (const char *, path_conv&, const char *);
};

int
av::unshift (const char *what, int conv)
{
  char **av;
  av = (char **) crealloc (argv, (argc + 2) * sizeof (char *));
  if (!av)
    return 0;

  argv = av;
  memmove (argv + 1, argv, (argc + 1) * sizeof (char *));
  char buf[CYG_MAX_PATH];
  if (conv)
    {
      cygwin_conv_to_posix_path (what, buf);
      char *p = strchr (buf, '\0') - 4;
      if (p > buf && strcasematch (p, ".exe"))
	*p = '\0';
      what = buf;
    }
  *argv = cstrdup1 (what);
  calloced++;
  argc++;
  return 1;
}

struct pthread_cleanup
{
  _sig_func_ptr oldint;
  _sig_func_ptr oldquit;
  sigset_t oldmask;
  pthread_cleanup (): oldint (NULL), oldquit (NULL), oldmask ((sigset_t) -1) {}
};

static void
do_cleanup (void *args)
{
# define cleanup ((pthread_cleanup *) args)
  if (cleanup->oldmask != (sigset_t) -1)
    {
      signal (SIGINT, cleanup->oldint);
      signal (SIGQUIT, cleanup->oldquit);
      sigprocmask (SIG_SETMASK, &(cleanup->oldmask), NULL);
    }
# undef cleanup
}


static int __stdcall
spawn_guts (const char * prog_arg, const char *const *argv,
	    const char *const envp[], int mode)
{
  bool rc;
  pid_t cygpid;
  int res = -1;

  if (prog_arg == NULL)
    {
      syscall_printf ("prog_arg is NULL");
      set_errno (EINVAL);
      return -1;
    }

  syscall_printf ("spawn_guts (%d, %.9500s)", mode, prog_arg);

  if (argv == NULL)
    {
      syscall_printf ("argv is NULL");
      set_errno (EINVAL);
      return -1;
    }

  /* FIXME: There is a small race here and FIXME: not thread safe! */

  pthread_cleanup cleanup;
  if (mode == _P_SYSTEM)
    {
      sigset_t child_block;
      cleanup.oldint = signal (SIGINT, SIG_IGN);
      cleanup.oldquit = signal (SIGQUIT, SIG_IGN);
      sigemptyset (&child_block);
      sigaddset (&child_block, SIGCHLD);
      sigprocmask (SIG_BLOCK, &child_block, &cleanup.oldmask);
    }
  pthread_cleanup_push (do_cleanup, (void *) &cleanup);
  av newargv;
  linebuf one_line;
  child_info_spawn ch;

  char *envblock = NULL;
  path_conv real_path;
  bool reset_sendsig = false;

  bool null_app_name = false;
  STARTUPINFO si = {0, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL};
  int looped = 0;
  HANDLE orig_wr_proc_pipe = NULL;

  myfault efault;
  if (efault.faulted ())
    {
      if (get_errno () == ENOMEM)
	set_errno (E2BIG);
      else
	set_errno (EFAULT);
      res = -1;
      goto out;
    }

  child_info_types chtype;
  if (mode != _P_OVERLAY)
    chtype = PROC_SPAWN;
  else
    chtype = PROC_EXEC;

  cygheap_exec_info *moreinfo = (cygheap_exec_info *) ccalloc (HEAP_1_EXEC, 1, sizeof (cygheap_exec_info));
  moreinfo->old_title = NULL;

  /* CreateProcess takes one long string that is the command line (sigh).
     We need to quote any argument that has whitespace or embedded "'s.  */

  int ac;
  for (ac = 0; argv[ac]; ac++)
    /* nothing */;

  newargv.set (ac, argv);

  int err;
  const char *ext;
  if ((ext = perhaps_suffix (prog_arg, real_path, err, FE_NADA)) == NULL)
    {
      set_errno (err);
      res = -1;
      goto out;
    }

  bool wascygexec = real_path.iscygexec ();
  res = newargv.fixup (prog_arg, real_path, ext);

  if (res)
    goto out;

  if (ac == 3 && argv[1][0] == '/' && argv[1][1] == 'c' &&
      (iscmd (argv[0], "command.com") || iscmd (argv[0], "cmd.exe")))
    {
      real_path.check (prog_arg);
      one_line.add ("\"");
      if (!real_path.error)
	one_line.add (real_path);
      else
	one_line.add (argv[0]);
      one_line.add ("\"");
      one_line.add (" ");
      one_line.add (argv[1]);
      one_line.add (" ");
      one_line.add (argv[2]);
      strcpy (real_path, argv[0]);
      null_app_name = true;
    }
  else
    {
      if (wascygexec)
	newargv.dup_all ();
      else
	{
	  for (int i = 0; i < newargv.argc; i++)
	    {
	      char *p = NULL;
	      const char *a;

	      newargv.dup_maybe (i);
	      a = i ? newargv[i] : (char *) real_path;
	      int len = strlen (a);
	      if (len != 0 && !strpbrk (a, " \t\n\r\""))
		one_line.add (a, len);
	      else
		{
		  one_line.add ("\"", 1);
		  /* Handle embedded special characters " and \.
		     A " is always preceded by a \.
		     A \ is not special unless it precedes a ".  If it does,
		     then all preceding \'s must be doubled to avoid having
		     the Windows command line parser interpret the \ as quoting
		     the ".  This rule applies to a string of \'s before the end
		     of the string, since cygwin/windows uses a " to delimit the
		     argument. */
		  for (; (p = strpbrk (a, "\"\\")); a = ++p)
		    {
		      one_line.add (a, p - a);
		      /* Find length of string of backslashes */
		      int n = strspn (p, "\\");
		      if (!n)
			one_line.add ("\\\"", 2);	/* No backslashes, so it must be a ".
						       The " has to be protected with a backslash. */
		      else
			{
			  one_line.add (p, n);	/* Add the run of backslashes */
			  /* Need to double up all of the preceding
			     backslashes if they precede a quote or EOS. */
			  if (!p[n] || p[n] == '"')
			    one_line.add (p, n);
			  p += n - 1;		/* Point to last backslash */
			}
		    }
		  if (*a)
		    one_line.add (a);
		  one_line.add ("\"", 1);
		}
	      one_line.add (" ", 1);
	    }

	  one_line.finish (real_path.iscygexec ());

	  if (one_line.ix >= MAXWINCMDLEN)
	    {
	      debug_printf ("command line too long (>32K), return E2BIG");
	      set_errno (E2BIG);
	      res = -1;
	      goto out;
	    }
	}

      newargv.all_calloced ();
      moreinfo->argc = newargv.argc;
      moreinfo->argv = newargv;

      if (mode != _P_OVERLAY ||
	  !DuplicateHandle (hMainProc, myself.shared_handle (), hMainProc,
			    &moreinfo->myself_pinfo, 0,
			    TRUE, DUPLICATE_SAME_ACCESS))
	moreinfo->myself_pinfo = NULL;
      else
	VerifyHandle (moreinfo->myself_pinfo);
    }

  PROCESS_INFORMATION pi;
  pi.hProcess = pi.hThread = NULL;
  pi.dwProcessId = pi.dwThreadId = 0;
  si.lpReserved = NULL;
  si.lpDesktop = NULL;
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = handle (0, 0); /* Get input handle */
  si.hStdOutput = handle (1, 1); /* Get output handle */
  si.hStdError = handle (2, 1); /* Get output handle */
  si.cb = sizeof (si);
  if (!wincap.pty_needs_alloc_console () && newargv.iscui && myself->ctty == -1)
    {
      si.dwFlags |= STARTF_USESHOWWINDOW;
      si.wShowWindow = SW_HIDE;
    }

  int flags = GetPriorityClass (hMainProc);
  sigproc_printf ("priority class %d", flags);
  flags |= CREATE_SEPARATE_WOW_VDM;

  if (mode == _P_DETACH)
    flags |= DETACHED_PROCESS;

  if (mode != _P_OVERLAY)
    myself->exec_sendsig = NULL;
  else
    {
      /* Reset sendsig so that any process which wants to send a signal
	 to this pid will wait for the new process to become active.
	 Save the old value in case the exec fails.  */
      if (!myself->exec_sendsig)
	{
	  myself->exec_sendsig = myself->sendsig;
	  myself->exec_dwProcessId = myself->dwProcessId;
	  myself->sendsig = NULL;
	  reset_sendsig = true;
	}
      /* Save a copy of a handle to the current process around the first time we
	 exec so that the pid will not be reused.  Why did I stop cygwin from
	 generating its own pids again? */
      if (cygheap->pid_handle)
	/* already done previously */;
      else if (DuplicateHandle (hMainProc, hMainProc, hMainProc, &cygheap->pid_handle,
				PROCESS_QUERY_INFORMATION, TRUE, 0))
	ProtectHandle (cygheap->pid_handle);
      else
	system_printf ("duplicate to pid_handle failed, %E");
      if (mode != _P_DETACH)
	set_console_state_for_spawn (real_path.iscygexec ());
    }

  /* Some file types (currently only sockets) need extra effort in the parent
     after CreateProcess and before copying the datastructures to the child.
     So we have to start the child in suspend state, unfortunately, to avoid
     a race condition. */
  if (!newargv.win16_exe
      && (wincap.start_proc_suspended () || mode != _P_OVERLAY
	  || cygheap->fdtab.need_fixup_before ()))
    flags |= CREATE_SUSPENDED;

  const char *runpath = null_app_name ? NULL : (const char *) real_path;

  syscall_printf ("null_app_name %d (%s, %.9500s)", null_app_name, runpath, one_line.buf);

  cygbench ("spawn-guts");

  cygheap->fdtab.set_file_pointers_for_exec ();

  moreinfo->envp = build_env (envp, envblock, moreinfo->envc, real_path.iscygexec ());
  if (!moreinfo->envp || !envblock)
    {
      set_errno (E2BIG);
      res = -1;
      goto out;
    }
  ch.set (chtype, real_path.iscygexec ());
  ch.moreinfo = moreinfo;

  si.lpReserved2 = (LPBYTE) &ch;
  si.cbReserved2 = sizeof (ch);

  /* When ruid != euid we create the new process under the current original
     account and impersonate in child, this way maintaining the different
     effective vs. real ids.
     FIXME: If ruid != euid and ruid != saved_uid we currently give
     up on ruid. The new process will have ruid == euid. */
loop:
  cygheap->user.deimpersonate ();

  if (!cygheap->user.issetuid ()
      || (cygheap->user.saved_uid == cygheap->user.real_uid
	  && cygheap->user.saved_gid == cygheap->user.real_gid
	  && !cygheap->user.groups.issetgroups ()))
    {
      rc = CreateProcess (runpath,	/* image name - with full path */
			  one_line.buf,	/* what was passed to exec */
			  &sec_none_nih,/* process security attrs */
			  &sec_none_nih,/* thread security attrs */
			  TRUE,		/* inherit handles from parent */
			  flags,
			  envblock,	/* environment */
			  0,		/* use current drive/directory */
			  &si,
			  &pi);
    }
  else
    {
      /* Give access to myself */
      if (mode == _P_OVERLAY)
	myself.set_acl();

      /* allow the child to interact with our window station/desktop */
      HANDLE hwst, hdsk;
      SECURITY_INFORMATION dsi = DACL_SECURITY_INFORMATION;
      DWORD n;
      char wstname[1024];
      char dskname[1024];

      hwst = GetProcessWindowStation ();
      SetUserObjectSecurity (hwst, &dsi, get_null_sd ());
      GetUserObjectInformation (hwst, UOI_NAME, wstname, 1024, &n);
      hdsk = GetThreadDesktop (GetCurrentThreadId ());
      SetUserObjectSecurity (hdsk, &dsi, get_null_sd ());
      GetUserObjectInformation (hdsk, UOI_NAME, dskname, 1024, &n);
      strcat (wstname, "\\");
      strcat (wstname, dskname);
      si.lpDesktop = wstname;

      rc = CreateProcessAsUser (cygheap->user.primary_token (),
		       runpath,		/* image name - with full path */
		       one_line.buf,	/* what was passed to exec */
		       &sec_none_nih,   /* process security attrs */
		       &sec_none_nih,   /* thread security attrs */
		       TRUE,		/* inherit handles from parent */
		       flags,
		       envblock,	/* environment */
		       0,		/* use current drive/directory */
		       &si,
		       &pi);
    }

  /* Restore impersonation. In case of _P_OVERLAY this isn't
     allowed since it would overwrite child data. */
  if (mode != _P_OVERLAY || !rc)
    cygheap->user.reimpersonate ();

  /* Set errno now so that debugging messages from it appear before our
     final debugging message [this is a general rule for debugging
     messages].  */
  if (!rc)
    {
      __seterrno ();
      syscall_printf ("CreateProcess failed, %E");
      /* If this was a failed exec, restore the saved sendsig. */
      if (reset_sendsig)
	{
	  myself->sendsig = myself->exec_sendsig;
	  myself->exec_sendsig = NULL;
	}
      res = -1;
      if (moreinfo->myself_pinfo)
	CloseHandle (moreinfo->myself_pinfo);
      goto out;
    }

  if (!(flags & CREATE_SUSPENDED))
    strace.write_childpid (ch, pi.dwProcessId);

  /* Fixup the parent data structures if needed and resume the child's
     main thread. */
  if (cygheap->fdtab.need_fixup_before ())
    cygheap->fdtab.fixup_before_exec (pi.dwProcessId);

  if (mode != _P_OVERLAY)
    cygpid = cygwin_pid (pi.dwProcessId);
  else
    cygpid = myself->pid;

  /* We print the original program name here so the user can see that too.  */
  syscall_printf ("%d = spawn_guts (%s, %.9500s)",
		  rc ? cygpid : (unsigned int) -1, prog_arg, one_line.buf);

  /* Name the handle similarly to proc_subproc. */
  ProtectHandle1 (pi.hProcess, childhProc);

  bool synced;
  pid_t pid;
  if (mode == _P_OVERLAY)
    {
      myself->dwProcessId = dwExeced = pi.dwProcessId;
      strace.execing = 1;
      myself.hProcess = hExeced = pi.hProcess;
      strcpy (myself->progname, real_path); // FIXME: race?
      sigproc_printf ("new process name %s", myself->progname);
      /* If wr_proc_pipe doesn't exist then this process was not started by a cygwin
	 process.  So, we need to wait around until the process we've just "execed"
	 dies.  Use our own wait facility to wait for our own pid to exit (there
	 is some minor special case code in proc_waiter and friends to accommodate
	 this).

	 If wr_proc_pipe exists, then it should be duplicated to the child.
	 If the child has exited already, that's ok.  The parent will pick up
	 on this fact when we exit.  dup_proc_pipe will close our end of the pipe.
	 Note that wr_proc_pipe may also be == INVALID_HANDLE_VALUE.  That will make
	 dup_proc_pipe essentially a no-op.  */
      if (!newargv.win16_exe && myself->wr_proc_pipe)
	{
	  if (!looped)
	    {
	      myself->sync_proc_pipe ();	/* Make sure that we own wr_proc_pipe
						   just in case we've been previously
						   execed. */
	      myself.zap_cwd ();
	    }
	  orig_wr_proc_pipe = myself->dup_proc_pipe (pi.hProcess);
	}
      pid = myself->pid;
    }
  else
    {
      myself->set_has_pgid_children ();
      ProtectHandle (pi.hThread);
      pinfo child (cygpid, PID_IN_USE);
      if (!child)
	{
	  syscall_printf ("pinfo failed");
	  if (get_errno () != ENOMEM)
	    set_errno (EAGAIN);
	  res = -1;
	  goto out;
	}
      child->dwProcessId = pi.dwProcessId;
      child.hProcess = pi.hProcess;

      strcpy (child->progname, real_path);
      /* FIXME: This introduces an unreferenced, open handle into the child.
	 The purpose is to keep the pid shared memory open so that all of
	 the fields filled out by child.remember do not disappear and so there
	 is not a brief period during which the pid is not available.
	 However, we should try to find another way to do this eventually. */
      DuplicateHandle (hMainProc, child.shared_handle (), pi.hProcess,
			      NULL, 0, 0, DUPLICATE_SAME_ACCESS);
      child->start_time = time (NULL); /* Register child's starting time. */
      child->nice = myself->nice;
      if (!child.remember (mode == _P_DETACH))
	{
	  /* FIXME: Child in strange state now */
	  CloseHandle (pi.hProcess);
	  ForceCloseHandle (pi.hThread);
	  res = -1;
	  goto out;
	}
      pid = child->pid;
    }

  /* Start the child running */
  if (flags & CREATE_SUSPENDED)
    {
      ResumeThread (pi.hThread);
      strace.write_childpid (ch, pi.dwProcessId);
    }
  ForceCloseHandle (pi.hThread);

  sigproc_printf ("spawned windows pid %d", pi.dwProcessId);

  synced = ch.sync (pi.dwProcessId, pi.hProcess, INFINITE);

  switch (mode)
    {
    case _P_OVERLAY:
      myself.hProcess = pi.hProcess;
      if (!synced)
	{
	  if (orig_wr_proc_pipe)
	    {
	      myself->wr_proc_pipe_owner = GetCurrentProcessId ();
	      myself->wr_proc_pipe = orig_wr_proc_pipe;
	    }
	  DWORD res = ch.proc_retry (pi.hProcess);
	  if (!res)
	    {
	      looped++;
	      goto loop;
	    }
	  close_all_files (true);
	}
      else
	{
	  close_all_files (true);
	  if (!myself->wr_proc_pipe
	      && WaitForSingleObject (pi.hProcess, 0) == WAIT_TIMEOUT)
	    {
	      extern bool is_toplevel_proc;
	      is_toplevel_proc = true;
	      myself.remember (false);
	      waitpid (myself->pid, &res, 0);
	    }
	}
      myself.exit (EXITCODE_NOSET);
      break;
    case _P_WAIT:
    case _P_SYSTEM:
      if (waitpid (cygpid, &res, 0) != cygpid)
	res = -1;
      break;
    case _P_DETACH:
      res = 0;	/* Lost all memory of this child. */
      break;
    case _P_NOWAIT:
    case _P_NOWAITO:
    case _P_VFORK:
      res = cygpid;
      break;
    default:
      break;
    }

out:
  if (envblock)
    free (envblock);
  pthread_cleanup_pop (1);
  return (int) res;
}

extern "C" int
cwait (int *result, int pid, int)
{
  return waitpid (pid, result, 0);
}

/*
* Helper function for spawn runtime calls.
* Doesn't search the path.
*/

extern "C" int
spawnve (int mode, const char *path, const char *const *argv,
       const char *const *envp)
{
  int ret;
#ifdef NEWVFORK
  vfork_save *vf = vfork_storage.val ();

  if (vf != NULL && (vf->pid < 0) && mode == _P_OVERLAY)
    mode = _P_NOWAIT;
  else
    vf = NULL;
#endif

  syscall_printf ("spawnve (%s, %s, %x)", path, argv[0], envp);

  switch (mode)
    {
    case _P_OVERLAY:
      /* We do not pass _P_SEARCH_PATH here. execve doesn't search PATH.*/
      /* Just act as an exec if _P_OVERLAY set. */
      spawn_guts (path, argv, envp, mode);
      /* Errno should be set by spawn_guts.  */
      ret = -1;
      break;
    case _P_VFORK:
    case _P_NOWAIT:
    case _P_NOWAITO:
    case _P_WAIT:
    case _P_DETACH:
    case _P_SYSTEM:
      ret = spawn_guts (path, argv, envp, mode);
#ifdef NEWVFORK
      if (vf)
	{
	  if (ret > 0)
	    {
	      debug_printf ("longjmping due to vfork");
	      vf->restore_pid (ret);
	    }
	}
#endif
      break;
    default:
      set_errno (EINVAL);
      ret = -1;
      break;
    }
  return ret;
}

/*
* spawn functions as implemented in the MS runtime library.
* Most of these based on (and copied from) newlib/libc/posix/execXX.c
*/

extern "C" int
spawnl (int mode, const char *path, const char *arg0, ...)
{
  int i;
  va_list args;
  const char *argv[256];

  va_start (args, arg0);
  argv[0] = arg0;
  i = 1;

  do
      argv[i] = va_arg (args, const char *);
  while (argv[i++] != NULL);

  va_end (args);

  return spawnve (mode, path, (char * const  *) argv, cur_environ ());
}

extern "C" int
spawnle (int mode, const char *path, const char *arg0, ...)
{
  int i;
  va_list args;
  const char * const *envp;
  const char *argv[256];

  va_start (args, arg0);
  argv[0] = arg0;
  i = 1;

  do
    argv[i] = va_arg (args, const char *);
  while (argv[i++] != NULL);

  envp = va_arg (args, const char * const *);
  va_end (args);

  return spawnve (mode, path, (char * const *) argv, (char * const *) envp);
}

extern "C" int
spawnlp (int mode, const char *path, const char *arg0, ...)
{
  int i;
  va_list args;
  const char *argv[256];

  va_start (args, arg0);
  argv[0] = arg0;
  i = 1;

  do
      argv[i] = va_arg (args, const char *);
  while (argv[i++] != NULL);

  va_end (args);

  return spawnvpe (mode, path, (char * const *) argv, cur_environ ());
}

extern "C" int
spawnlpe (int mode, const char *path, const char *arg0, ...)
{
  int i;
  va_list args;
  const char * const *envp;
  const char *argv[256];

  va_start (args, arg0);
  argv[0] = arg0;
  i = 1;

  do
    argv[i] = va_arg (args, const char *);
  while (argv[i++] != NULL);

  envp = va_arg (args, const char * const *);
  va_end (args);

  return spawnvpe (mode, path, (char * const *) argv, envp);
}

extern "C" int
spawnv (int mode, const char *path, const char * const *argv)
{
  return spawnve (mode, path, argv, cur_environ ());
}

extern "C" int
spawnvp (int mode, const char *path, const char * const *argv)
{
  return spawnvpe (mode, path, argv, cur_environ ());
}

extern "C" int
spawnvpe (int mode, const char *file, const char * const *argv,
					   const char * const *envp)
{
  path_conv buf;
  return spawnve (mode, find_exec (file, buf), argv, envp);
}

int
av::fixup (const char *prog_arg, path_conv& real_path, const char *ext)
{
  const char *p;
  bool exeext = strcasematch (ext, ".exe");
  if (exeext && real_path.iscygexec () || strcasematch (ext, ".bat"))
    return 0;
  if (!*ext && ((p = ext - 4) > (char *) real_path)
      && (strcasematch (p, ".bat") || strcasematch (p, ".cmd")
	  || strcasematch (p, ".btm")))
    return 0;
  while (1)
    {
      char *pgm = NULL;
      char *arg1 = NULL;

      HANDLE h = CreateFile (real_path, GENERIC_READ,
			       FILE_SHARE_READ | FILE_SHARE_WRITE,
			       &sec_none_nih, OPEN_EXISTING,
			       FILE_ATTRIBUTE_NORMAL, 0);
      if (h == INVALID_HANDLE_VALUE)
	goto err;

      HANDLE hm = CreateFileMapping (h, &sec_none_nih, PAGE_READONLY, 0, 0, NULL);
      CloseHandle (h);
      if (!hm)
        {
	  /* ERROR_FILE_INVALID indicates very likely an empty file. */
	  if (GetLastError () == ERROR_FILE_INVALID)
	    {
	      debug_printf ("zero length file, treat as script.");
	      goto just_shell;
	    }
	  goto err;
	}
      char *buf = (char *) MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
      CloseHandle (hm);
      if (!buf)
	goto err;

      {
	myfault efault;
	if (efault.faulted ())
	  {
	    UnmapViewOfFile (buf);
	    real_path.set_cygexec (false);
	    break;
	  }
	if (buf[0] == 'M' && buf[1] == 'Z')
	  {
	    WORD subsys;
	    unsigned off = (unsigned char) buf[0x18] | (((unsigned char) buf[0x19]) << 8);
	    win16_exe = off < sizeof (IMAGE_DOS_HEADER);
	    if (!win16_exe)
	      real_path.set_cygexec (!!hook_or_detect_cygwin (buf, NULL, subsys));
	    else
	      real_path.set_cygexec (false);
	    UnmapViewOfFile (buf);
	    iscui = subsys == IMAGE_SUBSYSTEM_WINDOWS_CUI;
	    break;
	  }
      }

      debug_printf ("%s is possibly a script", (char *) real_path);

      char *ptr = buf;
      if (*ptr++ == '#' && *ptr++ == '!')
	{
	  ptr += strspn (ptr, " \t");
	  size_t len = strcspn (ptr, "\r\n");
	  if (len)
	    {
	      char *namebuf = (char *) alloca (len + 1);
	      memcpy (namebuf, ptr, len);
	      namebuf[len] = '\0';
	      for (ptr = pgm = namebuf; *ptr; ptr++)
		if (!arg1 && (*ptr == ' ' || *ptr == '\t'))
		  {
		    /* Null terminate the initial command and step over any additional white
		       space.  If we've hit the end of the line, exit the loop.  Otherwise,
		       we've found the first argument. Position the current pointer on the
		       last known white space. */
		    *ptr = '\0';
		    char *newptr = ptr + 1;
		    newptr += strspn (newptr, " \t");
		    if (!*newptr)
		      break;
		    arg1 = newptr;
		    ptr = newptr - 1;
		  }
	    }
	}
      UnmapViewOfFile (buf);
just_shell:
      if (!pgm)
	{
	  if (strcasematch (ext, ".com"))
	    break;
	  pgm = (char *) "/bin/sh";
	  arg1 = NULL;
	}

      /* Replace argv[0] with the full path to the script if this is the
	 first time through the loop. */
      replace0_maybe (prog_arg);

      /* pointers:
       * pgm	interpreter name
       * arg1	optional string
       */
      if (arg1)
	unshift (arg1);

      /* FIXME: This should not be using FE_NATIVE.  It should be putting
	 the posix path on the argv list. */
      find_exec (pgm, real_path, "PATH=", FE_NATIVE, &ext);
      unshift (real_path, 1);
    }
  return 0;

err:
  __seterrno ();
  return -1;
}
