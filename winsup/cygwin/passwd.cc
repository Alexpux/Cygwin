/* passwd.cc: getpwnam () and friends

   Copyright 1996, 1997, 1998 Cygnus Solutions.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <stdlib.h>
#include <pwd.h>
#include <stdio.h>
#include <errno.h>
#include "cygerrno.h"
#include "security.h"
#include "fhandler.h"
#include "dtable.h"
#include "path.h"
#include "sync.h"
#include "sigproc.h"
#include "pinfo.h"
#include "cygheap.h"
#include <sys/termios.h>

/* Read /etc/passwd only once for better performance.  This is done
   on the first call that needs information from it. */

static struct passwd *passwd_buf = NULL;	/* passwd contents in memory */
static int curr_lines = 0;
static int max_lines = 0;

/* Set to loaded when /etc/passwd has been read in by read_etc_passwd ().
   Set to emulated if passwd is emulated. */
/* Functions in this file need to check the value of passwd_state
   and read in the password file if it isn't set. */
enum pwd_state {
  uninitialized = 0,
  initializing,
  emulated,
  loaded
};
class pwd_check {
  pwd_state state;
  FILETIME  last_modified;
  char	    pwd_w32[MAX_PATH];

public:
  pwd_check () : state (uninitialized)
    {
      last_modified.dwLowDateTime = last_modified.dwHighDateTime = 0;
      pwd_w32[0] = '\0';
    }
  operator pwd_state ()
    {
      HANDLE h;
      WIN32_FIND_DATA data;

      if (!pwd_w32[0])	/* First call. */
	{
	  path_conv p ("/etc/passwd", PC_SYM_FOLLOW | PC_FULL);
	  if (!p.error)
	    strcpy (pwd_w32, p.get_win32 ());
	}

      if ((h = FindFirstFile (pwd_w32, &data)) != INVALID_HANDLE_VALUE)
	{
	  if (CompareFileTime (&data.ftLastWriteTime, &last_modified) > 0)
	    {
	      state = uninitialized;
	      last_modified = data.ftLastWriteTime;
	    }
	  FindClose (h);
        }
      return state;
    }
  void operator = (pwd_state nstate)
    {
      state = nstate;
    }
};

static pwd_check passwd_state;


/* Position in the passwd cache */
#ifdef _MT_SAFE
#define pw_pos  _reent_winsup ()->_pw_pos
#else
static int pw_pos = 0;
#endif

/* Remove a : teminated string from the buffer, and increment the pointer */
static char *
grab_string (char **p)
{
  char *src = *p;
  char *res = src;

  while (*src && *src != ':' && *src != '\n')
    src++;

  if (*src == ':')
    {
      *src = 0;
      src++;
    }
  *p = src;
  return res;
}

/* same, for ints */
static int
grab_int (char **p)
{
  char *src = *p;
  int val = strtol (src, NULL, 10);
  while (*src && *src != ':' && *src != '\n')
    src++;
  if (*src == ':')
    src++;
  *p = src;
  return val;
}

/* Parse /etc/passwd line into passwd structure. */
void
parse_pwd (struct passwd &res, char *buf)
{
  /* Allocate enough room for the passwd struct and all the strings
     in it in one go */
  size_t len = strlen (buf);
  char *mybuf = (char *) malloc (len + 1);
  (void) memcpy (mybuf, buf, len + 1);
  if (mybuf[--len] == '\n')
    mybuf[len] = '\0';

  res.pw_name = grab_string (&mybuf);
  res.pw_passwd = grab_string (&mybuf);
  res.pw_uid = grab_int (&mybuf);
  res.pw_gid = grab_int (&mybuf);
  res.pw_comment = 0;
  res.pw_gecos = grab_string (&mybuf);
  res.pw_dir =  grab_string (&mybuf);
  res.pw_shell = grab_string (&mybuf);
}

/* Add one line from /etc/passwd into the password cache */
static void
add_pwd_line (char *line)
{
    if (curr_lines >= max_lines)
      {
	max_lines += 10;
	passwd_buf = (struct passwd *) realloc (passwd_buf, max_lines * sizeof (struct passwd));
      }
    parse_pwd (passwd_buf[curr_lines++], line);
}

/* Read in /etc/passwd and save contents in the password cache.
   This sets passwd_state to loaded or emulated so functions in this file can
   tell that /etc/passwd has been read in or will be emulated. */
void
read_etc_passwd ()
{
    char linebuf[1024];
    /* A mutex is ok for speed here - pthreads will use critical sections not mutex's
     * for non-shared mutexs in the future. Also, this function will at most be called
     * once from each thread, after that the passwd_state test will succeed
     */
    static NO_COPY pthread_mutex_t etc_passwd_mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock (&etc_passwd_mutex);

    /* if we got blocked by the mutex, then etc_passwd may have been processed */
    if (passwd_state != uninitialized)
      {
	pthread_mutex_unlock(&etc_passwd_mutex);
	return;
      }

    if (passwd_state != initializing)
      {
	passwd_state = initializing;
	if (max_lines) /* When rereading, free allocated memory first. */
	  {
	    for (int i = 0; i < curr_lines; ++i)
	      free (passwd_buf[i].pw_name);
	    free (passwd_buf);
	    curr_lines = max_lines = 0;
	  }

	FILE *f = fopen ("/etc/passwd", "rt");

	if (f)
	  {
	    while (fgets (linebuf, sizeof (linebuf), f) != NULL)
	      {
		if (strlen (linebuf))
		  add_pwd_line (linebuf);
	      }

	    fclose (f);
	    passwd_state = loaded;
	  }
	else
	  {
	    debug_printf ("Emulating /etc/passwd");
	    snprintf (linebuf, sizeof (linebuf), "%s::%u:%u::%s:/bin/sh", cygheap->user.name (),
		      DEFAULT_UID, DEFAULT_GID, getenv ("HOME") ?: "/");
	    add_pwd_line (linebuf);
	    passwd_state = emulated;
	  }

      }

  pthread_mutex_unlock (&etc_passwd_mutex);
}

/* Cygwin internal */
/* If this ever becomes non-reentrant, update all the getpw*_r functions */
static struct passwd *
search_for (uid_t uid, const char *name)
{
  struct passwd *res = 0;
  struct passwd *default_pw = 0;

  for (int i = 0; i < curr_lines; i++)
    {
      res = passwd_buf + i;
      if (res->pw_uid == DEFAULT_UID)
	default_pw = res;
      /* on Windows NT user names are case-insensitive */
      if (name)
	{
	  if (strcasematch (name, res->pw_name))
	    return res;
	}
      else if (uid == res->pw_uid)
	return res;
    }

  /* Return default passwd entry if passwd is emulated or it's a
     request for the current user. */
  if (passwd_state != loaded
      || (!name && uid == myself->uid)
      || (name && strcasematch (name, cygheap->user.name ())))
    return default_pw;

  return NULL;
}

extern "C" struct passwd *
getpwuid (uid_t uid)
{
  if (passwd_state  <= initializing)
    read_etc_passwd ();

  pthread_testcancel();

  return search_for (uid, 0);
}

extern "C" int
getpwuid_r (uid_t uid, struct passwd *pwd, char *buffer, size_t bufsize, struct passwd **result)
{
  *result = NULL;

  if (!pwd || !buffer)
    return ERANGE;

  if (passwd_state  <= initializing)
    read_etc_passwd ();

  pthread_testcancel();

  struct passwd *temppw = search_for (uid, 0);

  if (!temppw)
    return 0;

  /* check needed buffer size. */
  size_t needsize = strlen (temppw->pw_name) + strlen (temppw->pw_dir) +
		    strlen (temppw->pw_shell) + strlen (temppw->pw_gecos) +
		    strlen (temppw->pw_passwd) + 5;
  if (needsize > bufsize)
    return ERANGE;

  /* make a copy of temppw */
  *result = pwd;
  pwd->pw_uid = temppw->pw_uid;
  pwd->pw_gid = temppw->pw_gid;
  pwd->pw_name = buffer;
  pwd->pw_dir = pwd->pw_name + strlen (temppw->pw_name) + 1;
  pwd->pw_shell = pwd->pw_dir + strlen (temppw->pw_dir) + 1;
  pwd->pw_gecos = pwd->pw_shell + strlen (temppw->pw_shell) + 1;
  pwd->pw_passwd = pwd->pw_gecos + strlen (temppw->pw_gecos) + 1;
  strcpy (pwd->pw_name, temppw->pw_name);
  strcpy (pwd->pw_dir, temppw->pw_dir);
  strcpy (pwd->pw_shell, temppw->pw_shell);
  strcpy (pwd->pw_gecos, temppw->pw_gecos);
  strcpy (pwd->pw_passwd, temppw->pw_passwd);
  return 0;
}

extern "C" struct passwd *
getpwnam (const char *name)
{
  if (passwd_state  <= initializing)
    read_etc_passwd ();

  pthread_testcancel();

  return search_for (0, name);
}


/* the max size buffer we can expect to
 * use is returned via sysconf with _SC_GETPW_R_SIZE_MAX.
 * This may need updating! - Rob Collins April 2001.
 */
extern "C" int
getpwnam_r (const char *nam, struct passwd *pwd, char *buffer, size_t bufsize, struct passwd **result)
{
  *result = NULL;

  if (!pwd || !buffer || !nam)
    return ERANGE;

  if (passwd_state  <= initializing)
    read_etc_passwd ();

  pthread_testcancel();

  struct passwd *temppw = search_for (0, nam);

  if (!temppw)
    return 0;

  /* check needed buffer size. */
  size_t needsize = strlen (temppw->pw_name) + strlen (temppw->pw_dir) +
		    strlen (temppw->pw_shell) + strlen (temppw->pw_gecos) +
		    strlen (temppw->pw_passwd) + 5;
  if (needsize > bufsize)
    return ERANGE;

  /* make a copy of temppw */
  *result = pwd;
  pwd->pw_uid = temppw->pw_uid;
  pwd->pw_gid = temppw->pw_gid;
  pwd->pw_name = buffer;
  pwd->pw_dir = pwd->pw_name + strlen (temppw->pw_name) + 1;
  pwd->pw_shell = pwd->pw_dir + strlen (temppw->pw_dir) + 1;
  pwd->pw_gecos = pwd->pw_shell + strlen (temppw->pw_shell) + 1;
  pwd->pw_passwd = pwd->pw_gecos + strlen (temppw->pw_gecos) + 1;
  strcpy (pwd->pw_name, temppw->pw_name);
  strcpy (pwd->pw_dir, temppw->pw_dir);
  strcpy (pwd->pw_shell, temppw->pw_shell);
  strcpy (pwd->pw_gecos, temppw->pw_gecos);
  strcpy (pwd->pw_passwd, temppw->pw_passwd);
  return 0;
}

extern "C" struct passwd *
getpwent (void)
{
  if (passwd_state  <= initializing)
    read_etc_passwd ();

  if (pw_pos < curr_lines)
    return passwd_buf + pw_pos++;

  return NULL;
}

extern "C" struct passwd *
getpwduid (uid_t)
{
  return NULL;
}

extern "C" void
setpwent (void)
{
  pw_pos = 0;
}

extern "C" void
endpwent (void)
{
  pw_pos = 0;
}

extern "C" int
setpassent ()
{
  return 0;
}

/* Internal function. ONLY USE THIS INTERNALLY, NEVER `getpwent'!!! */
struct passwd *
internal_getpwent (int pos)
{
  if (passwd_state  <= initializing)
    read_etc_passwd ();

  if (pos < curr_lines)
    return passwd_buf + pos;
  return NULL;
}

extern "C" char *
getpass (const char * prompt)
{
#ifdef _MT_SAFE
  char *pass=_reent_winsup ()->_pass;
#else
  static char pass[_PASSWORD_LEN];
#endif
  struct termios ti, newti;

  if (passwd_state  <= initializing)
    read_etc_passwd ();

  if (cygheap->fdtab.not_open (0))
    {
      set_errno (EBADF);
      pass[0] = '\0';
    }
  else
    {
      fhandler_base *fhstdin = cygheap->fdtab[0];
      fhstdin->tcgetattr (&ti);
      newti = ti;
      newti.c_lflag &= ~ECHO;
      fhstdin->tcsetattr (TCSANOW, &newti);
      fputs (prompt, stderr);
      fgets (pass, _PASSWORD_LEN, stdin);
      fprintf (stderr, "\n");
      for (int i=0; pass[i]; i++)
	if (pass[i] == '\r' || pass[i] == '\n')
	  pass[i] = '\0';
      fhstdin->tcsetattr (TCSANOW, &ti);
    }
  return pass;
}
