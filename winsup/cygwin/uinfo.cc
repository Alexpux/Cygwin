/* uinfo.cc: user info (uid, gid, etc...)

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <pwd.h>
#include <unistd.h>
#include <winnls.h>
#include <wininet.h>
#include <utmp.h>
#include <limits.h>
#include <stdlib.h>
#include <lm.h>
#include <errno.h>
#include <sys/cygwin.h>
#include "pinfo.h"
#include "security.h"
#include "fhandler.h"
#include "path.h"
#include "dtable.h"
#include "cygerrno.h"
#include "cygheap.h"
#include "registry.h"

struct passwd *
internal_getlogin (cygheap_user &user)
{
  char buf[512];
  char username[UNLEN + 1];
  DWORD username_len = UNLEN + 1;
  struct passwd *pw = NULL;

  if (!GetUserName (username, &username_len))
    user.set_name ("unknown");
  else
    user.set_name (username);
  debug_printf ("GetUserName() = %s", user.name ());

  if (wincap.has_security ())
    {
      LPWKSTA_USER_INFO_1 wui;
      NET_API_STATUS ret;
      char *env;

      user.set_logsrv (NULL);
      /* First trying to get logon info from environment */
      if ((env = getenv ("USERNAME")) != NULL)
	user.set_name (env);
      if ((env = getenv ("USERDOMAIN")) != NULL)
	user.set_domain (env);
      if ((env = getenv ("LOGONSERVER")) != NULL)
	user.set_logsrv (env + 2); /* filter leading double backslashes */
      if (user.name () && user.domain ())
	debug_printf ("User: %s, Domain: %s, Logon Server: %s",
		      user.name (), user.domain (), user.logsrv ());
      else if (!(ret = NetWkstaUserGetInfo (NULL, 1, (LPBYTE *) &wui)))
	{
	  sys_wcstombs (buf, wui->wkui1_username, UNLEN + 1);
	  user.set_name (buf);
	  sys_wcstombs (buf, wui->wkui1_logon_server,
			INTERNET_MAX_HOST_NAME_LENGTH + 1);
	  user.set_logsrv (buf);
	  sys_wcstombs (buf, wui->wkui1_logon_domain,
			INTERNET_MAX_HOST_NAME_LENGTH + 1);
	  user.set_domain (buf);
	  NetApiBufferFree (wui);
	}
      if (!user.logsrv () && user.domain() &&
          get_logon_server(user.domain(), buf, NULL))
	{
	  user.set_logsrv (buf + 2);
	  setenv ("LOGONSERVER", buf, 1);
	}
      debug_printf ("Domain: %s, Logon Server: %s, Windows Username: %s",
		    user.domain (), user.logsrv (), user.name ());

      /* NetUserGetInfo() can be slow in NT domain environment, thus we
       * only obtain HOMEDRIVE and HOMEPATH if they are not already set
       * in the environment. */
      if (!getenv ("HOMEPATH") || !getenv ("HOMEDRIVE"))
	{
	  LPUSER_INFO_3 ui = NULL;
	  WCHAR wuser[UNLEN + 1];

	  sys_mbstowcs (wuser, user.name (), sizeof (wuser) / sizeof (*wuser));
	  if ((ret = NetUserGetInfo (NULL, wuser, 3, (LPBYTE *)&ui)))
	    {
	      if (user.logsrv ())
		{
		  WCHAR wlogsrv[INTERNET_MAX_HOST_NAME_LENGTH + 3];
		  strcat (strcpy (buf, "\\\\"), user.logsrv ());

		  sys_mbstowcs (wlogsrv, buf,
				sizeof (wlogsrv) / sizeof(*wlogsrv));
		  ret = NetUserGetInfo (wlogsrv, wuser, 3,(LPBYTE *)&ui);
		}
	    }
	  if (!ret)
	    {
	      sys_wcstombs (buf, ui->usri3_home_dir, MAX_PATH);
	      if (!buf[0])
		{
		  sys_wcstombs (buf, ui->usri3_home_dir_drive, MAX_PATH);
		  if (buf[0])
		    strcat (buf, "\\");
		  else
		    {
		      env = getenv ("SYSTEMDRIVE");
		      if (env && *env)
			strcat (strcpy (buf, env), "\\");
		      else
			GetSystemDirectoryA (buf, MAX_PATH);
		    }
		}
	      setenv ("HOMEPATH", buf + 2, 1);
	      buf[2] = '\0';
	      setenv ("HOMEDRIVE", buf, 1);
	    }
	  if (ui)
	    NetApiBufferFree (ui);
	}

      HANDLE ptok = user.token; /* Which is INVALID_HANDLE_VALUE if no
				   impersonation took place. */
      DWORD siz;
      cygsid tu;
      ret = 0;

      /* Try to get the SID either from already impersonated token
	 or from current process first. To differ that two cases is
	 important, because you can't rely on the user information
	 in a process token of a currently impersonated process. */
      if (ptok == INVALID_HANDLE_VALUE
	  && !OpenProcessToken (GetCurrentProcess (),
				TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
				&ptok))
	debug_printf ("OpenProcessToken(): %E\n");
      else if (!GetTokenInformation (ptok, TokenUser, &tu, sizeof tu, &siz))
	debug_printf ("GetTokenInformation(): %E");
      else if (!(ret = user.set_sid (tu)))
	debug_printf ("Couldn't retrieve SID from access token!");
      /* If that failes, try to get the SID from localhost. This can only
	 be done if a domain is given because there's a chance that a local
	 and a domain user may have the same name. */
      if (!ret && user.domain ())
	{
	  char domain[DNLEN + 1];
	  DWORD dlen = sizeof (domain);
	  siz = sizeof (tu);
	  SID_NAME_USE use = SidTypeInvalid;
	  /* Concat DOMAIN\USERNAME for the next lookup */
	  strcat (strcat (strcpy (buf, user.domain ()), "\\"), user.name ());
          if (!LookupAccountName (NULL, buf, tu, &siz,
	                          domain, &dlen, &use) ||
               !legal_sid_type (use))
	        debug_printf ("Couldn't retrieve SID locally!");
	  else user.set_sid (tu);

	}

      /* If we have a SID, try to get the corresponding Cygwin user name
	 which can be different from the Windows user name. */
      cygsid gsid (NO_SID);
      if (ret)
	{
	  cygsid psid;

	  for (int pidx = 0; (pw = internal_getpwent (pidx)); ++pidx)
	    if (psid.getfrompw (pw) && EqualSid (user.sid (), psid))
	      {
		user.set_name (pw->pw_name);
		struct __group32 *gr = getgrgid32 (pw->pw_gid);
		if (gr)
		  if (!gsid.getfromgr (gr))
		      gsid = NO_SID;
		break;
	      }
	  if (!strcasematch (user.name (), "SYSTEM")
	      && user.domain () && user.logsrv ())
	    {
	      if (get_registry_hive_path (user.sid (), buf))
		setenv ("USERPROFILE", buf, 1);
	      else
		unsetenv ("USERPROFILE");
	    }
	}

      /* If this process is started from a non Cygwin process,
	 set token owner to the same value as token user and
	 primary group to the group which is set as primary group
	 in /etc/passwd. */
      if (ptok != INVALID_HANDLE_VALUE && myself->ppid == 1)
	{
	  if (!SetTokenInformation (ptok, TokenOwner, &tu, sizeof tu))
	    debug_printf ("SetTokenInformation(TokenOwner): %E");
	  if (gsid && !SetTokenInformation (ptok, TokenPrimaryGroup,
					    &gsid, sizeof gsid))
	    debug_printf ("SetTokenInformation(TokenPrimaryGroup): %E");
	}

      /* Close token only if it's a result from OpenProcessToken(). */
      if (ptok != INVALID_HANDLE_VALUE
	  && user.token == INVALID_HANDLE_VALUE)
	CloseHandle (ptok);
    }

  debug_printf ("Cygwins Username: %s", user.name ());

  if (!pw)
    pw = getpwnam(user.name ());
  if (!getenv ("HOME"))
    {
      const char *homedrive, *homepath;
      if (pw && pw->pw_dir && *pw->pw_dir)
	{
	  setenv ("HOME", pw->pw_dir, 1);
	  debug_printf ("Set HOME (from /etc/passwd) to %s", pw->pw_dir);
	}
      else if ((homedrive = getenv ("HOMEDRIVE"))
	       && (homepath = getenv ("HOMEPATH")))
	{
	  char home[MAX_PATH];
	  strcpy (buf, homedrive);
	  strcat (buf, homepath);
	  cygwin_conv_to_full_posix_path (buf, home);
	  setenv ("HOME", home, 1);
	  debug_printf ("Set HOME (from HOMEDRIVE/HOMEPATH) to %s", home);
	}
    }
  return pw;
}

void
uinfo_init ()
{
  struct passwd *p;

  /* Initialize to non impersonated values.
     Setting `impersonated' to TRUE seems to be wrong but it
     isn't. Impersonated is thought as "Current User and `token'
     are coincident". See seteuid() for the mechanism behind that. */
  if (cygheap->user.token != INVALID_HANDLE_VALUE && cygheap->user.token != NULL)
    CloseHandle (cygheap->user.token);
  cygheap->user.token = INVALID_HANDLE_VALUE;
  cygheap->user.impersonated = TRUE;

  /* If uid is ILLEGAL_UID, the process is started from a non cygwin
     process or the user context was changed in spawn.cc */
  if (myself->uid == ILLEGAL_UID)
    if ((p = internal_getlogin (cygheap->user)) != NULL)
      {
	myself->uid = p->pw_uid;
	/* Set primary group only if process has been started from a
	   non cygwin process. */
	if (!myself->ppid_handle)
	  myself->gid = p->pw_gid;
      }
    else
      {
	myself->uid = DEFAULT_UID;
	myself->gid = DEFAULT_GID;
      }
  /* Real and effective uid/gid are always identical on process start up.
     This is at least true for NT/W2K. */
  cygheap->user.orig_uid = cygheap->user.real_uid = myself->uid;
  cygheap->user.orig_gid = cygheap->user.real_gid = myself->gid;
}

extern "C" char *
getlogin (void)
{
#ifdef _MT_SAFE
  char *this_username=_reent_winsup ()->_username;
#else
  static char this_username[UNLEN + 1] NO_COPY;
#endif

  return strcpy (this_username, cygheap->user.name ());
}

extern "C" __uid32_t
getuid32 (void)
{
  return cygheap->user.real_uid;
}

extern "C" __uid16_t
getuid (void)
{
  return cygheap->user.real_uid;
}

extern "C" __gid32_t
getgid32 (void)
{
  return cygheap->user.real_gid;
}

extern "C" __gid16_t
getgid (void)
{
  return cygheap->user.real_gid;
}

extern "C" __uid32_t
geteuid32 (void)
{
  return myself->uid;
}

extern "C" __uid16_t
geteuid (void)
{
  return myself->uid;
}

extern "C" __gid32_t
getegid32 (void)
{
  return myself->gid;
}

extern "C" __gid16_t
getegid (void)
{
  return myself->gid;
}

/* Not quite right - cuserid can change, getlogin can't */
extern "C" char *
cuserid (char *src)
{
  if (src)
    {
      strcpy (src, getlogin ());
      return src;
    }
  else
    {
      return getlogin ();
    }
}
