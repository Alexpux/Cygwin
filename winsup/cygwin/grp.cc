/* grp.cc

   Copyright 1996, 1997, 1998, 2000, 2001, 2002, 2003 Red Hat, Inc.

   Original stubs by Jason Molenda of Cygnus Support, crash@cygnus.com
   First implementation by Gunther Ebert, gunther.ebert@ixos-leipzig.de

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <grp.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "pinfo.h"
#include "security.h"
#include "fhandler.h"
#include "path.h"
#include "dtable.h"
#include "cygerrno.h"
#include "cygheap.h"
#include "pwdgrp.h"

/* Read /etc/group only once for better performance.  This is done
   on the first call that needs information from it. */

static struct __group32 NO_COPY *group_buf;		/* group contents in memory */
static int NO_COPY curr_lines;
static int NO_COPY max_lines;

/* Position in the group cache */
#define grp_pos _reent_winsup ()->_grp_pos

static pwdgrp NO_COPY gr;
static char * NO_COPY null_ptr;

static int
parse_grp (struct __group32 &grp, char *line)
{
  char *dp = strchr (line, ':');

  if (!dp)
    return 0;

  *dp++ = '\0';
  grp.gr_name = line;

  grp.gr_passwd = dp;
  dp = strchr (grp.gr_passwd, ':');
  if (dp)
    {
      *dp++ = '\0';
      grp.gr_gid = strtoul (line = dp, &dp, 10);
      if (dp != line && *dp == ':')
	{
	  grp.gr_mem = &null_ptr;
	  if (*++dp)
	    {
	      int i = 0;
	      char *cp;

	      for (cp = dp; (cp = strchr (cp, ',')) != NULL; ++cp)
		++i;
	      char **namearray = (char **) calloc (i + 2, sizeof (char *));
	      if (namearray)
		{
		  i = 0;
		  for (cp = dp; (cp = strchr (dp, ',')) != NULL; dp = cp + 1)
		    {
		      *cp = '\0';
		      namearray[i++] = dp;
		    }
		  namearray[i++] = dp;
		  namearray[i] = NULL;
		  grp.gr_mem = namearray;
		}
	    }
	  return 1;
	}
    }
  return 0;
}

/* Read one line from /etc/group into the group cache */
static void
add_grp_line (char *line)
{
    if (curr_lines == max_lines)
      {
	max_lines += 10;
	group_buf = (struct __group32 *) realloc (group_buf, max_lines * sizeof (struct __group32));
      }
    if (parse_grp (group_buf[curr_lines], line))
      curr_lines++;
}

class group_lock
{
  bool armed;
  static NO_COPY pthread_mutex_t mutex;
public:
  group_lock (bool doit)
    {
      if (armed = doit)
        pthread_mutex_lock (&mutex);
    }
  ~group_lock ()
    {
      if (armed)
        pthread_mutex_unlock (&mutex);
    }
};

pthread_mutex_t NO_COPY group_lock::mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

/* Cygwin internal */
/* Read in /etc/group and save contents in the group cache */
/* This sets group_in_memory_p to 1 so functions in this file can
   tell that /etc/group has been read in */
static void
read_etc_group ()
{
  group_lock here (cygwin_finished_initializing);

  /* if we got blocked by the mutex, then etc_group may have been processed */
  if (gr.isinitializing ())
    {
      for (int i = 0; i < curr_lines; i++)
	if ((group_buf + i)->gr_mem != &null_ptr)
	  free ((group_buf + i)->gr_mem);

      curr_lines = 0;
      if (!gr.load ("/etc/group", add_grp_line))
	debug_printf ("gr.load failed");

      /* Complete /etc/group in memory if needed */
      if (!internal_getgrgid (myself->gid))
        {
	  static char linebuf [200];
	  char group_name [UNLEN + 1] = "mkgroup";
	  char strbuf[128] = "";

	  if (wincap.has_security ())
            {
	      struct __group32 *gr;

	      cygheap->user.groups.pgsid.string (strbuf);
	      if ((gr = internal_getgrsid (cygheap->user.groups.pgsid)))
		strlcpy (group_name, gr->gr_name, sizeof (group_name));
	    }
	  snprintf (linebuf, sizeof (linebuf), "%s:%s:%lu:%s",
		    group_name, strbuf, myself->gid, cygheap->user.name ());
	  debug_printf ("Completing /etc/group: %s", linebuf);
	  add_grp_line (linebuf);
	}
      static char NO_COPY pretty_ls[] = "????????::-1:";
      if (wincap.has_security ())
	add_grp_line (pretty_ls);
    }
  return;
}

struct __group32 *
internal_getgrsid (cygsid &sid)
{
  char sid_string[128];

  if (gr.isuninitialized ())
    read_etc_group ();

  if (sid.string (sid_string))
    for (int i = 0; i < curr_lines; i++)
      if (!strcmp (sid_string, group_buf[i].gr_passwd))
        return group_buf + i;
  return NULL;
}

struct __group32 *
internal_getgrgid (__gid32_t gid, bool check)
{
  if (gr.isuninitialized () || (check && gr.isinitializing ()))
    read_etc_group ();

  for (int i = 0; i < curr_lines; i++)
    if (group_buf[i].gr_gid == gid)
      return group_buf + i;
  return NULL;
}

struct __group32 *
internal_getgrnam (const char *name, bool check)
{
  if (gr.isuninitialized () || (check && gr.isinitializing ()))
    read_etc_group ();

  for (int i = 0; i < curr_lines; i++)
    if (strcasematch (group_buf[i].gr_name, name))
      return group_buf + i;

  /* Didn't find requested group */
  return NULL;
}

static
struct __group16 *
grp32togrp16 (struct __group16 *gp16, struct __group32 *gp32)
{
  if (!gp16 || !gp32)
    return NULL;

  /* Copying the pointers is actually unnecessary.  Just having the correct
     return type is important. */
  gp16->gr_name = gp32->gr_name;
  gp16->gr_passwd = gp32->gr_passwd;
  gp16->gr_gid = (__gid16_t) gp32->gr_gid;		/* Not loss-free */
  gp16->gr_mem = gp32->gr_mem;

  return gp16;
}

extern "C" struct __group32 *
getgrgid32 (__gid32_t gid)
{
  return internal_getgrgid (gid, TRUE);
}

extern "C" struct __group16 *
getgrgid (__gid16_t gid)
{
  static struct __group16 g16;	/* FIXME: thread-safe? */

  return grp32togrp16 (&g16, getgrgid32 ((__gid32_t) gid));
}

extern "C" struct __group32 *
getgrnam32 (const char *name)
{
  return internal_getgrnam (name, TRUE);
}

extern "C" struct __group16 *
getgrnam (const char *name)
{
  static struct __group16 g16;	/* FIXME: thread-safe? */

  return grp32togrp16 (&g16, getgrnam32 (name));
}

extern "C" void
endgrent ()
{
  grp_pos = 0;
}

extern "C" struct __group32 *
getgrent32 ()
{
  if (gr.isinitializing ())
    read_etc_group ();

  if (grp_pos < curr_lines)
    return group_buf + grp_pos++;

  return NULL;
}

extern "C" struct __group16 *
getgrent ()
{
  static struct __group16 g16;	/* FIXME: thread-safe? */

  return grp32togrp16 (&g16, getgrent32 ());
}

extern "C" void
setgrent ()
{
  grp_pos = 0;
}

/* Internal function. ONLY USE THIS INTERNALLY, NEVER `getgrent'!!! */
struct __group32 *
internal_getgrent (int pos)
{
  if (gr.isuninitialized ())
    read_etc_group ();

  if (pos < curr_lines)
    return group_buf + pos;
  return NULL;
}

int
internal_getgroups (int gidsetsize, __gid32_t *grouplist, cygsid * srchsid)
{
  HANDLE hToken = NULL;
  DWORD size;
  int cnt = 0;
  struct __group32 *gr;
  __gid32_t gid;
  const char *username;

  if (allow_ntsec)
    {
      /* If impersonated, use impersonation token. */
      if (cygheap->user.issetuid ())
        hToken = cygheap->user.token;
      else if (!OpenProcessToken (hMainProc, TOKEN_QUERY, &hToken))
        hToken = NULL;
    }
  if (hToken)
    {
      if (GetTokenInformation (hToken, TokenGroups, NULL, 0, &size)
	  || GetLastError () == ERROR_INSUFFICIENT_BUFFER)
	{
	  char buf[size];
	  TOKEN_GROUPS *groups = (TOKEN_GROUPS *) buf;

	  if (GetTokenInformation (hToken, TokenGroups, buf, size, &size))
	    {
	      cygsid sid;

	      if (srchsid)
	        {
		  for (DWORD pg = 0; pg < groups->GroupCount; ++pg)
		    if (*srchsid == groups->Groups[pg].Sid)
		      return 1;
		  return 0;
		}
	      for (int gidx = 0; (gr = internal_getgrent (gidx)); ++gidx)
		if (sid.getfromgr (gr))
		  for (DWORD pg = 0; pg < groups->GroupCount; ++pg)
		    if (sid == groups->Groups[pg].Sid &&
			sid != well_known_world_sid)
		      {
			if (cnt < gidsetsize)
			  grouplist[cnt] = gr->gr_gid;
			++cnt;
			if (gidsetsize && cnt > gidsetsize)
			  {
			    if (hToken != cygheap->user.token)
			      CloseHandle (hToken);
			    goto error;
			  }
			break;
		      }
	    }
	}
      else
	debug_printf ("%d = GetTokenInformation(NULL) %E", size);
      if (hToken != cygheap->user.token)
        CloseHandle (hToken);
      if (cnt)
	return cnt;
    }

  gid = myself->gid;
  username = cygheap->user.name ();
  for (int gidx = 0; (gr = internal_getgrent (gidx)); ++gidx)
    if (gid == gr->gr_gid)
      {
	if (cnt < gidsetsize)
	  grouplist[cnt] = gr->gr_gid;
	++cnt;
	if (gidsetsize && cnt > gidsetsize)
	  goto error;
      }
    else if (gr->gr_mem)
      for (int gi = 0; gr->gr_mem[gi]; ++gi)
	if (strcasematch (username, gr->gr_mem[gi]))
	  {
	    if (cnt < gidsetsize)
	      grouplist[cnt] = gr->gr_gid;
	    ++cnt;
	    if (gidsetsize && cnt > gidsetsize)
	      goto error;
	  }
  return cnt;

error:
  set_errno (EINVAL);
  return -1;
}

extern "C" int
getgroups32 (int gidsetsize, __gid32_t *grouplist)
{
  return internal_getgroups (gidsetsize, grouplist);
}

extern "C" int
getgroups (int gidsetsize, __gid16_t *grouplist)
{
  __gid32_t *grouplist32 = NULL;

  if (gidsetsize < 0)
    {
      set_errno (EINVAL);
      return -1;
    }
  if (gidsetsize > 0 && grouplist)
    grouplist32 = (__gid32_t *) alloca (gidsetsize * sizeof (__gid32_t));

  int ret = internal_getgroups (gidsetsize, grouplist32);

  if (gidsetsize > 0 && grouplist)
    for (int i = 0; i < ret; ++ i)
      grouplist[i] = grouplist32[i];

  return ret;
}

extern "C" int
initgroups32 (const char *, __gid32_t)
{
  if (wincap.has_security ())
    cygheap->user.groups.clear_supp ();
  return 0;
}

extern "C" int
initgroups (const char * name, __gid16_t gid)
{
  return initgroups32 (name, gid16togid32(gid));
}

/* setgroups32: standards? */
extern "C" int
setgroups32 (int ngroups, const __gid32_t *grouplist)
{
  if (ngroups < 0 || (ngroups > 0 && !grouplist))
    {
      set_errno (EINVAL);
      return -1;
    }

  if (!wincap.has_security ())
    return 0;

  cygsidlist gsids (cygsidlist_alloc, ngroups);
  struct __group32 *gr;

  if (ngroups && !gsids.sids)
    return -1;

  for (int gidx = 0; gidx < ngroups; ++gidx)
    {
      for (int gidy = 0; gidy < gidx; gidy++)
	if (grouplist[gidy] == grouplist[gidx])
	  goto found; /* Duplicate */
      if ((gr = internal_getgrgid (grouplist[gidx])) &&
	  gsids.addfromgr (gr))
	goto found;
      debug_printf ("No sid found for gid %d", grouplist[gidx]);
      gsids.free_sids ();
      set_errno (EINVAL);
      return -1;
    found:
      continue;
    }
  cygheap->user.groups.update_supp (gsids);
  return 0;
}

extern "C" int
setgroups (int ngroups, const __gid16_t *grouplist)
{
  __gid32_t *grouplist32 = NULL;

  if (ngroups > 0 && grouplist)
    {
      grouplist32 = (__gid32_t *) alloca (ngroups * sizeof (__gid32_t));
      if (grouplist32 == NULL)
	return -1;
      for (int i = 0; i < ngroups; i++)
	grouplist32[i] = grouplist[i];
    }
  return setgroups32 (ngroups, grouplist32);
}
