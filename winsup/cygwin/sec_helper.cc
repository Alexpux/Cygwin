/* sec_helper.cc: NT security helper functions

   Copyright 2000, 2001, 2002 Red Hat, Inc.

   Written by Corinna Vinschen <corinna@vinschen.de>

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <ctype.h>
#include <wingdi.h>
#include <winuser.h>
#include <wininet.h>
#include "cygerrno.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "pinfo.h"
#include "cygheap.h"
#include "pwdgrp.h"

/* General purpose security attribute objects for global use. */
SECURITY_ATTRIBUTES NO_COPY sec_none;
SECURITY_ATTRIBUTES NO_COPY sec_none_nih;
SECURITY_ATTRIBUTES NO_COPY sec_all;
SECURITY_ATTRIBUTES NO_COPY sec_all_nih;

SID_IDENTIFIER_AUTHORITY NO_COPY sid_auth[] = {
	{SECURITY_NULL_SID_AUTHORITY},
	{SECURITY_WORLD_SID_AUTHORITY},
	{SECURITY_LOCAL_SID_AUTHORITY},
	{SECURITY_CREATOR_SID_AUTHORITY},
	{SECURITY_NON_UNIQUE_AUTHORITY},
	{SECURITY_NT_AUTHORITY}
};

cygsid well_known_null_sid;
cygsid well_known_world_sid;
cygsid well_known_local_sid;
cygsid well_known_creator_owner_sid;
cygsid well_known_creator_group_sid;
cygsid well_known_dialup_sid;
cygsid well_known_network_sid;
cygsid well_known_batch_sid;
cygsid well_known_interactive_sid;
cygsid well_known_service_sid;
cygsid well_known_authenticated_users_sid;
cygsid well_known_system_sid;
cygsid well_known_admins_sid;

bool
cygpsid::operator== (const char *nsidstr) const
{
  cygsid nsid (nsidstr);
  return psid == nsid;
}

__uid32_t
cygpsid::get_id (BOOL search_grp, int *type)
{
    /* First try to get SID from group, then passwd */
  __uid32_t id = ILLEGAL_UID;

  if (search_grp)
    {
      struct __group32 *gr;
      if (cygheap->user.groups.pgsid == psid)
	id = myself->gid;
      else if ((gr = internal_getgrsid (*this)))
	id = gr->gr_gid;
      if (id != ILLEGAL_UID)
	{
	  if (type)
	    *type = GROUP;
	  return id;
	}
    }
  if (!search_grp || type)
    {
      struct passwd *pw;
      if (*this == cygheap->user.sid ())
	id = myself->uid;
      else if ((pw = internal_getpwsid (*this)))
	id = pw->pw_uid;
      if (id != ILLEGAL_UID && type)
	*type = USER;
    }
  return id;
}


char *
cygpsid::string (char *nsidstr) const
{
  char *t;
  DWORD i;

  if (!psid || !nsidstr)
    return NULL;
  strcpy (nsidstr, "S-1-");
  t = nsidstr + sizeof ("S-1-") - 1;
  t += __small_sprintf (t, "%u", GetSidIdentifierAuthority (psid)->Value[5]);
  for (i = 0; i < *GetSidSubAuthorityCount (psid); ++i)
    t += __small_sprintf (t, "-%lu", *GetSidSubAuthority (psid, i));
  return nsidstr;
}

void
cygsid::init ()
{
  well_known_null_sid = "S-1-0-0";
  well_known_world_sid = "S-1-1-0";
  well_known_local_sid = "S-1-2-0";
  well_known_creator_owner_sid = "S-1-3-0";
  well_known_creator_group_sid = "S-1-3-1";
  well_known_dialup_sid = "S-1-5-1";
  well_known_network_sid = "S-1-5-2";
  well_known_batch_sid = "S-1-5-3";
  well_known_interactive_sid = "S-1-5-4";
  well_known_service_sid = "S-1-5-6";
  well_known_authenticated_users_sid = "S-1-5-11";
  well_known_system_sid = "S-1-5-18";
  well_known_admins_sid = "S-1-5-32-544";
}

PSID
cygsid::get_sid (DWORD s, DWORD cnt, DWORD *r)
{
  DWORD i;

  if (s > 5 || cnt < 1 || cnt > 8)
    {
      psid = NO_SID;
      return NULL;
    }
  set ();
  InitializeSid (psid, &sid_auth[s], cnt);
  for (i = 0; i < cnt; ++i)
    memcpy ((char *) psid + 8 + sizeof (DWORD) * i, &r[i], sizeof (DWORD));
  return psid;
}

const PSID
cygsid::getfromstr (const char *nsidstr)
{
  char *lasts;
  DWORD s, cnt = 0;
  DWORD r[8];

  if (nsidstr && !strncmp (nsidstr, "S-1-", 4))
    {
      s = strtoul (nsidstr + 4, &lasts, 10);
      while (cnt < 8 && *lasts == '-')
	r[cnt++] = strtoul (lasts + 1, &lasts, 10);
      if (!*lasts)
	return get_sid (s, cnt, r);
    }
  return psid = NO_SID;
}

BOOL
cygsid::getfrompw (const struct passwd *pw)
{
  char *sp = (pw && pw->pw_gecos) ? strrchr (pw->pw_gecos, ',') : NULL;
  return (*this = sp ? sp + 1 : sp) != NULL;
}

BOOL
cygsid::getfromgr (const struct __group32 *gr)
{
  char *sp = (gr && gr->gr_passwd) ? gr->gr_passwd : NULL;
  return (*this = sp) != NULL;
}

bool
get_sids_info (cygpsid owner_sid, cygpsid group_sid, __uid32_t * uidret, __gid32_t * gidret)
{
  struct passwd *pw;
  struct __group32 *gr = NULL;
  bool ret = false;

  owner_sid.debug_print ("get_sids_info: owner SID =");
  group_sid.debug_print ("get_sids_info: group SID =");

  if (group_sid == cygheap->user.groups.pgsid)
    *gidret = myself->gid;
  else if ((gr = internal_getgrsid (group_sid)))
    *gidret = gr->gr_gid;
  else
    *gidret = ILLEGAL_GID;

  if (owner_sid == cygheap->user.sid ())
    {
      *uidret = myself->uid;
      if (*gidret == myself->gid)
	ret = true;
      else
	ret = (internal_getgroups (0, NULL, &group_sid) > 0);
    }
  else if ((pw = internal_getpwsid (owner_sid)))
    {
      *uidret = pw->pw_uid;
      if (gr || (*gidret != ILLEGAL_GID
		 && (gr = internal_getgrgid (*gidret))))
	for (int idx = 0; gr->gr_mem[idx]; ++idx)
	  if ((ret = strcasematch (pw->pw_name, gr->gr_mem[idx])))
	    break;
    }
  else
    *uidret = ILLEGAL_UID;

  return ret;
}

PSECURITY_DESCRIPTOR
security_descriptor::malloc (size_t nsize)
{
  if (psd)
    ::free (psd);
  psd = (PSECURITY_DESCRIPTOR) ::malloc (nsize);
  sd_size = psd ? nsize : 0;
  return psd;
}

PSECURITY_DESCRIPTOR
security_descriptor::realloc (size_t nsize)
{
  PSECURITY_DESCRIPTOR tmp = (PSECURITY_DESCRIPTOR) ::realloc (psd, nsize);
  if (!tmp)
    return NULL;
  sd_size = nsize;
  return psd = tmp;
}

void
security_descriptor::free (void)
{
  if (psd)
    ::free (psd);
  psd = NULL;
  sd_size = 0;
}

#if 0 // unused
#define SIDLEN	(sidlen = MAX_SID_LEN, &sidlen)
#define DOMLEN	(domlen = INTERNET_MAX_HOST_NAME_LENGTH, &domlen)

BOOL
lookup_name (const char *name, const char *logsrv, PSID ret_sid)
{
  cygsid sid;
  DWORD sidlen;
  char domuser[INTERNET_MAX_HOST_NAME_LENGTH + UNLEN + 2];
  char dom[INTERNET_MAX_HOST_NAME_LENGTH + 1];
  DWORD domlen;
  SID_NAME_USE acc_type;

  debug_printf ("name  : %s", name ? name : "NULL");

  if (!name)
    return FALSE;

  if (cygheap->user.domain ())
    {
      strcat (strcat (strcpy (domuser, cygheap->user.domain ()), "\\"), name);
      if (LookupAccountName (NULL, domuser, sid, SIDLEN, dom, DOMLEN, &acc_type)
	  && legal_sid_type (acc_type))
	goto got_it;
      if (logsrv && *logsrv
	  && LookupAccountName (logsrv, domuser, sid, SIDLEN,
				dom, DOMLEN, &acc_type)
	  && legal_sid_type (acc_type))
	goto got_it;
    }
  if (logsrv && *logsrv)
    {
      if (LookupAccountName (logsrv, name, sid, SIDLEN, dom, DOMLEN, &acc_type)
	  && legal_sid_type (acc_type))
	goto got_it;
      if (acc_type == SidTypeDomain)
	{
	  strcat (strcat (strcpy (domuser, dom), "\\"), name);
	  if (LookupAccountName (logsrv, domuser, sid, SIDLEN,
				 dom, DOMLEN, &acc_type))
	    goto got_it;
	}
    }
  if (LookupAccountName (NULL, name, sid, SIDLEN, dom, DOMLEN, &acc_type)
      && legal_sid_type (acc_type))
    goto got_it;
  if (acc_type == SidTypeDomain)
    {
      strcat (strcat (strcpy (domuser, dom), "\\"), name);
      if (LookupAccountName (NULL, domuser, sid, SIDLEN, dom, DOMLEN,&acc_type))
	goto got_it;
    }
  debug_printf ("LookupAccountName (%s) %E", name);
  __seterrno ();
  return FALSE;

got_it:
  debug_printf ("sid : [%d]", *GetSidSubAuthority ((PSID) sid,
			      *GetSidSubAuthorityCount ((PSID) sid) - 1));

  if (ret_sid)
    memcpy (ret_sid, sid, sidlen);

  return TRUE;
}

#undef SIDLEN
#undef DOMLEN
#endif //unused

int
set_process_privilege (const char *privilege, bool enable, bool use_thread)
{
  HANDLE hToken = NULL;
  LUID restore_priv;
  TOKEN_PRIVILEGES new_priv, orig_priv;
  int ret = -1;
  DWORD size;

  if ((use_thread
       && !OpenThreadToken (GetCurrentThread (), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
			    0, &hToken))
      ||(!use_thread
	 && !OpenProcessToken (hMainProc, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
			     &hToken)))
    {
      __seterrno ();
      goto out;
    }

  if (!LookupPrivilegeValue (NULL, privilege, &restore_priv))
    {
      __seterrno ();
      goto out;
    }

  new_priv.PrivilegeCount = 1;
  new_priv.Privileges[0].Luid = restore_priv;
  new_priv.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

  if (!AdjustTokenPrivileges (hToken, FALSE, &new_priv,
			      sizeof orig_priv, &orig_priv, &size))
    {
      __seterrno ();
      goto out;
    }
  /* AdjustTokenPrivileges returns TRUE even if the privilege could not
     be enabled. GetLastError () returns an correct error code, though. */
  if (enable && GetLastError () == ERROR_NOT_ALL_ASSIGNED)
    {
      __seterrno ();
      goto out;
    }

  ret = orig_priv.Privileges[0].Attributes == SE_PRIVILEGE_ENABLED ? 1 : 0;

out:
  if (hToken)
    CloseHandle (hToken);

  syscall_printf ("%d = set_process_privilege (%s, %d)", ret, privilege, enable);
  return ret;
}

/*
 * Function to return a common SECURITY_DESCRIPTOR * that
 * allows all access.
 */

static NO_COPY SECURITY_DESCRIPTOR *null_sdp = 0;

SECURITY_DESCRIPTOR *__stdcall
get_null_sd ()
{
  static NO_COPY SECURITY_DESCRIPTOR sd;

  if (null_sdp == 0)
    {
      InitializeSecurityDescriptor (&sd, SECURITY_DESCRIPTOR_REVISION);
      SetSecurityDescriptorDacl (&sd, TRUE, 0, FALSE);
      null_sdp = &sd;
    }
  return null_sdp;
}

/*
 * Initialize global security attributes.
 *
 * Called from dcrt0.cc (_dll_crt0).
 */

void
init_global_security ()
{
  sec_none.nLength = sec_none_nih.nLength =
  sec_all.nLength = sec_all_nih.nLength = sizeof (SECURITY_ATTRIBUTES);
  sec_none.bInheritHandle = sec_all.bInheritHandle = TRUE;
  sec_none_nih.bInheritHandle = sec_all_nih.bInheritHandle = FALSE;
  sec_none.lpSecurityDescriptor = sec_none_nih.lpSecurityDescriptor = NULL;
  sec_all.lpSecurityDescriptor = sec_all_nih.lpSecurityDescriptor =
    get_null_sd ();
}

BOOL
sec_acl (PACL acl, bool original, bool admins, PSID sid1, PSID sid2, DWORD access2)
{
  size_t acl_len = MAX_DACL_LEN(5);
  LPVOID pAce;
  cygpsid psid;

  if (!InitializeAcl (acl, acl_len, ACL_REVISION))
    {
      debug_printf ("InitializeAcl %E");
      return FALSE;
    }
  if (sid1)
    if (!AddAccessAllowedAce (acl, ACL_REVISION,
			      GENERIC_ALL, sid1))
      debug_printf ("AddAccessAllowedAce(sid1) %E");
  if (original && (psid = cygheap->user.saved_sid ())
      && psid != sid1 && psid != well_known_system_sid)
    if (!AddAccessAllowedAce (acl, ACL_REVISION,
			      GENERIC_ALL, psid))
      debug_printf ("AddAccessAllowedAce(original) %E");
  if (sid2)
    if (!AddAccessAllowedAce (acl, ACL_REVISION,
			      access2, sid2))
      debug_printf ("AddAccessAllowedAce(sid2) %E");
  if (admins)
    if (!AddAccessAllowedAce (acl, ACL_REVISION,
			      GENERIC_ALL, well_known_admins_sid))
      debug_printf ("AddAccessAllowedAce(admin) %E");
  if (!AddAccessAllowedAce (acl, ACL_REVISION,
			    GENERIC_ALL, well_known_system_sid))
    debug_printf ("AddAccessAllowedAce(system) %E");
  FindFirstFreeAce (acl, &pAce);
  if (pAce)
    acl->AclSize = (char *) pAce - (char *) acl;
  else
    debug_printf ("FindFirstFreeAce %E");

  return TRUE;
}

PSECURITY_ATTRIBUTES __stdcall
__sec_user (PVOID sa_buf, PSID sid1, PSID sid2, DWORD access2, BOOL inherit)
{
  PSECURITY_ATTRIBUTES psa = (PSECURITY_ATTRIBUTES) sa_buf;
  PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)
			     ((char *) sa_buf + sizeof (*psa));
  PACL acl = (PACL) ((char *) sa_buf + sizeof (*psa) + sizeof (*psd));

  if (!wincap.has_security () || !sec_acl (acl, true, true, sid1, sid2, access2))
    return inherit ? &sec_none : &sec_none_nih;

  if (!InitializeSecurityDescriptor (psd, SECURITY_DESCRIPTOR_REVISION))
    debug_printf ("InitializeSecurityDescriptor %E");

/*
 * Setting the owner lets the created security attribute not work
 * on NT4 SP3 Server. Don't know why, but the function still does
 * what it should do also if the owner isn't set.
*/
#if 0
  if (!SetSecurityDescriptorOwner (psd, sid, FALSE))
    debug_printf ("SetSecurityDescriptorOwner %E");
#endif

  if (!SetSecurityDescriptorDacl (psd, TRUE, acl, FALSE))
    debug_printf ("SetSecurityDescriptorDacl %E");

  psa->nLength = sizeof (SECURITY_ATTRIBUTES);
  psa->lpSecurityDescriptor = psd;
  psa->bInheritHandle = inherit;
  return psa;
}
