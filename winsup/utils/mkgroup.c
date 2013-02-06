/* mkgroup.c:

   Copyright 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
   2008, 2009, 2010, 2011, 2012, 2013 Red Hat, Inc.

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

#define _WIN32_WINNT 0x0600
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <wchar.h>
#include <wctype.h>
#include <locale.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <getopt.h>
#include <io.h>
#include <sys/fcntl.h>
#include <sys/cygwin.h>
#include <cygwin/version.h>
#include <windows.h>
#include <lm.h>
#include <wininet.h>
#include <iptypes.h>
#include <ntsecapi.h>
#include <dsgetdc.h>
#include <ntdef.h>
#include "loadlib.h"

#define print_win_error(x) _print_win_error(x, __LINE__)

#define MAX_SID_LEN 40

SID_IDENTIFIER_AUTHORITY sid_world_auth = {SECURITY_WORLD_SID_AUTHORITY};
SID_IDENTIFIER_AUTHORITY sid_nt_auth = {SECURITY_NT_AUTHORITY};

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

typedef struct
{
  char *str;
  DWORD id_offset;
  BOOL domain;
  BOOL with_dom;
} domlist_t;

static void
_print_win_error (DWORD code, int line)
{
  char buf[4096];

  if (FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM
      | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL,
      code,
      MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPTSTR) buf, sizeof (buf), NULL))
    fprintf (stderr, "mkgroup (%d): [%" PRIu32 "] %s",
	     line, (unsigned int) code, buf);
  else
    fprintf (stderr, "mkgroup (%d): error %" PRIu32 ,
	     line, (unsigned int) code);
}

static PWCHAR
get_dcname (char *domain)
{
  static WCHAR server[INTERNET_MAX_HOST_NAME_LENGTH + 1];
  DWORD rc;
  WCHAR domain_name[MAX_DOMAIN_NAME_LEN + 1];
  PDOMAIN_CONTROLLER_INFOW pdci = NULL;

  if (domain)
    {
      mbstowcs (domain_name, domain, strlen (domain) + 1);
      rc = DsGetDcNameW (NULL, domain_name, NULL, NULL, 0, &pdci);
    }
  else
    rc = DsGetDcNameW (NULL, NULL, NULL, NULL, 0, &pdci);
  if (rc != ERROR_SUCCESS)
    {
      print_win_error (rc);
      return (PWCHAR) -1;
    }
  wcscpy (server, pdci->DomainControllerName);
  NetApiBufferFree (pdci);
  return server;
}

static char *
put_sid (PSID psid)
{
  static char s[512];
  char t[32];
  DWORD i;

  strcpy (s, "S-1-");
  sprintf(t, "%u", GetSidIdentifierAuthority (psid)->Value[5]);
  strcat (s, t);
  for (i = 0; i < *GetSidSubAuthorityCount (psid); ++i)
    {
      sprintf(t, "-%" PRIu32 , (unsigned int) *GetSidSubAuthority (psid, i));
      strcat (s, t);
    }
  return s;
}

typedef struct {
  BYTE  Revision;
  BYTE  SubAuthorityCount;
  SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
  DWORD SubAuthority[8];
} DBGSID, *PDBGSID;

#define MAX_BUILTIN_SIDS 100	/* Should be enough for the forseable future. */
DBGSID builtin_sid_list[MAX_BUILTIN_SIDS];
DWORD builtin_sid_cnt;

typedef struct {
  PSID psid;
  int buffer[10];
} sidbuf;

static sidbuf curr_pgrp;
static BOOL got_curr_pgrp = FALSE;

static void
fetch_current_pgrp_sid ()
{
  DWORD len;
  HANDLE ptok;

  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &ptok)
      || !GetTokenInformation (ptok, TokenPrimaryGroup, &curr_pgrp,
			       sizeof curr_pgrp, &len)
      || !CloseHandle (ptok))
    {
      print_win_error (GetLastError ());
      return;
    }
}

static void
current_group (const char *sep, DWORD id_offset)
{
  WCHAR grp[GNLEN + 1];
  WCHAR dom[MAX_DOMAIN_NAME_LEN + 1];
  DWORD glen = GNLEN + 1;
  DWORD dlen = MAX_DOMAIN_NAME_LEN + 1;
  int gid;
  SID_NAME_USE acc_type;

  if (!curr_pgrp.psid
      || !LookupAccountSidW (NULL, curr_pgrp.psid, grp, &glen, dom, &dlen,
			     &acc_type))
    {
      print_win_error (GetLastError ());
      return;
    }
  gid = *GetSidSubAuthority (curr_pgrp.psid,
			     *GetSidSubAuthorityCount(curr_pgrp.psid) - 1);
  printf ("%ls%s%ls:%s:%" PRIu32 ":\n",
	  sep ? dom : L"",
	  sep ?: "",
	  grp,
	  put_sid (curr_pgrp.psid),
	  (unsigned int) (id_offset + gid));
}

static void
enum_unix_groups (domlist_t *dom_or_machine, const char *sep, DWORD id_offset,
		  char *unix_grp_list)
{
  WCHAR machine[INTERNET_MAX_HOST_NAME_LENGTH + 1];
  PWCHAR servername = NULL;
  char *d_or_m = dom_or_machine ? dom_or_machine->str : NULL;
  BOOL with_dom = dom_or_machine ? dom_or_machine->with_dom : FALSE;
  SID_IDENTIFIER_AUTHORITY auth = { { 0, 0, 0, 0, 0, 22 } };
  char *gstr, *grp_list;
  WCHAR grp[GNLEN + sizeof ("Unix Group\\") + 1];
  WCHAR dom[MAX_DOMAIN_NAME_LEN + 1];
  DWORD glen, dlen, sidlen;
  PSID psid;
  char psid_buffer[MAX_SID_LEN];
  SID_NAME_USE acc_type;

  if (!d_or_m)
    return;

  int ret = mbstowcs (machine, d_or_m, INTERNET_MAX_HOST_NAME_LENGTH + 1);
  if (ret < 1 || ret >= INTERNET_MAX_HOST_NAME_LENGTH + 1)
    {
      fprintf (stderr, "%s: Invalid machine name '%s'.  Skipping...\n",
	       program_invocation_short_name, d_or_m);
      return;
    }
  servername = machine;

  if (!AllocateAndInitializeSid (&auth, 2, 2, 0, 0, 0, 0, 0, 0, 0, &psid))
    return;

  if (!(grp_list = strdup (unix_grp_list)))
    {
      FreeSid (psid);
      return;
    }

  for (gstr = strtok (grp_list, ","); gstr; gstr = strtok (NULL, ","))
    {
      if (!isdigit ((unsigned char) gstr[0]) && gstr[0] != '-')
	{
	  PWCHAR p = wcpcpy (grp, L"Unix Group\\");
	  ret = mbstowcs (p, gstr, GNLEN + 1);
	  if (ret < 1 || ret >= GNLEN + 1)
	    fprintf (stderr, "%s: Invalid group name '%s'.  Skipping...\n",
		     program_invocation_short_name, gstr);
	  else if (LookupAccountNameW (servername, grp,
				       psid = (PSID) psid_buffer,
				       (sidlen = MAX_SID_LEN, &sidlen),
				       dom,
				       (dlen = MAX_DOMAIN_NAME_LEN + 1, &dlen),
				       &acc_type))
	    printf ("%s%s%ls:%s:%" PRIu32 ":\n",
		    with_dom ? "Unix Group" : "",
		    with_dom ? sep : "",
		    p,
		    put_sid (psid),
		    (unsigned int) (id_offset +
		    *GetSidSubAuthority (psid,
					 *GetSidSubAuthorityCount(psid) - 1)));
	}
      else
	{
	  DWORD start, stop;
	  char *p = gstr;
	  if (*p == '-')
	    start = 0;
	  else
	    start = strtol (p, &p, 10);
	  if (!*p)
	    stop = start;
	  else if (*p++ != '-' || !isdigit ((unsigned char) *p)
		   || (stop = strtol (p, &p, 10)) < start || *p)
	    {
	      fprintf (stderr, "%s: Malformed unix group list entry '%s'.  "
			       "Skipping...\n",
			       program_invocation_short_name, gstr);
	      continue;
	    }
	  for (; start <= stop; ++ start)
	    {
	      *GetSidSubAuthority (psid, *GetSidSubAuthorityCount(psid) - 1)
	      = start;
	      if (LookupAccountSidW (servername, psid,
				     grp, (glen = GNLEN + 1, &glen),
				     dom,
				     (dlen = MAX_DOMAIN_NAME_LEN + 1, &dlen),
				     &acc_type)
		  && !iswdigit (grp[0]))
		printf ("%s%s%ls:%s:%" PRIu32 ":\n",
			with_dom ? "Unix Group" : "",
			with_dom ? sep : "",
			grp,
			put_sid (psid),
			(unsigned int) (id_offset + start));
	    }
	}
    }

  free (grp_list);
  FreeSid (psid);
}

static int
enum_local_groups (BOOL domain, domlist_t *dom_or_machine, const char *sep,
		   DWORD id_offset, char *disp_groupname, int print_builtin,
		   int print_current)
{
  WCHAR machine[INTERNET_MAX_HOST_NAME_LENGTH + 1];
  PWCHAR servername = NULL;
  char *d_or_m = dom_or_machine ? dom_or_machine->str : NULL;
  BOOL with_dom = dom_or_machine ? dom_or_machine->with_dom : FALSE;
  LOCALGROUP_INFO_0 *buffer;
  DWORD entriesread = 0;
  DWORD totalentries = 0;
  DWORD_PTR resume_handle = 0;
  WCHAR gname[GNLEN + 1];
  DWORD rc;

  if (domain)
    {
      servername = get_dcname (d_or_m);
      if (servername == (PWCHAR) -1)
	return 1;
    }
  else if (d_or_m)
    {
      int ret = mbstowcs (machine, d_or_m, INTERNET_MAX_HOST_NAME_LENGTH + 1);
      if (ret < 1 || ret >= INTERNET_MAX_HOST_NAME_LENGTH + 1)
	{
	  fprintf (stderr, "%s: Invalid machine name '%s'.  Skipping...\n",
		   program_invocation_short_name, d_or_m);
	  return 1;
	}
      servername = machine;
    }

  do
    {
      DWORD i;

      if (disp_groupname)
	{
	  mbstowcs (gname, disp_groupname, GNLEN + 1);
	  rc = NetLocalGroupGetInfo (servername, gname, 0, (void *) &buffer);
	  if (rc == ERROR_SUCCESS)
	    entriesread = 1;
	  /* Allow further searching for the group and avoid annoying
	     error messages just because the group is not a local group or
	     the group hasn't been found. */
	  else if (rc == ERROR_NO_SUCH_ALIAS || rc == NERR_GroupNotFound)
	    return 0;
	}
      else
	rc = NetLocalGroupEnum (servername, 0, (void *) &buffer,
				MAX_PREFERRED_LENGTH, &entriesread,
				&totalentries, &resume_handle);
      switch (rc)
	{
	case ERROR_ACCESS_DENIED:
	  print_win_error (rc);
	  return 1;

	case ERROR_MORE_DATA:
	case ERROR_SUCCESS:
	  break;

	default:
	  print_win_error (rc);
	  return 1;
	}

      for (i = 0; i < entriesread; i++)
	{
	  WCHAR domain_name[MAX_DOMAIN_NAME_LEN + 1];
	  DWORD domname_len = MAX_DOMAIN_NAME_LEN + 1;
	  char psid_buffer[MAX_SID_LEN];
	  PSID psid = (PSID) psid_buffer;
	  DWORD sid_length = MAX_SID_LEN;
	  DWORD gid;
	  SID_NAME_USE acc_type;
	  PDBGSID pdsid;
	  BOOL is_builtin = FALSE;

	  if (!LookupAccountNameW (servername, buffer[i].lgrpi0_name, psid,
				   &sid_length, domain_name, &domname_len,
				   &acc_type))
	    {
	      print_win_error (GetLastError ());
	      fprintf (stderr, " (%ls)\n", buffer[i].lgrpi0_name);
	      continue;
	    }
	  else if (acc_type == SidTypeDomain)
	    {
	      WCHAR domname[MAX_DOMAIN_NAME_LEN + GNLEN + 2];

	      wcscpy (domname, domain_name);
	      wcscat (domname, L"\\");
	      wcscat (domname, buffer[i].lgrpi0_name);
	      sid_length = MAX_SID_LEN;
	      domname_len = MAX_DOMAIN_NAME_LEN + 1;
	      if (!LookupAccountNameW (servername, domname,
				       psid, &sid_length,
				       domain_name, &domname_len,
				       &acc_type))
		{
		  print_win_error (GetLastError ());
		  fprintf(stderr, " (%ls)\n", domname);
		  continue;
		}
	    }

	  /* Store all local SIDs with prefix "S-1-5-32-" and check if it
	     has been printed already.  This allows to get all builtin
	     groups exactly once and not once per domain. */
	  pdsid = (PDBGSID) psid;
	  if (pdsid->IdentifierAuthority.Value[5] == sid_nt_auth.Value[5]
	      && pdsid->SubAuthority[0] == SECURITY_BUILTIN_DOMAIN_RID)
	    {
	      int b;

	      if (!print_builtin)
		goto skip_group;
	      is_builtin = TRUE;
	      if (builtin_sid_cnt)
		for (b = 0; b < builtin_sid_cnt; b++)
		  if (EqualSid (&builtin_sid_list[b], psid))
		    goto skip_group;
	      if (builtin_sid_cnt < MAX_BUILTIN_SIDS)
		CopySid (sizeof (DBGSID), &builtin_sid_list[builtin_sid_cnt++],
			 psid);
	    }
	  if (!print_current)
	    /* fall through */;
	  else if (EqualSid (curr_pgrp.psid, psid))
	    got_curr_pgrp = TRUE;

	  gid = *GetSidSubAuthority (psid, *GetSidSubAuthorityCount(psid) - 1);
	  printf ("%ls%s%ls:%s:%" PRIu32 ":\n",
		  with_dom && !is_builtin ? domain_name : L"",
		  with_dom && !is_builtin ? sep : "",
		  buffer[i].lgrpi0_name,
		  put_sid (psid),
		  (unsigned int) (gid + (is_builtin ? 0 : id_offset)));
skip_group:
	  ;
	}

      NetApiBufferFree (buffer);

    }
  while (rc == ERROR_MORE_DATA);

  /* Return 1 if the single group we're looking for has been found here to
     avoid calling enum_groups for the same group, thus avoiding a spurious
     error message "group name could not be found" in enum_groups. */
  return disp_groupname && entriesread ? 1 : 0;
}

static void
enum_groups (BOOL domain, domlist_t *dom_or_machine, const char *sep,
	     DWORD id_offset, char *disp_groupname, int print_current)
{
  WCHAR machine[INTERNET_MAX_HOST_NAME_LENGTH + 1];
  PWCHAR servername = NULL;
  char *d_or_m = dom_or_machine ? dom_or_machine->str : NULL;
  BOOL with_dom = dom_or_machine ? dom_or_machine->with_dom : FALSE;
  GROUP_INFO_2 *buffer;
  DWORD entriesread = 0;
  DWORD totalentries = 0;
  DWORD_PTR resume_handle = 0;
  WCHAR gname[GNLEN + 1];
  DWORD rc;

  if (domain)
    {
      servername = get_dcname (d_or_m);
      if (servername == (PWCHAR) -1)
	return;
    }
  else if (d_or_m)
    {
      int ret = mbstowcs (machine, d_or_m, INTERNET_MAX_HOST_NAME_LENGTH + 1);
      if (ret < 1 || ret >= INTERNET_MAX_HOST_NAME_LENGTH + 1)
	{
	  fprintf (stderr, "%s: Invalid machine name '%s'.  Skipping...\n",
		   program_invocation_short_name, d_or_m);
	  return;
	}
      servername = machine;
    }

  do
    {
      DWORD i;

      if (disp_groupname != NULL)
	{
	  mbstowcs (gname, disp_groupname, GNLEN + 1);
	  rc = NetGroupGetInfo (servername, (LPWSTR) & gname, 2,
				(void *) &buffer);
	  entriesread=1;
	  /* Avoid annoying error messages just because the group hasn't been
	     found. */
	  if (rc == NERR_GroupNotFound)
	    return;
	}
      else
	rc = NetGroupEnum (servername, 2, (void *) & buffer,
			   MAX_PREFERRED_LENGTH, &entriesread, &totalentries,
			   &resume_handle);
      switch (rc)
	{
	case ERROR_ACCESS_DENIED:
	  print_win_error (rc);
	  return;

	case ERROR_MORE_DATA:
	case ERROR_SUCCESS:
	  break;

	default:
	  print_win_error (rc);
	  return;
	}

      for (i = 0; i < entriesread; i++)
	{
	  WCHAR domain_name[MAX_DOMAIN_NAME_LEN + 1];
	  DWORD domname_len = MAX_DOMAIN_NAME_LEN + 1;
	  char psid_buffer[MAX_SID_LEN];
	  PSID psid = (PSID) psid_buffer;
	  DWORD sid_length = MAX_SID_LEN;
	  SID_NAME_USE acc_type;

	  int gid = buffer[i].grpi2_group_id;
	  if (!LookupAccountNameW (servername, buffer[i].grpi2_name,
				   psid, &sid_length,
				   domain_name, &domname_len,
				   &acc_type))
	    {
	      print_win_error (GetLastError ());
	      fprintf(stderr, " (%ls)\n", buffer[i].grpi2_name);
	      continue;
	    }
	  else if (acc_type == SidTypeDomain)
	    {
	      WCHAR domname[MAX_DOMAIN_NAME_LEN + GNLEN + 2];

	      wcscpy (domname, domain || !servername
			       ? domain_name : servername);
	      wcscat (domname, L"\\");
	      wcscat (domname, buffer[i].grpi2_name);
	      sid_length = MAX_SID_LEN;
	      domname_len = MAX_DOMAIN_NAME_LEN + 1;
	      if (!LookupAccountNameW (servername, domname,
				       psid, &sid_length,
				       domain_name, &domname_len,
				       &acc_type))
		{
		  print_win_error (GetLastError ());
		  fprintf(stderr, " (%ls)\n", domname);
		  continue;
		}
	    }
	  if (!print_current)
	    /* fall through */;
	  else if (EqualSid (curr_pgrp.psid, psid))
	    got_curr_pgrp = TRUE;

	  printf ("%ls%s%ls:%s:%" PRIu32 ":\n",
		  with_dom ? domain_name : L"",
		  with_dom ? sep : "",
		  buffer[i].grpi2_name,
		  put_sid (psid),
		  (unsigned int) (id_offset + gid));
	}

      NetApiBufferFree (buffer);

    }
  while (rc == ERROR_MORE_DATA);
}

static void
print_special_by_sid (PSID_IDENTIFIER_AUTHORITY auth, BYTE cnt,
		      DWORD sub1, DWORD sub2, DWORD sub3, DWORD sub4,
		      DWORD sub5, DWORD sub6, DWORD sub7, DWORD sub8)
{
  WCHAR grp[GNLEN + 1], dom[MAX_DOMAIN_NAME_LEN + 1];
  DWORD glen, dlen, rid;
  PSID psid;
  SID_NAME_USE acc_type;

  if (AllocateAndInitializeSid (auth, cnt, sub1, sub2, sub3, sub4,
				sub5, sub6, sub7, sub8, &psid))
    {
      if (LookupAccountSidW (NULL, psid,
			    grp, (glen = GNLEN + 1, &glen),
			    dom, (dlen = MAX_DOMAIN_NAME_LEN + 1, &dlen),
			    &acc_type))
	{
	  if (sub8)
	    rid = sub8;
	  else if (sub7)
	    rid = sub7;
	  else if (sub6)
	    rid = sub6;
	  else if (sub5)
	    rid = sub5;
	  else if (sub4)
	    rid = sub4;
	  else if (sub3)
	    rid = sub3;
	  else if (sub2)
	    rid = sub2;
	  else
	    rid = sub1;
	  printf ("%ls:%s:%" PRIu32 ":\n", grp, put_sid (psid),
	  	  (unsigned int) rid);
	}
      FreeSid (psid);
    }
}

static void
print_special_by_name (PCWSTR name, gid_t gid)
{
  DWORD size = 256, dom_size = 256;
  PSID sid = (PSID) alloca (size);
  WCHAR dom[dom_size];
  SID_NAME_USE use;

  PWCHAR name_only = wcschr (name, L'\\');
  if (name_only)
    ++name_only;

  if (LookupAccountNameW (NULL, name, sid, &size, dom, &dom_size, &use))
    printf ("%ls:%s:%lu:\n",
	    name_only ?: name, put_sid (sid), (unsigned long) gid);
}

static int
usage (FILE * stream)
{
  fprintf (stream,
"Usage: %s [OPTION]...\n"
"\n"
"Print /etc/group file to stdout\n"
"\n"
"Options:\n"
"\n"
"   -l,--local [machine[,offset]]\n"
"                           print local groups with gid offset offset\n"
"                           (from local machine if no machine specified)\n"
"   -L,--Local [machine[,offset]]\n"
"                           ditto, but generate groupname with machine prefix\n"
"   -d,--domain [domain[,offset]]\n"
"                           print domain groups with gid offset offset\n"
"                           (from current domain if no domain specified)\n"
"   -D,--Domain [domain[,offset]]\n"
"                           ditto, but generate groupname with machine prefix\n"
"   -c,--current            print current group\n"
"   -C,--Current            ditto, but generate groupname with machine or\n"
"                           domain prefix\n"
"   -S,--separator char     for -L, -D, -C use character char as domain\\group\n"
"                           separator in groupname instead of the default '\\'\n"
"   -o,--id-offset offset   change the default offset (10000) added to gids\n"
"                           in domain or foreign server accounts.\n"
"   -g,--group groupname    only return information for the specified group\n"
"                           one of -l, -L, -d, -D must be specified, too\n"
"   -b,--no-builtin         don't print BUILTIN groups\n"
"   -U,--unix grouplist     additionally print UNIX groups when using -l or -L\n"
"                           on a UNIX Samba server\n"
"                           grouplist is a comma-separated list of groupnames\n"
"                           or gid ranges (root,-25,50-100).\n"
"                           (enumerating large ranges can take a long time!)\n"
"   -s,--no-sids            (ignored)\n"
"   -u,--users              (ignored)\n"
"   -h,--help               print this message\n"
"   -v,--version            print version information and exit\n"
"\n"
"Default is to print local groups on stand-alone machines, plus domain\n"
"groups on domain controllers and domain member machines.\n"
"\n", program_invocation_short_name);
  return 1;
}

struct option longopts[] = {
  {"no-builtin", no_argument, NULL, 'b'},
  {"current", no_argument, NULL, 'c'},
  {"Current", no_argument, NULL, 'C'},
  {"domain", optional_argument, NULL, 'd'},
  {"Domain", optional_argument, NULL, 'D'},
  {"group", required_argument, NULL, 'g'},
  {"help", no_argument, NULL, 'h'},
  {"local", optional_argument, NULL, 'l'},
  {"Local", optional_argument, NULL, 'L'},
  {"id-offset", required_argument, NULL, 'o'},
  {"no-sids", no_argument, NULL, 's'},
  {"separator", required_argument, NULL, 'S'},
  {"users", no_argument, NULL, 'u'},
  {"unix", required_argument, NULL, 'U'},
  {"version", no_argument, NULL, 'V'},
  {0, no_argument, NULL, 0}
};

static char opts[] = "bcCd::D::g:hl::L::o:sS:uU:V";

static void
print_version ()
{
  printf ("mkgroup (cygwin) %d.%d.%d\n"
	  "Group File Generator\n"
	  "Copyright (C) 1997 - %s Red Hat, Inc.\n"
	  "This is free software; see the source for copying conditions.  There is NO\n"
	  "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
	  CYGWIN_VERSION_DLL_MAJOR / 1000,
	  CYGWIN_VERSION_DLL_MAJOR % 1000,
	  CYGWIN_VERSION_DLL_MINOR,
	  strrchr (__DATE__, ' ') + 1);
}

static PPOLICY_PRIMARY_DOMAIN_INFO p_dom;

static BOOL
fetch_primary_domain ()
{
  NTSTATUS status;
  LSA_OBJECT_ATTRIBUTES oa = { 0, 0, 0, 0, 0, 0 };
  LSA_HANDLE lsa;

  if (!p_dom)
    {
      status = LsaOpenPolicy (NULL, &oa, POLICY_EXECUTE, &lsa);
      if (!NT_SUCCESS (status))
	return FALSE;
      status = LsaQueryInformationPolicy (lsa, PolicyPrimaryDomainInformation,
					  (PVOID *) ((void *) &p_dom));
      LsaClose (lsa);
      if (!NT_SUCCESS (status))
	return FALSE;
    }
  return !!p_dom->Sid;
}

int
main (int argc, char **argv)
{
  int print_domlist = 0;
  domlist_t domlist[32];
  char *opt, *p, *ep;
  int print_current = 0;
  int print_system = 0;
  int print_builtin = 1;
  char *print_unix = NULL;
  const char *sep_char = "\\";
  DWORD id_offset = 10000, off;
  int c, i;
  char *disp_groupname = NULL;
  BOOL in_domain;
  int optional_args = 0;

  if (!isatty (1))
    setmode (1, O_BINARY);

  /* Use locale from environment.  If not set or set to "C", use UTF-8. */
  setlocale (LC_CTYPE, "");
  if (!strcmp (setlocale (LC_CTYPE, NULL), "C"))
    setlocale (LC_CTYPE, "en_US.UTF-8");
  in_domain = fetch_primary_domain ();
  fetch_current_pgrp_sid ();

  if (argc == 1)
    {
      print_special_by_sid (&sid_nt_auth, 1, SECURITY_LOCAL_SYSTEM_RID,
			    0, 0, 0, 0, 0, 0, 0);
      if (in_domain)
	{
	  if (!enum_local_groups (TRUE, NULL, sep_char, id_offset,
				  disp_groupname, print_builtin, 0))
	    enum_groups (TRUE, NULL, sep_char, id_offset, disp_groupname, 0);
	}
      else if (!enum_local_groups (FALSE, NULL, sep_char, 0, disp_groupname,
				   print_builtin, 0))
	enum_groups (FALSE, NULL, sep_char, 0, disp_groupname, 0);
      return 0;
    }

  unsetenv ("POSIXLY_CORRECT"); /* To get optional arg processing right. */
  while ((c = getopt_long (argc, argv, opts, longopts, NULL)) != EOF)
    switch (c)
      {
      case 'd':
      case 'D':
      case 'l':
      case 'L':
	if (print_domlist >= 32)
	  {
	    fprintf (stderr, "%s: Can not enumerate from more than 32 "
			     "domains and machines.\n",
			     program_invocation_short_name);
	    return 1;
	  }
	domlist[print_domlist].domain = (c == 'd' || c == 'D');
	opt = optarg ?:
	      argv[optind] && argv[optind][0] != '-' ? argv[optind] : NULL;
	if (argv[optind] && opt == argv[optind])
	  ++optional_args;
	for (i = 0; i < print_domlist; ++i)
	  if (domlist[i].domain == domlist[print_domlist].domain
	      && ((!domlist[i].str && !opt)
		  || (domlist[i].str && opt
		      && (off = strlen (domlist[i].str))
		      && !strncmp (domlist[i].str, opt, off)
		      && (!opt[off] || opt[off] == ','))))
	    {
	      fprintf (stderr, "%s: Duplicate %s '%s'.  Skipping...\n",
		       program_invocation_short_name,
		       domlist[i].domain ? "domain" : "machine",
		       domlist[i].str);
	      goto skip;
	    }
	if (!(domlist[print_domlist].str = opt))
	  print_system = 1;
	domlist[print_domlist].id_offset = UINT32_MAX;
	if (opt && (p = strchr (opt, ',')))
	  {
	    if (p == opt
		|| !isdigit ((unsigned char) p[1])
		|| (domlist[print_domlist].id_offset = strtol (p + 1, &ep, 10)
		    , *ep))
	      {
		fprintf (stderr, "%s: Malformed machine,offset string '%s'.  "
			 "Skipping...\n", program_invocation_short_name, opt);
		break;
	      }
	    *p = '\0';
	  }
	domlist[print_domlist++].with_dom = (c == 'D' || c == 'L');
skip:
	break;
      case 'S':
	sep_char = optarg;
	if (strlen (sep_char) > 1)
	  {
	    fprintf (stderr, "%s: Only one character allowed as domain\\user "
			     "separator character.\n",
			     program_invocation_short_name);
	    return 1;
	  }
	if (*sep_char == ':')
	  {
	    fprintf (stderr, "%s: Colon not allowed as domain\\user separator "
			     "character.\n", program_invocation_short_name);
	    return 1;
	  }
	break;
      case 'U':
	print_unix = optarg;
	break;
      case 'c':
	sep_char = NULL;
	/*FALLTHRU*/
      case 'C':
	print_current = 1;
	break;
      case 'o':
	id_offset = strtol (optarg, NULL, 10);
	break;
      case 'b':
	print_builtin = 0;
	break;
      case 's':
	break;
      case 'u':
	break;
      case 'g':
	disp_groupname = optarg;
	break;
      case 'h':
	usage (stdout);
	return 0;
      case 'V':
	print_version ();
	return 0;
      default:
	fprintf (stderr, "Try `%s --help' for more information.\n", argv[0]);
	return 1;
      }

  optind += optional_args;
  if (argv[optind])
    {
      fprintf (stderr,
	       "mkgroup: non-option command line argument `%s' is not allowed.\n"
	       "Try `mkgroup --help' for more information.\n", argv[optind]);
      exit (1);
    }

  /* Get 'system' group */
  if (!disp_groupname && print_system && print_builtin && print_domlist)
    {
      print_special_by_sid (&sid_nt_auth, 1, SECURITY_LOCAL_SYSTEM_RID,
			    0, 0, 0, 0, 0, 0, 0);
      print_special_by_name (L"NT SERVICE\\TrustedInstaller", -2);
    }

  off = id_offset;
  for (i = 0; i < print_domlist; ++i)
    {
      DWORD my_off = (domlist[i].domain || domlist[i].str)
		     ? domlist[i].id_offset != ULONG_MAX
		       ? domlist[i].id_offset : off : 0;
      if (!enum_local_groups (domlist[i].domain, domlist + i, sep_char,
			      my_off, disp_groupname, print_builtin, print_current))
	{
	  if (!domlist[i].domain && domlist[i].str && print_unix)
	    enum_unix_groups (domlist + i, sep_char, my_off, print_unix);
	  enum_groups (domlist[i].domain, domlist + i, sep_char, my_off,
		       disp_groupname, print_current);
	  if (my_off)
	    off += id_offset;
	}
    }

  if (print_current && !got_curr_pgrp)
    current_group (sep_char, off);

  return 0;
}
