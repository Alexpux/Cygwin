/* mkgroup.c:

   Copyright 1997, 1998 Cygnus Solutions.

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

#include <ctype.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdio.h>
#include <windows.h>
#include <sys/cygwin.h>
#include <getopt.h>
#include <lmaccess.h>
#include <lmapibuf.h>

SID_IDENTIFIER_AUTHORITY sid_world_auth = {SECURITY_WORLD_SID_AUTHORITY};
SID_IDENTIFIER_AUTHORITY sid_nt_auth = {SECURITY_NT_AUTHORITY};

NET_API_STATUS WINAPI (*netapibufferfree)(PVOID);
NET_API_STATUS WINAPI (*netgroupenum)(LPWSTR,DWORD,PBYTE*,DWORD,PDWORD,PDWORD,PDWORD);
NET_API_STATUS WINAPI (*netlocalgroupenum)(LPWSTR,DWORD,PBYTE*,DWORD,PDWORD,PDWORD,PDWORD);
NET_API_STATUS WINAPI (*netlocalgroupgetmembers)(LPWSTR,LPWSTR,DWORD,PBYTE*,DWORD,PDWORD,PDWORD,PDWORD);
NET_API_STATUS WINAPI (*netgetdcname)(LPWSTR,LPWSTR,PBYTE*);
NET_API_STATUS WINAPI (*netgroupgetusers)(LPWSTR,LPWSTR,DWORD,PBYTE*,DWORD,PDWORD,PDWORD,PDWORD);

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

BOOL
load_netapi ()
{
  HANDLE h = LoadLibrary ("netapi32.dll");

  if (!h)
    return FALSE;

  if (!(netapibufferfree = (void *) GetProcAddress (h, "NetApiBufferFree")))
    return FALSE;
  if (!(netgroupenum = (void *) GetProcAddress (h, "NetGroupEnum")))
    return FALSE;
  if (!(netgroupgetusers = (void *) GetProcAddress (h, "NetGroupGetUsers")))
    return FALSE;
  if (!(netlocalgroupenum = (void *) GetProcAddress (h, "NetLocalGroupEnum")))
    return FALSE;
  if (!(netlocalgroupgetmembers = (void *) GetProcAddress (h, "NetLocalGroupGetMembers")))
    return FALSE;
  if (!(netgetdcname = (void *) GetProcAddress (h, "NetGetDCName")))
    return FALSE;

  return TRUE;
}

char *
put_sid (PSID sid)
{
  static char s[512];
  char t[32];
  DWORD i;

  strcpy (s, "S-1-");
  sprintf(t, "%u", GetSidIdentifierAuthority (sid)->Value[5]);
  strcat (s, t);
  for (i = 0; i < *GetSidSubAuthorityCount (sid); ++i)
    {
      sprintf(t, "-%lu", *GetSidSubAuthority (sid, i));
      strcat (s, t);
    }
  return s;
}

void
psx_dir (char *in, char *out)
{
  if (isalpha (in[0]) && in[1] == ':')
    {
      sprintf (out, "/cygdrive/%c", in[0]);
      in += 2;
      out += strlen (out);
    }

  while (*in)
    {
      if (*in == '\\')
	*out = '/';
      else
	*out = *in;
      in++;
      out++;
    }

  *out = '\0';
}

void
uni2ansi (LPWSTR wcs, char *mbs, int size)
{
  if (wcs)
    WideCharToMultiByte (CP_ACP, 0, wcs, -1, mbs, size, NULL, NULL);
  else
    *mbs = '\0';
}

void
enum_local_users (LPWSTR groupname)
{
  LOCALGROUP_MEMBERS_INFO_1 *buf1;
  DWORD entries = 0;
  DWORD total = 0;
  DWORD reshdl = 0;

  if (!netlocalgroupgetmembers (NULL, groupname,
				1, (LPBYTE *) &buf1,
				MAX_PREFERRED_LENGTH,
				&entries, &total, &reshdl))
    {
      int i, first = 1;

      for (i = 0; i < entries; ++i)
	if (buf1[i].lgrmi1_sidusage == SidTypeUser)
	  {
	    char user[256];

	    if (!first)
	      printf (",");
	    first = 0;
	    uni2ansi (buf1[i].lgrmi1_name, user, sizeof (user));
	    printf ("%s", user);
	  }
      netapibufferfree (buf1);
    }
}

int
enum_local_groups (int print_sids, int print_users)
{
  LOCALGROUP_INFO_0 *buffer;
  DWORD entriesread = 0;
  DWORD totalentries = 0;
  DWORD resume_handle = 0;
  DWORD rc;

  do
    {
      DWORD i;

      rc = netlocalgroupenum (NULL, 0, (LPBYTE *) &buffer, 1024,
			      &entriesread, &totalentries, &resume_handle);
      switch (rc)
	{
	case ERROR_ACCESS_DENIED:
	  fprintf (stderr, "Access denied\n");
	  exit (1);

	case ERROR_MORE_DATA:
	case ERROR_SUCCESS:
	  break;

	default:
	  fprintf (stderr, "NetLocalGroupEnum() failed with %ld\n", rc);
	  exit (1);
	}

      for (i = 0; i < entriesread; i++)
	{
	  char localgroup_name[100];
	  char domain_name[100];
	  DWORD domname_len = 100;
	  char psid_buffer[1024];
	  PSID psid = (PSID) psid_buffer;
	  DWORD sid_length = 1024;
	  DWORD gid;
	  SID_NAME_USE acc_type;
	  uni2ansi (buffer[i].lgrpi0_name, localgroup_name, sizeof (localgroup_name));

	  if (!LookupAccountName (NULL, localgroup_name, psid,
				  &sid_length, domain_name, &domname_len,
				  &acc_type))
	    {
	      fprintf (stderr, "LookupAccountName(%s) failed with %ld\n",
		       localgroup_name, GetLastError ());
	      continue;
	    }
          else if (acc_type == SidTypeDomain)
            {
              char domname[356];

              strcpy (domname, domain_name);
              strcat (domname, "\\");
              strcat (domname, localgroup_name);
              sid_length = 1024;
              domname_len = 100;
              if (!LookupAccountName (NULL, domname,
                                      psid, &sid_length,
                                      domain_name, &domname_len,
                                      &acc_type))
                {
                  fprintf (stderr,
                           "LookupAccountName(%s) failed with error %ld\n",
                           localgroup_name, GetLastError ());
                  continue;
                }
            }

	  gid = *GetSidSubAuthority (psid, *GetSidSubAuthorityCount(psid) - 1);

	  printf ("%s:%s:%ld:", localgroup_name,
                                print_sids ? put_sid (psid) : "",
                                gid);
	  if (print_users)
	    enum_local_users (buffer[i].lgrpi0_name);
	  printf ("\n");
	}

      netapibufferfree (buffer);

    }
  while (rc == ERROR_MORE_DATA);

  return 0;
}

void
enum_users (LPWSTR servername, LPWSTR groupname)
{
  GROUP_USERS_INFO_0 *buf1;
  DWORD entries = 0;
  DWORD total = 0;
  DWORD reshdl = 0;

  if (!netgroupgetusers (servername, groupname,
			 0, (LPBYTE *) &buf1,
			 MAX_PREFERRED_LENGTH,
			 &entries, &total, &reshdl))
    {
      int i, first = 1;

      for (i = 0; i < entries; ++i)
	{
	  char user[256];

	  if (!first)
	    printf (",");
	  first = 0;
	  uni2ansi (buf1[i].grui0_name, user, sizeof (user));
	  printf ("%s", user);
	}
      netapibufferfree (buf1);
    }
}

void
enum_groups (LPWSTR servername, int print_sids, int print_users, int id_offset)
{
  GROUP_INFO_2 *buffer;
  DWORD entriesread = 0;
  DWORD totalentries = 0;
  DWORD resume_handle = 0;
  DWORD rc;
  char ansi_srvname[256];

  if (servername)
    uni2ansi (servername, ansi_srvname, sizeof (ansi_srvname));

  do
    {
      DWORD i;

      rc = netgroupenum (servername, 2, (LPBYTE *) & buffer, 1024,
		         &entriesread, &totalentries, &resume_handle);
      switch (rc)
	{
	case ERROR_ACCESS_DENIED:
	  fprintf (stderr, "Access denied\n");
	  exit (1);

	case ERROR_MORE_DATA:
	case ERROR_SUCCESS:
	  break;

	default:
	  fprintf (stderr, "NetGroupEnum() failed with %ld\n", rc);
	  exit (1);
	}

      for (i = 0; i < entriesread; i++)
	{
	  char groupname[100];
	  char domain_name[100];
	  DWORD domname_len = 100;
	  char psid_buffer[1024];
	  PSID psid = (PSID) psid_buffer;
	  DWORD sid_length = 1024;
	  SID_NAME_USE acc_type;

	  int gid = buffer[i].grpi2_group_id;
	  uni2ansi (buffer[i].grpi2_name, groupname, sizeof (groupname));
          if (print_sids)
            {
              if (!LookupAccountName (servername ? ansi_srvname : NULL,
                                      groupname,
                                      psid, &sid_length,
                                      domain_name, &domname_len,
			              &acc_type))
                {
                  fprintf (stderr,
                           "LookupAccountName (%s, %s) failed with error %ld\n",
                           servername ? ansi_srvname : "NULL",
                           groupname,
                           GetLastError ());
                  continue;
                }
              else if (acc_type == SidTypeDomain)
                {
                  char domname[356];

                  strcpy (domname, domain_name);
                  strcat (domname, "\\");
                  strcat (domname, groupname);
                  sid_length = 1024;
                  domname_len = 100;
                  if (!LookupAccountName (servername ? ansi_srvname : NULL,
                                          domname,
                                          psid, &sid_length,
                                          domain_name, &domname_len,
			                  &acc_type))
                    {
                      fprintf (stderr,
                               "LookupAccountName(%s,%s) failed with error %ld\n",
                               servername ? ansi_srvname : "NULL",
                               domname,
                               GetLastError ());
                      continue;
                    }
                }
            }
	  printf ("%s:%s:%d:", groupname,
                               print_sids ? put_sid (psid) : "",
                               gid + id_offset);
	  if (print_users)
	    enum_users (servername, buffer[i].grpi2_name);
	  printf ("\n");
	}

      netapibufferfree (buffer);

    }
  while (rc == ERROR_MORE_DATA);

  if (servername)
    netapibufferfree (servername);
}

void
print_special (int print_sids,
	       PSID_IDENTIFIER_AUTHORITY auth, BYTE cnt,
	       DWORD sub1, DWORD sub2, DWORD sub3, DWORD sub4,
	       DWORD sub5, DWORD sub6, DWORD sub7, DWORD sub8)
{
  char name[256], dom[256];
  DWORD len, len2, rid;
  PSID sid;
  SID_NAME_USE use;

  if (AllocateAndInitializeSid (auth, cnt, sub1, sub2, sub3, sub4,
  				sub5, sub6, sub7, sub8, &sid))
    {
      if (LookupAccountSid (NULL, sid,
			    name, (len = 256, &len),
			    dom, (len2 = 256, &len),
			    &use))
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
	  printf ("%s:%s:%lu:\n", name,
				 print_sids ? put_sid (sid) : "",
				 rid);
        }
      FreeSid (sid);
    }
}

int
usage ()
{
  fprintf (stderr, "Usage: mkgroup [OPTION]... [domain]\n\n");
  fprintf (stderr, "This program prints a /etc/group file to stdout\n\n");
  fprintf (stderr, "Options:\n");
  fprintf (stderr, "   -l,--local             print local group information\n");
  fprintf (stderr, "   -d,--domain            print global group information from the domain\n");
  fprintf (stderr, "                          specified (or from the current domain if there is\n");
  fprintf (stderr, "                          no domain specified)\n");
  fprintf (stderr, "   -o,--id-offset offset  change the default offset (10000) added to uids\n");
  fprintf (stderr, "                          in domain accounts.\n");
  fprintf (stderr, "   -s,--no-sids           don't print SIDs in pwd field\n");
  fprintf (stderr, "                          (this affects ntsec)\n");
  fprintf (stderr, "   -u,--users             print user list in gr_mem field\n");
  fprintf (stderr, "   -?,--help              print this message\n\n");
  fprintf (stderr, "One of `-l' or `-d' must be given on NT/W2K.\n");
  return 1;
}

struct option longopts[] = {
  {"local", no_argument, NULL, 'l'},
  {"domain", no_argument, NULL, 'd'},
  {"id-offset", required_argument, NULL, 'o'},
  {"no-sids", no_argument, NULL, 's'},
  {"users", no_argument, NULL, 'u'},
  {"help", no_argument, NULL, 'h'},
  {0, no_argument, NULL, 0}
};

char opts[] = "ldo:suh";

int
main (int argc, char **argv)
{
  LPWSTR servername;
  DWORD rc = ERROR_SUCCESS;
  WCHAR domain_name[100];
  int print_local = 0;
  int print_domain = 0;
  int print_sids = 1;
  int print_users = 0;
  int domain_specified = 0;
  int id_offset = 10000;
  int i;

  char name[256], dom[256];
  DWORD len, len2;
  PSID csid;
  SID_NAME_USE use;

  if (GetVersion () < 0x80000000)
    {
      if (argc == 1)
	return usage ();
      else
	{
	  while ((i = getopt_long (argc, argv, opts, longopts, NULL)) != EOF)
	    switch (i)
	      {
	      case 'l':
		print_local = 1;
		break;
	      case 'd':
		print_domain = 1;
		break;
	      case 'o':
		id_offset = strtol (optarg, NULL, 10);
		break;
	      case 's':
		print_sids = 0;
		break;
	      case 'u':
		print_users = 1;
		break;
	      case 'h':
		return usage ();
	      default:
		fprintf (stderr, "Try `%s --help' for more information.\n", argv[0]);
		return 1;
	      }
	  if (!print_local && !print_domain)
	    {
	      fprintf (stderr, "%s: Specify one of `-l' or `-d'\n", argv[0]);
	      return 1;
	    }
	  if (optind < argc)
	    {
	      if (!print_domain)
		{
		  fprintf (stderr, "%s: A domain name is only accepted "
				   "when `-d' is given.\n", argv[0]);
		  return 1;
		}
	      mbstowcs (domain_name, argv[optind], (strlen (argv[optind]) + 1));
	      domain_specified = 1;
	    }
	}
    }

  /* This takes Windows 9x/ME into account. */
  if (GetVersion () >= 0x80000000)
    {
      printf ("unknown::%ld:\n", DOMAIN_ALIAS_RID_ADMINS);
      return 0;
    }
  
  if (!load_netapi ())
    {
      fprintf (stderr, "Failed loading symbols from netapi32.dll "
      		       "with error %lu\n", GetLastError ());
      return 1;
    }

  /*
   * Get `Everyone' group
  */
  print_special (print_sids, &sid_world_auth, 1, SECURITY_WORLD_RID,
			     0, 0, 0, 0, 0, 0, 0);
  /*
   * Get `system' group
  */
  print_special (print_sids, &sid_nt_auth, 1, SECURITY_LOCAL_SYSTEM_RID,
			     0, 0, 0, 0, 0, 0, 0);
  if (print_local)
    {
      /*
       * Get `None' group
      */
      len = 256;
      GetComputerName (name, &len);
      csid = (PSID) malloc (1024);
      len = 1024;
      len2 = 256;
      LookupAccountName (NULL, name,
			 csid, &len,
			 dom, &len,
			 &use);
      print_special (print_sids, GetSidIdentifierAuthority (csid), 5,
				 *GetSidSubAuthority (csid, 0),
				 *GetSidSubAuthority (csid, 1),
				 *GetSidSubAuthority (csid, 2),
				 *GetSidSubAuthority (csid, 3),
				 513,
				 0,
				 0,
				 0);
      free (csid);
    }

  if (print_domain)
    {
      if (domain_specified)
	rc = netgetdcname (NULL, domain_name, (LPBYTE *) & servername);

      else
	rc = netgetdcname (NULL, NULL, (LPBYTE *) & servername);

      if (rc != ERROR_SUCCESS)
	{
	  fprintf (stderr, "Cannot get PDC, code = %ld\n", rc);
	  exit (1);
	}

      enum_groups (servername, print_sids, print_users, id_offset);
    }

  if (print_local)
    enum_local_groups (print_sids, print_users);

  return 0;
}
