/* mkpasswd.c:

   Copyright 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2005, 2006,
   2008 Red Hat, Inc.

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

#define _WIN32_WINNT 0x0600
#include <ctype.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <io.h>
#include <sys/fcntl.h>
#include <sys/cygwin.h>
#include <windows.h>
#include <lm.h>
#include <iptypes.h>
#include <wininet.h>
#include <ntsecapi.h>
#include <dsgetdc.h>
#include <ntdef.h>

#define print_win_error(x) _print_win_error(x, __LINE__)

#define MAX_SID_LEN 40

static const char version[] = "$Revision$";

extern char *__progname;

SID_IDENTIFIER_AUTHORITY sid_world_auth = {SECURITY_WORLD_SID_AUTHORITY};
SID_IDENTIFIER_AUTHORITY sid_nt_auth = {SECURITY_NT_AUTHORITY};

NET_API_STATUS WINAPI (*dsgetdcname)(LPWSTR,LPWSTR,GUID*,LPWSTR,ULONG,PDOMAIN_CONTROLLER_INFOW*);

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

typedef struct 
{
  char *str;
  BOOL with_dom;
} domlist_t;

void
_print_win_error(DWORD code, int line)
{
  char buf[4096];

  if (FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM
      | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL,
      code,
      MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPTSTR) buf, sizeof (buf), NULL))
    fprintf (stderr, "mkpasswd (%d): [%lu] %s", line, code, buf);
  else
    fprintf (stderr, "mkpasswd (%d): error %lu", line, code);
}

void
load_dsgetdcname ()
{
  HANDLE h = LoadLibrary ("netapi32.dll");

  if (h)
    dsgetdcname = (void *) GetProcAddress (h, "DsGetDcNameW");
}

static PWCHAR
get_dcname (char *domain)
{
  static WCHAR server[INTERNET_MAX_HOST_NAME_LENGTH + 1];
  DWORD rc;
  PWCHAR servername;
  WCHAR domain_name[MAX_DOMAIN_NAME_LEN + 1];
  PDOMAIN_CONTROLLER_INFOW pdci = NULL;

  if (dsgetdcname)
    {
      if (domain)
	{
	  mbstowcs (domain_name, domain, strlen (domain) + 1);
	  rc = dsgetdcname (NULL, domain_name, NULL, NULL, 0, &pdci);
	}
      else
	rc = dsgetdcname (NULL, NULL, NULL, NULL, 0, &pdci);
      if (rc != ERROR_SUCCESS)
	{
	  print_win_error(rc);
	  return (PWCHAR) -1;
	}
      wcscpy (server, pdci->DomainControllerName);
      NetApiBufferFree (pdci);
    }
  else
    {
      rc = NetGetDCName (NULL, NULL, (void *) &servername);
      if (rc == ERROR_SUCCESS && domain)
	{
	  LPWSTR server = servername;
	  mbstowcs (domain_name, domain, strlen (domain) + 1);
	  rc = NetGetDCName (server, domain_name, (void *) &servername);
	  NetApiBufferFree (server);
	}
      if (rc != ERROR_SUCCESS)
	{
	  print_win_error(rc);
	  return (PWCHAR) -1;
	}
      wcscpy (server, servername);
      NetApiBufferFree ((PVOID) servername);
    }
  return server;
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
    wcstombs (mbs, wcs, size);
  else
    *mbs = '\0';
}

void
current_user (int print_cygpath, const char *sep, const char *passed_home_path,
	      int id_offset, const char *disp_username)
{
  DWORD len;
  HANDLE ptok;
  struct {
    PSID psid;
    int buffer[10];
  } tu, tg;
  char user[UNLEN + 1];
  char dom[MAX_DOMAIN_NAME_LEN + 1];
  DWORD ulen = UNLEN + 1;
  DWORD dlen = MAX_DOMAIN_NAME_LEN + 1;
  SID_NAME_USE acc_type;
  int uid, gid;
  char homedir_psx[PATH_MAX] = {0}, homedir_w32[MAX_PATH] = {0};

  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &ptok)
      || !GetTokenInformation (ptok, TokenUser, &tu, sizeof tu, &len)
      || !GetTokenInformation (ptok, TokenPrimaryGroup, &tg, sizeof tg, &len)
      || !CloseHandle (ptok)
      || !LookupAccountSidA (NULL, tu.psid, user, &ulen, dom, &dlen, &acc_type))
    {
      print_win_error (GetLastError ());
      return;
    }

  uid = *GetSidSubAuthority (tu.psid, *GetSidSubAuthorityCount(tu.psid) - 1);
  gid = *GetSidSubAuthority (tg.psid, *GetSidSubAuthorityCount(tg.psid) - 1);
  if (passed_home_path[0] == '\0')
    {
      char *envhome = getenv ("HOME");
      char *envhomedrive = getenv ("HOMEDRIVE");
      char *envhomepath = getenv ("HOMEPATH");

      if (envhome && envhome[0])
        {
	  if (print_cygpath)
	    cygwin_conv_path (CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE, envhome,
			      homedir_psx, PATH_MAX);
	  else
	    psx_dir (envhome, homedir_psx);
	}
      else if (envhomepath && envhomepath[0])
        {
	  if (envhomedrive)
	    strlcpy (homedir_w32, envhomedrive, sizeof (homedir_w32));
	  if (envhomepath[0] != '\\')
	    strlcat (homedir_w32, "\\", sizeof (homedir_w32));
	  strlcat (homedir_w32, envhomepath, sizeof (homedir_w32));
	  if (print_cygpath)
	    cygwin_conv_path (CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE, homedir_w32,
			      homedir_psx, PATH_MAX);
	  else
	    psx_dir (homedir_w32, homedir_psx);
	}
      else
        {
	  strlcpy (homedir_psx, "/home/", sizeof (homedir_psx));
	  strlcat (homedir_psx, user, sizeof (homedir_psx));
	}
    }
  else
    {
      strlcpy (homedir_psx, passed_home_path, sizeof (homedir_psx));
      strlcat (homedir_psx, user, sizeof (homedir_psx));
    }

  printf ("%s%s%s:unused:%u:%u:U-%s\\%s,%s:%s:/bin/bash\n",
	  sep ? dom : "",
	  sep ?: "",
	  user,
	  uid + id_offset,
	  gid + id_offset,
	  dom,
	  user,
	  put_sid (tu.psid),
	  homedir_psx);
}

int
enum_users (BOOL domain, domlist_t *dom_or_machine, const char *sep,
	    int print_cygpath, const char *passed_home_path, int id_offset,
	    char *disp_username)
{
  WCHAR machine[INTERNET_MAX_HOST_NAME_LENGTH + 1];
  PWCHAR servername = NULL;
  char *d_or_m = dom_or_machine ? dom_or_machine->str : NULL;
  BOOL with_dom = dom_or_machine ? dom_or_machine->with_dom : FALSE;
  USER_INFO_3 *buffer;
  DWORD entriesread = 0;
  DWORD totalentries = 0;
  DWORD resume_handle = 0;
  DWORD rc;
  WCHAR uni_name[UNLEN + 1];
  
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
		   __progname, d_or_m);
	  return 1;
	}
      servername = machine;
    }

  do
    {
      DWORD i;

      if (disp_username != NULL)
	{
	  mbstowcs (uni_name, disp_username, UNLEN + 1);
	  rc = NetUserGetInfo (servername, (LPWSTR) &uni_name, 3,
			       (void *) &buffer);
	  entriesread = 1;
	}
      else 
	rc = NetUserEnum (servername, 3, FILTER_NORMAL_ACCOUNT,
			  (void *) &buffer, MAX_PREFERRED_LENGTH,
			  &entriesread, &totalentries, &resume_handle);
      switch (rc)
	{
	case ERROR_ACCESS_DENIED:
	  print_win_error(rc);
	  return 1;

	case ERROR_MORE_DATA:
	case ERROR_SUCCESS:
	  break;

	default:
	  print_win_error(rc);
	  return 1;
	}

      for (i = 0; i < entriesread; i++)
	{
	  char homedir_psx[PATH_MAX];
	  char homedir_w32[MAX_PATH];
	  WCHAR domain_name[MAX_DOMAIN_NAME_LEN + 1];
	  DWORD domname_len = MAX_DOMAIN_NAME_LEN + 1;
	  char psid_buffer[MAX_SID_LEN];
	  PSID psid = (PSID) psid_buffer;
	  DWORD sid_length = MAX_SID_LEN;
	  SID_NAME_USE acc_type;

	  int uid = buffer[i].usri3_user_id;
	  int gid = buffer[i].usri3_primary_group_id;
	  homedir_w32[0] = homedir_psx[0] = '\0';
	  if (passed_home_path[0] == '\0')
	    {
	      uni2ansi (buffer[i].usri3_home_dir, homedir_w32,
			sizeof (homedir_w32));
	      if (homedir_w32[0] != '\0')
		{
		  if (print_cygpath)
		    cygwin_conv_path (CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE,
				      homedir_w32, homedir_psx, PATH_MAX);
		  else
		    psx_dir (homedir_w32, homedir_psx);
		}
	      else
		uni2ansi (buffer[i].usri3_name,
			  stpcpy (homedir_psx, "/home/"), PATH_MAX - 6);
	    }
	  else
	    uni2ansi (buffer[i].usri3_name,
		      stpcpy (homedir_psx, passed_home_path),
		      PATH_MAX - strlen (passed_home_path));

	  if (!LookupAccountNameW (servername, buffer[i].usri3_name,
				   psid, &sid_length, domain_name,
				   &domname_len, &acc_type))
	    {
	      print_win_error(GetLastError ());
	      fprintf(stderr, " (%ls)\n", buffer[i].usri3_name);
	      continue;
	    }
	  else if (acc_type == SidTypeDomain)
	    {
	      WCHAR domname[MAX_DOMAIN_NAME_LEN + UNLEN + 2];

	      wcscpy (domname, domain_name);
	      wcscat (domname, L"\\");
	      wcscat (domname, buffer[i].usri3_name);
	      sid_length = MAX_SID_LEN;
	      domname_len = sizeof (domname);
	      if (!LookupAccountNameW (servername, domname, psid,
				       &sid_length, domain_name,
				       &domname_len, &acc_type))
		{
		  print_win_error(GetLastError ());
		  fprintf(stderr, " (%ls)\n", domname);
		  continue;
		}
	    }

	  printf ("%ls%s%ls:unused:%u:%u:%ls%sU-%ls\\%ls,%s:%s:/bin/bash\n",
		  with_dom ? domain_name : L"",
		  with_dom ? sep : "",
	  	  buffer[i].usri3_name,
		  uid + id_offset,
		  gid + id_offset,
		  buffer[i].usri3_full_name ?: L"",
		  buffer[i].usri3_full_name 
		  && buffer[i].usri3_full_name[0] ? "," : "",
		  domain_name,
		  buffer[i].usri3_name,
		  put_sid (psid),
		  homedir_psx);
	}

      NetApiBufferFree (buffer);

    }
  while (rc == ERROR_MORE_DATA);

  return 0;
}

void
print_special (PSID_IDENTIFIER_AUTHORITY auth, BYTE cnt,
	       DWORD sub1, DWORD sub2, DWORD sub3, DWORD sub4,
	       DWORD sub5, DWORD sub6, DWORD sub7, DWORD sub8)
{
  char name[UNLEN + 1], dom[MAX_DOMAIN_NAME_LEN + 1];
  DWORD len, len2, rid;
  PSID sid;
  SID_NAME_USE use;

  if (AllocateAndInitializeSid (auth, cnt, sub1, sub2, sub3, sub4,
  				sub5, sub6, sub7, sub8, &sid))
    {
      if (LookupAccountSid (NULL, sid,
			    name, (len = UNLEN + 1, &len),
			    dom, (len2 = MAX_DOMAIN_NAME_LEN + 1, &len),
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
	  printf ("%s:*:%lu:%lu:,%s::\n",
		  name, rid, rid == 18 ? 544 : rid, /* SYSTEM hack */
		  put_sid (sid));
        }
      FreeSid (sid);
    }
}

int
usage (FILE * stream)
{
  fprintf (stream,
"Usage: mkpasswd [OPTIONS]...\n"
"Print /etc/passwd file to stdout\n"
"\n"
"Options:\n"
"   -l,--local [machine]    print local user accounts (from local machine\n"
"                           if no machine specified)\n"
"   -L,--Local [machine]    ditto, but generate username with machine prefix\n"
"   -d,--domain [domain]    print domain accounts (from current domain\n"
"                           if no domain specified)\n"
"   -D,--Domain [domain]    ditto, but generate username with domain prefix\n"
"   -c,--current            print current user\n"
"   -C,--Current            ditto, but generate username with machine or\n"
"                           domain prefix\n"
"   -S,--separator char     for -L, -D, -C use character char as domain\\user\n"
"                           separator in username instead of the default '\\'\n"
"   -o,--id-offset offset   change the default offset (10000) added to uids\n"
"                           in domain or foreign server accounts.\n"
"   -u,--username username  only return information for the specified user\n"
"                           one of -l, -L, -d, -D must be specified, too\n"
"   -p,--path-to-home path  use specified path instead of user account home dir\n"
"                           or /home prefix\n"
"   -m,--no-mount           don't use mount points for home dir\n"
"   -s,--no-sids            (ignored)\n"
"   -g,--local-groups       (ignored)\n"
"   -h,--help               displays this message\n"
"   -v,--version            version information and exit\n"
"\n"
"Default is to print local accounts on stand-alone machines, domain accounts\n"
"on domain controllers and domain member machines.\n");
  return 1;
}

struct option longopts[] = {
  {"current", no_argument, NULL, 'c'},
  {"Current", no_argument, NULL, 'C'},
  {"domain", optional_argument, NULL, 'd'},
  {"Domain", optional_argument, NULL, 'D'},
  {"local-groups", no_argument, NULL, 'g'},
  {"help", no_argument, NULL, 'h'},
  {"local", optional_argument, NULL, 'l'},
  {"Local", optional_argument, NULL, 'L'},
  {"no-mount", no_argument, NULL, 'm'},
  {"id-offset", required_argument, NULL, 'o'},
  {"path-to-home", required_argument, NULL, 'p'},
  {"no-sids", no_argument, NULL, 's'},
  {"separator", required_argument, NULL, 'S'},
  {"username", required_argument, NULL, 'u'},
  {"version", no_argument, NULL, 'v'},
  {0, no_argument, NULL, 0}
};

char opts[] = "cCd::D::ghl::L::mo:sS:p:u:v";

static void
print_version ()
{
  const char *v = strchr (version, ':');
  int len;
  if (!v)
    {
      v = "?";
      len = 1;
    }
  else
    {
      v += 2;
      len = strchr (v, ' ') - v;
    }
  printf ("\
mkpasswd (cygwin) %.*s\n\
passwd File Generator\n\
Copyright 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2005, 2006, 2008 Red Hat, Inc.\n\
Compiled on %s\n\
", len, v, __DATE__);
}

static void
enum_std_accounts ()
{
  /* Generate service starter account entries. */
  printf ("SYSTEM:*:18:544:,S-1-5-18::\n");
  printf ("LocalService:*:19:544:U-NT AUTHORITY\\LocalService,S-1-5-19::\n");
  printf ("NetworkService:*:20:544:U-NT AUTHORITY\\NetworkService,S-1-5-20::\n");
  /* Get 'administrators' group (has localized name). */
  print_special (&sid_nt_auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
		 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0);
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
      status = LsaOpenPolicy (NULL, &oa, POLICY_VIEW_LOCAL_INFORMATION, &lsa);
      if (!NT_SUCCESS (status))
	return FALSE;
      status = LsaQueryInformationPolicy (lsa, PolicyPrimaryDomainInformation,
					  (PVOID *) &p_dom);
      LsaClose (lsa);
      if (!NT_SUCCESS (status))
	return FALSE;
    }
  return !!p_dom->Sid;
}

int
main (int argc, char **argv)
{
  int print_local = 0;
  domlist_t locals[16];
  int print_domain = 0;
  domlist_t domains[16];
  char *opt;
  int print_cygpath = 1;
  int print_current = 0;
  const char *sep_char = "\\";
  int id_offset = 10000;
  int c, i, off;
  char *disp_username = NULL;
  char passed_home_path[PATH_MAX];
  BOOL in_domain;

  passed_home_path[0] = '\0';
  if (!isatty (1))
    setmode (1, O_BINARY);

  load_dsgetdcname ();
  in_domain = fetch_primary_domain ();
  if (argc == 1)
    {
      enum_std_accounts ();
      if (in_domain)
	enum_users (TRUE, NULL, sep_char, print_cygpath, passed_home_path,
		    10000, disp_username);
      else
	enum_users (FALSE, NULL, sep_char, print_cygpath, passed_home_path, 0,
		    disp_username);
      return 0;
    }

  while ((c = getopt_long (argc, argv, opts, longopts, NULL)) != EOF)
    switch (c)
      {
      case 'l':
      case 'L':
	if (print_local >= 16)
	  {
	    fprintf (stderr, "%s: Can not enumerate from more than 16 "
			     "servers.\n", __progname);
	    return 1;
	  }
	opt = optarg ?:
	      argv[optind] && argv[optind][0] != '-' ? argv[optind] : NULL;
	for (i = 0; i < print_local; ++i)
	  if ((!locals[i].str && !opt)
	      || (locals[i].str && opt && !strcmp (locals[i].str, opt)))
	    goto skip_local;
	locals[print_local].str = opt;
	locals[print_local++].with_dom = c == 'L';
skip_local:
	break;
      case 'd':
      case 'D':
	if (print_domain >= 16)
	  {
	    fprintf (stderr, "%s: Can not enumerate from more than 16 "
			     "domains.\n", __progname);
	    return 1;
	  }
	opt = optarg ?:
	      argv[optind] && argv[optind][0] != '-' ? argv[optind] : NULL;
	for (i = 0; i < print_domain; ++i)
	  if ((!domains[i].str && !opt)
	      || (domains[i].str && opt && !strcmp (domains[i].str, opt)))
	    goto skip_domain;
	domains[print_domain].str = opt;
	domains[print_domain++].with_dom = c == 'D';
skip_domain:
	break;
      case 'S':
	sep_char = optarg;
	if (strlen (sep_char) > 1)
	  {
	    fprintf (stderr, "%s: Only one character allowed as domain\\user "
			     "separator character.\n", __progname);
	    return 1;
	  }
	if (*sep_char == ':')
	  {
	    fprintf (stderr, "%s: Colon not allowed as domain\\user separator "
			     "character.\n", __progname);
	    return 1;
	  }
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
      case 'g':
	break;
      case 's':
	break;
      case 'm':
	print_cygpath = 0;
	break;
      case 'p':
	if (optarg[0] != '/')
	{
	  fprintf (stderr, "%s: '%s' is not a fully qualified path.\n",
		   __progname, optarg);
	  return 1;
	}
	strcpy (passed_home_path, optarg);
	if (optarg[strlen (optarg)-1] != '/')
	  strcat (passed_home_path, "/");
	break;
      case 'u':
	disp_username = optarg;
	break;
      case 'h':
	usage (stdout);
	return 0;
      case 'v':
	print_version ();
	return 0;
      default:
	fprintf (stderr, "Try '%s --help' for more information.\n", __progname);
	return 1;
      }

  if (optind < argc - 1)
    usage (stdout);

  off = 1;
  for (i = 0; i < print_local; ++i)
    {
      if (locals[i].str)
	enum_users (FALSE, locals + i, sep_char, print_cygpath,
		    passed_home_path, id_offset * off++, disp_username);
      else
	{
	  enum_std_accounts ();
	  enum_users (FALSE, locals + i, sep_char, print_cygpath,
		      passed_home_path, 0, disp_username);
	}
    }

  for (i = 0; i < print_domain; ++i)
    enum_users (TRUE, domains + i, sep_char, print_cygpath, passed_home_path,
		id_offset * off++, disp_username);

  if (print_current)
    current_user (print_cygpath, sep_char, passed_home_path, id_offset, disp_username);

  return 0;
}
