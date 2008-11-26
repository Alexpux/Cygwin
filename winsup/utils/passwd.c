/* passwd.c: Changing passwords and managing account information

   Copyright 1999, 2000, 2001, 2002, 2003, 2008 Red Hat, Inc.

   Written by Corinna Vinschen <corinna.vinschen@cityweb.de>

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include <windows.h>
#include <wininet.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <lmcons.h>
#include <lmapibuf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <sys/cygwin.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

#define USER_PRIV_ADMIN		 2

static const char version[] = "$Revision$";
static char *prog_name;

static struct option longopts[] =
{
  {"cannot-change", no_argument, NULL, 'c'},
  {"can-change", no_argument, NULL, 'C'},
  {"logonserver", required_argument, NULL, 'd'},
  {"never-expires", no_argument, NULL, 'e'},
  {"expires", no_argument, NULL, 'E'},
  {"help", no_argument, NULL, 'h' },
  {"inactive", required_argument, NULL, 'i'},
  {"lock", no_argument, NULL, 'l'},
  {"minage", required_argument, NULL, 'n'},
  {"pwd-not-required", no_argument, NULL, 'p'},
  {"pwd-required", no_argument, NULL, 'P'},
  {"unlock", no_argument, NULL, 'u'},
  {"version", no_argument, NULL, 'v'},
  {"maxage", required_argument, NULL, 'x'},
  {"length", required_argument, NULL, 'L'},
  {"status", no_argument, NULL, 'S'},
  { "reg-store-pwd", no_argument, NULL, 'R'},
  {NULL, 0, NULL, 0}
};

static char opts[] = "cCd:eEhi:ln:pPuvx:L:SR";

int
eprint (int with_name, const char *fmt, ...)
{
  va_list ap;

  if (with_name)
    fprintf(stderr, "%s: ", prog_name);
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  fprintf(stderr, "\n");
  return 1;
}

int
EvalRet (int ret, const char *user)
{
  switch (ret)
    {
    case NERR_Success:
      return 0;

    case ERROR_ACCESS_DENIED:
      if (! user)
        eprint (0, "You may not change password expiry information.");
      else
        eprint (0, "You may not change the password for %s.", user);
      break;

      eprint (0, "Bad password: Invalid.");
      break;

    case NERR_PasswordTooShort:
      eprint (0, "Bad password: Too short.");
      break;

    case NERR_UserNotFound:
      eprint (1, "unknown user %s", user);
      break;

    case ERROR_INVALID_PASSWORD:
    case NERR_BadPassword:
      eprint (0, "Incorrect password for %s.", user);
      eprint (0, "The password for %s is unchanged.", user);
      break;

    default:
      eprint (1, "unrecoverable error %d", ret);
      break;
    }
  return 1;
}

PUSER_INFO_3
GetPW (char *user, int print_win_name, LPCWSTR server)
{
  char usr_buf[UNLEN + 1];
  WCHAR name[2 * (UNLEN + 1)];
  DWORD ret;
  PUSER_INFO_3 ui;
  struct passwd *pw;
  char *domain = (char *) alloca (INTERNET_MAX_HOST_NAME_LENGTH + 1);
     
  /* Try getting a Win32 username in case the user edited /etc/passwd */
  if ((pw = getpwnam (user)))
    {
      cygwin_internal (CW_EXTRACT_DOMAIN_AND_USER, pw, domain, usr_buf);
      if (strcasecmp (pw->pw_name, usr_buf))
	{
	  /* Hack to avoid problem with LookupAccountSid after impersonation */
	  if (strcasecmp (usr_buf, "SYSTEM"))
	    {
	      user = usr_buf;
	      if (print_win_name)
		printf ("Windows username : %s\n", user);
	    }
	}
    }
  MultiByteToWideChar (CP_ACP, 0, user, -1, name, 2 * (UNLEN + 1));
  ret = NetUserGetInfo (server, name, 3, (void *) &ui);
  return EvalRet (ret, user) ? NULL : ui;
}

int
ChangePW (const char *user, const char *oldpwd, const char *pwd, int justcheck,
	  LPCWSTR server)
{
  WCHAR name[2 * (UNLEN + 1)], oldpass[512], pass[512];
  DWORD ret;

  MultiByteToWideChar (CP_ACP, 0, user, -1, name, 2 * (UNLEN + 1));
  MultiByteToWideChar (CP_ACP, 0, pwd, -1, pass, 512);
  if (! oldpwd)
    {
      USER_INFO_1003 ui;

      ui.usri1003_password = pass;
      ret = NetUserSetInfo (server, name, 1003, (LPBYTE) &ui, NULL);
    }
  else
    {
      MultiByteToWideChar (CP_ACP, 0, oldpwd, -1, oldpass, 512);
      ret = NetUserChangePassword (server, name, oldpass, pass);
    }
  if (justcheck && ret != ERROR_INVALID_PASSWORD)
    return 0;
  if (! EvalRet (ret, user) && ! justcheck)
    {
      eprint (0, "Password changed.");
    }
  return ret;
}

void
PrintPW (PUSER_INFO_3 ui, LPCWSTR server)
{
  time_t t = time (NULL) - ui->usri3_password_age;
  int ret;
  PUSER_MODALS_INFO_0 mi;

  printf ("Account disabled           : %s",
  	(ui->usri3_flags & UF_ACCOUNTDISABLE) ? "yes\n" : "no\n");
  printf ("Password not required      : %s",
  	(ui->usri3_flags & UF_PASSWD_NOTREQD) ? "yes\n" : "no\n");
  printf ("User can't change password : %s",
  	(ui->usri3_flags & UF_PASSWD_CANT_CHANGE) ? "yes\n" : "no\n");
  printf ("Password never expires     : %s",
  	(ui->usri3_flags & UF_DONT_EXPIRE_PASSWD) ? "yes\n" : "no\n");
  printf ("Password expired           : %s",
	(ui->usri3_password_expired) ? "yes\n" : "no\n");
  printf ("Latest password change     : %s", ctime(&t));
  ret = NetUserModalsGet (server, 0, (void *) &mi);
  if (! ret)
    {
      if (mi->usrmod0_max_passwd_age == TIMEQ_FOREVER)
        mi->usrmod0_max_passwd_age = 0;
      if (mi->usrmod0_min_passwd_age == TIMEQ_FOREVER)
        mi->usrmod0_min_passwd_age = 0;
      if (mi->usrmod0_force_logoff == TIMEQ_FOREVER)
        mi->usrmod0_force_logoff = 0;
      if (ui->usri3_priv == USER_PRIV_ADMIN)
        mi->usrmod0_min_passwd_len = 0;
      printf ("\nSystem password settings:\n");
      printf ("Max. password age %ld days\n",
              mi->usrmod0_max_passwd_age / ONE_DAY);
      printf ("Min. password age %ld days\n",
              mi->usrmod0_min_passwd_age / ONE_DAY);
      printf ("Force logout after %ld days\n",
              mi->usrmod0_force_logoff / ONE_DAY);
      printf ("Min. password length: %ld\n",
              mi->usrmod0_min_passwd_len);
    }
}

int
SetModals (int xarg, int narg, int iarg, int Larg, LPCWSTR server)
{
  int ret;
  PUSER_MODALS_INFO_0 mi;

  ret = NetUserModalsGet (server, 0, (void *) &mi);
  if (! ret)
    {
      if (xarg == 0)
	mi->usrmod0_max_passwd_age = TIMEQ_FOREVER;
      else if (xarg > 0)
	mi->usrmod0_max_passwd_age = xarg * ONE_DAY;

      if (narg == 0)
	{
	  mi->usrmod0_min_passwd_age = TIMEQ_FOREVER;
	  mi->usrmod0_password_hist_len = 0;
	}
      else if (narg > 0)
	mi->usrmod0_min_passwd_age = narg * ONE_DAY;

      if (iarg == 0)
	mi->usrmod0_force_logoff = TIMEQ_FOREVER;
      else if (iarg > 0)
	mi->usrmod0_force_logoff = iarg * ONE_DAY;

      if (Larg >= 0)
	mi->usrmod0_min_passwd_len = Larg;

      ret = NetUserModalsSet (server, 0, (LPBYTE) mi, NULL);
      NetApiBufferFree (mi);
    }
  return EvalRet (ret, NULL);
}

static void usage (FILE * stream, int status) __attribute__ ((noreturn));
static void
usage (FILE * stream, int status)
{
  fprintf (stream, ""
  "Usage: %s [OPTION] [USER]\n"
  "Change USER's password or password attributes.\n"
  "\n"
  "User operations:\n"
  "  -l, --lock               lock USER's account.\n"
  "  -u, --unlock             unlock USER's account.\n"
  "  -c, --cannot-change      USER can't change password.\n"
  "  -C, --can-change         USER can change password.\n"
  "  -e, --never-expires      USER's password never expires.\n"
  "  -E, --expires            USER's password expires according to system's\n"
  "                           password aging rule.\n"
  "  -p, --pwd-not-required   no password required for USER.\n"
  "  -P, --pwd-required       password is required for USER.\n"
  "  -R, --reg-store-pwd      enter password to store it in the registry for\n"
  "                           later usage by services to be able to switch\n"
  "                           to this user context with network credentials.\n"
  "\n"
  "System operations:\n"
  "  -i, --inactive NUM       set NUM of days before inactive accounts are disabled\n"
  "                           (inactive accounts are those with expired passwords).\n"
  "  -n, --minage DAYS        set system minimum password age to DAYS days.\n"
  "  -x, --maxage DAYS        set system maximum password age to DAYS days.\n"
  "  -L, --length LEN         set system minimum password length to LEN.\n"
  "\n"
  "Other options:\n"
  "  -d, --logonserver SERVER connect to SERVER (e.g. domain controller).\n"
  "                           default server is the content of $LOGONSERVER.\n"
  "  -S, --status             display password status for USER (locked, expired,\n"
  "                           etc.) plus global system password settings.\n"
  "  -h, --help               output usage information and exit.\n"
  "  -v, --version            output version information and exit.\n"
  "\n"
  "If no option is given, change USER's password.  If no user name is given,\n"
  "operate on current user.  System operations must not be mixed with user\n"
  "operations.  Don't specify a USER when triggering a system operation.\n"
  "\n"
  "Don't specify a user or any other option together with the -R option.\n"
  "Non-Admin users can only store their password if cygserver is running and\n"
  "the CYGWIN environment variable is set to contain the word 'server'.\n"
  "Note that storing even obfuscated passwords in the registry is not overly\n"
  "secure.  Use this feature only if the machine is adequately locked down.\n"
  "Don't use this feature if you don't need network access within a remote\n"
  "session.  You can delete your stored password by using `passwd -R' and\n"
  "specifying an empty password.\n"
  "\n"
  "Report bugs to <cygwin@cygwin.com>\n", prog_name);
  exit (status);
}

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
%s (cygwin) %.*s\n\
Password Utility\n\
Copyright 1999, 2000, 2001, 2002, 2003 Red Hat, Inc.\n\
Compiled on %s\n\
", prog_name, len, v, __DATE__);
}

int
main (int argc, char **argv)
{
  char *c;
  char user[UNLEN + 1], oldpwd[_PASSWORD_LEN + 1], newpwd[_PASSWORD_LEN + 1];
  int ret = 0;
  int cnt = 0;
  int opt, len;
  int Larg = -1;
  int xarg = -1;
  int narg = -1;
  int iarg = -1;
  int lopt = 0;
  int uopt = 0;
  int copt = 0;
  int Copt = 0;
  int eopt = 0;
  int Eopt = 0;
  int popt = 0;
  int Popt = 0;
  int Sopt = 0;
  int Ropt = 0;
  PUSER_INFO_3 ui, li;
  LPWSTR server = NULL;

  prog_name = strrchr (argv[0], '/');
  if (prog_name == NULL)
    prog_name = strrchr (argv[0], '\\');
  if (prog_name == NULL)
    prog_name = argv[0];
  else
    prog_name++;
  c = strrchr (prog_name, '.');
  if (c)
    *c = '\0';

  while ((opt = getopt_long (argc, argv, opts, longopts, NULL)) != EOF)
    switch (opt)
      {
      case 'h':
	usage (stdout, 0);
        break;

      case 'i':
	if (lopt || uopt || copt || Copt || eopt || Eopt || popt || Popt || Sopt || Ropt)
	  usage (stderr, 1);
	if ((iarg = atoi (optarg)) < 0 || iarg > 999)
	  return eprint (1, "Force logout time must be between 0 and 999.");
        break;

      case 'l':
	if (xarg >= 0 || narg >= 0 || iarg >= 0 || Larg >= 0 || uopt || Sopt || Ropt)
	  usage (stderr, 1);
	lopt = 1;
        break;

      case 'n':
	if (lopt || uopt || copt || Copt || eopt || Eopt || popt || Popt || Sopt || Ropt)
	  usage (stderr, 1);
	if ((narg = atoi (optarg)) < 0 || narg > 999)
	  return eprint (1, "Minimum password age must be between 0 and 999.");
	if (xarg >= 0 && narg > xarg)
	  return eprint (1, "Minimum password age must be less than "
	                    "maximum password age.");
        break;

      case 'u':
	if (xarg >= 0 || narg >= 0 || iarg >= 0 || Larg >= 0 || lopt || Sopt || Ropt)
	  usage (stderr, 1);
	uopt = 1;
        break;

      case 'c':
	if (xarg >= 0 || narg >= 0 || iarg >= 0 || Larg >= 0 || Sopt || Ropt)
	  usage (stderr, 1);
	copt = 1;
        break;

      case 'C':
	if (xarg >= 0 || narg >= 0 || iarg >= 0 || Larg >= 0 || Sopt || Ropt)
	  usage (stderr, 1);
	Copt = 1;
        break;

      case 'd':
        {
	  if (Ropt)
	    usage (stderr, 1);
	  char *tmpbuf = alloca (strlen (optarg) + 3);
	  tmpbuf[0] = '\0';
	  if (*optarg != '\\')
	    strcpy (tmpbuf, "\\\\");
	  strcat (tmpbuf, optarg);
	  server = alloca ((strlen (tmpbuf) + 1) * sizeof (WCHAR));
	  if (MultiByteToWideChar (CP_ACP, 0, tmpbuf, -1, server,
				   strlen (tmpbuf) + 1) <= 0)
	    server = NULL;
	}
	break;

      case 'e':
	if (xarg >= 0 || narg >= 0 || iarg >= 0 || Larg >= 0 || Sopt || Ropt)
	  usage (stderr, 1);
	eopt = 1;
        break;

      case 'E':
	if (xarg >= 0 || narg >= 0 || iarg >= 0 || Larg >= 0 || Sopt || Ropt)
	  usage (stderr, 1);
	Eopt = 1;
        break;

      case 'p':
	if (xarg >= 0 || narg >= 0 || iarg >= 0 || Larg >= 0 || Sopt || Ropt)
	  usage (stderr, 1);
	popt = 1;
        break;

      case 'P':
	if (xarg >= 0 || narg >= 0 || iarg >= 0 || Larg >= 0 || Sopt || Ropt)
	  usage (stderr, 1);
	Popt = 1;
        break;

      case 'v':
	print_version ();
        exit (0);
        break;

      case 'x':
	if (lopt || uopt || copt || Copt || eopt || Eopt || popt || Popt || Sopt || Ropt)
	  usage (stderr, 1);
	if ((xarg = atoi (optarg)) < 0 || xarg > 999)
	  return eprint (1, "Maximum password age must be between 0 and 999.");
	if (narg >= 0 && xarg < narg)
	  return eprint (1, "Maximum password age must be greater than "
	                    "minimum password age.");
        break;

      case 'L':
	if (lopt || uopt || copt || Copt || eopt || Eopt || popt || Popt || Sopt || Ropt)
	  usage (stderr, 1);
	if ((Larg = atoi (optarg)) < 0 || Larg > LM20_PWLEN)
	  return eprint (1, "Minimum password length must be between "
	                    "0 and %d.", LM20_PWLEN);
        break;

      case 'S':
	if (xarg >= 0 || narg >= 0 || iarg >= 0 || Larg >= 0 || lopt || uopt
	    || copt || Copt || eopt || Eopt || popt || Popt || Ropt)
	  usage (stderr, 1);
	Sopt = 1;
        break;

      case 'R':
	if (xarg >= 0 || narg >= 0 || iarg >= 0 || Larg >= 0 || lopt || uopt
	    || copt || Copt || eopt || Eopt || popt || Popt || Sopt
	    || server)
	  usage (stderr, 1);
	Ropt = 1;
      	break;

      default:
        usage (stderr, 1);
      }

  if (Ropt)
    {
      if (optind < argc)
        usage (stderr, 1);
      printf (
"This functionality stores a password in the registry for usage by services\n"
"which need to change the user context and require network access.  Typical\n"
"applications are interactive remote logons using sshd, cron task, etc.\n"
"This password will always tried first when any privileged application is\n"
"about to switch the user context.\n\n"
"Note that storing even obfuscated passwords in the registry is not overly\n"
"secure.  Use this feature only if the machine is adequately locked down.\n"
"Don't use this feature if you don't need network access within a remote\n"
"session.  You can delete your stored password by specifying an empty password.\n\n");
      strcpy (newpwd, getpass ("Enter your current password: "));
      if (strcmp (newpwd, getpass ("Re-enter your current password: ")))
        eprint (0, "Password is not identical.");
      else if (cygwin_internal (CW_SET_PRIV_KEY, newpwd))
	return eprint (0, "Storing password failed: %s", strerror (errno));
      return 0;
    }

  if (!server)
    {
      len = GetEnvironmentVariableW (L"LOGONSERVER", NULL, 0);
      if (len > 0)
	{
	  server = alloca (len * sizeof (WCHAR));
	  if (GetEnvironmentVariableW (L"LOGONSERVER", server, len) <= 0)
	    server = NULL;
	}
    }

  if (Larg >= 0 || xarg >= 0 || narg >= 0 || iarg >= 0)
    {
      if (optind < argc)
        usage (stderr, 1);
      return SetModals (xarg, narg, iarg, Larg, server);
    }

  strcpy (user, optind >= argc ? getlogin () : argv[optind]);

  li = GetPW (getlogin (), 0, server);
  if (! li)
    return 1;

  ui = GetPW (user, 1, server);
  if (! ui)
    return 1;

  if (lopt || uopt || copt || Copt || eopt || Eopt || popt || Popt || Sopt)
    {
      USER_INFO_1008 uif;

      if (li->usri3_priv != USER_PRIV_ADMIN)
        return eprint (0, "You have no maintenance privileges.");
      uif.usri1008_flags = ui->usri3_flags;
      if (lopt)
        {
	  if (ui->usri3_priv == USER_PRIV_ADMIN)
	    return eprint (0, "Locking an admin account is disallowed.");
          uif.usri1008_flags |= UF_ACCOUNTDISABLE;
        }
      if (uopt)
        uif.usri1008_flags &= ~UF_ACCOUNTDISABLE;
      if (copt)
        uif.usri1008_flags |= UF_PASSWD_CANT_CHANGE;
      if (Copt)
        uif.usri1008_flags &= ~UF_PASSWD_CANT_CHANGE;
      if (eopt)
        uif.usri1008_flags |= UF_DONT_EXPIRE_PASSWD;
      if (Eopt)
        uif.usri1008_flags &= ~UF_DONT_EXPIRE_PASSWD;
      if (popt)
        uif.usri1008_flags |= UF_PASSWD_NOTREQD;
      if (Popt)
        uif.usri1008_flags &= ~UF_PASSWD_NOTREQD;

      if (lopt || uopt || copt || Copt || eopt || Eopt || popt || Popt)
	{
          ret = NetUserSetInfo (server, ui->usri3_name, 1008, (LPBYTE) &uif,
	  			NULL);
          return EvalRet (ret, NULL);
	}
      // Sopt
      PrintPW (ui, server);
      return 0;
    }

  if (li->usri3_priv != USER_PRIV_ADMIN && strcmp (getlogin (), user))
    return eprint (0, "You may not change the password for %s.", user);

  eprint (0, "Enter the new password (minimum of 5, maximum of 8 characters).");
  eprint (0, "Please use a combination of upper and lower case letters and numbers.");

  oldpwd[0] = '\0';
  if (li->usri3_priv != USER_PRIV_ADMIN)
    {
      strcpy (oldpwd, getpass ("Old password: "));
      if (ChangePW (user, oldpwd, oldpwd, 1, server))
        return 1;
    }

  do
    {
      strcpy (newpwd, getpass ("New password: "));
      if (strcmp (newpwd, getpass ("Re-enter new password: ")))
        eprint (0, "Password is not identical.");
      else if (! ChangePW (user, *oldpwd ? oldpwd : NULL, newpwd, 0, server))
        ret = 1;
      if (! ret && cnt < 2)
        eprint (0, "Try again.");
    }
  while (! ret && ++cnt < 3);
  return ! ret;
}
