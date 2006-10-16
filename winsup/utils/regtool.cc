/* regtool.cc

   Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006 Red Hat Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#define WINVER 0x0502
#include <windows.h>
#include <sys/cygwin.h>

#define DEFAULT_KEY_SEPARATOR '\\'

enum
{
  KT_AUTO, KT_BINARY, KT_INT, KT_STRING, KT_EXPAND, KT_MULTI
} key_type = KT_AUTO;

char key_sep = DEFAULT_KEY_SEPARATOR;

#define LIST_KEYS	0x01
#define LIST_VALS	0x02
#define LIST_ALL	(LIST_KEYS | LIST_VALS)

static const char version[] = "$Revision$";
static char *prog_name;

static struct option longopts[] =
{
  {"binary", no_argument, NULL, 'b' },
  {"expand-string", no_argument, NULL, 'e' },
  {"help", no_argument, NULL, 'h' },
  {"integer", no_argument, NULL, 'i' },
  {"keys", no_argument, NULL, 'k'},
  {"list", no_argument, NULL, 'l'},
  {"multi-string", no_argument, NULL, 'm'},
  {"postfix", no_argument, NULL, 'p'},
  {"quiet", no_argument, NULL, 'q'},
  {"string", no_argument, NULL, 's'},
  {"verbose", no_argument, NULL, 'v'},
  {"version", no_argument, NULL, 'V'},
  {"wow64", no_argument, NULL, 'w'},
  {"key-separator", required_argument, NULL, 'K'},
  {NULL, 0, NULL, 0}
};

static char opts[] = "behiklmpqsvVwK:";

int listwhat = 0;
int postfix = 0;
int verbose = 0;
int quiet = 0;
DWORD wow64 = 0;
char **argv;

HKEY key;
char *value;

static void
usage (FILE *where = stderr)
{
  fprintf (where, ""
  "Usage: %s [OPTION] (add|check|get|list|remove|unset|load|unload|save) KEY\n"
  "View or edit the Win32 registry\n"
  "\n"
  "", prog_name);
  if (where == stdout)
    fprintf (where, ""
    "Actions:\n"
    " add KEY\\SUBKEY             add new SUBKEY\n"
    " check KEY                  exit 0 if KEY exists, 1 if not\n"
    " get KEY\\VALUE              prints VALUE to stdout\n"
    " list KEY                   list SUBKEYs and VALUEs\n"
    " remove KEY                 remove KEY\n"
    " set KEY\\VALUE [data ...]   set VALUE\n"
    " unset KEY\\VALUE            removes VALUE from KEY\n"
    " load KEY\\SUBKEY PATH       load hive from PATH into new SUBKEY\n"
    " unload KEY\\SUBKEY          unload hive and remove SUBKEY\n"
    " save KEY\\SUBKEY PATH       save SUBKEY into new hive PATH\n"
    "\n");
  fprintf (where, ""
  "Options for 'list' Action:\n"
  " -k, --keys           print only KEYs\n"
  " -l, --list           print only VALUEs\n"
  " -p, --postfix        like ls -p, appends '\\' postfix to KEY names\n"
  "\n"
  "Options for 'get' Action:\n"
  " -b, --binary         print REG_BINARY data as hex bytes\n"
  "\n"
  "Options for 'set' Action:\n"
  " -b, --binary         set type to REG_BINARY (hex args or '-')\n"
  " -e, --expand-string  set type to REG_EXPAND_SZ\n"
  " -i, --integer        set type to REG_DWORD\n"
  " -m, --multi-string   set type to REG_MULTI_SZ\n"
  " -s, --string         set type to REG_SZ\n"
  "\n"
  "Options for 'set' and 'unset' Actions:\n"
  " -K<c>, --key-separator[=]<c>  set key-value separator to <c> instead of '\\'\n"
  "\n"
  "Other Options:\n"
  " -h, --help     output usage information and exit\n"
  " -q, --quiet    no error output, just nonzero return if KEY/VALUE missing\n"
  " -v, --verbose  verbose output, including VALUE contents when applicable\n"
  " -w, --wow64    access 64 bit registry view (ignored on 32 bit Windows)\n"
  " -V, --version  output version information and exit\n"
  "\n");
  if (where == stdout)
    {
      fprintf (where, ""
      "KEY is in the format [host]\\prefix\\KEY\\KEY\\VALUE, where host is optional\n"
      "remote host in either \\\\hostname or hostname: format and prefix is any of:\n"
      "  root     HKCR  HKEY_CLASSES_ROOT (local only)\n"
      "  config   HKCC  HKEY_CURRENT_CONFIG (local only)\n"
      "  user     HKCU  HKEY_CURRENT_USER (local only)\n"
      "  machine  HKLM  HKEY_LOCAL_MACHINE\n"
      "  users    HKU   HKEY_USERS\n"
      "\n"
      "If the keyname starts with a forward slash ('/'), the forward slash is used\n"
      "as separator and the backslash can be used as escape character.\n");
      fprintf (where, ""
      "Example:\n"
      "%s list '/machine/SOFTWARE/Classes/MIME/Database/Content Type/audio\\/wav'\n", prog_name);
    }
  if (where == stderr)
    fprintf (where, "Try '%s --help' for more information.\n", prog_name);
  exit (where == stderr ? 1 : 0);
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
Registry Tool\n\
Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006 Red Hat, Inc.\n\
Compiled on %s\n\
", prog_name, len, v, __DATE__);
}

void
Fail (DWORD rv)
{
  char *buf;
  if (!quiet)
    {
      FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER
		     | FORMAT_MESSAGE_FROM_SYSTEM,
		     0, rv, 0, (CHAR *) & buf, 0, 0);
      fprintf (stderr, "Error (%ld): %s\n", rv, buf);
      LocalFree (buf);
    }
  exit (1);
}

struct
{
  const char *string;
  HKEY key;
} wkprefixes[] =
{
  {"root", HKEY_CLASSES_ROOT},
  {"HKCR", HKEY_CLASSES_ROOT},
  {"HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT},
  {"config", HKEY_CURRENT_CONFIG},
  {"HKCC", HKEY_CURRENT_CONFIG},
  {"HKEY_CURRENT_CONFIG", HKEY_CURRENT_CONFIG},
  {"user", HKEY_CURRENT_USER},
  {"HKCU", HKEY_CURRENT_USER},
  {"HKEY_CURRENT_USER", HKEY_CURRENT_USER},
  {"machine", HKEY_LOCAL_MACHINE},
  {"HKLM", HKEY_LOCAL_MACHINE},
  {"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE},
  {"users", HKEY_USERS},
  {"HKU", HKEY_USERS},
  {"HKEY_USERS", HKEY_USERS},
  {0, 0}
};

void
translate (char *key)
{
#define isodigit(c) (strchr("01234567", c))
#define tooct(c)    ((c)-'0')
#define tohex(c)    (strchr(_hs,tolower(c))-_hs)
  static char _hs[] = "0123456789abcdef";

  char *d = key;
  char *s = key;
  char c;

  while (*s)
    {
      if (*s == '\\')
	switch (*++s)
	  {
	  case 'a':
	    *d++ = '\007';
	    break;
	  case 'b':
	    *d++ = '\b';
	    break;
	  case 'e':
	    *d++ = '\033';
	    break;
	  case 'f':
	    *d++ = '\f';
	    break;
	  case 'n':
	    *d++ = '\n';
	    break;
	  case 'r':
	    *d++ = '\r';
	    break;
	  case 't':
	    *d++ = '\t';
	    break;
	  case 'v':
	    *d++ = '\v';
	    break;
	  case '0':
	  case '1':
	  case '2':
	  case '3':
	  case '4':
	  case '5':
	  case '6':
	  case '7':
	    c = tooct (*s);
	    if (isodigit (s[1]))
	      {
		c = (c << 3) | tooct (*++s);
		if (isodigit (s[1]))
		  c = (c << 3) | tooct (*++s);
	      }
	    *d++ = c;
	    break;
	  case 'x':
	    if (!isxdigit (s[1]))
	      c = '0';
	    else
	      {
		c = tohex (*++s);
		if (isxdigit (s[1]))
		  c = (c << 4) | tohex (*++s);
	      }
	    *d++ = c;
	    break;
	  default:		/* before non-special char: just add the char */
	    *d++ = *s;
	    break;
	  }
      else if (*s == '/')
	*d++ = '\\';
      else
	*d++ = *s;
      ++s;
    }
  *d = '\0';
}

void
find_key (int howmanyparts, REGSAM access, int option = 0)
{
  HKEY base;
  int rv;
  char *n = argv[0], *e, *h, c;
  char* host = NULL;
  int i;
  if (*n == '/')
    translate (n);
  if (*n != '\\')
    {
      /* expect host:/key/value format */
      host = (char*) malloc (strlen (n) + 1);
      host[0] = host [1] = '\\';
      for (e = n, h = host + 2; *e && *e != ':'; e++, h++)
	*h = *e;
      *h = 0;
      n = e + 1;
      if (*n == '/')
	translate (n);
    }
  else if (n[0] == '\\' && n[1] == '\\')
    {
      /* expect //host/key/value format */
      host = (char*) malloc (strlen (n) + 1);
      host[0] = host[1] = '\\';
      for (e = n + 2, h = host + 2; *e && *e != '\\'; e++, h++)
	*h = *e;
      *h = 0;
      n = e;
    }
  while (*n != '\\')
    n++;
  *n++ = 0;
  for (e = n; *e && *e != '\\'; e++);
  c = *e;
  *e = 0;
  for (i = 0; wkprefixes[i].string; i++)
    if (strcmp (wkprefixes[i].string, n) == 0)
      break;
  if (!wkprefixes[i].string)
    {
      fprintf (stderr, "Unknown key prefix.  Valid prefixes are:\n");
      for (i = 0; wkprefixes[i].string; i++)
	fprintf (stderr, "\t%s\n", wkprefixes[i].string);
      exit (1);
    }

  n = e;
  *e = c;
  while (*n && *n == '\\')
    n++;
  e = n + strlen (n);
  if (howmanyparts > 1)
    {
      while (n < e && *e != key_sep)
	e--;
      if (*e != key_sep)
	{
	  key = wkprefixes[i].key;
	  value = n;
	  return;
	}
      else
	{
	  *e = 0;
	  value = e + 1;
	}
    }
  if (host)
    {
      rv = RegConnectRegistry (host, wkprefixes[i].key, &base);
      if (rv != ERROR_SUCCESS)
	Fail (rv);
      free (host);
    }
  else
    base = wkprefixes[i].key;

  if (n[0] == 0)
    key = base;
  else
    {
      if (access)
	{
	  rv = RegOpenKeyEx (base, n, 0, access | wow64, &key);
	  if (option && (rv == ERROR_SUCCESS || rv == ERROR_ACCESS_DENIED))
	    {
	      /* reopen with desired option due to missing option support in RegOpenKeyE */
	      /* FIXME: may create the key in rare cases (e.g. access denied in parent) */
	      HKEY key2;
	      if (RegCreateKeyEx (base, n, 0, NULL, option, access | wow64, NULL, &key2, NULL)
		  == ERROR_SUCCESS)
	        {
		  if (rv == ERROR_SUCCESS)
		    RegCloseKey (key);
		  key = key2;
		  rv = ERROR_SUCCESS;
	        }
	    }
	  if (rv != ERROR_SUCCESS)
	    Fail (rv);
	}
      else if (argv[1])
	{ 
	  char win32_path[MAX_PATH];
	  cygwin_conv_to_win32_path (argv[1], win32_path);
	  rv = RegLoadKey (base, n, win32_path);
	  if (rv != ERROR_SUCCESS)
	    Fail (rv);
	  if (verbose)
	    printf ("key %s loaded from file %s\n", n, win32_path);
	}
      else
	{ 
	  rv = RegUnLoadKey (base, n);
	  if (rv != ERROR_SUCCESS)
	    Fail (rv);
	  if (verbose)
	    printf ("key %s unloaded\n", n);
	}
    }
  //printf("key `%s' value `%s'\n", n, value);
}


int
cmd_list ()
{
  DWORD num_subkeys, maxsubkeylen, num_values, maxvalnamelen, maxvaluelen;
  DWORD maxclasslen;
  char *subkey_name, *value_name, *class_name;
  unsigned char *value_data, *vd;
  DWORD i, j, m, n, t;
  int v;

  find_key (1, KEY_READ);
  RegQueryInfoKey (key, 0, 0, 0, &num_subkeys, &maxsubkeylen, &maxclasslen,
		   &num_values, &maxvalnamelen, &maxvaluelen, 0, 0);

  subkey_name = (char *) malloc (maxsubkeylen + 1);
  class_name = (char *) malloc (maxclasslen + 1);
  value_name = (char *) malloc (maxvalnamelen + 1);
  value_data = (unsigned char *) malloc (maxvaluelen + 1);

  if (!listwhat)
    listwhat = LIST_ALL;

  if (listwhat & LIST_KEYS)
    for (i = 0; i < num_subkeys; i++)
      {
	m = maxsubkeylen + 1;
	n = maxclasslen + 1;
	RegEnumKeyEx (key, i, subkey_name, &m, 0, class_name, &n, 0);
	printf ("%s%s", subkey_name, (postfix || verbose) ? "\\" : "");

	if (verbose)
	  printf (" (%s)", class_name);

	puts ("");
      }

  if (listwhat & LIST_VALS)
    for (i = 0; i < num_values; i++)
      {
	m = maxvalnamelen + 1;
	n = maxvaluelen + 1;
	RegEnumValue (key, i, value_name, &m, 0, &t, (BYTE *) value_data, &n);
	value_data[n] = 0;
	if (!verbose)
	  printf ("%s\n", value_name);
	else
	  {
	    printf ("%s = ", value_name);
	    switch (t)
	      {
	      case REG_BINARY:
		for (j = 0; j < 8 && j < n; j++)
		  printf ("%02x ", value_data[j]);
		printf ("\n");
		break;
	      case REG_DWORD:
		printf ("0x%08lx (%lu)\n", *(DWORD *) value_data,
			*(DWORD *) value_data);
		break;
	      case REG_DWORD_BIG_ENDIAN:
		v = ((value_data[0] << 24)
		     | (value_data[1] << 16)
		     | (value_data[2] << 8) | (value_data[3]));
		printf ("0x%08x (%d)\n", v, v);
		break;
	      case REG_EXPAND_SZ:
	      case REG_SZ:
		printf ("\"%s\"\n", value_data);
		break;
	      case REG_MULTI_SZ:
		vd = value_data;
		while (vd && *vd)
		  {
		    printf ("\"%s\"", vd);
		    vd = vd + strlen ((const char *) vd) + 1;
		    if (*vd)
		      printf (", ");
		  }
		printf ("\n");
		break;
	      default:
		printf ("? (type %d)\n", (int) t);
	      }
	  }
      }
  return 0;
}

int
cmd_add ()
{
  find_key (2, KEY_ALL_ACCESS);
  HKEY newkey;
  DWORD newtype;
  int rv = RegCreateKeyEx (key, value, 0, (char *) "", REG_OPTION_NON_VOLATILE,
			   KEY_ALL_ACCESS | wow64, 0, &newkey, &newtype);
  if (rv != ERROR_SUCCESS)
    Fail (rv);

  if (verbose)
    {
      if (newtype == REG_OPENED_EXISTING_KEY)
	printf ("Key %s already exists\n", value);
      else
	printf ("Key %s created\n", value);
    }
  return 0;
}

extern "C" {
WINADVAPI LONG WINAPI (*regDeleteKeyEx)(HKEY, LPCSTR, REGSAM, DWORD);
}

int
cmd_remove ()
{
  DWORD rv;

  find_key (2, KEY_ALL_ACCESS);
  if (wow64)
    {
      HMODULE mod = LoadLibrary ("advapi32.dll");
      if (mod)
        regDeleteKeyEx = (WINADVAPI LONG WINAPI (*)(HKEY, LPCSTR, REGSAM, DWORD)) GetProcAddress (mod, "RegDeleteKeyExA");
    }
  if (regDeleteKeyEx)
    rv = (*regDeleteKeyEx) (key, value, wow64, 0);
  else
    rv = RegDeleteKey (key, value);
  if (rv != ERROR_SUCCESS)
    Fail (rv);
  if (verbose)
    printf ("subkey %s deleted\n", value);
  return 0;
}

int
cmd_check ()
{
  find_key (1, KEY_READ);
  if (verbose)
    printf ("key %s exists\n", argv[0]);
  return 0;
}

int
cmd_set ()
{
  int i, n;
  DWORD v, rv;
  char *a = argv[1], *data = 0;
  find_key (2, KEY_ALL_ACCESS);

  if (key_type == KT_AUTO)
    {
      char *e;
      strtoul (a, &e, 0);
      if (a[0] == '%')
	key_type = KT_EXPAND;
      else if (a[0] && !*e)
	key_type = KT_INT;
      else if (argv[2])
	key_type = KT_MULTI;
      else
	key_type = KT_STRING;
    }

  switch (key_type)
    {
    case KT_BINARY:
      for (n = 0; argv[n+1]; n++)
        ;
      if (n == 1 && strcmp (argv[1], "-") == 0)
	{ /* read from stdin */
	  i = n = 0;
	  for (;;)
	    {
	      if (i <= n)
		{
		  i = n + BUFSIZ;
		  data = (char *) realloc (data, i);
		}
	      int r = fread (data+n, 1, i-n, stdin);
	      if (r <= 0)
		break;
	      n += r;
	    }
	}
      else if (n > 0)
	{ /* parse hex from argv */
	  data = (char *) malloc (n);
	  for (i = 0; i < n; i++)
	    {
	      char *e;
	      errno = 0;
	      v = strtoul (argv[i+1], &e, 16);
	      if (errno || v > 0xff || *e)
		{
		  fprintf (stderr, "Invalid hex constant `%s'\n", argv[i+1]);
		  exit (1);
		}
	      data[i] = (char) v;
	    }
	}
      rv = RegSetValueEx (key, value, 0, REG_BINARY, (const BYTE *) data, n);
      break;
    case KT_INT:
      v = strtoul (a, 0, 0);
      rv = RegSetValueEx (key, value, 0, REG_DWORD, (const BYTE *) &v,
			  sizeof (v));
      break;
    case KT_STRING:
      rv = RegSetValueEx (key, value, 0, REG_SZ, (const BYTE *) a, strlen (a) + 1);
      break;
    case KT_EXPAND:
      rv = RegSetValueEx (key, value, 0, REG_EXPAND_SZ, (const BYTE *) a,
			  strlen (a) + 1);
      break;
    case KT_MULTI:
      for (i = 1, n = 1; argv[i]; i++)
	n += strlen (argv[i]) + 1;
      data = (char *) malloc (n);
      for (i = 1, n = 0; argv[i]; i++)
	{
	  strcpy (data + n, argv[i]);
	  n += strlen (argv[i]) + 1;
	}
      data[n] = 0;
      rv = RegSetValueEx (key, value, 0, REG_MULTI_SZ, (const BYTE *) data,
			  n + 1);
      break;
    case KT_AUTO:
      rv = ERROR_SUCCESS;
      break;
    default:
      rv = ERROR_INVALID_CATEGORY;
      break;
    }
 
  if (data)
    free(data);

  if (rv != ERROR_SUCCESS)
    Fail (rv);

  return 0;
}

int
cmd_unset ()
{
  find_key (2, KEY_ALL_ACCESS);
  DWORD rv = RegDeleteValue (key, value);
  if (rv != ERROR_SUCCESS)
    Fail (rv);
  if (verbose)
    printf ("value %s deleted\n", value);
  return 0;
}

int
cmd_get ()
{
  find_key (2, KEY_READ);
  DWORD vtype, dsize, rv;
  char *data, *vd;
  rv = RegQueryValueEx (key, value, 0, &vtype, 0, &dsize);
  if (rv != ERROR_SUCCESS)
    Fail (rv);
  data = (char *) malloc (dsize + 1);
  rv = RegQueryValueEx (key, value, 0, &vtype, (BYTE *) data, &dsize);
  if (rv != ERROR_SUCCESS)
    Fail (rv);
  switch (vtype)
    {
    case REG_BINARY:
      if (key_type == KT_BINARY)
	{
	  for (unsigned i = 0; i < dsize; i++)
	    printf ("%02x%c", (unsigned char)data[i],
	      (i < dsize-1 ? ' ' : '\n'));
	}
      else
 	fwrite (data, dsize, 1, stdout);
      break;
    case REG_DWORD:
      printf ("%lu\n", *(DWORD *) data);
      break;
    case REG_SZ:
      printf ("%s\n", data);
      break;
    case REG_EXPAND_SZ:
      if (key_type == KT_EXPAND)	// hack
	{
	  char *buf;
	  DWORD bufsize;
	  bufsize = ExpandEnvironmentStrings (data, 0, 0);
	  buf = (char *) malloc (bufsize + 1);
	  ExpandEnvironmentStrings (data, buf, bufsize + 1);
	  free (data);
	  data = buf;
	}
      printf ("%s\n", data);
      break;
    case REG_MULTI_SZ:
      vd = data;
      while (vd && *vd)
	{
	  printf ("%s\n", vd);
	  vd = vd + strlen ((const char *) vd) + 1;
	}
      break;
    }
  return 0;
}

int
cmd_load ()
{
  if (!argv[1])
    {
      usage ();
      return 1;
    }
  find_key (1, 0);
  return 0;
}

int
cmd_unload ()
{
  if (argv[1])
    {
      usage ();
      return 1;
    }
  find_key (1, 0);
  return 0;
}

DWORD
set_privilege (const char * name)
{
  TOKEN_PRIVILEGES tp;
  if (!LookupPrivilegeValue (NULL, name, &tp.Privileges[0].Luid))
    return GetLastError ();
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  HANDLE t;
  /* OpenProcessToken does not work here, because main thread has its own
     impersonation token */
  if (!OpenThreadToken (GetCurrentThread (), TOKEN_ADJUST_PRIVILEGES, FALSE, &t))
    return GetLastError ();
  AdjustTokenPrivileges (t, FALSE, &tp, 0, NULL, NULL);
  DWORD rv = GetLastError ();
  CloseHandle (t);
  return rv;
}

int
cmd_save ()
{
  if (!argv[1])
    {
      usage ();
      return 1;
    }
  /* try to set SeBackupPrivilege, let RegSaveKey report the error */
  set_privilege (SE_BACKUP_NAME);
  /* REG_OPTION_BACKUP_RESTORE is necessary to save /HKLM/SECURITY */
  find_key (1, KEY_QUERY_VALUE, REG_OPTION_BACKUP_RESTORE);
  char win32_path[MAX_PATH];
  cygwin_conv_to_win32_path (argv[1], win32_path);
  DWORD rv = RegSaveKey (key, win32_path, NULL);
  if (rv != ERROR_SUCCESS)
    Fail (rv);
  if (verbose)
    printf ("key saved to %s\n", win32_path);
  return 0;
}


struct
{
  const char *name;
  int (*func) ();
} commands[] =
{
  {"list", cmd_list},
  {"add", cmd_add},
  {"remove", cmd_remove},
  {"check", cmd_check},
  {"set", cmd_set},
  {"unset", cmd_unset},
  {"get", cmd_get},
  {"load", cmd_load},
  {"unload", cmd_unload},
  {"save", cmd_save},
  {0, 0}
};

int
main (int argc, char **_argv)
{
  int g;

  prog_name = strrchr (_argv[0], '/');
  if (prog_name == NULL)
    prog_name = strrchr (_argv[0], '\\');
  if (prog_name == NULL)
    prog_name = _argv[0];
  else
    prog_name++;

  while ((g = getopt_long (argc, _argv, opts, longopts, NULL)) != EOF)
    switch (g)
	{
	case 'b':
	  key_type = KT_BINARY;
	  break;
	case 'e':
	  key_type = KT_EXPAND;
	  break;
	case 'k':
	  listwhat |= LIST_KEYS;
	  break;
	case 'h':
	  usage (stdout);
	case 'i':
	  key_type = KT_INT;
	  break;
	case 'l':
	  listwhat |= LIST_VALS;
	  break;
	case 'm':
	  key_type = KT_MULTI;
	  break;
	case 'p':
	  postfix++;
	  break;
	case 'q':
	  quiet++;
	  break;
	case 's':
	  key_type = KT_STRING;
	  break;
	case 'v':
	  verbose++;
	  break;
	case 'V':
	  print_version ();
	  exit (0);
	case 'w':
	  wow64 = KEY_WOW64_64KEY;
	  break;
	case 'K':
	  key_sep = *optarg;
	  break;
	default :
	  usage ();
	}

  if ((_argv[optind] == NULL) || (_argv[optind+1] == NULL))
    usage ();

  argv = _argv + optind;
  int i;
  for (i = 0; commands[i].name; i++)
    if (strcmp (commands[i].name, argv[0]) == 0)
      {
	argv++;
	return commands[i].func ();
      }
  usage ();

  return 0;
}
