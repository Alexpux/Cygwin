/* cygpath.cc -- convert pathnames between Windows and Unix format
   Copyright 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
   2006, 2007 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#define NOCOMATTRIBUTE

#include <shlobj.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <getopt.h>
#include <windows.h>
#include <io.h>
#include <sys/fcntl.h>
#include <sys/cygwin.h>
#include <ctype.h>
#include <errno.h>
#include <ddk/ntddk.h>
#include <ddk/winddk.h>
#include <ddk/ntifs.h>

static const char version[] = "$Revision$";

static char *prog_name;
static char *file_arg, *output_arg;
static int path_flag, unix_flag, windows_flag, absolute_flag;
static int shortname_flag, longname_flag;
static int ignore_flag, allusers_flag, output_flag;
static int mixed_flag;
static const char *format_type_arg;

static struct option long_options[] = {
  {(char *) "absolute", no_argument, NULL, 'a'},
  {(char *) "close", required_argument, NULL, 'c'},
  {(char *) "dos", no_argument, NULL, 'd'},
  {(char *) "file", required_argument, NULL, 'f'},
  {(char *) "help", no_argument, NULL, 'h'},
  {(char *) "ignore", no_argument, NULL, 'i'},
  {(char *) "long-name", no_argument, NULL, 'l'},
  {(char *) "mixed", no_argument, NULL, 'm'},
  {(char *) "mode", no_argument, NULL, 'M'},
  {(char *) "option", no_argument, NULL, 'o'},
  {(char *) "path", no_argument, NULL, 'p'},
  {(char *) "short-name", no_argument, NULL, 's'},
  {(char *) "type", required_argument, NULL, 't'},
  {(char *) "unix", no_argument, NULL, 'u'},
  {(char *) "version", no_argument, NULL, 'v'},
  {(char *) "windows", no_argument, NULL, 'w'},
  {(char *) "allusers", no_argument, NULL, 'A'},
  {(char *) "desktop", no_argument, NULL, 'D'},
  {(char *) "homeroot", no_argument, NULL, 'H'},
  {(char *) "mydocs", no_argument, NULL, 'O'},
  {(char *) "smprograms", no_argument, NULL, 'P'},
  {(char *) "sysdir", no_argument, NULL, 'S'},
  {(char *) "windir", no_argument, NULL, 'W'},
  {(char *) "folder", required_argument, NULL, 'F'},
  {0, no_argument, 0, 0}
};

static char options[] = "ac:df:hilmMopst:uvwADHOPSWF:";

static void
usage (FILE * stream, int status)
{
  if (!ignore_flag || !status)
    fprintf (stream, "\
Usage: %s (-d|-m|-u|-w|-t TYPE) [-f FILE] [OPTION]... NAME...\n\
       %s [-c HANDLE] \n\
       %s [-ADHOPSW] \n\
       %s [-F ID] \n\
Convert Unix and Windows format paths, or output system path information\n\
\n\
Output type options:\n\
  -d, --dos             print DOS (short) form of NAMEs (C:\\PROGRA~1\\)\n\
  -m, --mixed           like --windows, but with regular slashes (C:/WINNT)\n\
  -M, --mode            report on mode of file (binmode or textmode)\n\
  -u, --unix            (default) print Unix form of NAMEs (/cygdrive/c/winnt)\n\
  -w, --windows         print Windows form of NAMEs (C:\\WINNT)\n\
  -t, --type TYPE       print TYPE form: 'dos', 'mixed', 'unix', or 'windows'\n\
Path conversion options:\n\
  -a, --absolute        output absolute path\n\
  -l, --long-name       print Windows long form of NAMEs (with -w, -m only)\n\
  -p, --path            NAME is a PATH list (i.e., '/bin:/usr/bin')\n\
  -s, --short-name      print DOS (short) form of NAMEs (with -w, -m only)\n\
System information:\n\
  -A, --allusers        use `All Users' instead of current user for -D, -O, -P\n\
  -D, --desktop         output `Desktop' directory and exit\n\
  -H, --homeroot        output `Profiles' directory (home root) and exit\n\
  -O, --mydocs          output `My Documents' directory and exit\n\
  -P, --smprograms      output Start Menu `Programs' directory and exit\n\
  -S, --sysdir          output system directory and exit\n\
  -W, --windir          output `Windows' directory and exit\n\
  -F, --folder ID       output special folder with numeric ID and exit\n\
", prog_name, prog_name, prog_name, prog_name);
  if (ignore_flag)
    /* nothing to do */;
  else if (stream != stdout)
    fprintf(stream, "Try `%s --help' for more information.\n", prog_name);
  else
    {
      fprintf (stream, "\
Other options:\n\
  -f, --file FILE       read FILE for input; use - to read from STDIN\n\
  -o, --option          read options from FILE as well (for use with --file)\n\
  -c, --close HANDLE    close HANDLE (for use in captured process)\n\
  -i, --ignore          ignore missing argument\n\
  -h, --help            output usage information and exit\n\
  -v, --version         output version information and exit\n\
");
    }
  exit (ignore_flag ? 0 : status);
}

static inline BOOLEAN
RtlAllocateUnicodeString (PUNICODE_STRING uni, ULONG size)
{
  uni->Length = 0;
  uni->MaximumLength = 512;
  uni->Buffer = (WCHAR *) malloc (size);
  return uni->Buffer != NULL;
}

static char *
get_device_name (char *path)
{
  UNICODE_STRING ntdev, tgtdev, ntdevdir;
  ANSI_STRING ans;
  OBJECT_ATTRIBUTES ntobj;
  NTSTATUS status;
  HANDLE lnk, dir;
  char *ret = strdup (path);
  PDIRECTORY_BASIC_INFORMATION odi = (PDIRECTORY_BASIC_INFORMATION)
				     alloca (4096);
  BOOLEAN restart;
  ULONG cont;

  if (strncasecmp (path, "\\Device\\", 8))
    return ret;

  if (!RtlAllocateUnicodeString (&ntdev, MAX_PATH * 2))
    return ret;
  if (!RtlAllocateUnicodeString (&tgtdev, MAX_PATH * 2))
    return ret;
  RtlInitAnsiString (&ans, path);
  RtlAnsiStringToUnicodeString (&ntdev, &ans, FALSE);

  /* First check if the given device name is a symbolic link itself.  If so,
     query it and use the new name as actual device name to search for in the
     DOS device name directory.  If not, just use the incoming device name. */
  InitializeObjectAttributes (&ntobj, &ntdev, OBJ_CASE_INSENSITIVE, NULL, NULL);
  status = ZwOpenSymbolicLinkObject (&lnk, SYMBOLIC_LINK_QUERY, &ntobj);
  if (NT_SUCCESS (status))
    {
      status = ZwQuerySymbolicLinkObject (lnk, &tgtdev, NULL);
      ZwClose (lnk);
      if (!NT_SUCCESS (status))
	goto out;
      RtlCopyUnicodeString (&ntdev, &tgtdev);
    }
  else if (status != STATUS_OBJECT_TYPE_MISMATCH)
    goto out;

  for (int i = 0; i < 2; ++i)
    {
      /* There are two DOS device directories, the local and the global dir.
	 Try both, local first. */
      RtlInitUnicodeString (&ntdevdir, i ? L"\\GLOBAL??" : L"\\??");

      /* Open the directory... */
      InitializeObjectAttributes (&ntobj, &ntdevdir, OBJ_CASE_INSENSITIVE,
				  NULL, NULL);
      status = ZwOpenDirectoryObject (&dir, DIRECTORY_QUERY, &ntobj);
      if (!NT_SUCCESS (status))
	break;

      /* ...and scan it. */
      for (restart = TRUE, cont = 0;
	   NT_SUCCESS (ZwQueryDirectoryObject (dir, odi, 4096, TRUE,
					       restart, &cont, NULL));
	   restart = FALSE)
	{
	  /* For each entry check if it's a symbolic link. */
	  InitializeObjectAttributes (&ntobj, &odi->ObjectName,
				      OBJ_CASE_INSENSITIVE, dir, NULL);
	  status = ZwOpenSymbolicLinkObject (&lnk, SYMBOLIC_LINK_QUERY, &ntobj);
	  if (!NT_SUCCESS (status))
	    continue;
	  tgtdev.Length = 0;
	  tgtdev.MaximumLength = 512;
	  /* If so, query it and compare the target of the symlink with the
	     incoming device name. */
	  status = ZwQuerySymbolicLinkObject (lnk, &tgtdev, NULL);
	  ZwClose (lnk);
	  if (!NT_SUCCESS (status))
	    continue;
	  if (RtlEqualUnicodeString (&ntdev, &tgtdev, TRUE))
	    {
	      /* If the comparison succeeds, the name of the directory entry is
		 a valid DOS device name, if prepended with "\\.\".  Return that
		 valid DOS path. */
	      ULONG len = RtlUnicodeStringToAnsiSize (&odi->ObjectName);
	      ret = (char *) malloc (len + 4);
	      strcpy (ret, "\\\\.\\");
	      ans.Length = 0;
	      ans.MaximumLength = len;
	      ans.Buffer = ret + 4;
	      RtlUnicodeStringToAnsiString (&ans, &odi->ObjectName, FALSE);
	      ZwClose (dir);
	      goto out;
	    }
	}
      ZwClose (dir);
    }

out:
  free (tgtdev.Buffer);
  free (ntdev.Buffer);
  return ret;
}

static char *
get_device_paths (char *path)
{
  char *sbuf;
  char *ptr;
  int n = 1;

  ptr = path;
  while ((ptr = strchr (ptr, ';')))
    {
      ptr++;
      n++;
    }

  char *paths[n];
  DWORD acc = 0;
  int i;
  if (!n)
    return strdup ("");

  for (i = 0, ptr = path; ptr; i++)
    {
      char *next = ptr;
      ptr = strchr (ptr, ';');
      if (ptr)
	*ptr++ = 0;
      paths[i] = get_device_name (next);
      acc += strlen (paths[i]) + 1;
    }

  sbuf = (char *) malloc (acc + 1);
  if (sbuf == NULL)
    {
      fprintf (stderr, "%s: out of memory\n", prog_name);
      exit (1);
    }

  sbuf[0] = '\0';
  for (i = 0; i < n; i++)
    {
      strcat (strcat (sbuf, paths[i]), ";");
      free (paths[i]);
    }

  strchr (sbuf, '\0')[-1] = '\0';
  return sbuf;
}

static char *
get_short_paths (char *path)
{
  char *sbuf;
  char *sptr;
  char *next;
  char *ptr = path;
  char *end = strrchr (path, 0);
  DWORD acc = 0;
  DWORD len;

  while (ptr != NULL)
    {
      next = ptr;
      ptr = strchr (ptr, ';');
      if (ptr)
	*ptr++ = 0;
      len = GetShortPathName (next, NULL, 0);
      if (!len)
	{
	  fprintf (stderr, "%s: cannot create short name of %s\n", prog_name,
		   next);
	  exit (2);
	}
      acc += len + 1;
    }
  sptr = sbuf = (char *) malloc (acc + 1);
  if (sbuf == NULL)
    {
      fprintf (stderr, "%s: out of memory\n", prog_name);
      exit (1);
    }
  ptr = path;
  for (;;)
    {
      len = GetShortPathName (ptr, sptr, acc);
      if (!len)
	{
	  fprintf (stderr, "%s: cannot create short name of %s\n", prog_name,
		   ptr);
	  exit (2);
	}

      ptr = strrchr (ptr, 0);
      sptr = strrchr (sptr, 0);
      if (ptr == end)
	break;
      *sptr = ';';
      ++ptr, ++sptr;
      acc -= len + 1;
    }
  return sbuf;
}

static char *
get_short_name (const char *filename)
{
  char *sbuf, buf[MAX_PATH];
  DWORD len = GetShortPathName (filename, buf, MAX_PATH);
  if (!len)
    {
      fprintf (stderr, "%s: cannot create short name of %s\n", prog_name,
	       filename);
      exit (2);
    }
  sbuf = (char *) malloc (++len);
  if (sbuf == NULL)
    {
      fprintf (stderr, "%s: out of memory\n", prog_name);
      exit (1);
    }
  return strcpy (sbuf, buf);
}

static DWORD WINAPI
get_long_path_name_w32impl (LPCSTR src, LPSTR sbuf, DWORD)
{
  char buf1[MAX_PATH], buf2[MAX_PATH], *ptr;
  const char *pelem, *next;
  WIN32_FIND_DATA w32_fd;
  int len;

  strcpy (buf1, src);
  *buf2 = 0;
  pelem = src;
  ptr = buf2;
  while (pelem)
    {
      next = pelem;
      if (*next == '\\')
	{
	  strcat (ptr++, "\\");
	  pelem++;
	  if (!*pelem)
	    break;
	  continue;
	}
      pelem = strchr (next, '\\');
      len = pelem ? (pelem++ - next) : strlen (next);
      strncpy (ptr, next, len);
      ptr[len] = 0;
      if (next[1] != ':' && strcmp(next, ".") && strcmp(next, ".."))
	{
	  HANDLE h;
	  h = FindFirstFile (buf2, &w32_fd);
	  if (h != INVALID_HANDLE_VALUE)
	    {
	    strcpy (ptr, w32_fd.cFileName);
	      FindClose (h);
	    }
	}
      ptr += strlen (ptr);
      if (pelem)
	{
	  *ptr++ = '\\';
	  *ptr = 0;
	}
    }
  if (sbuf)
    strcpy (sbuf, buf2);
  SetLastError (0);
  return strlen (buf2) + (sbuf ? 0 : 1);
}

static char *
get_long_name (const char *filename, DWORD& len)
{
  char *sbuf, buf[MAX_PATH];
  static HINSTANCE k32 = LoadLibrary ("kernel32.dll");
  static DWORD (WINAPI *GetLongPathName) (LPCSTR, LPSTR, DWORD) =
    (DWORD (WINAPI *) (LPCSTR, LPSTR, DWORD)) GetProcAddress (k32, "GetLongPathNameA");
  if (!GetLongPathName)
    GetLongPathName = get_long_path_name_w32impl;

  len = GetLongPathName (filename, buf, MAX_PATH);
  if (len == 0)
    {
      DWORD err = GetLastError ();

      if (err == ERROR_INVALID_PARAMETER)
	{
	  fprintf (stderr, "%s: cannot create long name of %s\n", prog_name,
		   filename);
	  exit (2);
	}
      else if (err == ERROR_FILE_NOT_FOUND)
	len = get_long_path_name_w32impl (filename, buf, MAX_PATH);
      else
	{
	  buf[0] = '\0';
	  strncat (buf, filename, MAX_PATH - 1);
	  len = strlen (buf);
	}
    }
  sbuf = (char *) malloc (len + 1);
  if (!sbuf)
    {
      fprintf (stderr, "%s: out of memory\n", prog_name);
      exit (1);
    }
  return strcpy (sbuf, buf);
}

static char *
get_long_paths (char *path)
{
  char *sbuf;
  char *ptr;
  int n = 1;

  ptr = path;
  while ((ptr = strchr (ptr, ';')))
    {
      ptr++;
      n++;
    }

  char *paths[n];
  DWORD acc = 0;
  int i;
  if (!n)
    return strdup ("");

  for (i = 0, ptr = path; ptr; i++)
    {
      DWORD len;
      char *next = ptr;
      ptr = strchr (ptr, ';');
      if (ptr)
	*ptr++ = 0;
      paths[i] = get_long_name (next, len);
      acc += len + 1;
    }

  sbuf = (char *) malloc (acc + 1);
  if (sbuf == NULL)
    {
      fprintf (stderr, "%s: out of memory\n", prog_name);
      exit (1);
    }

  sbuf[0] = '\0';
  for (i = 0; i < n; i++)
    {
      strcat (strcat (sbuf, paths[i]), ";");
      free (paths[i]);
    }

  strchr (sbuf, '\0')[-1] = '\0';
  return sbuf;
}

static void
convert_slashes (char* name)
{
  while ((name = strchr (name, '\\')) != NULL)
    {
      if (*name == '\\')
	*name = '/';
       name++;
   }
}

static char *
get_mixed_name (const char* filename)
{
  char* mixed_buf = strdup (filename);

  if (mixed_buf == NULL)
    {
      fprintf (stderr, "%s: out of memory\n", prog_name);
      exit (1);
    }

  convert_slashes (mixed_buf);

  return mixed_buf;
}

static bool
get_special_folder (char* path, int id)
{
  path[0] = 0;
  LPITEMIDLIST pidl = 0;
  if (SHGetSpecialFolderLocation (NULL, id, &pidl) != S_OK)
    return false;
  if (!SHGetPathFromIDList (pidl, path) || !path[0])
    return false;
  return true;
}

static void
get_user_folder (char* path, int id, int allid)
{
  if (!get_special_folder (path, allusers_flag ? allid : id) && allusers_flag)
    get_special_folder (path, id); // Fix for Win9x without any "All Users"
}

static void
dowin (char option)
{
  char *buf, buf1[MAX_PATH], buf2[MAX_PATH];
  DWORD len = MAX_PATH;
  WIN32_FIND_DATA w32_fd;
  HINSTANCE k32;
  BOOL (*GetProfilesDirectoryAPtr) (LPSTR, LPDWORD) = 0;

  buf = buf1;
  buf[0] = 0;
  switch (option)
    {
    case 'D':
      get_user_folder (buf, CSIDL_DESKTOPDIRECTORY,
			    CSIDL_COMMON_DESKTOPDIRECTORY);
      break;

    case 'P':
      get_user_folder (buf, CSIDL_PROGRAMS, CSIDL_COMMON_PROGRAMS);
      break;

    case 'O':
      get_user_folder (buf, CSIDL_PERSONAL, CSIDL_COMMON_DOCUMENTS);
      break;

    case 'F':
      {
	int val = -1, len = -1;
	if (!(sscanf (output_arg, "%i%n", &val, &len) == 1
	      && len == (int) strlen (output_arg) && val >= 0))
	  {
	    fprintf (stderr, "%s: syntax error in special folder ID %s\n",
		     prog_name, output_arg);
	    exit (1);
	  }
	get_special_folder (buf, val);
      }
      break;

    case 'H':
      k32 = LoadLibrary ("userenv");
      if (k32)
	GetProfilesDirectoryAPtr = (BOOL (*) (LPSTR, LPDWORD))
	  GetProcAddress (k32, "GetProfilesDirectoryA");
      if (GetProfilesDirectoryAPtr)
	(*GetProfilesDirectoryAPtr) (buf, &len);
      else
	{
	  GetWindowsDirectory (buf, MAX_PATH);
	  strcat (buf, "\\Profiles");
	}
      break;

    case 'S':
      GetSystemDirectory (buf, MAX_PATH);
      FindFirstFile (buf, &w32_fd);
      strcpy (strrchr (buf, '\\') + 1, w32_fd.cFileName);
      break;

    case 'W':
      GetWindowsDirectory (buf, MAX_PATH);
      break;

    default:
      usage (stderr, 1);
    }

  if (!buf[0])
    {
      fprintf (stderr, "%s: failed to retrieve special folder path\n", prog_name);
    }
  else if (!windows_flag)
    {
      if (cygwin_conv_to_posix_path (buf, buf2))
	fprintf (stderr, "%s: error converting \"%s\" - %s\n",
		 prog_name, buf, strerror (errno));
      else
	buf = buf2;
    }
  else
    {
      if (shortname_flag)
	buf = get_short_name (buf);
      if (mixed_flag)
	buf = get_mixed_name (buf);
    }
  printf ("%s\n", buf);
  exit (0);
}

static void
report_mode (char *filename)
{
  switch (cygwin_internal (CW_GET_BINMODE, filename))
    {
    case O_BINARY:
      printf ("%s: binary\n", filename);
      break;
    case O_TEXT:
      printf ("%s: text\n", filename);
      break;
    default:
      fprintf (stderr, "%s: file '%s' - %s\n", prog_name, filename,
	       strerror (errno));
      break;
    }
}

static void
doit (char *filename)
{
  char *buf;
  DWORD len;
  int err;
  int (*conv_func) (const char *, char *);

  if (!path_flag)
    {
      len = strlen (filename);
      if (len)
	len += MAX_PATH + 1001;
      else if (ignore_flag)
	exit (0);
      else
	{
	  fprintf (stderr, "%s: can't convert empty path\n", prog_name);
	  exit (1);
	}
    }
  else if (unix_flag)
    len = cygwin_win32_to_posix_path_list_buf_size (filename);
  else
    len = cygwin_posix_to_win32_path_list_buf_size (filename);

  buf = (char *) malloc (len);
  if (buf == NULL)
    {
      fprintf (stderr, "%s: out of memory\n", prog_name);
      exit (1);
    }

  if (path_flag)
    {
      if (unix_flag)
	err = cygwin_win32_to_posix_path_list (filename, buf);
      else
	{
	  err = cygwin_posix_to_win32_path_list (filename, buf);
	  if (err)
	    /* oops */;
	  buf = get_device_paths (buf);
	  if (shortname_flag)
	    buf = get_short_paths (buf);
	  if (longname_flag)
	    buf = get_long_paths (buf);
	  if (mixed_flag)
	    buf = get_mixed_name (buf);
	}
      if (err)
	{
	  fprintf (stderr, "%s: error converting \"%s\" - %s\n",
		   prog_name, filename, strerror (errno));
	  exit (1);
	}
    }
  else
    {
      if (unix_flag)
	conv_func = (absolute_flag ? cygwin_conv_to_full_posix_path :
		     cygwin_conv_to_posix_path);
      else
	conv_func = (absolute_flag ? cygwin_conv_to_full_win32_path :
		     cygwin_conv_to_win32_path);
      err = conv_func (filename, buf);
      if (err)
	{
	  fprintf (stderr, "%s: error converting \"%s\" - %s\n",
		   prog_name, filename, strerror (errno));
	  exit (1);
	}
      if (!unix_flag)
	{
	  buf = get_device_name (buf);
	  if (shortname_flag)
	    buf = get_short_name (buf);
	  if (longname_flag)
	    buf = get_long_name (buf, len);
	  if (mixed_flag)
	    buf = get_mixed_name (buf);
	}
    }

  puts (buf);
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
cygpath (cygwin) %.*s\n\
Path Conversion Utility\n\
Copyright 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005 Red Hat, Inc.\n\
Compiled on %s\n\
", len, v, __DATE__);
}

int
main (int argc, char **argv)
{
  int c, o = 0;
  int options_from_file_flag;
  int mode_flag;

  prog_name = strrchr (argv[0], '/');
  if (prog_name == NULL)
    prog_name = strrchr (argv[0], '\\');
  if (prog_name == NULL)
    prog_name = argv[0];
  else
    prog_name++;

  path_flag = 0;
  unix_flag = 1;
  windows_flag = 0;
  shortname_flag = 0;
  longname_flag = 0;
  mixed_flag = 0;
  ignore_flag = 0;
  options_from_file_flag = 0;
  allusers_flag = 0;
  output_flag = 0;
  mode_flag = 0;
  while ((c = getopt_long (argc, argv, options,
			   long_options, (int *) NULL)) != EOF)
    {
      switch (c)
	{
	case 'a':
	  absolute_flag = 1;
	  break;

	case 'c':
	  CloseHandle ((HANDLE) strtoul (optarg, NULL, 16));
	  break;

	case 'd':
	  if (windows_flag)
	    usage (stderr, 1);
	  unix_flag = 0;
	  windows_flag = 1;
	  shortname_flag = 1;
	  break;

	case 'f':
	  file_arg = optarg;
	  break;

	case 'M':
	  mode_flag = 1;
	  break;

	case 'o':
	  options_from_file_flag = 1;
	  break;

	case 'p':
	  path_flag = 1;
	  break;

	case 'u':
	  if (windows_flag || mixed_flag)
	    usage (stderr, 1);
	  unix_flag = 1;
	  break;

	case 'w':
	  if (windows_flag || mixed_flag)
	    usage (stderr, 1);
	  unix_flag = 0;
	  windows_flag = 1;
	  break;

	 case 'm':
	  unix_flag = 0;
	  windows_flag = 1;
	  mixed_flag = 1;
	  break;

	case 'l':
	  longname_flag = 1;
	  break;

	case 's':
	  shortname_flag = 1;
	  break;

	 case 't':
	  if (optarg == NULL)
	    usage (stderr, 1);

	  format_type_arg = (*optarg == '=') ? (optarg + 1) : (optarg);
	  if (strcasecmp (format_type_arg, "dos") == 0)
	    {
	    if (windows_flag || longname_flag)
	      usage (stderr, 1);
	    unix_flag = 0;
	    windows_flag = 1;
	    shortname_flag = 1;
	    }
	  else if (strcasecmp (format_type_arg, "mixed") == 0)
	    {
	    unix_flag = 0;
	    mixed_flag = 1;
	    }
	  else if (strcasecmp (format_type_arg, "unix") == 0)
	    {
	    if (windows_flag)
	      usage (stderr, 1);
	    unix_flag = 1;
	    }
	  else if (strcasecmp (format_type_arg, "windows") == 0)
	    {
	    if (mixed_flag)
	      usage (stderr, 1);
	    unix_flag = 0;
	    windows_flag = 1;
	    }
	  else
	    usage (stderr, 1);
	  break;

	case 'A':
	  allusers_flag = 1;
	  break;

	case 'D':
	case 'H':
	case 'O':
	case 'P':
	case 'S':
	case 'W':
	  if (output_flag)
	    usage (stderr, 1);
	  output_flag = 1;
	  o = c;
	  break;

	case 'F':
	  if (output_flag || !optarg)
	    usage (stderr, 1);
	  output_flag = 1;
	  output_arg = optarg;
	  o = c;
	  break;

	case 'i':
	  ignore_flag = 1;
	  break;

	case 'h':
	  usage (stdout, 0);
	  break;

	case 'v':
	  print_version ();
	  exit (0);

	default:
	  usage (stderr, 1);
	  break;
	}
    }

  if (options_from_file_flag && !file_arg)
    usage (stderr, 1);

  if (longname_flag && !windows_flag)
    usage (stderr, 1);

  if (shortname_flag && !windows_flag)
    usage (stderr, 1);

  if (!unix_flag && !windows_flag && !mixed_flag && !options_from_file_flag)
    usage (stderr, 1);

  if (!file_arg)
    {
      if (output_flag)
	dowin (o);

      if (optind > argc - 1)
	usage (stderr, 1);

      for (int i = optind; argv[i]; i++)
	if (mode_flag)
	  report_mode (argv[i]);
	else
	  doit (argv[i]);
    }
  else
    {
      FILE *fp;
      char buf[PATH_MAX * 2 + 1];

      if (argv[optind])
	usage (stderr, 1);

      if (strcmp (file_arg, "-") != 0)
	fp = fopen (file_arg, "rt");
      else
	{
	  fp = stdin;
	  setmode (0, O_TEXT);
	}
      if (fp == NULL)
	{
	  perror ("cygpath");
	  exit (1);
	}

      setbuf (stdout, NULL);
      while (fgets (buf, sizeof (buf), fp) != NULL)
	{
	  char *s = buf;
	  char *p = strchr (s, '\n');
	  if (p)
	    *p = '\0';
	  if (options_from_file_flag && *s == '-')
	    {
	      char c;
	      for (c = *++s; c && !isspace (c); c = *++s)
		switch (c)
		  {
		  case 'a':
		    absolute_flag = 1;
		    break;
		  case 'i':
		    ignore_flag = 1;
		    break;
		  case 's':
		    shortname_flag = 1;
		    longname_flag = 0;
		    break;
		  case 'l':
		    shortname_flag = 0;
		    longname_flag = 1;
		    break;
		  case 'm':
		    unix_flag = 0;
		    windows_flag = 1;
		    mixed_flag = 1;
		  case 'w':
		    unix_flag = 0;
		    windows_flag = 1;
		    break;
		  case 'u':
		    windows_flag = 0;
		    unix_flag = 1;
		    break;
		  case 'p':
		    path_flag = 1;
		    break;
		  case 'D':
		  case 'H':
		  case 'O':
		  case 'P':
		  case 'S':
		  case 'W':
		    output_flag = 1;
		    o = c;
		    break;
		  }
	      if (*s)
		do
		  s++;
		while (*s && isspace (*s));
	    }
	  if (*s && !output_flag)
	    doit (s);
	  if (!*s && output_flag)
	    dowin (o);
	}
    }

  exit (0);
}
