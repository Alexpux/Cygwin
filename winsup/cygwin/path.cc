/* path.cc: path support.

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

/* This module's job is to
   - convert between POSIX and Win32 style filenames,
   - support the `mount' functionality,
   - support symlinks for files and directories

   Pathnames are handled as follows:

   - A \ or : in a path denotes a pure windows spec.
   - Paths beginning with // (or \\) are not translated (i.e. looked
     up in the mount table) and are assumed to be UNC path names.

   The goal in the above set of rules is to allow both POSIX and Win32
   flavors of pathnames without either interfering.  The rules are
   intended to be as close to a superset of both as possible.

   Note that you can have more than one path to a file.  The mount
   table is always prefered when translating Win32 paths to POSIX
   paths.  Win32 paths in mount table entries may be UNC paths or
   standard Win32 paths starting with <drive-letter>:

   Text vs Binary issues are not considered here in path style
   decisions, although the appropriate flags are retrieved and
   stored in various structures.

   Removing mounted filesystem support would simplify things greatly,
   but having it gives us a mechanism of treating disk that lives on a
   UNIX machine as having UNIX semantics [it allows one to edit a text
   file on that disk and not have cr's magically appear and perhaps
   break apps running on UNIX boxes].  It also useful to be able to
   layout a hierarchy without changing the underlying directories.

   The semantics of mounting file systems is not intended to precisely
   follow normal UNIX systems.

   Each DOS drive is defined to have a current directory.  Supporting
   this would complicate things so for now things are defined so that
   c: means c:\.  FIXME: Is this still true?
*/

#include "winsup.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <mntent.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <winioctl.h>
#include <wingdi.h>
#include <winuser.h>
#include <winnls.h>
#include <winnetwk.h>
#include <sys/cygwin.h>
#include <cygwin/version.h>
#include "cygerrno.h"
#include "security.h"
#include "fhandler.h"
#include "path.h"
#include "sync.h"
#include "sigproc.h"
#include "pinfo.h"
#include "dtable.h"
#include "cygheap.h"
#include "shared_info.h"
#include "registry.h"
#include <assert.h>

#ifdef _MT_SAFE
#define iteration _reent_winsup ()->_iteration
#define available_drives _reent_winsup ()->available_drives
#else
static int iteration;
static DWORD available_drives;
#endif

static int normalize_win32_path (const char *src, char *dst);
static void slashify (const char *src, char *dst, int trailing_slash_p);
static void backslashify (const char *src, char *dst, int trailing_slash_p);

struct symlink_info
{
  char contents[MAX_PATH + 4];
  char *ext_here;
  int extn;
  unsigned pflags;
  DWORD fileattr;
  int is_symlink;
  bool ext_tacked_on;
  int error;
  bool case_clash;
  int check (char *path, const suffix_info *suffixes, unsigned opt);
  BOOL case_check (char *path);
};

int pcheck_case = PCHECK_RELAXED; /* Determines the case check behaviour. */

static char shortcut_header[SHORTCUT_HDR_SIZE];
static BOOL shortcut_initalized;

static void
create_shortcut_header (void)
{
  if (!shortcut_initalized)
    {
      shortcut_header[0] = 'L';
      shortcut_header[4] = '\001';
      shortcut_header[5] = '\024';
      shortcut_header[6] = '\002';
      shortcut_header[12] = '\300';
      shortcut_header[19] = 'F';
      shortcut_header[20] = '\f';
      shortcut_header[60] = '\001';
      shortcut_initalized = TRUE;
    }
}

#define CYGWIN_REGNAME (cygheap->cygwin_regname ?: CYGWIN_INFO_CYGWIN_REGISTRY_NAME)

/* Determine if path prefix matches current cygdrive */
#define iscygdrive(path) \
  (path_prefix_p (mount_table->cygdrive, (path), mount_table->cygdrive_len))

#define iscygdrive_device(path) \
  (isalpha (path[mount_table->cygdrive_len]) && \
   (path[mount_table->cygdrive_len + 1] == '/' || \
    !path[mount_table->cygdrive_len + 1]))

#define isproc(path) \
  (path_prefix_p (proc, (path), proc_len))

#define isvirtual_dev(devn) \
  (devn == FH_CYGDRIVE || devn == FH_PROC || devn == FH_REGISTRY || devn == FH_PROCESS)

/* Return non-zero if PATH1 is a prefix of PATH2.
   Both are assumed to be of the same path style and / vs \ usage.
   Neither may be "".
   LEN1 = strlen (PATH1).  It's passed because often it's already known.

   Examples:
   /foo/ is a prefix of /foo  <-- may seem odd, but desired
   /foo is a prefix of /foo/
   / is a prefix of /foo/bar
   / is not a prefix of foo/bar
   foo/ is a prefix foo/bar
   /foo is not a prefix of /foobar
*/

int
path_prefix_p (const char *path1, const char *path2, int len1)
{
  /* Handle case where PATH1 has trailing '/' and when it doesn't.  */
  if (len1 > 0 && isdirsep (path1[len1 - 1]))
    len1--;

  if (len1 == 0)
    return isdirsep (path2[0]) && !isdirsep (path2[1]);

  if (!pathnmatch (path1, path2, len1))
    return 0;

  return isdirsep (path2[len1]) || path2[len1] == 0 || path1[len1 - 1] == ':';
}

/* Return non-zero if paths match in first len chars.
   Check is dependent of the case sensitivity setting. */
int
pathnmatch (const char *path1, const char *path2, int len)
{
  return pcheck_case == PCHECK_STRICT ? !strncmp (path1, path2, len)
				      : strncasematch (path1, path2, len);
}

/* Return non-zero if paths match. Check is dependent of the case
   sensitivity setting. */
int
pathmatch (const char *path1, const char *path2)
{
  return pcheck_case == PCHECK_STRICT ? !strcmp (path1, path2)
				      : strcasematch (path1, path2);
}

/* Normalize a POSIX path.
   \'s are converted to /'s in the process.
   All duplicate /'s, except for 2 leading /'s, are deleted.
   The result is 0 for success, or an errno error value.  */

#define isslash(c) ((c) == '/')

static int
normalize_posix_path (const char *src, char *dst)
{
  const char *src_start = src;
  char *dst_start = dst;

  syscall_printf ("src %s", src);

  if (isdrive (src) || strpbrk (src, "\\:"))
    {
      int err = normalize_win32_path (src, dst);
      if (!err && isdrive (dst))
	for (char *p = dst; (p = strchr (p, '\\')); p++)
	  *p = '/';
      return err;
    }

  if (!isslash (src[0]))
    {
      if (!cygheap->cwd.get (dst))
	return get_errno ();
      dst = strchr (dst, '\0');
      if (*src == '.')
	{
	  if (dst == dst_start + 1 && *dst_start == '/')
	     --dst;
	  goto sawdot;
	}
      if (dst > dst_start && !isslash (dst[-1]))
	*dst++ = '/';
    }
  /* Two leading /'s?  If so, preserve them.  */
  else if (isslash (src[1]))
    {
      *dst++ = '/';
      *dst++ = '/';
      src += 2;
      if (isslash (*src))
	{ /* Starts with three or more slashes - reset. */
	  dst = dst_start;
	  *dst++ = '/';
	  src = src_start + 1;
	}
      else if (src[0] == '.' && isslash (src[1]))
	{
	  *dst++ = '.';
	  *dst++ = '/';
	  src += 2;
	}
    }
  else
    *dst = '\0';

  while (*src)
    {
      /* Strip runs of /'s.  */
      if (!isslash (*src))
	*dst++ = *src++;
      else
	{
	  while (*++src)
	    {
	      if (isslash (*src))
		continue;

	      if (*src != '.')
		break;

	    sawdot:
	      if (src[1] != '.')
		{
		  if (!src[1])
		    {
		      if (dst == dst_start)
			*dst++ = '/';
		      goto done;
		    }
		  if (!isslash (src[1]))
		    break;
		}
	      else if (src[2] && !isslash (src[2]))
		{
		  if (src[2] == '.')
		    return ENOENT;
		  break;
		}
	      else
		{
		  while (dst > dst_start && !isslash (*--dst))
		    continue;
		  src++;
		}
	    }

	  *dst++ = '/';
	}
	if ((dst - dst_start) >= MAX_PATH)
	  {
	    debug_printf ("ENAMETOOLONG = normalize_posix_path (%s)", src);
	    return ENAMETOOLONG;
	  }
    }

done:
  *dst = '\0';
  if (--dst > dst_start && isslash (*dst))
    *dst = '\0';

  debug_printf ("%s = normalize_posix_path (%s)", dst_start, src_start);
  return 0;
}

inline void
path_conv::add_ext_from_sym (symlink_info &sym)
{
  if (sym.ext_here && *sym.ext_here)
    {
      known_suffix = path + sym.extn;
      if (sym.ext_tacked_on)
	strcpy (known_suffix, sym.ext_here);
    }
}

static void __stdcall mkrelpath (char *dst) __attribute__ ((regparm (2)));
static void __stdcall
mkrelpath (char *path)
{
  char cwd_win32[MAX_PATH];
  if (!cygheap->cwd.get (cwd_win32, 0))
    return;

  unsigned cwdlen = strlen (cwd_win32);
  if (!path_prefix_p (cwd_win32, path, cwdlen))
    return;

  size_t n = strlen (path);
  if (n < cwdlen)
    return;

  char *tail = path;
  if (n == cwdlen)
    tail += cwdlen;
  else
    tail += isdirsep (cwd_win32[cwdlen - 1]) ? cwdlen : cwdlen + 1;

  memmove (path, tail, strlen (tail) + 1);
  if (!*path)
    strcpy (path, ".");
}

bool
fs_info::update (const char *win32_path)
{
  char tmp_buf [MAX_PATH];
  strncpy (tmp_buf, win32_path, MAX_PATH);

  if (!rootdir (tmp_buf))
    {
      debug_printf ("Cannot get root component of path %s", win32_path);
      name [0] = '\0';
      sym_opt = flags = serial = 0;
      return false;
    }

  if (strcmp (tmp_buf, root_dir) == 0)
    return 1;

  strncpy (root_dir, tmp_buf, MAX_PATH);
  drive_type = GetDriveType (root_dir);
  if (drive_type == DRIVE_REMOTE || (drive_type == DRIVE_UNKNOWN && (root_dir[0] == '\\' && root_dir[1] == '\\')))
    is_remote_drive = 1;
  else
    is_remote_drive = 0;

  if (!GetVolumeInformation (root_dir, NULL, 0, &serial, NULL, &flags,
				 name, sizeof (name)))
    {
      debug_printf ("Cannot get volume information (%s), %E", root_dir);
      name [0] = '\0';
      sym_opt = flags = serial = 0;
      return false;
    }
  /* FIXME: Samba by default returns "NTFS" in file system name, but
   * doesn't support Extended Attributes. If there's some fast way to
   * distinguish between samba and real ntfs, it should be implemented
   * here.
   */
  sym_opt = (!is_remote_drive && strcmp (name, "NTFS") == 0) ? PC_CHECK_EA : 0;

  return true;
}

char *
path_conv::return_and_clear_normalized_path ()
{
  char *s = normalized_path;
  normalized_path = NULL;
  return s;
}

void
path_conv::fillin (HANDLE h)
{
  BY_HANDLE_FILE_INFORMATION local;
  if (!GetFileInformationByHandle (h, &local))
    {
      fileattr = INVALID_FILE_ATTRIBUTES;
      fs.serial = 0;
    }
  else
    {
      fileattr = local.dwFileAttributes;
      fs.serial = local.dwVolumeSerialNumber;
    }
    fs.drive_type = DRIVE_UNKNOWN;
}

/* Convert an arbitrary path SRC to a pure Win32 path, suitable for
   passing to Win32 API routines.

   If an error occurs, `error' is set to the errno value.
   Otherwise it is set to 0.

   follow_mode values:
	SYMLINK_FOLLOW	    - convert to PATH symlink points to
	SYMLINK_NOFOLLOW    - convert to PATH of symlink itself
	SYMLINK_IGNORE	    - do not check PATH for symlinks
	SYMLINK_CONTENTS    - just return symlink contents
*/

void
path_conv::check (const char *src, unsigned opt,
		  const suffix_info *suffixes)
{
  /* This array is used when expanding symlinks.  It is MAX_PATH * 2
     in length so that we can hold the expanded symlink plus a
     trailer.  */
  char path_copy[MAX_PATH + 3];
  char tmp_buf[2 * MAX_PATH + 3];
  symlink_info sym;
  bool need_directory = 0;
  bool saw_symlinks = 0;
  int is_relpath;
  char *tail;
  sigframe thisframe (mainthread);

#if 0
  static path_conv last_path_conv;
  static char last_src[MAX_PATH + 1];

  if (*last_src && strcmp (last_src, src) == 0)
    {
      *this = last_path_conv;
      return;
    }
#endif

  int loop = 0;
  path_flags = 0;
  known_suffix = NULL;
  fileattr = INVALID_FILE_ATTRIBUTES;
  case_clash = false;
  devn = unit = 0;
  fs.root_dir[0] = '\0';
  fs.name[0] = '\0';
  fs.flags = fs.serial = 0;
  fs.sym_opt = 0;
  fs.drive_type = 0;
  fs.is_remote_drive = 0;
  normalized_path = NULL;

  if (!(opt & PC_NULLEMPTY))
    error = 0;
  else if ((error = check_null_empty_str (src)))
    return;
  /* This loop handles symlink expansion.  */
  for (;;)
    {
      MALLOC_CHECK;
      assert (src);

      char *p = strrchr (src, '\0');
      /* Detect if the user was looking for a directory.  We have to strip the
	 trailing slash initially and add it back on at the end due to Windows
	 brain damage. */
      if (--p > src)
	{
	  if (isdirsep (*p))
	    need_directory = 1;
	  else if (--p  > src && p[1] == '.' && isdirsep (*p))
	    need_directory = 1;
	}

      is_relpath = !isabspath (src);
      error = normalize_posix_path (src, path_copy);
      if (error)
	return;

      tail = strchr (path_copy, '\0');   // Point to end of copy
      char *path_end = tail;
      tail[1] = '\0';

      /* Scan path_copy from right to left looking either for a symlink
	 or an actual existing file.  If an existing file is found, just
	 return.  If a symlink is found exit the for loop.
	 Also: be careful to preserve the errno returned from
	 symlink.check as the caller may need it. */
      /* FIXME: Do we have to worry about multiple \'s here? */
      int component = 0;		// Number of translated components
      sym.contents[0] = '\0';

      for (;;)
	{
	  const suffix_info *suff;
	  char pathbuf[MAX_PATH];
	  char *full_path;

	  /* Don't allow symlink.check to set anything in the path_conv
	     class if we're working on an inner component of the path */
	  if (component)
	    {
	      suff = NULL;
	      sym.pflags = 0;
	      full_path = pathbuf;
	    }
	  else
	    {
	      suff = suffixes;
	      sym.pflags = path_flags;
	      full_path = this->path;
	    }

	  /* Convert to native path spec sans symbolic link info. */
	  error = mount_table->conv_to_win32_path (path_copy, full_path, devn,
						   unit, &sym.pflags, 1);

	  if (error)
	    return;

	  if (devn == FH_CYGDRIVE)
	    {
	      if (!component)
		fileattr = FILE_ATTRIBUTE_DIRECTORY;
	      else
		{
		  devn = FH_BAD;
		  fileattr = GetFileAttributes (this->path);
		}
	      goto out;
	    }
	  else if (isvirtual_dev (devn))
	    {
	      /* FIXME: Calling build_fhandler here is not the right way to handle this. */
	      fhandler_virtual *fh =
		(fhandler_virtual *) cygheap->fdtab.build_fhandler (-1, devn, (const char *) path_copy, NULL, unit);
	      int file_type = fh->exists ();
	      switch (file_type)
		{
		  case 1:
		  case 2:
		    fileattr = FILE_ATTRIBUTE_DIRECTORY;
		    break;
		  case -1:
		    fileattr = 0;
		    break;
		  default:
		    fileattr = INVALID_FILE_ATTRIBUTES;
		    break;
		}
	      delete fh;
	      goto out;
	    }
	  /* devn should not be a device.  If it is, then stop parsing now. */
	  else if (devn != FH_BAD)
	    {
	      fileattr = 0;
	      path_flags = sym.pflags;
	      if (component)
		{
		  error = ENOTDIR;
		  return;
		}
	      goto out;		/* Found a device.  Stop parsing. */
	    }

	  if (!fs.update (full_path))
	    fs.root_dir[0] = '\0';

	  /* Eat trailing slashes */
	  char *dostail = strchr (full_path, '\0');

	  /* If path is only a drivename, Windows interprets it as the
	     current working directory on this drive instead of the root
	     dir which is what we want. So we need the trailing backslash
	     in this case. */
	  while (dostail > full_path + 3 && (*--dostail == '\\'))
	    *tail = '\0';

	  if (full_path[0] && full_path[1] == ':' && full_path[2] == '\0')
	    {
	      full_path[2] = '\\';
	      full_path[3] = '\0';
	    }

	  if ((opt & PC_SYM_IGNORE) && pcheck_case == PCHECK_RELAXED)
	    {
	      fileattr = GetFileAttributes (this->path);
	      goto out;
	    }

	  int len = sym.check (full_path, suff, opt | fs.sym_opt);

	  if (sym.case_clash)
	    {
	      if (pcheck_case == PCHECK_STRICT)
		{
		  case_clash = TRUE;
		  error = ENOENT;
		  goto out;
		}
	      /* If pcheck_case==PCHECK_ADJUST the case_clash is remembered
		 if the last component is concerned. This allows functions
		 which shall create files to avoid overriding already existing
		 files with another case. */
	      if (!component)
		case_clash = TRUE;
	    }
	  if (!(opt & PC_SYM_IGNORE))
	    {
	      if (!component)
		{
		  fileattr = sym.fileattr;
		  path_flags = sym.pflags;
		}

	      /* If symlink.check found an existing non-symlink file, then
		 it sets the appropriate flag.  It also sets any suffix found
		 into `ext_here'. */
	      if (!sym.is_symlink && sym.fileattr != INVALID_FILE_ATTRIBUTES)
		{
		  error = sym.error;
		  if (component == 0)
		    add_ext_from_sym (sym);
		  if (pcheck_case == PCHECK_RELAXED)
		    goto out;	// file found
		  /* Avoid further symlink evaluation. Only case checks are
		     done now. */
		  opt |= PC_SYM_IGNORE;
		}
	      /* Found a symlink if len > 0.  If component == 0, then the
		 src path itself was a symlink.  If !follow_mode then
		 we're done.  Otherwise we have to insert the path found
		 into the full path that we are building and perform all of
		 these operations again on the newly derived path. */
	      else if (len > 0)
		{
		  saw_symlinks = 1;
		  if (component == 0 && !need_directory && !(opt & PC_SYM_FOLLOW))
		    {
		      set_symlink (); // last component of path is a symlink.
		      if (opt & PC_SYM_CONTENTS)
			{
			  strcpy (path, sym.contents);
			  goto out;
			}
		      add_ext_from_sym (sym);
		      if (pcheck_case == PCHECK_RELAXED)
			goto out;
		      /* Avoid further symlink evaluation. Only case checks are
			 done now. */
		      opt |= PC_SYM_IGNORE;
		    }
		  else
		    break;
		}
	      /* No existing file found. */
	    }

	  /* Find the "tail" of the path, e.g. in '/for/bar/baz',
	     /baz is the tail. */
	  char *newtail = strrchr (path_copy, '/');
	  if (tail != path_end)
	    *tail = '/';

	  /* Exit loop if there is no tail or we are at the
	     beginning of a UNC path */
	  if (!newtail || newtail == path_copy || (newtail == path_copy + 1 && newtail[-1] == '/'))
	    goto out;	// all done

	  tail = newtail;

	  /* Haven't found an existing pathname component yet.
	     Pinch off the tail and try again. */
	  *tail = '\0';
	  component++;
	}

      /* Arrive here if above loop detected a symlink. */
      if (++loop > MAX_LINK_DEPTH)
	{
	  error = ELOOP;   // Eep.
	  return;
	}

      MALLOC_CHECK;

      /* The tail is pointing at a null pointer.  Increment it and get the length.
	 If the tail was empty then this increment will end up pointing to the extra
	 \0 added to path_copy above. */
      int taillen = strlen (++tail);
      int buflen = strlen (sym.contents);
      if (buflen + taillen > MAX_PATH)
	  {
	    error = ENAMETOOLONG;
	    strcpy (path, "::ENAMETOOLONG::");
	    return;
	  }

      /* Strip off current directory component since this is the part that refers
	 to the symbolic link. */
      if ((p = strrchr (path_copy, '/')) == NULL)
	p = path_copy;
      else if (p == path_copy)
	p++;
      *p = '\0';

      char *headptr;
      if (isabspath (sym.contents))
	headptr = tmp_buf;	/* absolute path */
      else
	{
	  /* Copy the first part of the path and point to the end. */
	  strcpy (tmp_buf, path_copy);
	  headptr = strchr (tmp_buf, '\0');
	}

      /* See if we need to separate first part + symlink contents with a / */
      if (headptr > tmp_buf && headptr[-1] != '/')
	*headptr++ = '/';

      /* Copy the symlink contents to the end of tmp_buf.
	 Convert slashes.  FIXME? */
      for (p = sym.contents; *p; p++)
	*headptr++ = *p == '\\' ? '/' : *p;

      /* Copy any tail component */
      if (tail >= path_end)
	*headptr = '\0';
      else
	{
	  *headptr++ = '/';
	  strcpy (headptr, tail);
	}

      /* Now evaluate everything all over again. */
      src = tmp_buf;
    }

  if (!(opt & PC_SYM_CONTENTS))
    add_ext_from_sym (sym);

out:
  if (opt & PC_POSIX)
    {
      if (tail[1] != '\0')
	*tail = '/';
      normalized_path = cstrdup (path_copy);
    }
  /* Deal with Windows stupidity which considers filename\. to be valid
     even when "filename" is not a directory. */
  if (!need_directory || error)
    /* nothing to do */;
  else if (fileattr & FILE_ATTRIBUTE_DIRECTORY)
    path_flags &= ~PATH_SYMLINK;
  else
    {
      debug_printf ("%s is a non-directory", path);
      error = ENOTDIR;
      return;
    }

  if (devn == FH_BAD)
    {
      if (!fs.update (path))
	{
	  fs.root_dir[0] = '\0';
	  set_has_acls (false);
	  set_has_buggy_open (false);
	}
      else
	{
	  set_isdisk ();
	  debug_printf ("root_dir(%s), this->path(%s), set_has_acls(%d)",
			fs.root_dir, this->path, fs.flags & FS_PERSISTENT_ACLS);
	  if (!allow_smbntsec && fs.is_remote_drive)
	    set_has_acls (false);
	  else
	    {
	      set_has_acls (fs.flags & FS_PERSISTENT_ACLS);
	      if (exec_state () != dont_know_if_executable)
		/* ok */;
	      else if (isdir ())
		set_exec (1);
	      else if (issymlink () || issocket ()
		       || allow_ntsec && wincap.has_security ())
		set_exec (0);

	    }
	  /* Known file systems with buggy open calls. Further explanation
	     in fhandler.cc (fhandler_disk_file::open). */
	  set_has_buggy_open (strcmp (fs.name, "SUNWNFS") == 0);
	}
    }
  if (issocket ())
    devn = FH_SOCKET;

  if (!(opt & PC_FULL))
    {
      if (is_relpath)
	mkrelpath (this->path);
      if (need_directory)
	{
	  size_t n = strlen (this->path);
	  /* Do not add trailing \ to UNC device names like \\.\a: */
	  if (this->path[n - 1] != '\\' &&
	      (strncmp (this->path, "\\\\.\\", 4) != 0 ||
	       !strncasematch (this->path + 4, "unc\\", 4)))
	    {
	      this->path[n] = '\\';
	      this->path[n + 1] = '\0';
	    }
	}
    }

  if (saw_symlinks)
    set_has_symlinks ();

  if (!error && !isdir () && !(path_flags & PATH_ALL_EXEC))
    {
      const char *p = strchr (path, '\0') - 4;
      if (p >= path &&
	  (strcasematch (".exe", p) ||
	   strcasematch (".bat", p) ||
	   strcasematch (".com", p)))
	path_flags |= PATH_EXEC;
    }

#if 0
  if (!error)
    {
      last_path_conv = *this;
      strcpy (last_src, src);
    }
#endif
}

static __inline int
digits (const char *name)
{
  char *p;
  int n = strtol (name, &p, 10);

  return p > name && !*p ? n : -1;
}

const char *windows_device_names[] NO_COPY =
{
  NULL,
  "\\dev\\console",
  "conin",
  "conout",
  "\\dev\\ttym",
  "\\dev\\tty%d",
  "\\dev\\ptym",
  "\\\\.\\com%d",
  "\\dev\\pipe",
  "\\dev\\piper",
  "\\dev\\pipew",
  "\\dev\\socket",
  "\\dev\\windows",

  NULL, NULL, NULL,

  "\\dev\\disk",
  "\\dev\\fd%d",
  "\\dev\\st%d",
  "nul",
  "\\dev\\zero",
  "\\dev\\%srandom",
  "\\dev\\mem",
  "\\dev\\clipboard",
  "\\dev\\dsp"
};

#define deveq(s) (strcasematch (name, (s)))
#define deveqn(s, n) (strncasematch (name, (s), (n)))
#define wdeveq(s) (strcasematch (w32_path, (s)))
#define wdeveqn(s, n) (strncasematch (w32_path, (s), (n)))
#define udeveq(s) (strcasematch (unix_path, (s)))
#define udeveqn(s, n) (strncasematch (unix_path, (s), (n)))

static int __stdcall
get_devn (const char *name, int &unit)
{
  int devn = FH_BAD;
  name += 5;
  if (deveq ("tty"))
    {
      if (real_tty_attached (myself))
	{
	  unit = myself->ctty;
	  devn = FH_TTYS;
	}
      else if (myself->ctty > 0)
	devn = FH_CONSOLE;
    }
  else if (deveqn ("tty", 3) && (unit = digits (name + 3)) >= 0)
    devn = FH_TTYS;
  else if (deveq ("ttym"))
    devn = FH_TTYM;
  else if (deveq ("ptmx"))
    devn = FH_PTYM;
  else if (deveq ("windows"))
    devn = FH_WINDOWS;
  else if (deveq ("dsp"))
    devn = FH_OSS_DSP;
  else if (deveq ("conin"))
    devn = FH_CONIN;
  else if (deveq ("conout"))
    devn = FH_CONOUT;
  else if (deveq ("null"))
    devn = FH_NULL;
  else if (deveq ("zero"))
    devn = FH_ZERO;
  else if (deveq ("random") || deveq ("urandom"))
    {
      devn = FH_RANDOM;
      unit = 8 + (deveqn ("u", 1) ? 1 : 0); /* Keep unit Linux conformant */
    }
  else if (deveq ("mem"))
    {
      devn = FH_MEM;
      unit = 1;
    }
  else if (deveq ("clipboard"))
    devn = FH_CLIPBOARD;
  else if (deveq ("port"))
    {
      devn = FH_MEM;
      unit = 4;
    }
  else if (deveqn ("com", 3) && (unit = digits (name + 3)) >= 0 && unit < 100)
    devn = FH_SERIAL;
  else if (deveqn ("ttyS", 4) && (unit = digits (name + 4)) >= 0)
    {
      devn = FH_SERIAL;
      unit++;
    }
  else if (deveq ("pipe"))
    devn = FH_PIPE;
  else if (deveq ("piper"))
    devn = FH_PIPER;
  else if (deveq ("pipew"))
    devn = FH_PIPEW;
  else if (deveq ("tcp") || deveq ("udp") || deveq ("streamsocket")
	   || deveq ("dgsocket"))
    {
      devn = FH_SOCKET;
      unit = tolower (*name) - 'a';
    }

  return devn;
}

/*
    major      minor    POSIX filename	NT filename
    -----      -----	--------------	-------------------------
    FH_TAPE	  0	/dev/st0	\device\tape0
    FH_TAPE	  1	/dev/st1	\device\tape1
    ...
    FH_TAPE	128	/dev/nst0	\device\tape0
    FH_TAPE	129	/dev/nst1	\device\tape1
    ...

    FH_FLOPPY     0	/dev/fd0	\device\floppy0
    FH_FLOPPY	  1	/dev/fd1	\device\floppy1
    ...

    FH_FLOPPY	 16	/dev/scd0	\device\cdrom0
    FH_FLOPPY	 17	/dev/scd0	\device\cdrom1
    ...

    FH_FLOPPY	 32	/dev/sda	\device\harddisk0\partition0
    FH_FLOPPY	 33	/dev/sda1	\device\harddisk0\partition1
    ...
    FH_FLOPPY	 47	/dev/sda15	\device\harddisk0\partition15

    FH_FLOPPY	 48	/dev/sdb	\device\harddisk1\partition0
    FH_FLOPPY    33     /dev/sdb1       \device\harddisk1\partition1
    ...
    FH_FLOPPY	208	/dev/sdl	\device\harddisk11\partition0
    ...
    FH_FLOPPY	223	/dev/sdl15	\device\harddisk11\partition15

    The following are needed to maintain backward compatibility with
    the old Win32 partitioning scheme on W2K/XP.

    FH_FLOPPY	224	from mount tab	\\.\A:
    ...
    FH_FLOPPY	250	from mount tab	\\.\Z:
*/
static int
get_raw_device_number (const char *name, const char *w32_path, int &unit)
{
  DWORD devn = FH_BAD;

  if (!w32_path)  /* New approach using fixed device names. */
    {
      if (deveqn ("st", 2))
	{
	  unit = digits (name + 2);
	  if (unit >= 0 && unit < 128)
	    devn = FH_TAPE;
	}
      else if (deveqn ("nst", 3))
	{
	  unit = digits (name + 3) + 128;
	  if (unit >= 128 && unit < 256)
	    devn = FH_TAPE;
	}
      else if (deveqn ("fd", 2))
	{
	  unit = digits (name + 2);
	  if (unit >= 0 && unit < 16)
	    devn = FH_FLOPPY;
	}
      else if (deveqn ("scd", 3))
	{
	  unit = digits (name + 3) + 16;
	  if (unit >= 16 && unit < 32)
	    devn = FH_FLOPPY;
	}
      else if (deveqn ("sd", 2) && isalpha (name[2]))
	{
	  unit = (cyg_tolower (name[2]) - 'a') * 16 + 32;
	  if (unit >= 32 && unit < 224)
	    if (!name[3])
	      devn = FH_FLOPPY;
	    else
	      {
		int d = digits (name + 3);
		if (d >= 1 && d < 16)
		  {
		    unit += d;
		    devn = FH_FLOPPY;
		  }
	      }
	}
    }
  else /* Backward compatible checking of mount table device mapping. */
    {
      if (wdeveqn ("tape", 4))
	{
	  unit = digits (w32_path + 4);
	  /* Norewind tape devices have leading n in name. */
	  if (deveqn ("n", 1))
	    unit += 128;
	  devn = FH_TAPE;
	}
      else if (wdeveqn ("physicaldrive", 13))
	{
	  unit = digits (w32_path + 13) * 16 + 32;
	  devn = FH_FLOPPY;
	}
      else if (isdrive (w32_path))
	{
	  unit = cyg_tolower (w32_path[0]) - 'a' + 224;
	  devn = FH_FLOPPY;
	}
    }
  return devn;
}

static int __stdcall get_device_number (const char *unix_path,
					const char *w32_path, int &unit)
  __attribute__ ((regparm(3)));
static int __stdcall
get_device_number (const char *unix_path, const char *w32_path, int &unit)
{
  DWORD devn = FH_BAD;
  unit = 0;

  if (*unix_path == '/' && udeveqn ("/dev/", 5))
    {
      devn = get_devn (unix_path, unit);
      if (devn == FH_BAD && *w32_path == '\\' && wdeveqn ("\\dev\\", 5))
	devn = get_devn (w32_path, unit);
      if (devn == FH_BAD && wdeveqn ("\\\\.\\", 4))
	devn = get_raw_device_number (unix_path + 5, w32_path + 4, unit);
      if (devn == FH_BAD)
	devn = get_raw_device_number (unix_path + 5, NULL, unit);
    }
  else
    {
      char *p = strrchr (unix_path, '/');
      if (p)
	unix_path = p + 1;
      if (udeveqn ("com", 3)
	 && (unit = digits (unix_path + 3)) >= 0 && unit < 100)
	devn = FH_SERIAL;
    }

  return devn;
}

/* Return TRUE if src_path is a Win32 device name, filling out the device
   name in win32_path */

static BOOL
win32_device_name (const char *src_path, char *win32_path,
		   DWORD &devn, int &unit)
{
  const char *devfmt;

  devn = get_device_number (src_path, win32_path, unit);

  if (devn == FH_BAD)
    return false;

  if ((devfmt = windows_device_names[FHDEVN (devn)]) == NULL)
    return false;
  switch (devn)
    {
      case FH_SOCKET:
	char *c;
	strcpy (win32_path, src_path);
	while (c = strchr (win32_path, '/'))
	  *c = '\\';
	break;
      case FH_RANDOM:
	__small_sprintf (win32_path, devfmt, unit == 8 ? "" : "u");
	break;
      case FH_TAPE:
	__small_sprintf (win32_path, "\\Device\\Tape%d", unit % 128);
	break;
      case FH_FLOPPY:
	if (unit < 16)
	  __small_sprintf (win32_path, "\\Device\\Floppy%d", unit);
	else if (unit < 32)
	  __small_sprintf (win32_path, "\\Device\\CdRom%d", unit - 16);
	else if (unit < 224)
	  __small_sprintf (win32_path, "\\Device\\Harddisk%d\\Partition%d",
				       (unit - 32) / 16, unit % 16);
	else
	  __small_sprintf (win32_path, "\\DosDevices\\%c:", unit - 224 + 'A');
	break;
      default:
	__small_sprintf (win32_path, devfmt, unit);
	break;
    }
  return TRUE;
}

/* Normalize a Win32 path.
   /'s are converted to \'s in the process.
   All duplicate \'s, except for 2 leading \'s, are deleted.

   The result is 0 for success, or an errno error value.
   FIXME: A lot of this should be mergeable with the POSIX critter.  */
static int
normalize_win32_path (const char *src, char *dst)
{
  const char *src_start = src;
  char *dst_start = dst;
  char *dst_root_start = dst;
  bool beg_src_slash = isdirsep (src[0]);

  if (beg_src_slash && isdirsep (src[1]))
    {
      *dst++ = '\\';
      src++;
      if (src[1] == '.' && isdirsep (src[2]))
	{
	  *dst++ = '\\';
	  *dst++ = '.';
	  src += 2;
	}
    }
  else if (strchr (src, ':') == NULL && *src != '/')
    {
      if (!cygheap->cwd.get (dst, 0))
	return get_errno ();
      if (beg_src_slash)
	{
	  if (dst[1] == ':')
	    dst[2] = '\0';
	  else if (slash_unc_prefix_p (dst))
	    {
	      char *p = strpbrk (dst + 2, "\\/");
	      if (p && (p = strpbrk (p + 1, "\\/")))
		  *p = '\0';
	    }
	}
      if (strlen (dst) + 1 + strlen (src) >= MAX_PATH)
	{
	  debug_printf ("ENAMETOOLONG = normalize_win32_path (%s)", src);
	  return ENAMETOOLONG;
	}
      dst += strlen (dst);
      if (!beg_src_slash)
	*dst++ = '\\';
    }

  while (*src)
    {
      /* Strip duplicate /'s.  */
      if (isdirsep (src[0]) && isdirsep (src[1]))
	src++;
      /* Ignore "./".  */
      else if (src[0] == '.' && isdirsep (src[1])
	       && (src == src_start || isdirsep (src[-1])))
	src += 2;

      /* Backup if "..".  */
      else if (src[0] == '.' && src[1] == '.'
	       /* dst must be greater than dst_start */
	       && dst[-1] == '\\'
	       && (isdirsep (src[2]) || src[2] == 0))
	{
	  /* Back up over /, but not if it's the first one.  */
	  if (dst > dst_root_start + 1)
	    dst--;
	  /* Now back up to the next /.  */
	  while (dst > dst_root_start + 1 && dst[-1] != '\\' && dst[-2] != ':')
	    dst--;
	  src += 2;
	  if (isdirsep (*src))
	    src++;
	}
      /* Otherwise, add char to result.  */
      else
	{
	  if (*src == '/')
	    *dst++ = '\\';
	  else
	    *dst++ = *src;
	  ++src;
	}
      if ((dst - dst_start) >= MAX_PATH)
	return ENAMETOOLONG;
    }
  *dst = 0;
  debug_printf ("%s = normalize_win32_path (%s)", dst_start, src_start);
  return 0;
}

/* Various utilities.  */

/* slashify: Convert all back slashes in src path to forward slashes
   in dst path.  Add a trailing slash to dst when trailing_slash_p arg
   is set to 1. */

static void
slashify (const char *src, char *dst, int trailing_slash_p)
{
  const char *start = src;

  while (*src)
    {
      if (*src == '\\')
	*dst++ = '/';
      else
	*dst++ = *src;
      ++src;
    }
  if (trailing_slash_p
      && src > start
      && !isdirsep (src[-1]))
    *dst++ = '/';
  *dst++ = 0;
}

/* backslashify: Convert all forward slashes in src path to back slashes
   in dst path.  Add a trailing slash to dst when trailing_slash_p arg
   is set to 1. */

static void
backslashify (const char *src, char *dst, int trailing_slash_p)
{
  const char *start = src;

  while (*src)
    {
      if (*src == '/')
	*dst++ = '\\';
      else
	*dst++ = *src;
      ++src;
    }
  if (trailing_slash_p
      && src > start
      && !isdirsep (src[-1]))
    *dst++ = '\\';
  *dst++ = 0;
}

/* nofinalslash: Remove trailing / and \ from SRC (except for the
   first one).  It is ok for src == dst.  */

void __stdcall
nofinalslash (const char *src, char *dst)
{
  int len = strlen (src);
  if (src != dst)
    memcpy (dst, src, len + 1);
  while (len > 1 && isdirsep (dst[--len]))
    dst[len] = '\0';
}

/* slash_unc_prefix_p: Return non-zero if PATH begins with //UNC/SHARE */

int __stdcall
slash_unc_prefix_p (const char *path)
{
  char *p = NULL;
  int ret = (isdirsep (path[0])
	     && isdirsep (path[1])
	     && isalpha (path[2])
	     && path[3] != 0
	     && !isdirsep (path[3])
	     && ((p = strpbrk (path + 3, "\\/")) != NULL));
  if (!ret || p == NULL)
    return ret;
  return ret && isalnum (p[1]);
}

/* conv_path_list: Convert a list of path names to/from Win32/POSIX. */

static void
conv_path_list (const char *src, char *dst, int to_posix)
{
  char *s;
  char *d = dst;
  char src_delim = to_posix ? ';' : ':';
  char dst_delim = to_posix ? ':' : ';';
  int (*conv_fn) (const char *, char *) = (to_posix
					   ? cygwin_conv_to_posix_path
					   : cygwin_conv_to_win32_path);

  char *srcbuf = (char *) alloca (strlen (src) + 1);

  for (;;)
    {
      s = strccpy (srcbuf, &src, src_delim);
      int len = s - srcbuf;
      if (len >= MAX_PATH)
	srcbuf[MAX_PATH - 1] = '\0';
      (*conv_fn) (len ? srcbuf : ".", d);
      if (!*src++)
	break;
      d = strchr (d, '\0');
      *d++ = dst_delim;
    }
}

/* init: Initialize the mount table.  */

void
mount_info::init ()
{
  nmounts = 0;

  /* Fetch the mount table and cygdrive-related information from
     the registry.  */
  from_registry ();
}

static void
set_flags (unsigned *flags, unsigned val)
{
  *flags = val;
  if (!(*flags & PATH_BINARY))
    {
      *flags |= PATH_TEXT;
      debug_printf ("flags: text (%p)", *flags & (PATH_TEXT | PATH_BINARY));
    }
  else
    {
      *flags |= PATH_BINARY;
      debug_printf ("flags: binary (%p)", *flags & (PATH_TEXT | PATH_BINARY));
    }
}

void
mount_item::fnmunge (char *dst, const char *src)
{
  strcpy (dst, src);
  backslashify (dst, dst, 0);
}

void
mount_item::build_win32 (char *dst, const char *src, unsigned *outflags, unsigned chroot_pathlen)
{
  int n;
  const char *real_native_path;
  int real_posix_pathlen;
  set_flags (outflags, (unsigned) flags);
  if (!cygheap->root.exists () || posix_pathlen != 1 || posix_path[0] != '/')
    {
      n = native_pathlen;
      real_native_path = native_path;
      real_posix_pathlen = chroot_pathlen ?: posix_pathlen;
    }
  else
    {
      n = cygheap->root.native_length ();
      real_native_path = cygheap->root.native_path ();
      real_posix_pathlen = posix_pathlen;
    }
  memcpy (dst, real_native_path, n + 1);
  const char *p = src + real_posix_pathlen;
  if (*p == '/')
    /* nothing */;
  else if ((isdrive (dst) && !dst[2]) || *p)
    dst[n++] = '\\';
  fnmunge (dst + n, p);
}

/* conv_to_win32_path: Ensure src_path is a pure Win32 path and store
   the result in win32_path.

   If win32_path != NULL, the relative path, if possible to keep, is
   stored in win32_path.  If the relative path isn't possible to keep,
   the full path is stored.

   If full_win32_path != NULL, the full path is stored there.

   The result is zero for success, or an errno value.

   {,full_}win32_path must have sufficient space (i.e. MAX_PATH bytes).  */

int
mount_info::conv_to_win32_path (const char *src_path, char *dst,
				DWORD &devn, int &unit, unsigned *flags,
				bool no_normalize)
{
  while (sys_mount_table_counter < cygwin_shared->sys_mount_table_counter)
    {
      init ();
      sys_mount_table_counter++;
    }
  int src_path_len = strlen (src_path);
  MALLOC_CHECK;
  unsigned dummy_flags;

  devn = FH_BAD;
  unit = 0;

  if (!flags)
    flags = &dummy_flags;

  *flags = 0;
  debug_printf ("conv_to_win32_path (%s)", src_path);

  if (src_path_len >= MAX_PATH)
    {
      debug_printf ("ENAMETOOLONG = conv_to_win32_path (%s)", src_path);
      return ENAMETOOLONG;
    }

  int i, rc;
  mount_item *mi = NULL;	/* initialized to avoid compiler warning */
  char pathbuf[MAX_PATH];

  if (dst == NULL)
    goto out;		/* Sanity check. */

  /* An MS-DOS spec has either a : or a \.  If this is found, short
     circuit most of the rest of this function. */
  if (strpbrk (src_path, ":\\") != NULL || slash_unc_prefix_p (src_path))
    {
      debug_printf ("%s already win32", src_path);
      rc = normalize_win32_path (src_path, dst);
      if (rc)
	{
	  debug_printf ("normalize_win32_path failed, rc %d", rc);
	  return rc;
	}

      set_flags (flags, (unsigned) set_flags_from_win32_path (dst));
      goto out;
    }

  /* Normalize the path, taking out ../../ stuff, we need to do this
     so that we can move from one mounted directory to another with relative
     stuff.

     eg mounting c:/foo /foo
     d:/bar /bar

     cd /bar
     ls ../foo

     should look in c:/foo, not d:/foo.

     We do this by first getting an absolute UNIX-style path and then
     converting it to a DOS-style path, looking up the appropriate drive
     in the mount table.  */

  if (no_normalize)
    strcpy (pathbuf, src_path);
  else
    {
      rc = normalize_posix_path (src_path, pathbuf);

      if (rc)
	{
	  debug_printf ("%d = conv_to_win32_path (%s)", rc, src_path);
	  return rc;
	}
    }

  /* See if this is a cygwin "device" */
  if (win32_device_name (pathbuf, dst, devn, unit))
    {
      *flags = MOUNT_BINARY;	/* FIXME: Is this a sensible default for devices? */
      rc = 0;
      goto out_no_chroot_check;
    }

  /* Check if the cygdrive prefix was specified.  If so, just strip
     off the prefix and transform it into an MS-DOS path. */
  MALLOC_CHECK;
  if (isproc (pathbuf))
    {
      devn = fhandler_proc::get_proc_fhandler (pathbuf);
      if (devn == FH_BAD)
	return ENOENT;
    }
  else if (iscygdrive (pathbuf))
    {
      int n = mount_table->cygdrive_len - 1;
      if (!pathbuf[n] ||
	  (pathbuf[n] == '/' && pathbuf[n + 1] == '.' && !pathbuf[n + 2]))
	{
	  unit = 0;
	  dst[0] = '\0';
	  if (mount_table->cygdrive_len > 1)
	    devn = FH_CYGDRIVE;
	}
      else if (cygdrive_win32_path (pathbuf, dst, unit))
	{
	  set_flags (flags, (unsigned) cygdrive_flags);
	  goto out;
	}
      else if (mount_table->cygdrive_len > 1)
	return ENOENT;
    }

  int chroot_pathlen;
  chroot_pathlen = 0;
  /* Check the mount table for prefix matches. */
  for (i = 0; i < nmounts; i++)
    {
      const char *path;
      int len;

      mi = mount + posix_sorted[i];
      if (!cygheap->root.exists ()
	  || (mi->posix_pathlen == 1 && mi->posix_path[0] == '/'))
	{
	  path = mi->posix_path;
	  len = mi->posix_pathlen;
	}
      else if (cygheap->root.posix_ok (mi->posix_path))
	{
	  path = cygheap->root.unchroot (mi->posix_path);
	  chroot_pathlen = len = strlen (path);
	}
      else
	{
	  chroot_pathlen = 0;
	  continue;
	}

      if (path_prefix_p (path, pathbuf, len))
	break;
    }

  bool chroot_ok;
  chroot_ok = false; // sigh.  stop gcc warning
  if (i >= nmounts)
    {
      backslashify (pathbuf, dst, 0);	/* just convert */
      set_flags (flags, PATH_BINARY);
      chroot_ok = !cygheap->root.exists ();
    }
  else
    {
      mi->build_win32 (dst, pathbuf, flags, chroot_pathlen);
      chroot_ok = true;
    }

  if (!isvirtual_dev (devn))
    win32_device_name (src_path, dst, devn, unit);

 out:
  MALLOC_CHECK;
  if (chroot_ok || cygheap->root.ischroot_native (dst))
    rc = 0;
  else
    {
      debug_printf ("attempt to access outside of chroot '%s = %s'",
		    cygheap->root.posix_path (), cygheap->root.native_path ());
      rc = ENOENT;
    }

 out_no_chroot_check:
  debug_printf ("src_path %s, dst %s, flags %p, rc %d", src_path, dst, *flags, rc);
  return rc;
}

/* cygdrive_posix_path: Build POSIX path used as the
   mount point for cygdrives created when there is no other way to
   obtain a POSIX path from a Win32 one. */

void
mount_info::cygdrive_posix_path (const char *src, char *dst, int trailing_slash_p)
{
  int len = cygdrive_len;

  memcpy (dst, cygdrive, len + 1);

  /* Now finish the path off with the drive letter to be used.
     The cygdrive prefix always ends with a trailing slash so
     the drive letter is added after the path. */
  dst[len++] = cyg_tolower (src[0]);
  if (!src[2] || (isdirsep (src[2]) && !src[3]))
    dst[len++] = '\000';
  else
    {
      int n;
      dst[len++] = '/';
      if (isdirsep (src[2]))
	n = 3;
      else
	n = 2;
      strcpy (dst + len, src + n);
    }
  slashify (dst, dst, trailing_slash_p);
}

int
mount_info::cygdrive_win32_path (const char *src, char *dst, int& unit)
{
  int res;
  const char *p = src + cygdrive_len;
  if (!isalpha (*p) || (!isdirsep (p[1]) && p[1]))
    {
      unit = -1;
      dst[0] = '\0';
      res = 0;
    }
  else
    {
      dst[0] = cyg_tolower (*p);
      dst[1] = ':';
      strcpy (dst + 2, p + 1);
      backslashify (dst, dst, !dst[2]);
      unit = dst[0];
      res = 1;
    }
  debug_printf ("src '%s', dst '%s'", src, dst);
  return res;
}

/* conv_to_posix_path: Ensure src_path is a POSIX path.

   The result is zero for success, or an errno value.
   posix_path must have sufficient space (i.e. MAX_PATH bytes).
   If keep_rel_p is non-zero, relative paths stay that way.  */

int
mount_info::conv_to_posix_path (const char *src_path, char *posix_path,
				int keep_rel_p)
{
  int src_path_len = strlen (src_path);
  int relative_path_p = !isabspath (src_path);
  int trailing_slash_p;

  if (src_path_len <= 1)
    trailing_slash_p = 0;
  else
    {
      const char *lastchar = src_path + src_path_len - 1;
      trailing_slash_p = isdirsep (*lastchar) && lastchar[-1] != ':';
    }

  debug_printf ("conv_to_posix_path (%s, %s, %s)", src_path,
		keep_rel_p ? "keep-rel" : "no-keep-rel",
		trailing_slash_p ? "add-slash" : "no-add-slash");
  MALLOC_CHECK;

  if (src_path_len >= MAX_PATH)
    {
      debug_printf ("ENAMETOOLONG");
      return ENAMETOOLONG;
    }

  /* FIXME: For now, if the path is relative and it's supposed to stay
     that way, skip mount table processing. */

  if (keep_rel_p && relative_path_p)
    {
      slashify (src_path, posix_path, 0);
      debug_printf ("%s = conv_to_posix_path (%s)", posix_path, src_path);
      return 0;
    }

  char pathbuf[MAX_PATH];
  int rc = normalize_win32_path (src_path, pathbuf);
  if (rc != 0)
    {
      debug_printf ("%d = conv_to_posix_path (%s)", rc, src_path);
      return rc;
    }

  int pathbuflen = strlen (pathbuf);
  for (int i = 0; i < nmounts; ++i)
    {
      mount_item &mi = mount[native_sorted[i]];
      if (!path_prefix_p (mi.native_path, pathbuf, mi.native_pathlen))
	continue;

      if (cygheap->root.exists () && !cygheap->root.posix_ok (mi.posix_path))
	continue;

      /* SRC_PATH is in the mount table. */
      int nextchar;
      const char *p = pathbuf + mi.native_pathlen;

      if (!*p || !p[1])
	nextchar = 0;
      else if (isdirsep (*p))
	nextchar = -1;
      else
	nextchar = 1;

      int addslash = nextchar > 0 ? 1 : 0;
      if ((mi.posix_pathlen + (pathbuflen - mi.native_pathlen) + addslash) >= MAX_PATH)
	return ENAMETOOLONG;
      strcpy (posix_path, mi.posix_path);
      if (addslash)
	strcat (posix_path, "/");
      if (nextchar)
	slashify (p,
		  posix_path + addslash + (mi.posix_pathlen == 1 ? 0 : mi.posix_pathlen),
		  trailing_slash_p);

      if (cygheap->root.exists ())
	{
	  const char *p = cygheap->root.unchroot (posix_path);
	  memmove (posix_path, p, strlen (p) + 1);
	}
      goto out;
    }

  if (!cygheap->root.exists ())
    /* nothing */;
  else if (cygheap->root.ischroot_native (pathbuf))
    {
      const char *p = pathbuf + cygheap->root.native_length ();
      if (*p)
	slashify (p, posix_path, trailing_slash_p);
      else
	{
	  posix_path[0] = '/';
	  posix_path[1] = '\0';
	}
    }
  else
    return ENOENT;

  /* Not in the database.  This should [theoretically] only happen if either
     the path begins with //, or / isn't mounted, or the path has a drive
     letter not covered by the mount table.  If it's a relative path then the
     caller must want an absolute path (otherwise we would have returned
     above).  So we always return an absolute path at this point. */
  if (isdrive (pathbuf))
    cygdrive_posix_path (pathbuf, posix_path, trailing_slash_p);
  else
    {
      /* The use of src_path and not pathbuf here is intentional.
	 We couldn't translate the path, so just ensure no \'s are present. */
      slashify (src_path, posix_path, trailing_slash_p);
    }

out:
  debug_printf ("%s = conv_to_posix_path (%s)", posix_path, src_path);
  MALLOC_CHECK;
  return 0;
}

/* Return flags associated with a mount point given the win32 path. */

unsigned
mount_info::set_flags_from_win32_path (const char *p)
{
  for (int i = 0; i < nmounts; i++)
    {
      mount_item &mi = mount[native_sorted[i]];
      if (path_prefix_p (mi.native_path, p, mi.native_pathlen))
	return mi.flags;
    }
  return PATH_BINARY;
}

/* read_mounts: Given a specific regkey, read mounts from under its
   key. */

void
mount_info::read_mounts (reg_key& r)
{
  char posix_path[MAX_PATH];
  HKEY key = r.get_key ();
  DWORD i, posix_path_size;
  int res;

  /* Loop through subkeys */
  /* FIXME: we would like to not check MAX_MOUNTS but the heap in the
     shared area is currently statically allocated so we can't have an
     arbitrarily large number of mounts. */
  for (i = 0; ; i++)
    {
      char native_path[MAX_PATH];
      int mount_flags;

      posix_path_size = MAX_PATH;
      /* FIXME: if maximum posix_path_size is 256, we're going to
	 run into problems if we ever try to store a mount point that's
	 over 256 but is under MAX_PATH. */
      res = RegEnumKeyEx (key, i, posix_path, &posix_path_size, NULL,
			  NULL, NULL, NULL);

      if (res == ERROR_NO_MORE_ITEMS)
	break;
      else if (res != ERROR_SUCCESS)
	{
	  debug_printf ("RegEnumKeyEx failed, error %d!", res);
	  break;
	}

      /* Get a reg_key based on i. */
      reg_key subkey = reg_key (key, KEY_READ, posix_path, NULL);

      /* Fetch info from the subkey. */
      subkey.get_string ("native", native_path, sizeof (native_path), "");
      mount_flags = subkey.get_int ("flags", 0);

      /* Add mount_item corresponding to registry mount point. */
      res = mount_table->add_item (native_path, posix_path, mount_flags, false);
      if (res && get_errno () == EMFILE)
	break; /* The number of entries exceeds MAX_MOUNTS */
    }
}

/* from_registry: Build the entire mount table from the registry.  Also,
   read in cygdrive-related information from its registry location. */

void
mount_info::from_registry ()
{
  /* Use current mount areas if either user or system mount areas
     already exist.  Otherwise, import old mounts. */

  reg_key r;

  /* Retrieve cygdrive-related information. */
  read_cygdrive_info_from_registry ();

  nmounts = 0;

  /* First read mounts from user's table. */
  read_mounts (r);

  /* Then read mounts from system-wide mount table. */
  reg_key r1 (HKEY_LOCAL_MACHINE, KEY_READ, "SOFTWARE",
	      CYGWIN_INFO_CYGNUS_REGISTRY_NAME, CYGWIN_REGNAME,
	      CYGWIN_INFO_CYGWIN_MOUNT_REGISTRY_NAME,
	      NULL);
  read_mounts (r1);
}

/* add_reg_mount: Add mount item to registry.  Return zero on success,
   non-zero on failure. */
/* FIXME: Need a mutex to avoid collisions with other tasks. */

int
mount_info::add_reg_mount (const char * native_path, const char * posix_path, unsigned mountflags)
{
  int res = 0;

  /* Add the mount to the right registry location, depending on
     whether MOUNT_SYSTEM is set in the mount flags. */
  if (!(mountflags & MOUNT_SYSTEM)) /* current_user mount */
    {
      /* reg_key for user mounts in HKEY_CURRENT_USER. */
      reg_key reg_user;

      /* Start by deleting existing mount if one exists. */
      res = reg_user.kill (posix_path);
      if (res != ERROR_SUCCESS && res != ERROR_FILE_NOT_FOUND)
	goto err;

      /* Create the new mount. */
      reg_key subkey = reg_key (reg_user.get_key (),
				KEY_ALL_ACCESS,
				posix_path, NULL);
      res = subkey.set_string ("native", native_path);
      if (res != ERROR_SUCCESS)
	goto err;
      res = subkey.set_int ("flags", mountflags);
    }
  else /* local_machine mount */
    {
      /* reg_key for system mounts in HKEY_LOCAL_MACHINE. */
      reg_key reg_sys (HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, "SOFTWARE",
		       CYGWIN_INFO_CYGNUS_REGISTRY_NAME, CYGWIN_REGNAME,
		       CYGWIN_INFO_CYGWIN_MOUNT_REGISTRY_NAME,
		       NULL);

      /* Start by deleting existing mount if one exists. */
      res = reg_sys.kill (posix_path);
      if (res != ERROR_SUCCESS && res != ERROR_FILE_NOT_FOUND)
	goto err;

      /* Create the new mount. */
      reg_key subkey = reg_key (reg_sys.get_key (),
				KEY_ALL_ACCESS,
				posix_path, NULL);
      res = subkey.set_string ("native", native_path);
      if (res != ERROR_SUCCESS)
	goto err;
      res = subkey.set_int ("flags", mountflags);

      sys_mount_table_counter++;
      cygwin_shared->sys_mount_table_counter++;
    }

  return 0; /* Success */
 err:
  __seterrno_from_win_error (res);
  return -1;
}

/* del_reg_mount: delete mount item from registry indicated in flags.
   Return zero on success, non-zero on failure.*/
/* FIXME: Need a mutex to avoid collisions with other tasks. */

int
mount_info::del_reg_mount (const char * posix_path, unsigned flags)
{
  int res;

  if (!(flags & MOUNT_SYSTEM))	/* Delete from user registry */
    {
      reg_key reg_user (KEY_ALL_ACCESS,
			CYGWIN_INFO_CYGWIN_MOUNT_REGISTRY_NAME, NULL);
      res = reg_user.kill (posix_path);
    }
  else					/* Delete from system registry */
    {
      sys_mount_table_counter++;
      cygwin_shared->sys_mount_table_counter++;
      reg_key reg_sys (HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, "SOFTWARE",
		       CYGWIN_INFO_CYGNUS_REGISTRY_NAME, CYGWIN_REGNAME,
		       CYGWIN_INFO_CYGWIN_MOUNT_REGISTRY_NAME,
		       NULL);
      res = reg_sys.kill (posix_path);
    }

  if (res != ERROR_SUCCESS)
    {
      __seterrno_from_win_error (res);
      return -1;
    }

  return 0; /* Success */
}

/* read_cygdrive_info_from_registry: Read the default prefix and flags
   to use when creating cygdrives from the special user registry
   location used to store cygdrive information. */

void
mount_info::read_cygdrive_info_from_registry ()
{
  /* reg_key for user path prefix in HKEY_CURRENT_USER. */
  reg_key r;

  if (r.get_string (CYGWIN_INFO_CYGDRIVE_PREFIX, cygdrive, sizeof (cygdrive), "") != 0)
    {
      /* Didn't find the user path prefix so check the system path prefix. */

      /* reg_key for system path prefix in HKEY_LOCAL_MACHINE.  */
      reg_key r2 (HKEY_LOCAL_MACHINE, KEY_READ, "SOFTWARE",
		 CYGWIN_INFO_CYGNUS_REGISTRY_NAME, CYGWIN_REGNAME,
		 CYGWIN_INFO_CYGWIN_MOUNT_REGISTRY_NAME,
		 NULL);

      if (r2.get_string (CYGWIN_INFO_CYGDRIVE_PREFIX, cygdrive,
	  sizeof (cygdrive), ""))
	strcpy (cygdrive, CYGWIN_INFO_CYGDRIVE_DEFAULT_PREFIX);
      cygdrive_flags = r2.get_int (CYGWIN_INFO_CYGDRIVE_FLAGS, MOUNT_CYGDRIVE);
      slashify (cygdrive, cygdrive, 1);
      cygdrive_len = strlen (cygdrive);
    }
  else
    {
      /* Fetch user cygdrive_flags from registry; returns MOUNT_CYGDRIVE on
	 error. */
      cygdrive_flags = r.get_int (CYGWIN_INFO_CYGDRIVE_FLAGS, MOUNT_CYGDRIVE);
      slashify (cygdrive, cygdrive, 1);
      cygdrive_len = strlen (cygdrive);
    }
}

/* write_cygdrive_info_to_registry: Write the default prefix and flags
   to use when creating cygdrives to the special user registry
   location used to store cygdrive information. */

int
mount_info::write_cygdrive_info_to_registry (const char *cygdrive_prefix, unsigned flags)
{
  /* Determine whether to modify user or system cygdrive path prefix. */
  HKEY top = (flags & MOUNT_SYSTEM) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;

  if (flags & MOUNT_SYSTEM)
    {
      sys_mount_table_counter++;
      cygwin_shared->sys_mount_table_counter++;
    }

  /* reg_key for user path prefix in HKEY_CURRENT_USER or system path prefix in
     HKEY_LOCAL_MACHINE.  */
  reg_key r (top, KEY_ALL_ACCESS, "SOFTWARE",
	     CYGWIN_INFO_CYGNUS_REGISTRY_NAME, CYGWIN_REGNAME,
	     CYGWIN_INFO_CYGWIN_MOUNT_REGISTRY_NAME,
	     NULL);

  /* Verify cygdrive prefix starts with a forward slash and if there's
     another character, it's not a slash. */
  if ((cygdrive_prefix == NULL) || (*cygdrive_prefix == 0) ||
      (!isslash (cygdrive_prefix[0])) ||
      ((cygdrive_prefix[1] != '\0') && (isslash (cygdrive_prefix[1]))))
      {
	set_errno (EINVAL);
	return -1;
      }

  char hold_cygdrive_prefix[strlen (cygdrive_prefix) + 1];
  /* Ensure that there is never a final slash */
  nofinalslash (cygdrive_prefix, hold_cygdrive_prefix);

  int res;
  res = r.set_string (CYGWIN_INFO_CYGDRIVE_PREFIX, hold_cygdrive_prefix);
  if (res != ERROR_SUCCESS)
    {
      __seterrno_from_win_error (res);
      return -1;
    }
  r.set_int (CYGWIN_INFO_CYGDRIVE_FLAGS, flags);

  /* This also needs to go in the in-memory copy of "cygdrive", but only if
     appropriate:
       1. setting user path prefix, or
       2. overwriting (a previous) system path prefix */
  if (!(flags & MOUNT_SYSTEM) || (mount_table->cygdrive_flags & MOUNT_SYSTEM))
    {
      slashify (cygdrive_prefix, mount_table->cygdrive, 1);
      mount_table->cygdrive_flags = flags;
      mount_table->cygdrive_len = strlen (mount_table->cygdrive);
    }

  return 0;
}

int
mount_info::remove_cygdrive_info_from_registry (const char *cygdrive_prefix, unsigned flags)
{
  /* Determine whether to modify user or system cygdrive path prefix. */
  HKEY top = (flags & MOUNT_SYSTEM) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;

  if (flags & MOUNT_SYSTEM)
    {
      sys_mount_table_counter++;
      cygwin_shared->sys_mount_table_counter++;
    }

  /* reg_key for user path prefix in HKEY_CURRENT_USER or system path prefix in
     HKEY_LOCAL_MACHINE.  */
  reg_key r (top, KEY_ALL_ACCESS, "SOFTWARE",
	     CYGWIN_INFO_CYGNUS_REGISTRY_NAME, CYGWIN_REGNAME,
	     CYGWIN_INFO_CYGWIN_MOUNT_REGISTRY_NAME,
	     NULL);

  /* Delete cygdrive prefix and flags. */
  int res = r.killvalue (CYGWIN_INFO_CYGDRIVE_PREFIX);
  int res2 = r.killvalue (CYGWIN_INFO_CYGDRIVE_FLAGS);

  /* Reinitialize the cygdrive path prefix to reflect to removal from the
     registry. */
  read_cygdrive_info_from_registry ();

  return (res != ERROR_SUCCESS) ? res : res2;
}

int
mount_info::get_cygdrive_info (char *user, char *system, char* user_flags,
			       char* system_flags)
{
  /* Get the user path prefix from HKEY_CURRENT_USER. */
  reg_key r;
  int res = r.get_string (CYGWIN_INFO_CYGDRIVE_PREFIX, user, MAX_PATH, "");

  /* Get the user flags, if appropriate */
  if (res == ERROR_SUCCESS)
    {
      int flags = r.get_int (CYGWIN_INFO_CYGDRIVE_FLAGS, MOUNT_CYGDRIVE);
      strcpy (user_flags, (flags & MOUNT_BINARY) ? "binmode" : "textmode");
    }

  /* Get the system path prefix from HKEY_LOCAL_MACHINE. */
  reg_key r2 (HKEY_LOCAL_MACHINE, KEY_READ, "SOFTWARE",
	      CYGWIN_INFO_CYGNUS_REGISTRY_NAME, CYGWIN_REGNAME,
	      CYGWIN_INFO_CYGWIN_MOUNT_REGISTRY_NAME,
	      NULL);
  int res2 = r2.get_string (CYGWIN_INFO_CYGDRIVE_PREFIX, system, MAX_PATH, "");

  /* Get the system flags, if appropriate */
  if (res2 == ERROR_SUCCESS)
    {
      int flags = r2.get_int (CYGWIN_INFO_CYGDRIVE_FLAGS, MOUNT_CYGDRIVE);
      strcpy (system_flags, (flags & MOUNT_BINARY) ? "binmode" : "textmode");
    }

  return (res != ERROR_SUCCESS) ? res : res2;
}

static mount_item *mounts_for_sort;

/* sort_by_posix_name: qsort callback to sort the mount entries.  Sort
   user mounts ahead of system mounts to the same POSIX path. */
/* FIXME: should the user should be able to choose whether to
   prefer user or system mounts??? */
static int
sort_by_posix_name (const void *a, const void *b)
{
  mount_item *ap = mounts_for_sort + (*((int*) a));
  mount_item *bp = mounts_for_sort + (*((int*) b));

  /* Base weighting on longest posix path first so that the most
     obvious path will be chosen. */
  size_t alen = strlen (ap->posix_path);
  size_t blen = strlen (bp->posix_path);

  int res = blen - alen;

  if (res)
    return res;		/* Path lengths differed */

  /* The two paths were the same length, so just determine normal
     lexical sorted order. */
  res = strcmp (ap->posix_path, bp->posix_path);

  if (res == 0)
   {
     /* need to select between user and system mount to same POSIX path */
     if (!(bp->flags & MOUNT_SYSTEM))	/* user mount */
      return 1;
     else
      return -1;
   }

  return res;
}

/* sort_by_native_name: qsort callback to sort the mount entries.  Sort
   user mounts ahead of system mounts to the same POSIX path. */
/* FIXME: should the user should be able to choose whether to
   prefer user or system mounts??? */
static int
sort_by_native_name (const void *a, const void *b)
{
  mount_item *ap = mounts_for_sort + (*((int*) a));
  mount_item *bp = mounts_for_sort + (*((int*) b));

  /* Base weighting on longest win32 path first so that the most
     obvious path will be chosen. */
  size_t alen = strlen (ap->native_path);
  size_t blen = strlen (bp->native_path);

  int res = blen - alen;

  if (res)
    return res;		/* Path lengths differed */

  /* The two paths were the same length, so just determine normal
     lexical sorted order. */
  res = strcmp (ap->native_path, bp->native_path);

  if (res == 0)
   {
     /* need to select between user and system mount to same POSIX path */
     if (!(bp->flags & MOUNT_SYSTEM))	/* user mount */
      return 1;
     else
      return -1;
   }

  return res;
}

void
mount_info::sort ()
{
  for (int i = 0; i < nmounts; i++)
    native_sorted[i] = posix_sorted[i] = i;
  /* Sort them into reverse length order, otherwise we won't
     be able to look for /foo in /.  */
  mounts_for_sort = mount;	/* ouch. */
  qsort (posix_sorted, nmounts, sizeof (posix_sorted[0]), sort_by_posix_name);
  qsort (native_sorted, nmounts, sizeof (native_sorted[0]), sort_by_native_name);
}

/* Add an entry to the mount table.
   Returns 0 on success, -1 on failure and errno is set.

   This is where all argument validation is done.  It may not make sense to
   do this when called internally, but it's cleaner to keep it all here.  */

int
mount_info::add_item (const char *native, const char *posix, unsigned mountflags, int reg_p)
{
  /* Something's wrong if either path is NULL or empty, or if it's
     not a UNC or absolute path. */

  if ((native == NULL) || (*native == 0) ||
      (posix == NULL) || (*posix == 0) ||
      !isabspath (native) || !isabspath (posix) ||
      slash_unc_prefix_p (posix) || isdrive (posix))
    {
      set_errno (EINVAL);
      return -1;
    }

  /* Make sure both paths do not end in /. */
  char nativetmp[MAX_PATH];
  char posixtmp[MAX_PATH];

  backslashify (native, nativetmp, 0);
  nofinalslash (nativetmp, nativetmp);

  slashify (posix, posixtmp, 0);
  nofinalslash (posixtmp, posixtmp);

  debug_printf ("%s[%s], %s[%s], %p",
		native, nativetmp, posix, posixtmp, mountflags);

  /* Duplicate /'s in path are an error. */
  for (char *p = posixtmp + 1; *p; ++p)
    {
      if (p[-1] == '/' && p[0] == '/')
	{
	  set_errno (EINVAL);
	  return -1;
	}
    }

  /* Write over an existing mount item with the same POSIX path if
     it exists and is from the same registry area. */
  int i;
  for (i = 0; i < nmounts; i++)
    {
      if (strcasematch (mount[i].posix_path, posixtmp) &&
	  (mount[i].flags & MOUNT_SYSTEM) == (mountflags & MOUNT_SYSTEM))
	break;
    }

  if (i == nmounts && nmounts == MAX_MOUNTS)
    {
      set_errno (EMFILE);
      return -1;
    }

  if (reg_p && add_reg_mount (nativetmp, posixtmp, mountflags))
    return -1;

  if (i == nmounts)
    nmounts++;
  mount[i].init (nativetmp, posixtmp, mountflags);
  sort ();

  return 0;
}

/* Delete a mount table entry where path is either a Win32 or POSIX
   path. Since the mount table is really just a table of aliases,
   deleting / is ok (although running without a slash mount is
   strongly discouraged because some programs may run erratically
   without one).  If MOUNT_SYSTEM is set in flags, remove from system
   registry, otherwise remove the user registry mount.
*/

int
mount_info::del_item (const char *path, unsigned flags, int reg_p)
{
  char pathtmp[MAX_PATH];
  int posix_path_p = false;

  /* Something's wrong if path is NULL or empty. */
  if (path == NULL || *path == 0 || !isabspath (path))
    {
      set_errno (EINVAL);
      return -1;
    }

  if (slash_unc_prefix_p (path) || strpbrk (path, ":\\"))
    backslashify (path, pathtmp, 0);
  else
    {
      slashify (path, pathtmp, 0);
      posix_path_p = TRUE;
    }
  nofinalslash (pathtmp, pathtmp);

  if (reg_p && posix_path_p &&
      del_reg_mount (pathtmp, flags) &&
      del_reg_mount (path, flags)) /* for old irregular entries */
    return -1;

  for (int i = 0; i < nmounts; i++)
    {
      int ent = native_sorted[i]; /* in the same order as getmntent() */
      if (((posix_path_p)
	   ? strcasematch (mount[ent].posix_path, pathtmp)
	   : strcasematch (mount[ent].native_path, pathtmp)) &&
	  (mount[ent].flags & MOUNT_SYSTEM) == (flags & MOUNT_SYSTEM))
	{
	  if (!posix_path_p &&
	      reg_p && del_reg_mount (mount[ent].posix_path, flags))
	    return -1;

	  nmounts--; /* One less mount table entry */
	  /* Fill in the hole if not at the end of the table */
	  if (ent < nmounts)
	    memmove (mount + ent, mount + ent + 1,
		     sizeof (mount[ent]) * (nmounts - ent));
	  sort (); /* Resort the table */
	  return 0;
	}
    }
  set_errno (EINVAL);
  return -1;
}

/************************* mount_item class ****************************/

static mntent *
fillout_mntent (const char *native_path, const char *posix_path, unsigned flags)
{
#ifdef _MT_SAFE
  struct mntent &ret=_reent_winsup ()->mntbuf;
#else
  static NO_COPY struct mntent ret;
#endif

  /* Remove drivenum from list if we see a x: style path */
  if (strlen (native_path) == 2 && native_path[1] == ':')
    {
      int drivenum = cyg_tolower (native_path[0]) - 'a';
      if (drivenum >= 0 && drivenum <= 31)
	available_drives &= ~(1 << drivenum);
    }

  /* Pass back pointers to mount_table strings reserved for use by
     getmntent rather than pointers to strings in the internal mount
     table because the mount table might change, causing weird effects
     from the getmntent user's point of view. */

  strcpy (_reent_winsup ()->mnt_fsname, native_path);
  ret.mnt_fsname = _reent_winsup ()->mnt_fsname;
  strcpy (_reent_winsup ()->mnt_dir, posix_path);
  ret.mnt_dir = _reent_winsup ()->mnt_dir;

  if (!(flags & MOUNT_SYSTEM))		/* user mount */
    strcpy (_reent_winsup ()->mnt_type, (char *) "user");
  else					/* system mount */
    strcpy (_reent_winsup ()->mnt_type, (char *) "system");

  ret.mnt_type = _reent_winsup ()->mnt_type;

  /* mnt_opts is a string that details mount params such as
     binary or textmode, or exec.  We don't print
     `silent' here; it's a magic internal thing. */

  if (!(flags & MOUNT_BINARY))
    strcpy (_reent_winsup ()->mnt_opts, (char *) "textmode");
  else
    strcpy (_reent_winsup ()->mnt_opts, (char *) "binmode");

  if (flags & MOUNT_CYGWIN_EXEC)
    strcat (_reent_winsup ()->mnt_opts, (char *) ",cygexec");
  else if (flags & MOUNT_EXEC)
    strcat (_reent_winsup ()->mnt_opts, (char *) ",exec");
  else if (flags & MOUNT_NOTEXEC)
    strcat (_reent_winsup ()->mnt_opts, (char *) ",noexec");

  if ((flags & MOUNT_CYGDRIVE))		/* cygdrive */
    strcat (_reent_winsup ()->mnt_opts, (char *) ",noumount");

  ret.mnt_opts = _reent_winsup ()->mnt_opts;

  ret.mnt_freq = 1;
  ret.mnt_passno = 1;
  return &ret;
}

struct mntent *
mount_item::getmntent ()
{
  return fillout_mntent (native_path, posix_path, flags);
}

static struct mntent *
cygdrive_getmntent ()
{
  char native_path[4];
  char posix_path[MAX_PATH];
  DWORD mask = 1, drive = 'a';
  struct mntent *ret = NULL;

  while (available_drives)
    {
      for (/* nothing */; drive <= 'z'; mask <<= 1, drive++)
	if (available_drives & mask)
	  break;

      __small_sprintf (native_path, "%c:\\", drive);
      if (GetDriveType (native_path) == DRIVE_REMOVABLE ||
	  GetFileAttributes (native_path) == INVALID_FILE_ATTRIBUTES)
	{
	  available_drives &= ~mask;
	  continue;
	}
      native_path[2] = '\0';
      __small_sprintf (posix_path, "%s%c", mount_table->cygdrive, drive);
      ret = fillout_mntent (native_path, posix_path, mount_table->cygdrive_flags);
      break;
    }

  return ret;
}

struct mntent *
mount_info::getmntent (int x)
{
  if (x < 0 || x >= nmounts)
    return cygdrive_getmntent ();

  return mount[native_sorted[x]].getmntent ();
}

/* Fill in the fields of a mount table entry.  */

void
mount_item::init (const char *native, const char *posix, unsigned mountflags)
{
  strcpy ((char *) native_path, native);
  strcpy ((char *) posix_path, posix);

  native_pathlen = strlen (native_path);
  posix_pathlen = strlen (posix_path);

  flags = mountflags;
}

/********************** Mount System Calls **************************/

/* Mount table system calls.
   Note that these are exported to the application.  */

/* mount: Add a mount to the mount table in memory and to the registry
   that will cause paths under win32_path to be translated to paths
   under posix_path. */

extern "C" int
mount (const char *win32_path, const char *posix_path, unsigned flags)
{
  int res = -1;

  if (flags & MOUNT_CYGDRIVE) /* normal mount */
    {
      /* When flags include MOUNT_CYGDRIVE, take this to mean that
	we actually want to change the cygdrive prefix and flags
	without actually mounting anything. */
      res = mount_table->write_cygdrive_info_to_registry (posix_path, flags);
      win32_path = NULL;
    }
  else
    res = mount_table->add_item (win32_path, posix_path, flags, TRUE);

  syscall_printf ("%d = mount (%s, %s, %p)", res, win32_path, posix_path, flags);
  return res;
}

/* umount: The standard umount call only has a path parameter.  Since
   it is not possible for this call to specify whether to remove the
   mount from the user or global mount registry table, assume the user
   table. */

extern "C" int
umount (const char *path)
{
  return cygwin_umount (path, 0);
}

/* cygwin_umount: This is like umount but takes an additional flags
   parameter that specifies whether to umount from the user or system-wide
   registry area. */

extern "C" int
cygwin_umount (const char *path, unsigned flags)
{
  int res = -1;

  if (flags & MOUNT_CYGDRIVE)
    {
      /* When flags include MOUNT_CYGDRIVE, take this to mean that we actually want
	 to remove the cygdrive prefix and flags without actually unmounting
	 anything. */
      res = mount_table->remove_cygdrive_info_from_registry (path, flags);
    }
  else
    {
      res = mount_table->del_item (path, flags, TRUE);
    }

  syscall_printf ("%d = cygwin_umount (%s, %d)", res,  path, flags);
  return res;
}

extern "C" FILE *
setmntent (const char *filep, const char *)
{
  iteration = 0;
  available_drives = GetLogicalDrives ();
  return (FILE *) filep;
}

extern "C" struct mntent *
getmntent (FILE *)
{
  return mount_table->getmntent (iteration++);
}

extern "C" int
endmntent (FILE *)
{
  return 1;
}

/********************** Symbolic Link Support **************************/

/* Read symlink from Extended Attribute */
int
get_symlink_ea (const char* frompath, char* buf, int buf_size)
{
  int res = NTReadEA (frompath, SYMLINK_EA_NAME, buf, buf_size);
  if (res == 0)
    debug_printf ("Cannot read symlink from EA");
  return (res - 1);
}

/* Save symlink to Extended Attribute */
BOOL
set_symlink_ea (const char* frompath, const char* topath)
{
  if (!NTWriteEA (frompath, SYMLINK_EA_NAME, topath, strlen (topath) + 1))
    {
      debug_printf ("Cannot save symlink in EA");
      return false;
    }
  return TRUE;
}

/* Create a symlink from FROMPATH to TOPATH. */

/* If TRUE create symlinks as Windows shortcuts, if false create symlinks
   as normal files with magic number and system bit set. */
int allow_winsymlinks = TRUE;

extern "C" int
symlink (const char *topath, const char *frompath)
{
  HANDLE h;
  int res = -1;
  path_conv win32_path, win32_topath;
  char from[MAX_PATH + 5];
  char cwd[MAX_PATH + 1], *cp = NULL, c = 0;
  char w32topath[MAX_PATH + 1];
  DWORD written;
  SECURITY_ATTRIBUTES sa = sec_none_nih;

  /* POSIX says that empty 'frompath' is invalid input whlie empty
     'topath' is valid -- it's symlink resolver job to verify if
     symlink contents point to existing filesystem object */
  if (check_null_empty_str_errno (topath) == EFAULT ||
      check_null_empty_str_errno (frompath))
    goto done;

  if (strlen (topath) >= MAX_PATH)
    {
      set_errno (ENAMETOOLONG);
      goto done;
    }

  win32_path.check (frompath, PC_SYM_NOFOLLOW);
  if (allow_winsymlinks && !win32_path.exists ())
    {
      strcpy (from, frompath);
      strcat (from, ".lnk");
      win32_path.check (from, PC_SYM_NOFOLLOW);
    }

  if (win32_path.error)
    {
      set_errno (win32_path.case_clash ? ECASECLASH : win32_path.error);
      goto done;
    }

  syscall_printf ("symlink (%s, %s)", topath, win32_path.get_win32 ());

  if (win32_path.is_device () || win32_path.exists ())
    {
      set_errno (EEXIST);
      goto done;
    }

  if (allow_winsymlinks)
    {
      if (!isabspath (topath))
	{
	  getcwd (cwd, MAX_PATH + 1);
	  if ((cp = strrchr (from, '/')) || (cp = strrchr (from, '\\')))
	    {
	      c = *cp;
	      *cp = '\0';
	      chdir (from);
	    }
	  backslashify (topath, w32topath, 0);
	}
      if (!cp || GetFileAttributes (w32topath) == INVALID_FILE_ATTRIBUTES)
	{
	  win32_topath.check (topath, PC_SYM_NOFOLLOW);
	  if (!cp || win32_topath.error != ENOENT)
	    strcpy (w32topath, win32_topath);
	}
      if (cp)
	{
	  *cp = c;
	  chdir (cwd);
	}
    }

  if (allow_ntsec && win32_path.has_acls ())
    set_security_attribute (S_IFLNK | STD_RBITS | STD_WBITS,
			    &sa, alloca (4096), 4096);

  h = CreateFile (win32_path, GENERIC_WRITE, 0, &sa,
		  CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
  if (h == INVALID_HANDLE_VALUE)
    __seterrno ();
  else
    {
      BOOL success;

      if (allow_winsymlinks)
	{
	  create_shortcut_header ();
	  /* Don't change the datatypes of `len' and `win_len' since
	     their sizeof is used when writing. */
	  unsigned short len = strlen (topath);
	  unsigned short win_len = strlen (w32topath);
	  success = WriteFile (h, shortcut_header, SHORTCUT_HDR_SIZE,
			       &written, NULL)
		    && written == SHORTCUT_HDR_SIZE
		    && WriteFile (h, &len, sizeof len, &written, NULL)
		    && written == sizeof len
		    && WriteFile (h, topath, len, &written, NULL)
		    && written == len
		    && WriteFile (h, &win_len, sizeof win_len, &written, NULL)
		    && written == sizeof win_len
		    && WriteFile (h, w32topath, win_len, &written, NULL)
		    && written == win_len;
	}
      else
	{
	  /* This is the old technique creating a symlink. */
	  char buf[sizeof (SYMLINK_COOKIE) + MAX_PATH + 10];

	  __small_sprintf (buf, "%s%s", SYMLINK_COOKIE, topath);
	  DWORD len = strlen (buf) + 1;

	  /* Note that the terminating nul is written.  */
	  success = WriteFile (h, buf, len, &written, NULL)
		    || written != len;

	}
      if (success)
	{
	  CloseHandle (h);
	  if (!allow_ntsec && allow_ntea)
	    set_file_attribute (win32_path.has_acls (),
				win32_path.get_win32 (),
				S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO);

	  DWORD attr = allow_winsymlinks ? FILE_ATTRIBUTE_READONLY
					 : FILE_ATTRIBUTE_SYSTEM;
#ifdef HIDDEN_DOT_FILES
	  cp = strrchr (win32_path, '\\');
	  if ((cp && cp[1] == '.') || *win32_path == '.')
	    attr |= FILE_ATTRIBUTE_HIDDEN;
#endif
	  SetFileAttributes (win32_path.get_win32 (), attr);

	  if (win32_path.fs_fast_ea ())
	    set_symlink_ea (win32_path, topath);
	  res = 0;
	}
      else
	{
	  __seterrno ();
	  CloseHandle (h);
	  DeleteFileA (win32_path.get_win32 ());
	}
    }

done:
  syscall_printf ("%d = symlink (%s, %s)", res, topath, frompath);
  return res;
}

static BOOL
cmp_shortcut_header (const char *file_header)
{
  create_shortcut_header ();
  return memcmp (shortcut_header, file_header, SHORTCUT_HDR_SIZE);
}

static int
check_shortcut (const char *path, DWORD fileattr, HANDLE h,
		char *contents, int *error, unsigned *pflags)
{
  char file_header[SHORTCUT_HDR_SIZE];
  unsigned short len;
  int res = 0;
  DWORD got = 0;

  /* Valid Cygwin & U/WIN shortcuts are R/O. */
  if (!(fileattr & FILE_ATTRIBUTE_READONLY))
    goto file_not_symlink;
  /* Read the files header information. This is used to check for a
     Cygwin or U/WIN shortcut or later to check for executable files. */
  if (!ReadFile (h, file_header, SHORTCUT_HDR_SIZE, &got, 0))
    {
      *error = EIO;
      goto close_it;
    }
  /* Check header if the shortcut is really created by Cygwin or U/WIN. */
  if (got != SHORTCUT_HDR_SIZE || cmp_shortcut_header (file_header))
    goto file_not_symlink;
  /* Next 2 byte are USHORT, containing length of description entry. */
  if (!ReadFile (h, &len, sizeof len, &got, 0))
    {
      *error = EIO;
      goto close_it;
    }
  if (got != sizeof len || len == 0 || len > MAX_PATH)
    goto file_not_symlink;
  /* Now read description entry. */
  if (!ReadFile (h, contents, len, &got, 0))
    {
      *error = EIO;
      goto close_it;
    }
  if (got != len)
    goto file_not_symlink;
  contents[len] = '\0';
  res = len;
  if (res) /* It's a symlink.  */
    *pflags = PATH_SYMLINK | PATH_LNK;
  goto close_it;

file_not_symlink:
  /* Not a symlink, see if executable.  */
  if (!(*pflags & PATH_ALL_EXEC) && has_exec_chars (file_header, got))
    *pflags |= PATH_EXEC;

close_it:
  CloseHandle (h);
  return res;
}


static int
check_sysfile (const char *path, DWORD fileattr, HANDLE h,
	       char *contents, int *error, unsigned *pflags)
{
  char cookie_buf[sizeof (SYMLINK_COOKIE) - 1];
  DWORD got;
  int res = 0;

  if (!ReadFile (h, cookie_buf, sizeof (cookie_buf), &got, 0))
    {
      debug_printf ("ReadFile1 failed");
      *error = EIO;
    }
  else if (got == sizeof (cookie_buf)
	   && memcmp (cookie_buf, SYMLINK_COOKIE, sizeof (cookie_buf)) == 0)
    {
      /* It's a symlink.  */
      *pflags = PATH_SYMLINK;

      res = ReadFile (h, contents, MAX_PATH + 1, &got, 0);
      if (!res)
	{
	  debug_printf ("ReadFile2 failed");
	  *error = EIO;
	}
      else
	{
	  /* Versions prior to b16 stored several trailing
	     NULs with the path (to fill the path out to 1024
	     chars).  Current versions only store one trailing
	     NUL.  The length returned is the path without
	     *any* trailing NULs.  We also have to handle (or
	     at least not die from) corrupted paths.  */
	  if (memchr (contents, 0, got) != NULL)
	    res = strlen (contents);
	  else
	    res = got;
	}
    }
  else if (got == sizeof (cookie_buf)
	   && memcmp (cookie_buf, SOCKET_COOKIE, sizeof (cookie_buf)) == 0)
    *pflags |= PATH_SOCKET;
  else
    {
      /* Not a symlink, see if executable.  */
      if (*pflags & PATH_ALL_EXEC)
	/* Nothing to do */;
      else if (has_exec_chars (cookie_buf, got))
	*pflags |= PATH_EXEC;
      else
	*pflags |= PATH_NOTEXEC;
      }
  syscall_printf ("%d = symlink.check_sysfile (%s, %s) (%p)",
		  res, path, contents, *pflags);

  CloseHandle (h);
  return res;
}

enum
{
  SCAN_BEG,
  SCAN_LNK,
  SCAN_HASLNK,
  SCAN_JUSTCHECK,
  SCAN_APPENDLNK,
  SCAN_EXTRALNK,
  SCAN_DONE,
};

class suffix_scan
{
  const suffix_info *suffixes, *suffixes_start;
  int nextstate;
  char *eopath;
public:
  const char *path;
  char *has (const char *, const suffix_info *);
  int next ();
  int lnk_match () {return nextstate >= SCAN_EXTRALNK;}
};

char *
suffix_scan::has (const char *in_path, const suffix_info *in_suffixes)
{
  nextstate = SCAN_BEG;
  suffixes = suffixes_start = in_suffixes;

  char *ext_here = strrchr (in_path, '.');
  path = in_path;
  eopath = strchr (path, '\0');

  if (!ext_here)
    goto noext;

  if (suffixes)
    {
      /* Check if the extension matches a known extension */
      for (const suffix_info *ex = in_suffixes; ex->name != NULL; ex++)
	if (strcasematch (ext_here, ex->name))
	  {
	    nextstate = SCAN_JUSTCHECK;
	    suffixes = NULL;	/* Has an extension so don't scan for one. */
	    goto done;
	  }
    }

  /* Didn't match.  Use last resort -- .lnk. */
  if (strcasematch (ext_here, ".lnk"))
    {
      nextstate = SCAN_HASLNK;
      suffixes = NULL;
    }

 noext:
  ext_here = eopath;

 done:
  return ext_here;
}

int
suffix_scan::next ()
{
  for (;;)
    {
      if (!suffixes)
	switch (nextstate)
	  {
	  case SCAN_BEG:
	    suffixes = suffixes_start;
	    if (!suffixes)
	      {
		nextstate = SCAN_LNK;
		return 1;
	      }
	    if (!*suffixes->name)
	      suffixes++;
	    nextstate = SCAN_EXTRALNK;
	    /* fall through to suffix checking below */
	    break;
	  case SCAN_HASLNK:
	    nextstate = SCAN_EXTRALNK;	/* Skip SCAN_BEG */
	    return 1;
	  case SCAN_LNK:
	  case SCAN_EXTRALNK:
	    strcpy (eopath, ".lnk");
	    nextstate = SCAN_DONE;
	    return 1;
	  case SCAN_JUSTCHECK:
	    nextstate = SCAN_APPENDLNK;
	    return 1;
	  case SCAN_APPENDLNK:
	    strcat (eopath, ".lnk");
	    nextstate = SCAN_DONE;
	    return 1;
	  default:
	    *eopath = '\0';
	    return 0;
	  }

      while (suffixes && suffixes->name)
	if (!suffixes->addon)
	  suffixes++;
	else
	  {
	    strcpy (eopath, suffixes->name);
	    if (nextstate == SCAN_EXTRALNK)
	      strcat (eopath, ".lnk");
	    suffixes++;
	    return 1;
	  }
      suffixes = NULL;
    }
}

/* Check if PATH is a symlink.  PATH must be a valid Win32 path name.

   If PATH is a symlink, put the value of the symlink--the file to
   which it points--into BUF.  The value stored in BUF is not
   necessarily null terminated.  BUFLEN is the length of BUF; only up
   to BUFLEN characters will be stored in BUF.  BUF may be NULL, in
   which case nothing will be stored.

   Set *SYML if PATH is a symlink.

   Set *EXEC if PATH appears to be executable.  This is an efficiency
   hack because we sometimes have to open the file anyhow.  *EXEC will
   not be set for every executable file.

   Return -1 on error, 0 if PATH is not a symlink, or the length
   stored into BUF if PATH is a symlink.  */

int
symlink_info::check (char *path, const suffix_info *suffixes, unsigned opt)
{
  HANDLE h;
  int res = 0;
  suffix_scan suffix;
  contents[0] = '\0';

  is_symlink = true;
  ext_here = suffix.has (path, suffixes);
  extn = ext_here - path;

  pflags &= ~(PATH_SYMLINK | PATH_LNK);

  case_clash = false;

  while (suffix.next ())
    {
      error = 0;
      fileattr = GetFileAttributes (suffix.path);
      if (fileattr == INVALID_FILE_ATTRIBUTES)
	{
	  /* The GetFileAttributes call can fail for reasons that don't
	     matter, so we just return 0.  For example, getting the
	     attributes of \\HOST will typically fail.  */
	  debug_printf ("GetFileAttributes (%s) failed", suffix.path);
	  error = geterrno_from_win_error (GetLastError (), EACCES);
	  continue;
	}


      ext_tacked_on = !!*ext_here;

      if (pcheck_case != PCHECK_RELAXED && !case_check (path)
	  || (opt & PC_SYM_IGNORE))
	goto file_not_symlink;

      int sym_check;

      sym_check = 0;

      if (fileattr & FILE_ATTRIBUTE_DIRECTORY)
	goto file_not_symlink;

      /* Windows shortcuts are treated as symlinks. */
      if (suffix.lnk_match ())
	sym_check = 1;

      /* This is the old Cygwin method creating symlinks: */
      /* A symlink will have the `system' file attribute. */
      /* Only files can be symlinks (which can be symlinks to directories). */
      if (fileattr & FILE_ATTRIBUTE_SYSTEM)
	sym_check = 2;

      if (!sym_check)
	goto file_not_symlink;

      if (sym_check > 0 && opt & PC_CHECK_EA &&
	  (res = get_symlink_ea (suffix.path, contents, sizeof (contents))) > 0)
	{
	  pflags = PATH_SYMLINK;
	  if (sym_check == 1)
	    pflags |= PATH_LNK;
	  debug_printf ("Got symlink from EA: %s", contents);
	  break;
	}

      /* Open the file.  */

      h = CreateFile (suffix.path, GENERIC_READ, FILE_SHARE_READ,
		      &sec_none_nih, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
      res = -1;
      if (h == INVALID_HANDLE_VALUE)
	goto file_not_symlink;

      /* FIXME: if symlink isn't present in EA, but EAs are supported,
       * should we write it there?
       */
      switch (sym_check)
	{
	case 1:
	  res = check_shortcut (suffix.path, fileattr, h, contents, &error, &pflags);
	  if (res)
	    break;
	  /* If searching for `foo' and then finding a `foo.lnk' which is
	     no shortcut, return the same as if file not found. */
	  if (!suffix.lnk_match () || !ext_tacked_on)
	    goto file_not_symlink;

	  fileattr = INVALID_FILE_ATTRIBUTES;
	  continue;		/* in case we're going to tack *another* .lnk on this filename. */
	case 2:
	  res = check_sysfile (suffix.path, fileattr, h, contents, &error, &pflags);
	  if (!res)
	    goto file_not_symlink;
	  break;
	}
      break;

    file_not_symlink:
      is_symlink = false;
      syscall_printf ("not a symlink");
      res = 0;
      break;
    }

  syscall_printf ("%d = symlink.check (%s, %p) (%p)",
		  res, suffix.path, contents, pflags);
  return res;
}

/* Check the correct case of the last path component (given in DOS style).
   Adjust the case in this->path if pcheck_case == PCHECK_ADJUST or return
   false if pcheck_case == PCHECK_STRICT.
   Dont't call if pcheck_case == PCHECK_RELAXED.
*/

BOOL
symlink_info::case_check (char *path)
{
  WIN32_FIND_DATA data;
  HANDLE h;
  char *c;

  /* Set a pointer to the beginning of the last component. */
  if (!(c = strrchr (path, '\\')))
    c = path;
  else
    ++c;

  if ((h = FindFirstFile (path, &data))
      != INVALID_HANDLE_VALUE)
    {
      FindClose (h);

      /* If that part of the component exists, check the case. */
      if (strcmp (c, data.cFileName))
	{
	  case_clash = TRUE;

	  /* If check is set to STRICT, a wrong case results
	     in returning a ENOENT. */
	  if (pcheck_case == PCHECK_STRICT)
	    return false;

	  /* PCHECK_ADJUST adjusts the case in the incoming
	     path which points to the path in *this. */
	  strcpy (c, data.cFileName);
	}
    }
  return TRUE;
}

/* readlink system call */

extern "C" int
readlink (const char *path, char *buf, int buflen)
{
  extern suffix_info stat_suffixes[];

  if (buflen < 0)
    {
      set_errno (ENAMETOOLONG);
      return -1;
    }

  path_conv pathbuf (path, PC_SYM_CONTENTS, stat_suffixes);

  if (pathbuf.error)
    {
      set_errno (pathbuf.error);
      syscall_printf ("-1 = readlink (%s, %p, %d)", path, buf, buflen);
      return -1;
    }

  if (!pathbuf.exists ())
    {
      set_errno (ENOENT);
      return -1;
    }

  if (!pathbuf.issymlink ())
    {
      if (pathbuf.exists ())
	set_errno (EINVAL);
      return -1;
    }

  int len = min (buflen, (int) strlen (pathbuf.get_win32 ()));
  memcpy (buf, pathbuf.get_win32 (), len);

  /* errno set by symlink.check if error */
  return len;
}

/* Some programs rely on st_dev/st_ino being unique for each file.
   Hash the path name and hope for the best.  The hash arg is not
   always initialized to zero since readdir needs to compute the
   dirent ino_t based on a combination of the hash of the directory
   done during the opendir call and the hash or the filename within
   the directory.  FIXME: Not bullet-proof. */
/* Cygwin internal */

__ino64_t __stdcall
hash_path_name (__ino64_t hash, const char *name)
{
  if (!*name)
    return hash;

  /* Perform some initial permutations on the pathname if this is
     not "seeded" */
  if (!hash)
    {
      /* Simplistic handling of drives.  If there is a drive specified,
	 make sure that the initial letter is upper case.  If there is
	 no \ after the ':' assume access through the root directory
	 of that drive.
	 FIXME:  Should really honor MS-Windows convention of using
	 the environment to track current directory on various drives. */
      if (name[1] == ':')
	{
	  char *nn, *newname = (char *) alloca (strlen (name) + 2);
	  nn = newname;
	  *nn = isupper (*name) ? cyg_tolower (*name) : *name;
	  *++nn = ':';
	  name += 2;
	  if (*name != '\\')
	    *++nn = '\\';
	  strcpy (++nn, name);
	  name = newname;
	  goto hashit;
	}

      /* Fill out the hashed path name with the current working directory if
	 this is not an absolute path and there is no pre-specified hash value.
	 Otherwise the inodes same will differ depending on whether a file is
	 referenced with an absolute value or relatively. */

      if (!hash && !isabspath (name))
	{
	  hash = cygheap->cwd.get_hash ();
	  if (name[0] == '.' && name[1] == '\0')
	    return hash;
	  hash = (hash << 5) - hash + '\\';
	}
    }

hashit:
  /* Build up hash.  Ignore single trailing slash or \a\b\ != \a\b or
     \a\b\.  but allow a single \ if that's all there is. */
  do
    {
      int ch = cyg_tolower (*name);
      hash = (hash << 5) - hash + ch;
    }
  while (*++name != '\0' &&
	 !(*name == '\\' && (!name[1] || (name[1] == '.' && !name[2]))));
  return hash;
}

char *
getcwd (char *buf, size_t ulen)
{
  char* res = NULL;
  if (ulen == 0 && buf)
    set_errno (EINVAL);
  else if (buf == NULL || !__check_null_invalid_struct_errno (buf, ulen))
    res = cygheap->cwd.get (buf, 1, 1, ulen);
  return res;
}

/* getwd: standards? */
extern "C" char *
getwd (char *buf)
{
  return getcwd (buf, MAX_PATH);
}

/* chdir: POSIX 5.2.1.1 */
extern "C" int
chdir (const char *in_dir)
{
  if (check_null_empty_str_errno (in_dir))
    return -1;

  syscall_printf ("dir '%s'", in_dir);

  char *s;
  char dir[strlen (in_dir) + 1];
  strcpy (dir, in_dir);
  /* Incredibly. Windows allows you to specify a path with trailing
     whitespace to SetCurrentDirectory.  This doesn't work too well
     with other parts of the API, though, apparently.  So nuke trailing
     white space. */
  for (s = strchr (dir, '\0'); --s >= dir && isspace ((unsigned int) (*s & 0xff)); )
    *s = '\0';

  if (!*s)
    {
      set_errno (ENOENT);
      return -1;
    }

  /* Convert path.  First argument ensures that we don't check for NULL/empty/invalid
     again. */
  path_conv path (PC_NONULLEMPTY, dir, PC_FULL | PC_SYM_FOLLOW);
  if (path.error)
    {
      set_errno (path.error);
      syscall_printf ("-1 = chdir (%s)", dir);
      return -1;
    }


  /* Look for trailing path component consisting entirely of dots.  This
     is needed only in case of chdir since Windows simply ignores count
     of dots > 2 here instead of returning an error code.  Counts of dots
     <= 2 are already eliminated by normalize_posix_path. */
  const char *p = strrchr (dir, '/');
  if (!p)
    p = dir;
  else
    p++;

  size_t len = strlen (p);
  if (len > 2 && strspn (p, ".") == len)
    {
      set_errno (ENOENT);
      return -1;
    }

  const char *native_dir = path.get_win32 ();

  /* Check to see if path translates to something like C:.
     If it does, append a \ to the native directory specification to
     defeat the Windows 95 (i.e. MS-DOS) tendency of returning to
     the last directory visited on the given drive. */
  if (isdrive (native_dir) && !native_dir[2])
    {
      path.get_win32 ()[2] = '\\';
      path.get_win32 ()[3] = '\0';
    }
  int res;
  int devn = path.get_devn ();
  if (!isvirtual_dev (devn))
    res = SetCurrentDirectory (native_dir) ? 0 : -1;
  else if (!path.exists ())
    {
      set_errno (ENOENT);
      return -1;
    }
  else if (!path.isdir ())
    {
      set_errno (ENOTDIR);
      return -1;
    }
  else
    {
      native_dir = "c:\\";
      res = 0;
    }

  /* If res != 0, we didn't change to a new directory.
     Otherwise, set the current windows and posix directory cache from input.
     If the specified directory is a MS-DOS style directory or if the directory
     was symlinked, convert the MS-DOS path back to posix style.  Otherwise just
     store the given directory.  This allows things like "find", which traverse
     directory trees, to work correctly with Cygwin mounted directories.
     FIXME: Is just storing the posixized windows directory the correct thing to
     do when we detect a symlink?  Should we instead rebuild the posix path from
     the input by traversing links?  This would be an expensive operation but
     we'll see if Cygwin mailing list users whine about the current behavior. */
  if (res)
    __seterrno ();
  else if ((!path.has_symlinks () && strpbrk (dir, ":\\") == NULL
	    && pcheck_case == PCHECK_RELAXED) || isvirtual_dev (devn))
    cygheap->cwd.set (native_dir, dir);
  else
    cygheap->cwd.set (native_dir, NULL);

  /* Note that we're accessing cwd.posix without a lock here.  I didn't think
     it was worth locking just for strace. */
  syscall_printf ("%d = chdir() cygheap->cwd.posix '%s' native '%s'", res,
		  cygheap->cwd.posix, native_dir);
  MALLOC_CHECK;
  return res;
}

extern "C" int
fchdir (int fd)
{
  int res;
  sigframe thisframe (mainthread);

  cygheap_fdget cfd (fd);
  if (cfd >= 0)
    res = chdir (cfd->get_win32_name ());
  else
    res = -1;

  syscall_printf ("%d = fchdir (%d)", res, fd);
  return res;
}

/******************** Exported Path Routines *********************/

/* Cover functions to the path conversion routines.
   These are exported to the world as cygwin_foo by cygwin.din.  */

extern "C" int
cygwin_conv_to_win32_path (const char *path, char *win32_path)
{
  path_conv p (path, PC_SYM_FOLLOW);
  if (p.error)
    {
      win32_path[0] = '\0';
      set_errno (p.error);
      return -1;
    }

  strcpy (win32_path, p);
  return 0;
}

extern "C" int
cygwin_conv_to_full_win32_path (const char *path, char *win32_path)
{
  path_conv p (path, PC_SYM_FOLLOW | PC_FULL);
  if (p.error)
    {
      win32_path[0] = '\0';
      set_errno (p.error);
      return -1;
    }

  strcpy (win32_path, p);
  return 0;
}

/* This is exported to the world as cygwin_foo by cygwin.din.  */

extern "C" int
cygwin_conv_to_posix_path (const char *path, char *posix_path)
{
  if (check_null_empty_str_errno (path))
    return -1;
  mount_table->conv_to_posix_path (path, posix_path, 1);
  return 0;
}

extern "C" int
cygwin_conv_to_full_posix_path (const char *path, char *posix_path)
{
  if (check_null_empty_str_errno (path))
    return -1;
  mount_table->conv_to_posix_path (path, posix_path, 0);
  return 0;
}

/* The realpath function is supported on some UNIX systems.  */

extern "C" char *
realpath (const char *path, char *resolved)
{
  int err;

  path_conv real_path (path, PC_SYM_FOLLOW | PC_FULL);

  if (real_path.error)
    err = real_path.error;
  else
    {
      err = mount_table->conv_to_posix_path (real_path.get_win32 (), resolved, 0);
      if (err == 0)
	return resolved;
    }

  /* FIXME: on error, we are supposed to put the name of the path
     component which could not be resolved into RESOLVED.  */
  resolved[0] = '\0';

  set_errno (err);
  return NULL;
}

/* Return non-zero if path is a POSIX path list.
   This is exported to the world as cygwin_foo by cygwin.din.

DOCTOOL-START
<sect1 id="add-func-cygwin-posix-path-list-p">
  <para>Rather than use a mode to say what the "proper" path list
  format is, we allow any, and give apps the tools they need to
  convert between the two.  If a ';' is present in the path list it's
  a Win32 path list.  Otherwise, if the first path begins with
  [letter]: (in which case it can be the only element since if it
  wasn't a ';' would be present) it's a Win32 path list.  Otherwise,
  it's a POSIX path list.</para>
</sect1>
DOCTOOL-END
  */

extern "C" int
cygwin_posix_path_list_p (const char *path)
{
  int posix_p = !(strchr (path, ';') || isdrive (path));
  return posix_p;
}

/* These are used for apps that need to convert env vars like PATH back and
   forth.  The conversion is a two step process.  First, an upper bound on the
   size of the buffer needed is computed.  Then the conversion is done.  This
   allows the caller to use alloca if it wants.  */

static int
conv_path_list_buf_size (const char *path_list, bool to_posix)
{
  int i, num_elms, max_mount_path_len, size;
  const char *p;

  path_conv pc(".", PC_FULL | PC_POSIX);
  /* The theory is that an upper bound is
     current_size + (num_elms * max_mount_path_len)  */

  unsigned nrel;
  char delim = to_posix ? ';' : ':';
  for (p = path_list, num_elms = nrel = 0; p; num_elms++)
    {
      if (!isabspath (p))
	nrel++;
      p = strchr (++p, delim);
    }

  /* 7: strlen ("//c") + slop, a conservative initial value */
  for (max_mount_path_len = sizeof ("/cygdrive/X"), i = 0;
       i < mount_table->nmounts; i++)
    {
      int mount_len = (to_posix
		       ? mount_table->mount[i].posix_pathlen
		       : mount_table->mount[i].native_pathlen);
      if (max_mount_path_len < mount_len)
	max_mount_path_len = mount_len;
    }

  /* 100: slop */
  size = strlen (path_list)
    + (num_elms * max_mount_path_len)
    + (nrel * strlen (to_posix ? pc.get_win32 () : pc.normalized_path))
    + 100;
  return size;
}

extern "C" int
cygwin_win32_to_posix_path_list_buf_size (const char *path_list)
{
  return conv_path_list_buf_size (path_list, true);
}

extern "C" int
cygwin_posix_to_win32_path_list_buf_size (const char *path_list)
{
  return conv_path_list_buf_size (path_list, false);
}

extern "C" int
cygwin_win32_to_posix_path_list (const char *win32, char *posix)
{
  conv_path_list (win32, posix, 1);
  return 0;
}

extern "C" int
cygwin_posix_to_win32_path_list (const char *posix, char *win32)
{
  conv_path_list (posix, win32, 0);
  return 0;
}

/* cygwin_split_path: Split a path into directory and file name parts.
   Buffers DIR and FILE are assumed to be big enough.

   Examples (path -> `dir' / `file'):
   / -> `/' / `'
   "" -> `.' / `'
   . -> `.' / `.' (FIXME: should this be `.' / `'?)
   .. -> `.' / `..' (FIXME: should this be `..' / `'?)
   foo -> `.' / `foo'
   foo/bar -> `foo' / `bar'
   foo/bar/ -> `foo' / `bar'
   /foo -> `/' / `foo'
   /foo/bar -> `/foo' / `bar'
   c: -> `c:/' / `'
   c:/ -> `c:/' / `'
   c:foo -> `c:/' / `foo'
   c:/foo -> `c:/' / `foo'
 */

extern "C" void
cygwin_split_path (const char *path, char *dir, char *file)
{
  int dir_started_p = 0;

  /* Deal with drives.
     Remember that c:foo <==> c:/foo.  */
  if (isdrive (path))
    {
      *dir++ = *path++;
      *dir++ = *path++;
      *dir++ = '/';
      if (!*path)
	{
	  *dir = 0;
	  *file = 0;
	  return;
	}
      if (isdirsep (*path))
	++path;
      dir_started_p = 1;
    }

  /* Determine if there are trailing slashes and "delete" them if present.
     We pretend as if they don't exist.  */
  const char *end = path + strlen (path);
  /* path + 1: keep leading slash.  */
  while (end > path + 1 && isdirsep (end[-1]))
    --end;

  /* At this point, END points to one beyond the last character
     (with trailing slashes "deleted").  */

  /* Point LAST_SLASH at the last slash (duh...).  */
  const char *last_slash;
  for (last_slash = end - 1; last_slash >= path; --last_slash)
    if (isdirsep (*last_slash))
      break;

  if (last_slash == path)
    {
      *dir++ = '/';
      *dir = 0;
    }
  else if (last_slash > path)
    {
      memcpy (dir, path, last_slash - path);
      dir[last_slash - path] = 0;
    }
  else
    {
      if (dir_started_p)
	; /* nothing to do */
      else
	*dir++ = '.';
      *dir = 0;
    }

  memcpy (file, last_slash + 1, end - last_slash - 1);
  file[end - last_slash - 1] = 0;
}

/*****************************************************************************/

/* Return the hash value for the current win32 value.
   This is used when constructing inodes. */
DWORD
cwdstuff::get_hash ()
{
  DWORD hashnow;
  cwd_lock->acquire ();
  hashnow = hash;
  cwd_lock->release ();
  return hashnow;
}

/* Initialize cygcwd 'muto' for serializing access to cwd info. */
void
cwdstuff::init ()
{
  new_muto (cwd_lock);
}

/* Get initial cwd.  Should only be called once in a
   process tree. */
bool
cwdstuff::get_initial ()
{
  cwd_lock->acquire ();

  if (win32)
    return 1;

  int i;
  DWORD len, dlen;
  for (i = 0, dlen = MAX_PATH, len = 0; i < 3; dlen *= 2, i++)
    {
      win32 = (char *) crealloc (win32, dlen + 2);
      if ((len = GetCurrentDirectoryA (dlen, win32)) < dlen)
	break;
    }

  if (len == 0)
    {
      __seterrno ();
      cwd_lock->release ();
      debug_printf ("get_initial_cwd failed, %E");
      cwd_lock->release ();
      return 0;
    }
  set (NULL);
  return 1;	/* Leaves cwd lock unreleased */
}

/* Fill out the elements of a cwdstuff struct.
   It is assumed that the lock for the cwd is acquired if
   win32_cwd == NULL. */
void
cwdstuff::set (const char *win32_cwd, const char *posix_cwd)
{
  char pathbuf[MAX_PATH];

  if (win32_cwd)
    {
      cwd_lock->acquire ();
      win32 = (char *) crealloc (win32, strlen (win32_cwd) + 1);
      strcpy (win32, win32_cwd);
    }

  if (!posix_cwd)
    mount_table->conv_to_posix_path (win32, pathbuf, 0);
  else
    (void) normalize_posix_path (posix_cwd, pathbuf);

  posix = (char *) crealloc (posix, strlen (pathbuf) + 1);
  strcpy (posix, pathbuf);

  hash = hash_path_name (0, win32);

  if (win32_cwd)
    cwd_lock->release ();

  return;
}

/* Copy the value for either the posix or the win32 cwd into a buffer. */
char *
cwdstuff::get (char *buf, int need_posix, int with_chroot, unsigned ulen)
{
  MALLOC_CHECK;

  if (ulen)
    /* nothing */;
  else if (buf == NULL)
    ulen = (unsigned) -1;
  else
    {
      set_errno (EINVAL);
      goto out;
    }

  if (!get_initial ())	/* Get initial cwd and set cwd lock */
    return NULL;

  char *tocopy;
  if (!need_posix)
    tocopy = win32;
  else
    tocopy = posix;

  debug_printf ("posix %s", posix);
  if (strlen (tocopy) >= ulen)
    {
      set_errno (ERANGE);
      buf = NULL;
    }
  else
    {
      if (!buf)
	buf = (char *) malloc (strlen (tocopy) + 1);
      strcpy (buf, tocopy);
      if (!buf[0])	/* Should only happen when chroot */
	strcpy (buf, "/");
    }

  cwd_lock->release ();

out:
  syscall_printf ("(%s) = cwdstuff::get (%p, %d, %d, %d), errno %d",
		  buf, buf, ulen, need_posix, with_chroot, errno);
  MALLOC_CHECK;
  return buf;
}

int etc::curr_ix = 0;
/* Note that the first elements of the below arrays are unused */
bool etc::change_possible[MAX_ETC_FILES + 1];
const char *etc::fn[MAX_ETC_FILES + 1];
FILETIME etc::last_modified[MAX_ETC_FILES + 1];

int
etc::init (int n, const char *etc_fn)
{
  if (n > 0)
    /* ok */;
  else if (++curr_ix <= MAX_ETC_FILES)
    n = curr_ix;
  else
    api_fatal ("internal error");

  fn[n] = etc_fn;
  change_possible[n] = false;
  (void) test_file_change (n);
  paranoid_printf ("fn[%d] %s, curr_ix %d", n, fn[n], curr_ix);
  return n;
}

bool
etc::test_file_change (int n)
{
  HANDLE h;
  WIN32_FIND_DATA data;
  bool res;

  if ((h = FindFirstFile (fn[n], &data)) == INVALID_HANDLE_VALUE)
    {
      res = true;
      memset (last_modified + n, 0, sizeof (last_modified[n]));
      debug_printf ("FindFirstFile failed, %E");
    }
  else
    {
      FindClose (h);
      res = CompareFileTime (&data.ftLastWriteTime, last_modified + n) > 0;
      last_modified[n] = data.ftLastWriteTime;
      debug_printf ("FindFirstFile succeeded");
    }

  paranoid_printf ("fn[%d] %s res %d", n, fn[n], res);
  return res;
}

bool
etc::dir_changed (int n)
{
  if (!change_possible[n])
    {
      static HANDLE changed_h NO_COPY;

      if (!changed_h)
	{
	  path_conv pwd ("/etc");
	  changed_h = FindFirstChangeNotification (pwd, FALSE,
						  FILE_NOTIFY_CHANGE_LAST_WRITE
						  | FILE_NOTIFY_CHANGE_FILE_NAME);
#ifdef DEBUGGING
	  if (changed_h == INVALID_HANDLE_VALUE)
	    system_printf ("Can't open %s for checking, %E", (char *) pwd);
#endif
	  memset (change_possible, true, sizeof (change_possible));
	}

      if (changed_h == INVALID_HANDLE_VALUE)
	change_possible[n] = true;
      else if (WaitForSingleObject (changed_h, 0) == WAIT_OBJECT_0)
	{
	  (void) FindNextChangeNotification (changed_h);
	  memset (change_possible, true, sizeof change_possible);
	}
    }

  paranoid_printf ("fn[%d] %s change_possible %d", n, fn[n], change_possible[n]);
  return change_possible[n];
}

bool
etc::file_changed (int n)
{
  bool res = false;
  if (dir_changed (n) && test_file_change (n))
    res = true;
  change_possible[n] = false;	/* Change is no longer possible */
  paranoid_printf ("fn[%d] %s res %d", n, fn[n], res);
  return res;
}
