/* path.h: path data structures

   Copyright 1996, 1997, 1998, 2000 Cygnus Solutions.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

struct suffix_info
{
  const char *name;
  int addon;
  suffix_info (const char *s, int addit = 0) {name = s, addon = addit;}
};

enum symlink_follow
{
  SYMLINK_FOLLOW,
  SYMLINK_NOFOLLOW,
  SYMLINK_IGNORE,
  SYMLINK_CONTENTS
};

#include <sys/mount.h>

enum
{
  PATH_NOTHING = 0,
  PATH_SYMLINK = 1,
  PATH_BINARY = MOUNT_BINARY,
  PATH_EXEC = MOUNT_EXEC,
  PATH_SOCKET =  0x40000000,
  PATH_HASACLS = 0x80000000
};


class path_conv
{
  char path[MAX_PATH];
 public:

  unsigned path_flags;

  int has_acls () {return path_flags & PATH_HASACLS;}
  int hasgood_inode () {return path_flags & PATH_HASACLS;}  // Not strictly correct
  int isbinary () {return path_flags & PATH_BINARY;}
  int issymlink () {return path_flags & PATH_SYMLINK;}
  int issocket () {return path_flags & PATH_SOCKET;}
  int isexec () {return path_flags & PATH_EXEC;}

  void set_binary () {path_flags |= PATH_BINARY;}
  void set_symlink () {path_flags |= PATH_SYMLINK;}
  void set_exec (int x = 1) {path_flags |= x ? PATH_EXEC : PATH_NOTHING;}
  void set_has_acls (int x = 1) {path_flags |= x ? PATH_HASACLS : PATH_NOTHING;}

  char *known_suffix;

  int error;
  DWORD devn;
  int unit;

  DWORD fileattr;

  path_conv (const char * const, symlink_follow follow_mode = SYMLINK_FOLLOW,
	     int use_full_path = 0, const suffix_info *suffixes = NULL);
  inline char *get_win32 () { return path; }
  operator char *() {return path; }
  BOOL is_device () {return devn != FH_BAD;}
  DWORD get_devn () {return devn == FH_BAD ? (DWORD) FH_DISK : devn;}
  short get_unitn () {return devn == FH_BAD ? 0 : unit;}
  DWORD file_attributes () {return fileattr;}
};

/* Symlink marker */
#define SYMLINK_COOKIE "!<symlink>"

/* Socket marker */
#define SOCKET_COOKIE  "!<socket >"

/* Maximum depth of symlinks (after which ELOOP is issued).  */
#define MAX_LINK_DEPTH 10

extern suffix_info std_suffixes[];

int __stdcall get_device_number (const char *name, int &unit, BOOL from_conv = FALSE);
int __stdcall slash_unc_prefix_p (const char *path);

/* Common macros for checking for invalid path names */
#define check_null_empty_path(src) \
  (!(src) ? EFAULT : *(src) ? 0 : ENOENT)

#define check_null_empty_path_errno(src) \
({ \
  int __err; \
  if ((__err = check_null_empty_path(src))) \
    set_errno (__err); \
  __err; \
})
