/* path.h: path data structures

   Copyright 1996, 1997, 1998, 2000, 2001, 2002 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

struct suffix_info
{
  const char *name;
  int addon;
  suffix_info (const char *s, int addit = 0): name (s), addon (addit) {}
};

enum pathconv_arg
{
  PC_SYM_FOLLOW		= 0x0001,
  PC_SYM_NOFOLLOW	= 0x0002,
  PC_SYM_IGNORE		= 0x0004,
  PC_SYM_CONTENTS	= 0x0008,
  PC_FULL		= 0x0010,
  PC_NULLEMPTY		= 0x0020,
  PC_CHECK_EA		= 0x0040,
  PC_POSIX		= 0x0080
};

enum case_checking
{
  PCHECK_RELAXED	= 0,
  PCHECK_ADJUST		= 1,
  PCHECK_STRICT		= 2
};

#define PC_NONULLEMPTY -1

#include <sys/mount.h>

enum path_types
{
  PATH_NOTHING = 0,
  PATH_SYMLINK = MOUNT_SYMLINK,
  PATH_BINARY = MOUNT_BINARY,
  PATH_EXEC = MOUNT_EXEC,
  PATH_NOTEXEC = MOUNT_NOTEXEC,
  PATH_CYGWIN_EXEC = MOUNT_CYGWIN_EXEC,
  PATH_ALL_EXEC = (PATH_CYGWIN_EXEC | PATH_EXEC),
  PATH_TEXT =	      0x02000000,
  PATH_ISDISK =	      0x04000000,
  PATH_HAS_SYMLINKS = 0x10000000,
  PATH_HASBUGGYOPEN = 0x20000000,
  PATH_SOCKET =       0x40000000,
  PATH_HASACLS =      0x80000000
};

class symlink_info;
struct fs_info
{
  char name[MAX_PATH];
  char root_dir[MAX_PATH];
  DWORD flags;
  DWORD serial;
  DWORD sym_opt; /* additional options to pass to symlink_info resolver */
  DWORD is_remote_drive;
  DWORD drive_type;
  bool update (const char *);
};
class path_conv
{
  char path[MAX_PATH];
  DWORD fileattr;
  fs_info fs;
  void add_ext_from_sym (symlink_info&);
 public:

  unsigned path_flags;
  char *known_suffix;
  int error;
  DWORD devn;
  int unit;
  BOOL case_clash;
  char *normalized_path;

  int isdisk () const { return path_flags & PATH_ISDISK;}
  int isremote () const {return fs.is_remote_drive;}
  int has_acls () const {return path_flags & PATH_HASACLS;}
  int has_symlinks () const {return path_flags & PATH_HAS_SYMLINKS;}
  int hasgood_inode () const {return path_flags & PATH_HASACLS;}  // Not strictly correct
  int has_buggy_open () const {return path_flags & PATH_HASBUGGYOPEN;}
  int binmode () const
  {
    if (path_flags & PATH_BINARY)
      return O_BINARY;
    if (path_flags & PATH_TEXT)
      return O_TEXT;
    return 0;
  }
  int issymlink () const {return path_flags & PATH_SYMLINK;}
  int issocket () const {return path_flags & PATH_SOCKET;}
  int iscygexec () const {return path_flags & PATH_CYGWIN_EXEC;}
  bool exists () const {return fileattr != INVALID_FILE_ATTRIBUTES;}
  bool has_attribute (DWORD x) const {return exists () && (fileattr & x);}
  int isdir () const {return has_attribute (FILE_ATTRIBUTE_DIRECTORY);}
  executable_states exec_state ()
  {
    extern int _check_for_executable;
    if (path_flags & PATH_ALL_EXEC)
      return is_executable;
    if (path_flags & PATH_NOTEXEC)
      return not_executable;
    if (!_check_for_executable)
      return dont_care_if_executable;
    return dont_know_if_executable;
  }

  void set_binary () {path_flags |= PATH_BINARY;}
  void set_symlink () {path_flags |= PATH_SYMLINK;}
  void set_has_symlinks () {path_flags |= PATH_HAS_SYMLINKS;}
  void set_isdisk () {path_flags |= PATH_ISDISK; devn = FH_DISK;}
  void set_exec (int x = 1) {path_flags |= x ? PATH_EXEC : PATH_NOTEXEC;}
  void set_has_acls (int x = 1) {path_flags |= x ? PATH_HASACLS : PATH_NOTHING;}
  void set_has_buggy_open (int x = 1) {path_flags |= x ? PATH_HASBUGGYOPEN : PATH_NOTHING;}

  void check (const char *src, unsigned opt = PC_SYM_FOLLOW,
	      const suffix_info *suffixes = NULL)  __attribute__ ((regparm(3)));

  path_conv (int, const char *src, unsigned opt = PC_SYM_FOLLOW,
	     const suffix_info *suffixes = NULL)
  {
    check (src, opt, suffixes);
  }

  path_conv (const char *src, unsigned opt = PC_SYM_FOLLOW,
	     const suffix_info *suffixes = NULL)
  {
    check (src, opt | PC_NULLEMPTY, suffixes);
  }

  path_conv (): fileattr (INVALID_FILE_ATTRIBUTES), path_flags (0),
  		known_suffix (NULL), error (0), devn (0), unit (0),
		normalized_path (NULL) {path[0] = '\0';}

  inline char *get_win32 () { return path; }
  operator char *() {return path;}
  operator const char *() {return path;}
  operator DWORD &() {return fileattr;}
  operator int () {return fileattr; }
  char operator [](int i) const {return path[i];}
  BOOL is_device () {return devn != FH_BAD && devn != FH_DISK;}
  DWORD get_devn () {return devn == FH_BAD ? (DWORD) FH_DISK : devn;}
  short get_unitn () {return devn == FH_BAD ? 0 : unit;}
  DWORD file_attributes () {return fileattr;}
  DWORD drive_type () {return fs.drive_type;}
  BOOL fs_fast_ea () {return fs.sym_opt & PC_CHECK_EA;}
  void set_path (const char *p) {strcpy (path, p);}
  char *return_and_clear_normalized_path ();
  const char * root_dir () { return fs.root_dir; }
  DWORD volser () { return fs.serial; }
  const char *volname () {return fs.name; }
  void fillin (HANDLE h);
};

/* Symlink marker */
#define SYMLINK_COOKIE "!<symlink>"

#define SYMLINK_EA_NAME ".CYGSYMLINK"

/* Socket marker */
#define SOCKET_COOKIE  "!<socket >"

/* The sizeof header written to a shortcut by Cygwin or U/WIN. */
#define SHORTCUT_HDR_SIZE       76

/* Maximum depth of symlinks (after which ELOOP is issued).  */
#define MAX_LINK_DEPTH 10
int __stdcall slash_unc_prefix_p (const char *path) __attribute__ ((regparm(1)));

enum fe_types
{
  FE_NADA = 0,		/* Nothing special */
  FE_NNF = 1,		/* Return NULL if not found */
  FE_NATIVE = 2,	/* Return native path in path_conv struct */
  FE_CWD = 4		/* Search CWD for program */
};
const char * __stdcall find_exec (const char *name, path_conv& buf,
				  const char *winenv = "PATH=",
				  unsigned opt = FE_NADA,
				  const char **known_suffix = NULL)
  __attribute__ ((regparm(3)));

/* Common macros for checking for invalid path names */
#define isdrive(s) (isalpha (*(s)) && (s)[1] == ':')

static inline bool
has_exec_chars (const char *buf, int len)
{
  return len >= 2 &&
	 ((buf[0] == '#' && buf[1] == '!') ||
	  (buf[0] == ':' && buf[1] == '\n') ||
	  (buf[0] == 'M' && buf[1] == 'Z'));
}

int pathmatch (const char *path1, const char *path2) __attribute__ ((regparm (2)));
int pathnmatch (const char *path1, const char *path2, int len) __attribute__ ((regparm (2)));

int path_prefix_p (const char *path1, const char *path2, int len1) __attribute__ ((regparm (3)));
