/* shared_info.h: shared info for cygwin

   Copyright 2000, 2001 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "tty.h"
#include "security.h"

struct charplus
{
  char buf[CYG_MAX_PATH];
  char tailch;
  char *tail;
  operator char * () { return buf; }
  operator const char * () const { return buf; }
  charplus (const char *s) : tailch (0), tail (0) {strcpy (buf, s);}
  charplus () : tailch (0), tail (0) {*buf = '\0';}
};

/* Mount table entry */

class mount_item
{
 public:
  /* FIXME: Nasty static allocation.  Need to have a heap in the shared
     area [with the user being able to configure at runtime the max size].  */
  /* Win32-style mounted partition source ("C:\foo\bar").
     native_path[0] == 0 for unused entries.  */
  char native_path[CYG_MAX_PATH];
  int native_pathlen;

  /* POSIX-style mount point ("/foo/bar") */
  char posix_path[CYG_MAX_PATH];
  int posix_pathlen;

  unsigned flags;

  void init (const char *dev, const char *path, unsigned flags);

  struct mntent *getmntent ();
  int fnmunge (char *, const char *, int&);
  int build_win32 (char *, const charplus&, unsigned *, unsigned);
};

/* Warning: Decreasing this value will cause cygwin.dll to ignore existing
   higher numbered registry entries.  Don't change this number willy-nilly.
   What we need is to have a more dynamic allocation scheme, but the current
   scheme should be satisfactory for a long while yet.  */
#define MAX_MOUNTS 30

#define USER_VERSION	1	// increment when mount table changes and
#define USER_VERSION_MAGIC CYGWIN_VERSION_MAGIC (USER_MAGIC, USER_VERSION)
#define CURR_USER_MAGIC 0x8dc7b1d5U

class reg_key;
struct device;

/* NOTE: Do not make gratuitous changes to the names or organization of the
   below class.  The layout is checksummed to determine compatibility between
   different cygwin versions. */
class mount_info
{
 public:
  DWORD sys_mount_table_counter;
  int nmounts;
  mount_item mount[MAX_MOUNTS];

  /* cygdrive_prefix is used as the root of the path automatically
     prepended to a path when the path has no associated mount.
     cygdrive_flags are the default flags for the cygdrives. */
  char cygdrive[CYG_MAX_PATH];
  size_t cygdrive_len;
  unsigned cygdrive_flags;
 private:
  int posix_sorted[MAX_MOUNTS];
  int native_sorted[MAX_MOUNTS];

 public:
  void init ();
  int add_item (const char *dev, const char *path, unsigned flags, int reg_p);
  int del_item (const char *path, unsigned flags, int reg_p);

  void from_registry ();
  int add_reg_mount (const char * native_path, const char * posix_path,
		      unsigned mountflags);
  int del_reg_mount (const char * posix_path, unsigned mountflags);

  unsigned set_flags_from_win32_path (const char *path);
  int conv_to_win32_path (const charplus& src_path, char *dst, device&,
			  unsigned *flags = NULL);
  int conv_to_posix_path (const charplus& src_path, char *posix_path,
			  int keep_rel_p);
  struct mntent *getmntent (int x);

  int write_cygdrive_info_to_registry (const char *cygdrive_prefix, unsigned flags);
  int remove_cygdrive_info_from_registry (const char *cygdrive_prefix, unsigned flags);
  int get_cygdrive_info (char *user, char *system, char* user_flags,
			 char* system_flags);

 private:

  void sort ();
  void read_mounts (reg_key& r);
  void mount_slash ();
  void to_registry ();

  int cygdrive_win32_path (const char *src, char *dst, int& unit);
  void cygdrive_posix_path (const char *src, char *dst, int trailing_slash_p);
  void read_cygdrive_info_from_registry ();
};

/******** Close-on-delete queue ********/

/* First pass at a file deletion queue structure.

   We can't keep this list in the per-process info, since
   one process may open a file, and outlive a process which
   wanted to unlink the file - and the data would go away.
*/

#define MAX_DELQUEUES_PENDING 100

class delqueue_list
{
  char name[MAX_DELQUEUES_PENDING][CYG_MAX_PATH];
  char inuse[MAX_DELQUEUES_PENDING];
  int empty;

public:
  void init ();
  void queue_file (const char *dosname);
  void process_queue ();
};

class user_info
{
public:
  DWORD version;
  DWORD cb;
  delqueue_list delqueue;
  mount_info mountinfo;
};
/******** Shared Info ********/
/* Data accessible to all tasks */

#define SHARED_VERSION (unsigned)(cygwin_version.api_major << 8 | \
				  cygwin_version.api_minor)
#define SHARED_VERSION_MAGIC CYGWIN_VERSION_MAGIC (SHARED_MAGIC, SHARED_VERSION)

#define SHARED_INFO_CB 21008

#define CURR_SHARED_MAGIC 0x818f75beU

/* NOTE: Do not make gratuitous changes to the names or organization of the
   below class.  The layout is checksummed to determine compatibility between
   different cygwin versions. */
class shared_info
{
  DWORD version;
  DWORD cb;
 public:
  unsigned heap_chunk;
  DWORD sys_mount_table_counter;

  tty_list tty;
  void initialize ();
  unsigned heap_chunk_size ();
};

extern shared_info *cygwin_shared;
extern user_info *user_shared; 
#define mount_table (&(user_shared->mountinfo))
extern HANDLE cygwin_user_h;

enum shared_locations
{
  SH_CYGWIN_SHARED,
  SH_USER_SHARED,
  SH_SHARED_CONSOLE,
  SH_MYSELF,
  SH_MTINFO,
  SH_TOTAL_SIZE
};
void __stdcall memory_init ();

#define shared_align_past(p) \
  ((char *) (system_info.dwAllocationGranularity * \
	     (((DWORD) ((p) + 1) + system_info.dwAllocationGranularity - 1) / \
	      system_info.dwAllocationGranularity)))

#define cygwin_shared_address	((void *) 0xa000000)

#ifdef _FHANDLER_H_
struct console_state
{
  tty_min tty_min_state;
  dev_console dev_state;
};
#endif

char *__stdcall shared_name (char *, const char *, int);
void *__stdcall open_shared (const char *name, int n, HANDLE &shared_h, DWORD size, 
			     shared_locations, PSECURITY_ATTRIBUTES psa = &sec_all);
extern void user_shared_initialize (bool reinit);

