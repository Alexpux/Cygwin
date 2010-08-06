/* Posix dirent.h for WIN32.

   Copyright 2001, 2002, 2003, 2005, 2006, 2007, 2010 Red Hat, Inc.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

/* Including this file should not require any Windows headers.  */

#ifndef _SYS_DIRENT_H
#define _SYS_DIRENT_H

#include <sys/types.h>
#include <limits.h>

#define __DIRENT_VERSION	2

#pragma pack(push,4)
#define _DIRENT_HAVE_D_TYPE
struct dirent
{
  long __d_version;			/* Used internally */
  __ino64_t d_ino;
  unsigned char d_type;
  unsigned char __d_unused1[3];
  __uint32_t __d_internal1;
  char d_name[NAME_MAX + 1];
};
#pragma pack(pop)

#define d_fileno d_ino			/* BSD compatible definition */

#define __DIRENT_COOKIE 0xdede4242

#pragma pack(push,4)
typedef struct __DIR
{
  /* This is first to set alignment in non _COMPILING_NEWLIB case.  */
  unsigned long __d_cookie;
  struct dirent *__d_dirent;
  char *__d_dirname;			/* directory name with trailing '*' */
  long __d_position;			/* used by telldir/seekdir */
  int __d_fd;
  unsigned __d_internal;
  void *__handle;
  void *__fh;
  unsigned __flags;
} DIR;
#pragma pack(pop)

DIR *opendir (const char *);
DIR *fdopendir (int);
struct dirent *readdir (DIR *);
int readdir_r (DIR *, struct dirent *, struct dirent **);
void rewinddir (DIR *);
int closedir (DIR *);

int dirfd (DIR *);

#ifndef _POSIX_SOURCE
#ifndef __INSIDE_CYGWIN__
long telldir (DIR *);
void seekdir (DIR *, long loc);
#endif

int scandir (const char *__dir,
	     struct dirent ***__namelist,
	     int (*select) (const struct dirent *),
	     int (*compar) (const struct dirent **, const struct dirent **));

int alphasort (const struct dirent **__a, const struct dirent **__b);
#ifdef _DIRENT_HAVE_D_TYPE
/* File types for `d_type'.  */
enum
{
  DT_UNKNOWN = 0,
# define DT_UNKNOWN     DT_UNKNOWN
  DT_FIFO = 1,
# define DT_FIFO        DT_FIFO
  DT_CHR = 2,
# define DT_CHR         DT_CHR
  DT_DIR = 4,
# define DT_DIR         DT_DIR
  DT_BLK = 6,
# define DT_BLK         DT_BLK
  DT_REG = 8,
# define DT_REG         DT_REG
  DT_LNK = 10,
# define DT_LNK         DT_LNK
  DT_SOCK = 12,
# define DT_SOCK        DT_SOCK
  DT_WHT = 14
# define DT_WHT         DT_WHT
};

/* Convert between stat structure types and directory types.  */
# define IFTODT(mode)		(((mode) & 0170000) >> 12)
# define DTTOIF(dirtype)        ((dirtype) << 12)
#endif /* _DIRENT_HAVE_D_TYPE */
#endif /* _POSIX_SOURCE */
#endif /*_SYS_DIRENT_H*/
