/* msys_symlink.c
 * Copyright (C) 2002, Earnie Boyd
 *               2010, Cesar Strauss
 * This file is a part of MSYS.
 * ***************************************************************************/

/*
  Native w32 applications have no notion of POSIX-style symlinks. On the
  other hand, it is natural to assume that useful scripts and tools have
  come to rely on their existence. So, having some sort of symlink
  emulation makes it easier to port them to MSYS, provided they are
  transparent to w32 applications. One approximation that works in pratice
  is to replace symlink creation with a copy operation.

  The semantics of the symlink operation under MSYS are as follow:
  1) The original source is copied to the destination.
  2) In case of a directory, a deep copy is performed.
  3) If the source path is relative, it is taken relative to the
     directory of the destination.

  The following are the differences with respect to standard symlink
  behaviour:
  1) The original source must already exist at symlink creation time.
  2) Modifying the contents of the original source does not affect the
     destination and vice-versa.
  3) When creating a symlink pointing to a component of the symlink own
     path, the deep copy operation avoids descending into the newly created
     tree, to avoid infinite recursion.
     For instance:
     $ mkdir foo
     $ ln -s .. foo/bar
     On POSIX, you can dereference foo/bar/foo/bar/...
     On MSYS, it stops after foo/bar/foo
  4) When doing a deep copy operation, the directory traversal is done
     in the w32 domain. As a result, it does not traverse mount points
     found within the directory hierarchy.
     For instance: if foo/mnt is a mount point, then ls -s foo bar does
     not copy the contents of foo/mnt.
*/

#include "msys_symlink.h"
#include "winsup.h"
#include "security.h"
#include "fhandler.h"
#include "path.h"
#include <ctype.h>
#if !DO_CPP_NEW
#include <stdlib.h>
#endif

/*
  Create a deep copy of src as dst, while avoiding descending in origpath.
*/
static int
RecursiveCopy (char * src, char * dst, const char * origpath)
{
#if DO_CPP_NEW
  struct _WIN32_FIND_DATAA *dHfile = new struct _WIN32_FIND_DATAA;
#else
  struct _WIN32_FIND_DATAA *dHfile = (struct _WIN32_FIND_DATAA *) malloc (sizeof (struct _WIN32_FIND_DATAA));
#endif
  HANDLE dH;
  BOOL findfiles;
  int srcpos = strlen (src);
  int dstpos = strlen (dst);
  int res = -1;

  debug_printf("RecursiveCopy (%s, %s)", src, dst);

  /* Create the destination directory */
  if (!CreateDirectoryEx (src, dst, NULL))
    {
      debug_printf("CreateDirectoryEx(%s, %s, 0) failed", src, dst);
      __seterrno ();
      goto done;
    }
  /* Descend into the source directory */
  if (srcpos + 2 >= MAX_PATH || dstpos + 1 >= MAX_PATH)
    {
      set_errno (ENAMETOOLONG);
      goto done;
    }
  strcat (src, "\\*");
  strcat (dst, "\\");
  dH = FindFirstFile (src, dHfile);
  debug_printf("dHfile(1): %s", dHfile->cFileName);
  findfiles = FindNextFile (dH, dHfile);
  debug_printf("dHfile(2): %s", dHfile->cFileName);
  findfiles = FindNextFile (dH, dHfile);
  while (findfiles)
    {
      /* Append the directory item filename to both source and destination */
      int filelen = strlen (dHfile->cFileName);
      debug_printf("dHfile(3): %s", dHfile->cFileName);
      if (srcpos + 1 + filelen >= MAX_PATH ||
          dstpos + 1 + filelen >= MAX_PATH)
        {
          set_errno (ENAMETOOLONG);
          goto done;
        }
      strcpy (&src[srcpos+1], dHfile->cFileName);
      strcpy (&dst[dstpos+1], dHfile->cFileName);
      debug_printf("%s -> %s", src, dst);
      if (dHfile->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
          /* Recurse into the child directory */
          debug_printf("%s <-> %s", src, origpath);
          if (strcmp (src, origpath)) // avoids endless recursion
            if (RecursiveCopy (src, dst, origpath))
              goto done;
        }
      else
        {
          /* Just copy the file */
          if (!CopyFile (src, dst, FALSE))
            {
              __seterrno ();
              goto done;
            }
        }
      findfiles = FindNextFile (dH, dHfile);
    }
  if (GetLastError() != ERROR_NO_MORE_FILES)
    {
      __seterrno ();
      goto done;
    }
  res = 0;

done:
#if DO_CPP_NEW
  delete dHfile;
#else
  free (dHfile);
#endif
  return res;
}

extern "C"
int
msys_symlink (const char * topath, const char * frompath)
{
#if DO_CPP_NEW
  struct stat *sb_frompath = new struct stat;
  struct stat *sb_topath = new struct stat;
#else
  struct stat *sb_frompath = (struct stat *) malloc (sizeof (struct stat));
  struct stat *sb_topath = (struct stat *) malloc (sizeof (struct stat));
#endif
  char real_topath[MAX_PATH];
  int res = -1;

  debug_printf("msys_symlink (%s, %s)", topath, frompath);

  if (strlen (frompath) >= MAX_PATH || strlen (topath) >= MAX_PATH)
    {
      set_errno (ENAMETOOLONG);
      goto done;
    }

  if (isabspath (topath))
    strcpy (real_topath, topath);
  else
    /* Find the real source path, relative
       to the directory of the destination */
    {
      /* Determine the character position of the last path component */
      int pos = strlen (frompath);
      while (--pos >= 0)
        if (isdirsep (frompath[pos]))
          break;
      /* Append the source path to the directory
         component of the destination */
      if (pos+1+strlen(topath) >= MAX_PATH)
        {
          set_errno(ENAMETOOLONG);
          goto done;
        }
      strcpy (real_topath, frompath);
      strcpy (&real_topath[pos+1], topath);
    }

  debug_printf("real_topath: %s", real_topath);

  /* As a MSYS limitation, the source path must exist. */
  if (stat (real_topath, sb_topath))
    {
      debug_printf("Failed stat");
      goto done;
    }
  /* As per POSIX, the destination must not exist */
  if (stat (frompath, sb_frompath))
    {
      if (errno != ENOENT)
        {
          debug_printf("error: %d", errno);
          goto done;
        }
      else
        set_errno (0);
    }
  else
    {
      set_errno(EEXIST);
      goto done;
    }
  {
    /* Find the w32 equivalent of the source and destination */
    path_conv w_topath (real_topath, PC_SYM_NOFOLLOW | PC_FULL);
    if (w_topath.error)
      {
        set_errno (w_topath.error);
        goto done;
      }
    path_conv w_frompath (frompath, PC_SYM_NOFOLLOW | PC_FULL);
    if (w_frompath.error)
      {
        set_errno (w_frompath.error);
        goto done;
      }

    debug_printf ("w32 paths: %s , %s",
                  w_topath.get_win32(), w_frompath.get_win32());

    if (S_ISDIR (sb_topath->st_mode))
      /* Start a deep recursive directory copy */
      {
        char origpath[MAX_PATH];
        strcpy (origpath, w_frompath);
        res = RecursiveCopy (w_topath, w_frompath, origpath);
        goto done;
      }
    else
      /* Just copy the file */
      {
        if (!CopyFile (w_topath, w_frompath, FALSE))
          {
            __seterrno ();
            goto done;
          }
      }
  }
  res = 0;

done:
#if DO_CPP_NEW
  delete sb_frompath;
  delete sb_topath;
#else
  free (sb_frompath);
  free (sb_topath);
#endif
  return res;
}
