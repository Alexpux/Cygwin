/* cygwin/grp.h

   Copyright 2002, 2011 Red Hat Inc.
   Written by Corinna Vinschen <corinna@vinschen.de>

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _CYGWIN_GRP_H_
#define _CYGWIN_GRP_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __INSIDE_CYGWIN__
#ifndef __x86_64__
struct __group16
{
  char *gr_name;
  char *gr_passwd;
  __gid16_t gr_gid;
  char **gr_mem;
};
#endif

struct group * getgrgid32 (gid_t gid);
struct group * getgrnam32 (const char *name);
gid_t getgid32 ();
gid_t getegid32 ();
#endif

extern int getgrouplist (const char *, gid_t, gid_t *, int *);

#ifdef __cplusplus
}
#endif

#endif /* _CYGWIN_GRP_H_ */
