/* environ.h: Declarations for environ manipulation

   Copyright 2000, 2001, 2002 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

/* Initialize the environment */
void environ_init (char **, int)
  __attribute__ ((regparm (2)));

/* The structure below is used to control conversion to/from posix-style
   file specs.  Currently, only PATH and HOME are converted, but PATH
   needs to use a "convert path list" function while HOME needs a simple
   "convert to posix/win32".  For the simple case, where a calculated length
   is required, just return MAX_PATH.  *FIXME* */
struct win_env
  {
    const char *name;
    size_t namelen;
    char *posix;
    char *native;
    int (*toposix) (const char *, char *);
    int (*towin32) (const char *, char *);
    int (*posix_len) (const char *);
    int (*win32_len) (const char *);
    void add_cache (const char *in_posix, const char *in_native = NULL)
      __attribute__ ((regparm (3)));
    const char * get_native () const {return native ? native + namelen : NULL;}
    const char * get_posix () const {return posix ? posix : NULL;}
  };

win_env * __stdcall getwinenv (const char *name, const char *posix = NULL)
  __attribute__ ((regparm (3)));
char * __stdcall getwinenveq (const char *name, size_t len, int)
  __attribute__ ((regparm (3)));

void __stdcall update_envptrs ();
extern char **__cygwin_environ, ***main_environ;
extern "C" char __stdcall **cur_environ ();
char ** __stdcall build_env (const char * const *envp, char *&envblock,
			     int &envc, bool need_envblock)
  __attribute__ ((regparm (3)));
