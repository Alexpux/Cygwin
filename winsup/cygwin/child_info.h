/* child_info.h: shared child info for cygwin

   Copyright 2000, 2001, 2002, 2003, 2004 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include <setjmp.h>

enum child_info_types
{
  _PROC_EXEC,
  _PROC_SPAWN,
  _PROC_FORK,
  _PROC_WHOOPS
};

#define OPROC_MAGIC_MASK 0xff00ff00
#define OPROC_MAGIC_GENERIC 0xaf00f000

#define PROC_MAGIC_GENERIC 0xaf00fa00

#define PROC_EXEC (_PROC_EXEC)
#define PROC_SPAWN (_PROC_SPAWN)
#define PROC_FORK (_PROC_FORK)

#define EXEC_MAGIC_SIZE sizeof(child_info)

#define CURR_CHILD_INFO_MAGIC 0x694cd4b8U

/* NOTE: Do not make gratuitous changes to the names or organization of the
   below class.  The layout is checksummed to determine compatibility between
   different cygwin versions. */
class child_info
{
public:
  DWORD zero[4];	// must be zeroed
  DWORD cb;		// size of this record
  DWORD intro;		// improbable string
  unsigned long magic;	// magic number unique to child_info
  unsigned short type;	// type of record, exec, spawn, fork
  HANDLE subproc_ready;	// used for synchronization with parent
  HANDLE user_h;
  HANDLE parent;
  init_cygheap *cygheap;
  void *cygheap_max;
  DWORD cygheap_reserve_sz;
  HANDLE cygheap_h;
  HANDLE parent_wr_proc_pipe;
  unsigned fhandler_union_cb;
  child_info (unsigned, child_info_types);
  ~child_info ();
  void ready (bool);
  bool sync (pinfo&, DWORD);
};

class mount_info;
class _pinfo;

class child_info_fork: public child_info
{
public:
  HANDLE forker_finished;// for synchronization with child
  DWORD stacksize;	// size of parent stack
  jmp_buf jmp;		// where child will jump to
  void *stacktop;	// location of top of parent stack
  void *stackbottom;	// location of bottom of parent stack
  child_info_fork ();
};

class fhandler_base;

class cygheap_exec_info
{
public:
  char *old_title;
  int argc;
  char **argv;
  int envc;
  char **envp;
  HANDLE myself_pinfo;
};

class child_info_spawn: public child_info
{
public:
  cygheap_exec_info *moreinfo;

  ~child_info_spawn ()
  {
    if (moreinfo)
      {
	if (moreinfo->old_title)
	  cfree (moreinfo->old_title);
	if (moreinfo->envp)
	  {
	    for (char **e = moreinfo->envp; *e; e++)
	      cfree (*e);
	    cfree (moreinfo->envp);
	  }
	CloseHandle (moreinfo->myself_pinfo);
	cfree (moreinfo);
      }
  }
  child_info_spawn (child_info_types);
};

void __stdcall init_child_info (DWORD, child_info *, HANDLE);

extern child_info *child_proc_info;
extern child_info_spawn *spawn_info __attribute__ ((alias ("child_proc_info")));
extern child_info_fork *fork_info __attribute__ ((alias ("child_proc_info")));
