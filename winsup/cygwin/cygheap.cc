/* cygheap.cc: Cygwin heap manager.

   Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
   2010 Red Hat, Inc.

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

#include "winsup.h"
#include <assert.h>
#include <stdlib.h>
#include "cygerrno.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "child_info.h"
#include "heap.h"
#include "sigproc.h"
#include "pinfo.h"
#include <unistd.h>
#include <wchar.h>

static mini_cygheap NO_COPY cygheap_at_start =
{
  {__utf8_mbtowc, __utf8_wctomb}
};

init_cygheap NO_COPY *cygheap = (init_cygheap *) &cygheap_at_start;
void NO_COPY *cygheap_max;

extern "C" char  _cygheap_mid[] __attribute__((section(".cygheap")));
extern "C" char  _cygheap_end[];

static NO_COPY muto cygheap_protect;

struct cygheap_entry
{
  int type;
  struct cygheap_entry *next;
  char data[0];
};

#define NBUCKETS (sizeof (cygheap->buckets) / sizeof (cygheap->buckets[0]))
#define N0 ((_cmalloc_entry *) NULL)
#define to_cmalloc(s) ((_cmalloc_entry *) (((char *) (s)) - (unsigned) (N0->data)))

#define CFMAP_OPTIONS (SEC_RESERVE | PAGE_READWRITE)
#define MVMAP_OPTIONS (FILE_MAP_WRITE)

extern "C" {
static void __stdcall _cfree (void *) __attribute__((regparm(1)));
static void *__stdcall _csbrk (int);
}

/* Called by fork or spawn to reallocate cygwin heap */
void __stdcall
cygheap_fixup_in_child (bool execed)
{
  cygheap_max = child_proc_info->cygheap;
  cygheap = (init_cygheap *) cygheap_max;
  _csbrk ((char *) child_proc_info->cygheap_max - (char *) cygheap);
  child_copy (child_proc_info->parent, false, "cygheap", cygheap, cygheap_max, NULL);
  cygheap_init ();
  debug_fixup_after_fork_exec ();
  if (execed)
    {
      cygheap->hooks.next = NULL;
      cygheap->user_heap.base = NULL;		/* We can allocate the heap anywhere */
      /* Walk the allocated memory chain looking for orphaned memory from
	 previous execs */
      for (_cmalloc_entry *rvc = cygheap->chain; rvc; rvc = rvc->prev)
	{
	  cygheap_entry *ce = (cygheap_entry *) rvc->data;
	  if (!rvc->ptr || rvc->b >= NBUCKETS || ce->type <= HEAP_1_START)
	    continue;
	  else if (ce->type < HEAP_1_MAX)
	    ce->type += HEAP_1_MAX;	/* Mark for freeing after next exec */
	  else
	    _cfree (ce);		/* Marked by parent for freeing in child */
	}
    }
}

int
init_cygheap::manage_console_count (const char *something, int amount, bool avoid_freeing_console)
{
  if (console_count == 0 && amount > 0)
    init_console_handler (true);
  console_count += amount;
  debug_printf ("%s: console_count %d, amount %d, %s, avoid_freeing_console %d",
		something, console_count, amount, myctty (), avoid_freeing_console);
  if (!avoid_freeing_console && amount <= 0 && !console_count && myself->ctty == -1)
    {
      BOOL res = FreeConsole ();
      debug_printf ("freed console, res %d", res);
      init_console_handler (false);
    }
  return console_count;
}

void
init_cygheap::close_ctty ()
{
  debug_printf ("closing cygheap->ctty %p", cygheap->ctty);
  cygheap->ctty->close ();
  cygheap->ctty = NULL;
}

#define nextpage(x) ((char *) (((DWORD) ((char *) x + granmask)) & ~granmask))
#define allocsize(x) ((DWORD) nextpage (x))
#ifdef DEBUGGING
#define somekinda_printf debug_printf
#else
#define somekinda_printf malloc_printf
#endif

static void *__stdcall
_csbrk (int sbs)
{
  void *prebrk = cygheap_max;
  size_t granmask = getpagesize () - 1;
  char *newbase = nextpage (prebrk);
  cygheap_max = (char *) cygheap_max + sbs;
  if (!sbs || (newbase >= cygheap_max) || (cygheap_max <= _cygheap_end))
    /* nothing to do */;
  else
    {
      if (prebrk <= _cygheap_end)
	newbase = _cygheap_end;

      DWORD adjsbs = allocsize ((char *) cygheap_max - newbase);
      if (adjsbs && !VirtualAlloc (newbase, adjsbs, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
	{
	  MEMORY_BASIC_INFORMATION m;
	  if (!VirtualQuery (newbase, &m, sizeof m))
	    system_printf ("couldn't get memory info, %E");
	  somekinda_printf ("Couldn't reserve/commit %d bytes of space for cygwin's heap, %E",
			    adjsbs);
	  somekinda_printf ("AllocationBase %p, BaseAddress %p, RegionSize %p, State %p\n",
			    m.AllocationBase, m.BaseAddress, m.RegionSize, m.State);
	  __seterrno ();
	  cygheap_max = (char *) cygheap_max - sbs;
	  return NULL;
	}
    }

  return prebrk;
}

void __stdcall
cygheap_init ()
{
  cygheap_protect.init ("cygheap_protect");
  if (cygheap == &cygheap_at_start)
    {
      cygheap = (init_cygheap *) memset (_cygheap_start, 0,
					 _cygheap_mid - _cygheap_start);
      cygheap_max = cygheap;
      _csbrk (sizeof (*cygheap));
      /* Default locale settings. */
      cygheap->locale.mbtowc = __utf8_mbtowc;
      cygheap->locale.wctomb = __utf8_wctomb;
      strcpy (cygheap->locale.charset, "UTF-8");
      /* Set umask to a sane default. */
      cygheap->umask = 022;
      cygheap->rlim_core = RLIM_INFINITY;
    }
  if (!cygheap->fdtab)
    cygheap->fdtab.init ();
  if (!cygheap->sigs)
    sigalloc ();
}

/* Copyright (C) 1997, 2000 DJ Delorie */

static void *_cmalloc (unsigned size) __attribute ((regparm(1)));
static void *__stdcall _crealloc (void *ptr, unsigned size) __attribute ((regparm(2)));

static void *__stdcall
_cmalloc (unsigned size)
{
  _cmalloc_entry *rvc;
  unsigned b, sz;

  /* Calculate "bit bucket" and size as a power of two. */
  for (b = 3, sz = 8; sz && sz < size; b++, sz <<= 1)
    continue;

  cygheap_protect.acquire ();
  if (cygheap->buckets[b])
    {
      rvc = (_cmalloc_entry *) cygheap->buckets[b];
      cygheap->buckets[b] = rvc->ptr;
      rvc->b = b;
    }
  else
    {
      rvc = (_cmalloc_entry *) _csbrk (sz + sizeof (_cmalloc_entry));
      if (!rvc)
	{
	  cygheap_protect.release ();
	  return NULL;
	}

      rvc->b = b;
      rvc->prev = cygheap->chain;
      cygheap->chain = rvc;
    }
  cygheap_protect.release ();
  return rvc->data;
}

static void __stdcall
_cfree (void *ptr)
{
  cygheap_protect.acquire ();
  _cmalloc_entry *rvc = to_cmalloc (ptr);
  DWORD b = rvc->b;
  rvc->ptr = cygheap->buckets[b];
  cygheap->buckets[b] = (char *) rvc;
  cygheap_protect.release ();
}

static void *__stdcall
_crealloc (void *ptr, unsigned size)
{
  void *newptr;
  if (ptr == NULL)
    newptr = _cmalloc (size);
  else
    {
      unsigned oldsize = 1 << to_cmalloc (ptr)->b;
      if (size <= oldsize)
	return ptr;
      newptr = _cmalloc (size);
      if (newptr)
	{
	  memcpy (newptr, ptr, oldsize);
	  _cfree (ptr);
	}
    }
  return newptr;
}

/* End Copyright (C) 1997 DJ Delorie */

#define sizeof_cygheap(n) ((n) + sizeof (cygheap_entry))

#define N ((cygheap_entry *) NULL)
#define tocygheap(s) ((cygheap_entry *) (((char *) (s)) - (int) (N->data)))

inline static void *
creturn (cygheap_types x, cygheap_entry * c, unsigned len, const char *fn = NULL)
{
  if (c)
    /* nothing to do */;
  else if (fn)
    api_fatal ("%s would have returned NULL", fn);
  else
    {
      set_errno (ENOMEM);
      return NULL;
    }
  c->type = x;
  char *cend = ((char *) c + sizeof (*c) + len);
  if (cygheap_max < cend)
    cygheap_max = cend;
  MALLOC_CHECK;
  return (void *) c->data;
}

inline static void *
cmalloc (cygheap_types x, DWORD n, const char *fn)
{
  cygheap_entry *c;
  MALLOC_CHECK;
  c = (cygheap_entry *) _cmalloc (sizeof_cygheap (n));
  return creturn (x, c, n, fn);
}

extern "C" void *
cmalloc (cygheap_types x, DWORD n)
{
  return cmalloc (x, n, NULL);
}

extern "C" void *
cmalloc_abort (cygheap_types x, DWORD n)
{
  return cmalloc (x, n, "cmalloc");
}

inline static void *
crealloc (void *s, DWORD n, const char *fn)
{
  MALLOC_CHECK;
  if (s == NULL)
    return cmalloc (HEAP_STR, n);	// kludge

  assert (!inheap (s));
  cygheap_entry *c = tocygheap (s);
  cygheap_types t = (cygheap_types) c->type;
  c = (cygheap_entry *) _crealloc (c, sizeof_cygheap (n));
  return creturn (t, c, n, fn);
}

extern "C" void *__stdcall
crealloc (void *s, DWORD n)
{
  return crealloc (s, n, NULL);
}

extern "C" void *__stdcall
crealloc_abort (void *s, DWORD n)
{
  return crealloc (s, n, "crealloc");
}

extern "C" void __stdcall
cfree (void *s)
{
  assert (!inheap (s));
  _cfree (tocygheap (s));
  MALLOC_CHECK;
}

extern "C" void __stdcall
cfree_and_set (char *&s, char *what)
{
  if (s && s != almost_null)
    cfree (s);
  s = what;
}

inline static void *
ccalloc (cygheap_types x, DWORD n, DWORD size, const char *fn)
{
  cygheap_entry *c;
  MALLOC_CHECK;
  n *= size;
  c = (cygheap_entry *) _cmalloc (sizeof_cygheap (n));
  if (c)
    memset (c->data, 0, n);
  return creturn (x, c, n, fn);
}

extern "C" void *__stdcall
ccalloc (cygheap_types x, DWORD n, DWORD size)
{
  return ccalloc (x, n, size, NULL);
}

extern "C" void *__stdcall
ccalloc_abort (cygheap_types x, DWORD n, DWORD size)
{
  return ccalloc (x, n, size, "ccalloc");
}

extern "C" PWCHAR __stdcall
cwcsdup (const PWCHAR s)
{
  MALLOC_CHECK;
  PWCHAR p = (PWCHAR) cmalloc (HEAP_STR, (wcslen (s) + 1) * sizeof (WCHAR));
  if (!p)
    return NULL;
  wcpcpy (p, s);
  MALLOC_CHECK;
  return p;
}

extern "C" PWCHAR __stdcall
cwcsdup1 (const PWCHAR s)
{
  MALLOC_CHECK;
  PWCHAR p = (PWCHAR) cmalloc (HEAP_1_STR, (wcslen (s) + 1) * sizeof (WCHAR));
  if (!p)
    return NULL;
  wcpcpy (p, s);
  MALLOC_CHECK;
  return p;
}

extern "C" char *__stdcall
cstrdup (const char *s)
{
  MALLOC_CHECK;
  char *p = (char *) cmalloc (HEAP_STR, strlen (s) + 1);
  if (!p)
    return NULL;
  strcpy (p, s);
  MALLOC_CHECK;
  return p;
}

extern "C" char *__stdcall
cstrdup1 (const char *s)
{
  MALLOC_CHECK;
  char *p = (char *) cmalloc (HEAP_1_STR, strlen (s) + 1);
  if (!p)
    return NULL;
  strcpy (p, s);
  MALLOC_CHECK;
  return p;
}

void
cygheap_root::set (const char *posix, const char *native, bool caseinsensitive)
{
  if (*posix == '/' && posix[1] == '\0')
    {
      if (m)
	{
	  cfree (m);
	  m = NULL;
	}
      return;
    }
  if (!m)
    m = (struct cygheap_root_mount_info *) ccalloc (HEAP_MOUNT, 1, sizeof (*m));
  strcpy (m->posix_path, posix);
  m->posix_pathlen = strlen (posix);
  if (m->posix_pathlen >= 1 && m->posix_path[m->posix_pathlen - 1] == '/')
    m->posix_path[--m->posix_pathlen] = '\0';

  strcpy (m->native_path, native);
  m->native_pathlen = strlen (native);
  if (m->native_pathlen >= 1 && m->native_path[m->native_pathlen - 1] == '\\')
    m->native_path[--m->native_pathlen] = '\0';
  m->caseinsensitive = caseinsensitive;
}

cygheap_user::~cygheap_user ()
{
}

void
cygheap_user::set_name (const char *new_name)
{
  bool allocated = !!pname;

  if (allocated)
    {
      if (strcasematch (new_name, pname))
	return;
      cfree (pname);
    }

  pname = cstrdup (new_name ? new_name : "");
  if (!allocated)
    return;		/* Initializing.  Don't bother with other stuff. */

  cfree_and_set (homedrive);
  cfree_and_set (homepath);
  cfree_and_set (plogsrv);
  cfree_and_set (pdomain);
  cfree_and_set (pwinname);
}
