/* cygheap.h: Cygwin heap manager.

   Copyright 2000 Cygnus Solutions.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#undef cfree

enum cygheap_types
{
  HEAP_FHANDLER,
  HEAP_STR,
  HEAP_ARGV,
  HEAP_BUF,
  HEAP_1_START,
  HEAP_1_STR,
  HEAP_1_ARGV,
  HEAP_1_BUF,
  HEAP_1_EXEC,
  HEAP_1_MAX = 100
};

#define CYGHEAPSIZE ((4000 * sizeof (fhandler_union)) + (2 * 65536))

#define incygheap(s) (cygheap && ((char *) (s) >= (char *) cygheap) && ((char *) (s) <= ((char *) cygheap_max)))

struct _cmalloc_entry
{
  union
  {
    DWORD b;
    char *ptr;
  };
  struct _cmalloc_entry *prev;
  char data[0];
};


struct init_cygheap
{
  _cmalloc_entry *chain;
  struct
  {
    size_t rootlen;
    char *root;
  };
  mode_t umask;
};

extern init_cygheap *cygheap;
extern void *cygheap_max;

extern "C" {
void __stdcall cfree (void *) __attribute__ ((regparm(1)));
void __stdcall cygheap_fixup_in_child (HANDLE, bool);
void *__stdcall cmalloc (cygheap_types, DWORD) __attribute__ ((regparm(2)));
void *__stdcall crealloc (void *, DWORD) __attribute__ ((regparm(2)));
void *__stdcall ccalloc (cygheap_types, DWORD, DWORD) __attribute__ ((regparm(3)));
char *__stdcall cstrdup (const char *) __attribute__ ((regparm(1)));
char *__stdcall cstrdup1 (const char *) __attribute__ ((regparm(1)));
void __stdcall cygheap_init ();
}
