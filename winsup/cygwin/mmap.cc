/* mmap.cc

   Copyright 1996, 1997, 1998, 2000, 2001, 2002, 2003 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/mman.h>
#include "security.h"
#include "fhandler.h"
#include "path.h"
#include "dtable.h"
#include "cygerrno.h"
#include "cygheap.h"
#include "pinfo.h"
#include "sys/cygwin.h"

#define PAGE_CNT(bytes) howmany((bytes),getpagesize())

#define PGBITS		(sizeof (DWORD)*8)
#define MAPSIZE(pages)	howmany ((pages), PGBITS)

#define MAP_SET(n)	(map_map_[(n)/PGBITS] |= (1L << ((n) % PGBITS)))
#define MAP_CLR(n)	(map_map_[(n)/PGBITS] &= ~(1L << ((n) % PGBITS)))
#define MAP_ISSET(n)	(map_map_[(n)/PGBITS] & (1L << ((n) % PGBITS)))

/*
 * Simple class used to keep a record of all current
 * mmap areas in a process. Needed so that
 * they can be duplicated after a fork().
 */

class mmap_record
{
  private:
    int fdesc_;
    HANDLE mapping_handle_;
    int devtype_;
    DWORD access_mode_;
    _off64_t offset_;
    DWORD size_to_map_;
    caddr_t base_address_;
    DWORD *map_map_;

  public:
    mmap_record (int fd, HANDLE h, DWORD ac, _off64_t o, DWORD s, caddr_t b) :
       fdesc_ (fd),
       mapping_handle_ (h),
       devtype_ (0),
       access_mode_ (ac),
       offset_ (o),
       size_to_map_ (s),
       base_address_ (b),
       map_map_ (NULL)
      {
	if (fd >= 0 && !cygheap->fdtab.not_open (fd))
	  devtype_ = cygheap->fdtab[fd]->get_device ();
      }

    /* Default Copy constructor/operator=/destructor are ok */

    /* Simple accessors */
    int get_fd () const { return fdesc_; }
    HANDLE get_handle () const { return mapping_handle_; }
    DWORD get_device () const { return devtype_; }
    DWORD get_access () const { return access_mode_; }
    DWORD get_offset () const { return offset_; }
    DWORD get_size () const { return size_to_map_; }
    caddr_t get_address () const { return base_address_; }
    DWORD *get_map () const { return map_map_; }
    void alloc_map (_off64_t off, DWORD len);
    void free_map () { if (map_map_) free (map_map_); }

    DWORD find_empty (DWORD pages);
    _off64_t map_map (_off64_t off, DWORD len);
    BOOL unmap_map (caddr_t addr, DWORD len);
    void fixup_map (void);
    int access (caddr_t address);

    fhandler_base *alloc_fh ();
    void free_fh (fhandler_base *fh);
};

DWORD
mmap_record::find_empty (DWORD pages)
{
  DWORD mapped_pages = PAGE_CNT (size_to_map_);
  DWORD start;

  if (pages > mapped_pages)
    return (DWORD)-1;
  for (start = 0; start <= mapped_pages - pages; ++start)
    if (!MAP_ISSET (start))
      {
	DWORD cnt;
	for (cnt = 0; cnt < pages; ++cnt)
	  if (MAP_ISSET (start + cnt))
	    break;
	if (cnt >= pages)
	  return start;
      }
  return (DWORD)-1;
}

void
mmap_record::alloc_map (_off64_t off, DWORD len)
{
  /* Allocate one bit per page */
  map_map_ = (DWORD *) calloc (MAPSIZE (PAGE_CNT (size_to_map_)),
			       sizeof (DWORD));
  if (wincap.virtual_protect_works_on_shared_pages ())
    {
      DWORD old_prot;

      off -= offset_;
      len = PAGE_CNT (len) * getpagesize ();
      if (off > 0 &&
	  !VirtualProtect (base_address_, off, PAGE_NOACCESS, &old_prot))
	syscall_printf ("VirtualProtect(%x,%D) failed: %E", base_address_, off);
      if (off + len < size_to_map_
	  && !VirtualProtect (base_address_ + off + len,
			      size_to_map_ - len - off,
			      PAGE_NOACCESS, &old_prot))
	syscall_printf ("VirtualProtect(%x,%D) failed: %E",
			base_address_ + off + len, size_to_map_ - len - off);
      off /= getpagesize ();
      len /= getpagesize ();
      while (len-- > 0)
	MAP_SET (off + len);
    }
}

_off64_t
mmap_record::map_map (_off64_t off, DWORD len)
{
  /* Used ONLY if this mapping matches into the chunk of another already
     performed mapping in a special case of MAP_ANON|MAP_PRIVATE.

     Otherwise it's job is now done by alloc_map(). */
  DWORD prot, old_prot;
  switch (access_mode_)
    {
    case FILE_MAP_WRITE:
      prot = PAGE_READWRITE;
      break;
    case FILE_MAP_READ:
      prot = PAGE_READONLY;
      break;
    default:
      prot = PAGE_WRITECOPY;
      break;
    }

  debug_printf ("map_map (fd=%d, off=%D, len=%u)", fdesc_, off, len);
  len = PAGE_CNT (len);

  if ((off = find_empty (len)) == (DWORD)-1)
    return 0L;
  if (wincap.virtual_protect_works_on_shared_pages ()
      && !VirtualProtect (base_address_ + off * getpagesize (),
			  len * getpagesize (), prot, &old_prot))
    {
      __seterrno ();
      return (_off64_t)-1;
    }

  while (len-- > 0)
    MAP_SET (off + len);
  return off * getpagesize ();
}

BOOL
mmap_record::unmap_map (caddr_t addr, DWORD len)
{
  DWORD old_prot;
  DWORD off = addr - base_address_;
  off /= getpagesize ();
  len = PAGE_CNT (len);
  if (wincap.virtual_protect_works_on_shared_pages ()
      && !VirtualProtect (base_address_ + off * getpagesize (),
			  len * getpagesize (), PAGE_NOACCESS, &old_prot))
    syscall_printf ("-1 = unmap_map (): %E");

  for (; len-- > 0; ++off)
    MAP_CLR (off);
  /* Return TRUE if all pages are free'd which may result in unmapping
     the whole chunk. */
  for (len = MAPSIZE (PAGE_CNT (size_to_map_)); len > 0; )
    if (map_map_[--len])
      return FALSE;
  return TRUE;
}

void
mmap_record::fixup_map ()
{
  if (!wincap.virtual_protect_works_on_shared_pages ())
    return;

  DWORD prot, old_prot;
  switch (access_mode_)
    {
    case FILE_MAP_WRITE:
      prot = PAGE_READWRITE;
      break;
    case FILE_MAP_READ:
      prot = PAGE_READONLY;
      break;
    default:
      prot = PAGE_WRITECOPY;
      break;
    }

  for (DWORD off = PAGE_CNT (size_to_map_); off > 0; --off)
    VirtualProtect (base_address_ + off * getpagesize (), getpagesize (),
		    MAP_ISSET (off - 1) ? prot : PAGE_NOACCESS, &old_prot);
}

int
mmap_record::access (caddr_t address)
{
  if (address < base_address_ || address >= base_address_ + size_to_map_)
    return 0;
  DWORD off = (address - base_address_) / getpagesize ();
  return MAP_ISSET (off);
}

static fhandler_disk_file fh_paging_file;

fhandler_base *
mmap_record::alloc_fh ()
{
  if (get_fd () == -1)
    {
      fh_paging_file.set_io_handle (INVALID_HANDLE_VALUE);
      return &fh_paging_file;
    }

  /* The file descriptor could have been closed or, even
     worse, could have been reused for another file before
     the call to fork(). This requires creating a fhandler
     of the correct type to be sure to call the method of the
     correct class. */
  return cygheap->fdtab.build_fhandler (-1, get_device ());
}

void
mmap_record::free_fh (fhandler_base *fh)
{
  if (get_fd () != -1)
    cfree (fh);
}

class list {
public:
  mmap_record *recs;
  int nrecs, maxrecs;
  int fd;
  DWORD hash;
  list ();
  ~list ();
  mmap_record *add_record (mmap_record r, _off64_t off, DWORD len);
  void erase (int i);
  void erase ();
  mmap_record *match (_off64_t off, DWORD len);
  long match (caddr_t addr, DWORD len, caddr_t &m_addr, DWORD &m_len,
	      long start);
};

list::list ()
: nrecs (0), maxrecs (10), fd (0), hash (0)
{
  recs = (mmap_record *) malloc (10 * sizeof (mmap_record));
}

list::~list ()
{
  for (mmap_record *rec = recs; nrecs-- > 0; ++rec)
    rec->free_map ();
  free (recs);
}

mmap_record *
list::add_record (mmap_record r, _off64_t off, DWORD len)
{
  if (nrecs == maxrecs)
    {
      maxrecs += 5;
      recs = (mmap_record *) realloc (recs, maxrecs * sizeof (mmap_record));
    }
  recs[nrecs] = r;
  recs[nrecs].alloc_map (off, len);
  return recs + nrecs++;
}

/* Used in mmap() */
mmap_record *
list::match (_off64_t off, DWORD len)
{
  if (fd == -1 && !off)
    {
      len = PAGE_CNT (len);
      for (int i = 0; i < nrecs; ++i)
	if (recs[i].find_empty (len) != (DWORD)-1)
	  return recs + i;
    }
  else
    {
      for (int i = 0; i < nrecs; ++i)
	if (off >= recs[i].get_offset ()
	    && off + len <= recs[i].get_offset ()
			 + (PAGE_CNT (recs[i].get_size ()) * getpagesize ()))
	  return recs + i;
    }
  return NULL;
}

/* Used in munmap() */
long
list::match (caddr_t addr, DWORD len, caddr_t &m_addr, DWORD &m_len,
	     _off_t start)
{
  caddr_t low, high;

  for (int i = start + 1; i < nrecs; ++i)
    {
      low = (addr >= recs[i].get_address ()) ? addr : recs[i].get_address ();
      high = recs[i].get_address ()
	     + (PAGE_CNT (recs[i].get_size ()) * getpagesize ());
      high = (addr + len < high) ? addr + len : high;
      if (low < high)
	{
	  m_addr = low;
	  m_len = high - low;
	  return i;
	}
    }
  return -1;
}

void
list::erase (int i)
{
  recs[i].free_map ();
  for (; i < nrecs-1; i++)
    recs[i] = recs[i+1];
  nrecs--;
}

void
list::erase ()
{
  erase (nrecs-1);
}

class map {
public:
  list **lists;
  int nlists, maxlists;
  map ();
  ~map ();
  list *get_list_by_fd (int fd);
  list *add_list (list *l, int fd);
  void erase (int i);
};

map::map ()
{
  lists = (list **) malloc (10 * sizeof (list *));
  nlists = 0;
  maxlists = 10;
}

map::~map ()
{
  free (lists);
}

list *
map::get_list_by_fd (int fd)
{
  int i;
  for (i=0; i<nlists; i++)
#if 0 /* The fd isn't sufficient since it could already be another file. */
    if (lists[i]->fd == fd
#else /* so we use the name hash value to identify the file unless
	 it's not an anonymous mapping. */
    if ((fd == -1 && lists[i]->fd == -1)
	|| (fd != -1 && lists[i]->hash == cygheap->fdtab[fd]->get_namehash ()))
#endif
      return lists[i];
  return 0;
}

list *
map::add_list (list *l, int fd)
{
  l->fd = fd;
  if (fd != -1)
    l->hash = cygheap->fdtab[fd]->get_namehash ();
  if (nlists == maxlists)
    {
      maxlists += 5;
      lists = (list **) realloc (lists, maxlists * sizeof (list *));
    }
  lists[nlists++] = l;
  return lists[nlists-1];
}

void
map::erase (int i)
{
  for (; i < nlists-1; i++)
    lists[i] = lists[i+1];
  nlists--;
}

/*
 * Code to keep a record of all mmap'ed areas in a process.
 * Needed to duplicate tham in a child of fork().
 * mmap_record classes are kept in an STL list in an STL map, keyed
 * by file descriptor. This is *NOT* duplicated across a fork(), it
 * needs to be specially handled by the fork code.
 */

static map *mmapped_areas;

extern "C" caddr_t
mmap64 (caddr_t addr, size_t len, int prot, int flags, int fd, _off64_t off)
{
  syscall_printf ("addr %x, len %u, prot %x, flags %x, fd %d, off %D",
		  addr, len, prot, flags, fd, off);

  static DWORD granularity;
  if (!granularity)
    {
      SYSTEM_INFO si;
      GetSystemInfo (&si);
      granularity = si.dwAllocationGranularity;
    }

  /* Error conditions according to SUSv2 */
  if (off % getpagesize ()
      || (!(flags & MAP_SHARED) && !(flags & MAP_PRIVATE))
      || ((flags & MAP_SHARED) && (flags & MAP_PRIVATE))
      || ((flags & MAP_FIXED) && ((DWORD)addr % getpagesize ()))
      || !len)
    {
      set_errno (EINVAL);
      syscall_printf ("-1 = mmap(): EINVAL");
      return MAP_FAILED;
    }

  SetResourceLock (LOCK_MMAP_LIST, READ_LOCK | WRITE_LOCK, "mmap");

  if (mmapped_areas == NULL)
    {
      /* First mmap call, create STL map */
      mmapped_areas = new map;
      if (mmapped_areas == NULL)
	{
	  set_errno (ENOMEM);
	  syscall_printf ("-1 = mmap(): ENOMEM");
	  ReleaseResourceLock (LOCK_MMAP_LIST, READ_LOCK | WRITE_LOCK, "mmap");
	  return MAP_FAILED;
	}
    }

  if (flags & MAP_ANONYMOUS)
    fd = -1;

  /* Map always in multipliers of `granularity'-sized chunks. */
  _off64_t gran_off = off & ~(granularity - 1);
  DWORD gran_len = howmany (off + len, granularity) * granularity - gran_off;

  fhandler_base *fh;

  if (fd != -1)
    {
      /* Ensure that fd is open */
      cygheap_fdget cfd (fd);
      if (cfd < 0)
	{
	  syscall_printf ("-1 = mmap(): EBADF");
	  ReleaseResourceLock (LOCK_MMAP_LIST, READ_LOCK | WRITE_LOCK, "mmap");
	  return MAP_FAILED;
	}
      fh = cfd;
      if (fh->get_device () == FH_DISK)
	{
	  DWORD high;
	  DWORD low = GetFileSize (fh->get_handle (), &high);
	  _off64_t fsiz = ((_off64_t)high << 32) + low;
	  /* Don't allow mappings beginning beyond EOF since Windows can't
	     handle that POSIX like.  FIXME: Still looking for a good idea
	     to allow that nevertheless. */
	  if (gran_off >= fsiz)
	    {
	      set_errno (ENXIO);
	      ReleaseResourceLock (LOCK_MMAP_LIST, READ_LOCK | WRITE_LOCK,
				   "mmap");
	      return MAP_FAILED;
	    }
	  fsiz -= gran_off;
	  if (gran_len > fsiz)
	    gran_len = fsiz;
	}
      else if (fh->get_device () == FH_ZERO)
	/* mmap /dev/zero is like MAP_ANONYMOUS. */
	fd = -1;
    }
  if (fd == -1)
    {
      fh_paging_file.set_io_handle (INVALID_HANDLE_VALUE);
      fh = &fh_paging_file;
    }

  list *map_list = mmapped_areas->get_list_by_fd (fd);

  /* First check if this mapping matches into the chunk of another
     already performed mapping. Only valid for MAP_ANON in a special
     case of MAP_PRIVATE. */
  if (map_list && fd == -1 && off == 0 && !(flags & MAP_FIXED))
    {
      mmap_record *rec;
      if ((rec = map_list->match (off, len)) != NULL)
	{
	  if ((off = rec->map_map (off, len)) == (_off64_t)-1)
	    {
	      syscall_printf ("-1 = mmap()");
	      ReleaseResourceLock (LOCK_MMAP_LIST, READ_LOCK|WRITE_LOCK, "mmap");
	      return MAP_FAILED;
	    }
	  caddr_t ret = rec->get_address () + off;
	  syscall_printf ("%x = mmap() succeeded", ret);
	  ReleaseResourceLock (LOCK_MMAP_LIST, READ_LOCK | WRITE_LOCK, "mmap");
	  return ret;
	}
    }

  DWORD access = (prot & PROT_WRITE) ? FILE_MAP_WRITE : FILE_MAP_READ;
  /* copy-on-write doesn't work at all on 9x using anonymous maps.
     Workaround: Anonymous mappings always use normal READ or WRITE
		 access and don't use named file mapping.
     copy-on-write doesn't also work properly on 9x with real files.
     While the changes are not propagated to the file, they are
     visible to other processes sharing the same file mapping object.
     Workaround: Don't use named file mapping.  That should work since
		 sharing file mappings only works reliable using named
		 file mapping on 9x.
  */
  if ((flags & MAP_PRIVATE)
      && (wincap.has_working_copy_on_write () || fd != -1))
    access = FILE_MAP_COPY;

  caddr_t base = addr;
  /* This shifts the base address to the next lower 64K boundary.
     The offset is re-added when evaluating the return value. */
  if (base)
    base -= off - gran_off;

  HANDLE h = fh->mmap (&base, gran_len, access, flags, gran_off);

  if (h == INVALID_HANDLE_VALUE)
    {
      ReleaseResourceLock (LOCK_MMAP_LIST, READ_LOCK | WRITE_LOCK, "mmap");
      return MAP_FAILED;
    }

  /* Now we should have a successfully mmapped area.
     Need to save it so forked children can reproduce it.
  */
  if (fd == -1)
    gran_len = PAGE_CNT (gran_len) * getpagesize ();
  mmap_record mmap_rec (fd, h, access, gran_off, gran_len, base);

  /* Get list of mmapped areas for this fd, create a new one if
     one does not exist yet.
  */
  if (!map_list)
    {
      /* Create a new one */
      map_list = new list;
      if (!map_list)
	{
	  fh->munmap (h, base, gran_len);
	  set_errno (ENOMEM);
	  syscall_printf ("-1 = mmap(): ENOMEM");
	  ReleaseResourceLock (LOCK_MMAP_LIST, READ_LOCK | WRITE_LOCK, "mmap");
	  return MAP_FAILED;
	}
      map_list = mmapped_areas->add_list (map_list, fd);
  }

  /* Insert into the list */
  mmap_record *rec = map_list->add_record (mmap_rec, off, len > gran_len ? gran_len : len);
  caddr_t ret = rec->get_address () + (off - gran_off);
  syscall_printf ("%x = mmap() succeeded", ret);
  ReleaseResourceLock (LOCK_MMAP_LIST, READ_LOCK | WRITE_LOCK, "mmap");
  return ret;
}

extern "C" caddr_t
mmap (caddr_t addr, size_t len, int prot, int flags, int fd, _off_t off)
{
  return mmap64 (addr, len, prot, flags, fd, (_off64_t)off);
}

/* munmap () removes all mmapped pages between addr and addr+len. */

extern "C" int
munmap (caddr_t addr, size_t len)
{
  syscall_printf ("munmap (addr %x, len %u)", addr, len);

  /* Error conditions according to SUSv3 */
  if (!addr || ((DWORD)addr % getpagesize ()) || !len
      || IsBadReadPtr (addr, len))
    {
      set_errno (EINVAL);
      syscall_printf ("-1 = munmap(): Invalid parameters");
      return -1;
    }

  SetResourceLock (LOCK_MMAP_LIST, WRITE_LOCK | READ_LOCK, "munmap");
  if (mmapped_areas == NULL)
    {
      syscall_printf ("-1 = munmap(): mmapped_areas == NULL");
      ReleaseResourceLock (LOCK_MMAP_LIST, WRITE_LOCK | READ_LOCK, "munmap");
      return 0;
    }

  /* Iterate through the map, unmap pages between addr and addr+len
     in all maps. */

  for (int it = 0; it < mmapped_areas->nlists; ++it)
    {
      list *map_list = mmapped_areas->lists[it];
      if (map_list)
	{
	  long li = -1;
	  caddr_t u_addr;
	  DWORD u_len;

	  while ((li = map_list->match(addr, len, u_addr, u_len, li)) >= 0)
	    {
	      mmap_record *rec = map_list->recs + li;
	      if (rec->unmap_map (u_addr, u_len))
		{
		  fhandler_base *fh = rec->alloc_fh ();
		  fh->munmap (rec->get_handle (), addr, len);
		  rec->free_fh (fh);

		  /* Delete the entry. */
		  map_list->erase (li);
		}
	    }
	}
    }

  ReleaseResourceLock (LOCK_MMAP_LIST, WRITE_LOCK | READ_LOCK, "munmap");
  syscall_printf ("0 = munmap(): %x", addr);
  return 0;
}

/* Sync file with memory. Ignore flags for now. */

extern "C" int
msync (caddr_t addr, size_t len, int flags)
{
  syscall_printf ("addr = %x, len = %u, flags = %x",
		  addr, len, flags);

  /* However, check flags for validity. */
  if ((flags & ~(MS_ASYNC | MS_SYNC | MS_INVALIDATE))
      || ((flags & MS_ASYNC) && (flags & MS_SYNC)))
    {
      syscall_printf ("-1 = msync(): Invalid flags");
      set_errno (EINVAL);
      return -1;
    }

  SetResourceLock (LOCK_MMAP_LIST, WRITE_LOCK | READ_LOCK, "msync");
  /* Check if a mmap'ed area was ever created */
  if (mmapped_areas == NULL)
    {
      syscall_printf ("-1 = msync(): mmapped_areas == NULL");
      set_errno (EINVAL);
      ReleaseResourceLock (LOCK_MMAP_LIST, WRITE_LOCK | READ_LOCK, "msync");
      return -1;
    }

  /* Iterate through the map, looking for the mmapped area.
     Error if not found. */

  for (int it = 0; it < mmapped_areas->nlists; ++it)
    {
      list *map_list = mmapped_areas->lists[it];
      if (map_list != 0)
	{
	  for (int li = 0; li < map_list->nrecs; ++li)
	    {
	      mmap_record *rec = map_list->recs + li;
	      if (rec->access (addr))
		{
		  /* Check whole area given by len. */
		  for (DWORD i = getpagesize (); i < len; ++i)
		    if (!rec->access (addr + i))
		      goto invalid_address_range;
		  fhandler_base *fh = rec->alloc_fh ();
		  int ret = fh->msync (rec->get_handle (), addr, len, flags);
		  rec->free_fh (fh);

		  if (ret)
		    syscall_printf ("%d = msync(): %E", ret);
		  else
		    syscall_printf ("0 = msync()");

		  ReleaseResourceLock (LOCK_MMAP_LIST, WRITE_LOCK | READ_LOCK,
				       "msync");
		  return 0;
		}
	    }
	}
    }

invalid_address_range:
  /* SUSv2: Return code if indicated memory was not mapped is ENOMEM. */
  set_errno (ENOMEM);
  syscall_printf ("-1 = msync(): ENOMEM");

  ReleaseResourceLock (LOCK_MMAP_LIST, WRITE_LOCK | READ_LOCK, "msync");
  return -1;
}

/*
 * Base implementation:
 *
 * `mmap' returns ENODEV as documented in SUSv2.
 * In contrast to the global function implementation, the member function
 * `mmap' has to return the mapped base address in `addr' and the handle to
 * the mapping object as return value. In case of failure, the fhandler
 * mmap has to close that handle by itself and return INVALID_HANDLE_VALUE.
 *
 * `munmap' and `msync' get the handle to the mapping object as first parameter
 * additionally.
*/
HANDLE
fhandler_base::mmap (caddr_t *addr, size_t len, DWORD access,
		     int flags, _off64_t off)
{
  set_errno (ENODEV);
  return INVALID_HANDLE_VALUE;
}

int
fhandler_base::munmap (HANDLE h, caddr_t addr, size_t len)
{
  set_errno (ENODEV);
  return -1;
}

int
fhandler_base::msync (HANDLE h, caddr_t addr, size_t len, int flags)
{
  set_errno (ENODEV);
  return -1;
}

BOOL
fhandler_base::fixup_mmap_after_fork (HANDLE h, DWORD access, DWORD offset,
				      DWORD size, void *address)
{
  set_errno (ENODEV);
  return -1;
}

/* Implementation for disk files. */
HANDLE
fhandler_disk_file::mmap (caddr_t *addr, size_t len, DWORD access,
			  int flags, _off64_t off)
{
  DWORD protect;

  switch (access)
    {
      case FILE_MAP_WRITE:
	protect = PAGE_READWRITE;
	break;
      case FILE_MAP_READ:
	protect = PAGE_READONLY;
	break;
      default:
	protect = PAGE_WRITECOPY;
	break;
    }

  HANDLE h;

  /* On 9x/ME try first to open the mapping by name when opening a
     shared file object. This is needed since 9x/ME only shares
     objects between processes by name. What a mess... */
  if (wincap.share_mmaps_only_by_name ()
      && get_handle () != INVALID_HANDLE_VALUE
      && !(access & FILE_MAP_COPY))
    {
      /* Grrr, the whole stuff is just needed to try to get a reliable
	 mapping of the same file. Even that uprising isn't bullet
	 proof but it does it's best... */
      char namebuf[MAX_PATH];
      cygwin_conv_to_full_posix_path (get_name (), namebuf);
      for (int i = strlen (namebuf) - 1; i >= 0; --i)
	namebuf[i] = cyg_tolower (namebuf [i]);

      debug_printf ("named sharing");
      if (!(h = OpenFileMapping (access, TRUE, namebuf)))
	h = CreateFileMapping (get_handle (), &sec_none, protect, 0, 0, namebuf);
    }
  else
    h = CreateFileMapping (get_handle (), &sec_none, protect, 0,
			   get_handle () == INVALID_HANDLE_VALUE ? len : 0,
			   NULL);
  if (!h)
    {
      __seterrno ();
      syscall_printf ("-1 = mmap(): CreateFileMapping failed with %E");
      return INVALID_HANDLE_VALUE;
    }

  DWORD high = off >> 32, low = off & 0xffffffff;
  void *base = NULL;
  /* If a non-zero address is given, try mapping using the given address first.
     If it fails and flags is not MAP_FIXED, try again with NULL address. */
  if (*addr)
    base = MapViewOfFileEx (h, access, high, low, len, *addr);
  if (!base && !(flags & MAP_FIXED))
    base = MapViewOfFileEx (h, access, high, low, len, NULL);
  debug_printf ("%x = MapViewOfFileEx (h:%x, access:%x, 0, off:%D, "
		"len:%u, addr:%x)", base, h, access, off, len, *addr);
  if (!base || ((flags & MAP_FIXED) && base != *addr))
    {
      if (!base)
	{
	  __seterrno ();
	  syscall_printf ("-1 = mmap(): MapViewOfFileEx failed with %E");
	}
      else
	{
	  set_errno (EINVAL);
	  syscall_printf ("-1 = mmap(): address shift with MAP_FIXED given");
	}
      CloseHandle (h);
      return INVALID_HANDLE_VALUE;
    }

  *addr = (caddr_t) base;
  return h;
}

int
fhandler_disk_file::munmap (HANDLE h, caddr_t addr, size_t len)
{
  UnmapViewOfFile (addr);
  CloseHandle (h);
  return 0;
}

int
fhandler_disk_file::msync (HANDLE h, caddr_t addr, size_t len, int flags)
{
  if (FlushViewOfFile (addr, len) == 0)
    {
      __seterrno ();
      return -1;
    }
  return 0;
}

BOOL
fhandler_disk_file::fixup_mmap_after_fork (HANDLE h, DWORD access, DWORD offset,
					   DWORD size, void *address)
{
  /* Re-create the MapViewOfFileEx call */
  void *base = MapViewOfFileEx (h, access, 0, offset, size, address);
  if (base != address)
    {
      MEMORY_BASIC_INFORMATION m;
      (void) VirtualQuery (address, &m, sizeof (m));
      system_printf ("requested %p != %p mem alloc base %p, state %p, size %d, %E",
		     address, base, m.AllocationBase, m.State, m.RegionSize);
    }
  return base == address;
}

/* Set memory protection */

extern "C" int
mprotect (caddr_t addr, size_t len, int prot)
{
  DWORD old_prot;
  DWORD new_prot = 0;

  syscall_printf ("mprotect (addr %x, len %u, prot %x)", addr, len, prot);

  if (!wincap.virtual_protect_works_on_shared_pages ()
      && addr >= (caddr_t)0x80000000 && addr <= (caddr_t)0xBFFFFFFF)
    {
      syscall_printf ("0 = mprotect (9x: No VirtualProtect on shared memory)");
      return 0;
    }

  switch (prot)
    {
      case PROT_READ | PROT_WRITE | PROT_EXEC:
      case PROT_WRITE | PROT_EXEC:
	new_prot = PAGE_EXECUTE_READWRITE;
	break;
      case PROT_READ | PROT_WRITE:
      case PROT_WRITE:
	new_prot = PAGE_READWRITE;
	break;
      case PROT_READ | PROT_EXEC:
	new_prot = PAGE_EXECUTE_READ;
	break;
      case PROT_READ:
	new_prot = PAGE_READONLY;
	break;
      case PROT_EXEC:
	new_prot = PAGE_EXECUTE;
	break;
      case PROT_NONE:
	new_prot = PAGE_NOACCESS;
	break;
      default:
	syscall_printf ("-1 = mprotect (): invalid prot value");
	set_errno (EINVAL);
	return -1;
     }

  if (VirtualProtect (addr, len, new_prot, &old_prot) == 0)
    {
      __seterrno ();
      syscall_printf ("-1 = mprotect (): %E");
      return -1;
    }

  syscall_printf ("0 = mprotect ()");
  return 0;
}

/*
 * Call to re-create all the file mappings in a forked
 * child. Called from the child in initialization. At this
 * point we are passed a valid mmapped_areas map, and all the
 * HANDLE's are valid for the child, but none of the
 * mapped areas are in our address space. We need to iterate
 * through the map, doing the MapViewOfFile calls.
 */

int __stdcall
fixup_mmaps_after_fork (HANDLE parent)
{

  debug_printf ("recreate_mmaps_after_fork, mmapped_areas %p", mmapped_areas);

  /* Check if a mmapped area was ever created */
  if (mmapped_areas == NULL)
    return 0;

  /* Iterate through the map */
  for (int it = 0; it < mmapped_areas->nlists; ++it)
    {
      list *map_list = mmapped_areas->lists[it];
      if (map_list)
	{
	  int li;
	  for (li = 0; li < map_list->nrecs; ++li)
	    {
	      mmap_record *rec = map_list->recs + li;

	      debug_printf ("fd %d, h %x, access %x, offset %D, size %u, address %p",
		  rec->get_fd (), rec->get_handle (), rec->get_access (),
		  rec->get_offset (), rec->get_size (), rec->get_address ());

	      fhandler_base *fh = rec->alloc_fh ();
	      BOOL ret = fh->fixup_mmap_after_fork (rec->get_handle (),
						    rec->get_access (),
						    rec->get_offset (),
						    rec->get_size (),
						    rec->get_address ());
	      rec->free_fh (fh);

	      if (!ret)
		return -1;
	      if (rec->get_access () == FILE_MAP_COPY)
		{
		  for (char *address = rec->get_address ();
		       address < rec->get_address () + rec->get_size ();
		       address += getpagesize ())
		    if (rec->access (address)
			&& !ReadProcessMemory (parent, address, address,
					       getpagesize (), NULL))
		      {
			DWORD old_prot;
			DWORD last_error = GetLastError ();

			if (last_error != ERROR_PARTIAL_COPY
			    && last_error != ERROR_NOACCESS
			    || !wincap.virtual_protect_works_on_shared_pages ())
			  {
			    system_printf ("ReadProcessMemory failed for "
					   "MAP_PRIVATE address %p, %E",
					   rec->get_address ());
			    return -1;
			  }
			if (!VirtualProtectEx (parent,
					       address, getpagesize (),
					       PAGE_READONLY, &old_prot))
			  {
			    system_printf ("VirtualProtectEx failed for "
					   "MAP_PRIVATE address %p, %E",
					   rec->get_address ());
			    return -1;
			  }
			else
			  {
			    BOOL ret;
			    DWORD dummy_prot;

			    ret = ReadProcessMemory (parent, address, address,
						     getpagesize (), NULL);
			    if (!VirtualProtectEx(parent,
						  address, getpagesize (),
						  old_prot, &dummy_prot))
			      system_printf ("WARNING: VirtualProtectEx to "
					     "return to previous state "
					     "in parent failed for "
					     "MAP_PRIVATE address %p, %E",
					     rec->get_address ());
			    if (!VirtualProtect (address, getpagesize (),
						 old_prot, &dummy_prot))
			      system_printf ("WARNING: VirtualProtect to copy "
					     "protection to child failed for"
					     "MAP_PRIVATE address %p, %E",
					     rec->get_address ());
			    if (!ret)
			      {
				system_printf ("ReadProcessMemory (2nd try) "
					       "failed for "
					       "MAP_PRIVATE address %p, %E",
					       rec->get_address ());
				return -1;
			      }
			  }
		      }
		}
	      rec->fixup_map ();
	    }
	}
    }

  debug_printf ("succeeded");
  return 0;
}
