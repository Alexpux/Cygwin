/* fhandler_mem.cc.  See fhandler.h for a description of the fhandler classes.

   Copyright 1999, 2000 Cygnus Solutions.

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

#include "winsup.h"
#include <sys/termios.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <ntdef.h>

#include "autoload.h"
#include "cygheap.h"
#include "cygerrno.h"
#include "fhandler.h"
#include "path.h"

extern "C" {
NTSTATUS NTAPI NtMapViewOfSection(HANDLE,HANDLE,PVOID*,ULONG,ULONG,
                                      PLARGE_INTEGER,PULONG,SECTION_INHERIT,
                                      ULONG,ULONG);
NTSTATUS NTAPI NtOpenSection(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE,PVOID);
VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING,PCWSTR);
ULONG NTAPI RtlNtStatusToDosError(NTSTATUS);
}

/**********************************************************************/
/* fhandler_dev_mem */

fhandler_dev_mem::fhandler_dev_mem (const char *name, int nunit)
: fhandler_base (FH_MEM, name),
  unit (nunit),
  init_phase (false)
{
}

fhandler_dev_mem::~fhandler_dev_mem (void)
{
}

void
fhandler_dev_mem::init ()
{
  if (unit == 1) /* /dev/mem */
    {
      long page_size = getpagesize ();
      char buf[1];

      init_phase = true;
      mem_size = pos = 1 << 30;
      for (off_t afct = 1 << 29; afct >= page_size; afct >>= 1)
        {
          if (read (buf, 1) > 0)
            pos += afct;
          else
            {
              if (pos < mem_size)
                mem_size = pos;
              pos -= afct;
            }
        }
      pos = 0;
      debug_printf ("MemSize: %d MB", mem_size >>= 20);
    }
  else if (unit == 2) /* /dev/kmem - Not yet supported */
    {
      mem_size = 0;
      debug_printf ("KMemSize: %d MB", mem_size >>= 20);
    }
  else if (unit == 4) /* /dev/port == First 64K of /dev/mem */
    {
      mem_size = 65536;
      debug_printf ("PortSize: 64 KB");
    }
  else
    {
      debug_printf ("Illegal unit!!!");
    }
  init_phase = false;
}

int
fhandler_dev_mem::open (const char *, int flags, mode_t)
{
  if (os_being_run != winNT)
    {
      set_errno (ENOENT);
      debug_printf ("%s is accessible under NT/W2K only",
                    unit == 1 ? "/dev/mem" :
                    unit == 2 ? "/dev/kmem" :
                                "/dev/port" );
      return 0;
    }

  /* Check for illegal flags. */
  if (flags & (O_APPEND | O_TRUNC | O_EXCL))
    {
      set_errno (EINVAL);
      return 0;
    }

  UNICODE_STRING memstr;
  RtlInitUnicodeString (&memstr, L"\\device\\physicalmemory");

  OBJECT_ATTRIBUTES attr;
  InitializeObjectAttributes(&attr, &memstr, OBJ_CASE_INSENSITIVE, NULL, NULL);

  ACCESS_MASK section_access;
  if ((flags & (O_RDONLY | O_WRONLY | O_RDWR)) == O_RDONLY)
    {
      set_access (GENERIC_READ);
      section_access = SECTION_MAP_READ;
    }
  else if ((flags & (O_RDONLY | O_WRONLY | O_RDWR)) == O_WRONLY)
    {
      set_access (GENERIC_WRITE);
      section_access = SECTION_MAP_READ | SECTION_MAP_WRITE;
    }
  else
    {
      set_access (GENERIC_READ | GENERIC_WRITE);
      section_access = SECTION_MAP_READ | SECTION_MAP_WRITE;
    }

  HANDLE mem;
  NTSTATUS ret = NtOpenSection (&mem, section_access, &attr);
  if (!NT_SUCCESS(ret))
    {
      __seterrno_from_win_error (RtlNtStatusToDosError (ret));
      set_io_handle (NULL);
      return 0;
    }

  set_io_handle (mem);
  init ();
  return 1;
}

int
fhandler_dev_mem::write (const void *ptr, size_t ulen)
{
  if (!ulen || pos >= mem_size)
    return 0;

  if (!(get_access () & GENERIC_WRITE))
    {
      set_errno (EINVAL);
      return -1;
    }

  if (pos + ulen > mem_size)
    ulen = mem_size - pos;

  PHYSICAL_ADDRESS phys;
  NTSTATUS ret;
  void *viewmem = NULL;
  DWORD len = ulen + getpagesize () - 1;

  phys.QuadPart = (ULONGLONG) pos;
  if ((ret = NtMapViewOfSection (get_handle (),
                                 INVALID_HANDLE_VALUE,
                                 &viewmem,
                                 0L,
                                 len,
                                 &phys,
                                 &len,
                                 ViewShare,
                                 0,
                                 PAGE_READONLY)) != STATUS_SUCCESS)
    {
      __seterrno_from_win_error (RtlNtStatusToDosError (ret));
      return -1;
    }

  memcpy ((char *) viewmem + (pos - phys.QuadPart), ptr, ulen);

  if (!NT_SUCCESS(ret = NtUnmapViewOfSection (INVALID_HANDLE_VALUE, viewmem)))
    {
      __seterrno_from_win_error (RtlNtStatusToDosError (ret));
      return -1;
    }

  pos += ulen;
  return ulen;
}

int
fhandler_dev_mem::read (void *ptr, size_t ulen)
{
  if (!ulen || pos >= mem_size)
    return 0;

  if (!(get_access () & GENERIC_READ))
    {
      set_errno (EINVAL);
      return -1;
    }

  if (pos + ulen > mem_size)
    ulen = mem_size - pos;

  PHYSICAL_ADDRESS phys;
  NTSTATUS ret;
  void *viewmem = NULL;
  DWORD len = ulen + getpagesize () - 1;

  phys.QuadPart = (ULONGLONG) pos;
  if ((ret = NtMapViewOfSection (get_handle (),
                                 INVALID_HANDLE_VALUE,
                                 &viewmem,
                                 0L,
                                 len,
                                 &phys,
                                 &len,
                                 ViewShare,
                                 0,
                                 PAGE_READONLY)) != STATUS_SUCCESS)
    {
      if (!init_phase) /* Don't want to flood debug output with init crap. */
        __seterrno_from_win_error (RtlNtStatusToDosError (ret));
      return -1;
    }

  memcpy (ptr, (char *) viewmem + (pos - phys.QuadPart), ulen);

  if (!NT_SUCCESS(ret = NtUnmapViewOfSection (INVALID_HANDLE_VALUE, viewmem)))
    {
      __seterrno_from_win_error (RtlNtStatusToDosError (ret));
      return -1;
    }

  pos += ulen;
  return ulen;
}

int
fhandler_dev_mem::close (void)
{
  return fhandler_base::close ();
}

off_t
fhandler_dev_mem::lseek (off_t offset, int whence)
{
  switch (whence)
    {
    case SEEK_SET:
      pos = offset;
      break;
    
    case SEEK_CUR:
      pos += offset;
      break;

    case SEEK_END:
      pos = mem_size;
      pos += offset;
      break;
    
    default:
      set_errno (EINVAL);
      return (off_t) -1;
    }

  if (pos > mem_size)
    {
      set_errno (EINVAL);
      return (off_t) -1;
    }

  return pos;
}

HANDLE
fhandler_dev_mem::mmap (caddr_t *addr, size_t len, DWORD access,
			int flags, off_t off)
{
  if ((DWORD) off >= mem_size
      || (DWORD) len >= mem_size
      || (DWORD) off + len >= mem_size)
    {
      set_errno (EINVAL);
      syscall_printf ("-1 = mmap(): illegal parameter, set EINVAL");
      return INVALID_HANDLE_VALUE;
    }

  UNICODE_STRING memstr;
  RtlInitUnicodeString (&memstr, L"\\device\\physicalmemory");

  OBJECT_ATTRIBUTES attr;
  InitializeObjectAttributes(&attr, &memstr, OBJ_CASE_INSENSITIVE, NULL, NULL);

  ACCESS_MASK section_access;
  ULONG protect;

  if (access & FILE_MAP_COPY)
    {
      section_access = SECTION_MAP_READ | SECTION_MAP_WRITE;
      protect = PAGE_WRITECOPY;
    }
  else if (access & FILE_MAP_WRITE)
    {
      section_access = SECTION_MAP_READ | SECTION_MAP_WRITE;
      protect = PAGE_READWRITE;
    }
  else
    {
      section_access = SECTION_MAP_READ;
      protect = PAGE_READONLY;
    }

  HANDLE h;
  NTSTATUS ret = NtOpenSection (&h, section_access, &attr);
  if (!NT_SUCCESS(ret))
    {
      __seterrno_from_win_error (RtlNtStatusToDosError (ret));
      syscall_printf ("-1 = mmap(): NtOpenSection failed with %E");
      return INVALID_HANDLE_VALUE;
    }

  PHYSICAL_ADDRESS phys;
  void *base = *addr;
  DWORD dlen = len;

  phys.QuadPart = (ULONGLONG) off;

  if ((ret = NtMapViewOfSection (h,
  				 INVALID_HANDLE_VALUE,
				 &base,
				 0L,
				 dlen,
				 &phys,
				 &dlen,
				 ViewShare /*??*/,
				 0,
				 protect)) != STATUS_SUCCESS)
    {
      __seterrno_from_win_error (RtlNtStatusToDosError (ret));
      syscall_printf ("-1 = mmap(): NtMapViewOfSection failed with %E");
      return INVALID_HANDLE_VALUE;
    }
  if ((flags & MAP_FIXED) && base != addr)
    {
      set_errno (EINVAL);
      syscall_printf ("-1 = mmap(): address shift with MAP_FIXED given");
      NtUnmapViewOfSection (INVALID_HANDLE_VALUE, base);
      return INVALID_HANDLE_VALUE;
    }

  *addr = (caddr_t) base;
  return h;
}

int
fhandler_dev_mem::munmap (HANDLE h, caddr_t addr, size_t len)
{
  NTSTATUS ret;
  if (!NT_SUCCESS(ret = NtUnmapViewOfSection (INVALID_HANDLE_VALUE, addr)))
    {
      __seterrno_from_win_error (RtlNtStatusToDosError (ret));
      return -1;
    }
  CloseHandle (h);
  return 0;
}

int
fhandler_dev_mem::msync (HANDLE h, caddr_t addr, size_t len, int flags)
{
  return 0;
}

int
fhandler_dev_mem::fstat (struct stat *buf)
{
  if (!buf)
    {
      set_errno (EINVAL);
      return -1;
    }

  memset (buf, 0, sizeof *buf);
  buf->st_mode = S_IFCHR;
  if (os_being_run != winNT)
    buf->st_mode |= S_IRUSR | S_IWUSR |
		    S_IRGRP | S_IWGRP |
		    S_IROTH | S_IWOTH;
  buf->st_nlink = 1;
  buf->st_blksize = getpagesize ();
  buf->st_dev = buf->st_rdev = get_device () << 8 | (unit & 0xff);

  return 0;
}

int
fhandler_dev_mem::dup (fhandler_base *child)
{
  int ret = fhandler_base::dup (child);

  if (! ret)
    {
      fhandler_dev_mem *fhc = (fhandler_dev_mem *) child;

      fhc->mem_size = mem_size;
      fhc->pos = pos;
    }
  return ret;
}

void
fhandler_dev_mem::dump ()
{
  paranoid_printf("here, fhandler_dev_mem");
}

extern "C" {

LoadDLLinitfunc (ntdll)
{
  HANDLE h;
  static NO_COPY LONG here = -1L;

  while (InterlockedIncrement (&here))
    {
      InterlockedDecrement (&here);
small_printf ("Multiple tries to read ntdll.dll\n");
      Sleep (0);
    }

  if (ntdll_handle)
    /* nothing to do */;
  else if ((h = LoadLibrary ("ntdll.dll")) != NULL)
    ntdll_handle = h;
  else if (!ntdll_handle)
    api_fatal ("could not load ntdll.dll, %E");

  InterlockedDecrement (&here);
  return 0;
}

static void dummy_autoload (void) __attribute__ ((unused));
static void
dummy_autoload (void)
{
LoadDLLinit (ntdll)
LoadDLLfuncEx (NtMapViewOfSection, 40, ntdll, 1)
LoadDLLfuncEx (NtOpenSection, 12, ntdll, 1)
LoadDLLfuncEx (NtUnmapViewOfSection, 8, ntdll, 1)
LoadDLLfuncEx (RtlInitUnicodeString, 8, ntdll, 1)
LoadDLLfuncEx (RtlNtStatusToDosError, 4, ntdll, 1)
}
}
