/* fhandler_procnet.cc: fhandler for /proc/net virtual filesystem

   Copyright 2007, 2008, 2009 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#define  __INSIDE_CYGWIN_NET__

#include "winsup.h"
#include "cygerrno.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "fhandler_virtual.h"
#include "dtable.h"
#include "cygheap.h"

#include <netdb.h>
#define USE_SYS_TYPES_FD_SET
#include <winsock2.h>
#include <iphlpapi.h>
#include <asm/byteorder.h>
#include <cygwin/in6.h>

#define _COMPILING_NEWLIB
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int ip_addr_prefix (PIP_ADAPTER_UNICAST_ADDRESS pua,
			       PIP_ADAPTER_PREFIX pap);
bool get_adapters_addresses (PIP_ADAPTER_ADDRESSES *pa0, ULONG family);

static _off64_t format_procnet_ifinet6 (void *, char *&);

static const virt_tab_t procnet_tab[] =
{
  { ".",        FH_PROCNET, virt_directory, NULL },
  { "..",       FH_PROCNET, virt_directory, NULL },
  { "if_inet6", FH_PROCNET, virt_file,      format_procnet_ifinet6 },
  { NULL,       0,          virt_none,      NULL }
};

static const int PROCNET_LINK_COUNT =
  (sizeof (procnet_tab) / sizeof (virt_tab_t)) - 1;

/* Returns 0 if path doesn't exist, >0 if path is a directory,
 * -1 if path is a file, -2 if path is a symlink, -3 if path is a pipe,
 * -4 if path is a socket.
 */
int
fhandler_procnet::exists ()
{
  const char *path = get_name ();
  debug_printf ("exists (%s)", path);
  path += proc_len + 1;
  while (*path != 0 && !isdirsep (*path))
    path++;
  if (*path == 0)
    return 1;

  for (int i = 0; procnet_tab[i].name; i++)
    if (!strcmp (path + 1, procnet_tab[i].name))
      {
	if (procnet_tab[i].type == virt_file)
	  {
	    if (!wincap.has_gaa_prefixes ()
	    	|| !get_adapters_addresses (NULL, AF_INET6))
	      return virt_none;
	  }
	fileid = i;
	return procnet_tab[i].type;
      }
  return virt_none;
}

fhandler_procnet::fhandler_procnet ():
  fhandler_proc ()
{
}

int
fhandler_procnet::fstat (struct __stat64 *buf)
{
  fhandler_base::fstat (buf);
  buf->st_mode &= ~_IFMT & NO_W;
  int file_type = exists ();
  switch (file_type)
    {
    case virt_none:
      set_errno (ENOENT);
      return -1;
    case virt_directory:
    case virt_rootdir:
      buf->st_mode |= S_IFDIR | S_IXUSR | S_IXGRP | S_IXOTH;
      buf->st_nlink = 2;
      return 0;
    case virt_file:
    default:
      buf->st_mode |= S_IFREG | S_IRUSR | S_IRGRP | S_IROTH;
      return 0;
    }
}

int
fhandler_procnet::readdir (DIR *dir, dirent *de)
{
  int res = ENMFILE;
  if (dir->__d_position >= PROCNET_LINK_COUNT)
    goto out;
  if (procnet_tab[dir->__d_position].type == virt_file)
    {
      if (!wincap.has_gaa_prefixes ()
	  || !get_adapters_addresses (NULL, AF_INET6))
	goto out;
    }
  strcpy (de->d_name, procnet_tab[dir->__d_position++].name);
  dir->__flags |= dirent_saw_dot | dirent_saw_dot_dot;
  res = 0;
out:
  syscall_printf ("%d = readdir (%p, %p) (%s)", res, dir, de, de->d_name);
  return res;
}

int
fhandler_procnet::open (int flags, mode_t mode)
{
  int process_file_no = -1;

  int res = fhandler_virtual::open (flags, mode);
  if (!res)
    goto out;

  nohandle (true);

  const char *path;
  path = get_name () + proc_len + 1;
  while (*path != 0 && !isdirsep (*path))
    path++;

  if (*path == 0)
    {
      if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))
	{
	  set_errno (EEXIST);
	  res = 0;
	  goto out;
	}
      else if (flags & O_WRONLY)
	{
	  set_errno (EISDIR);
	  res = 0;
	  goto out;
	}
      else
	{
	  flags |= O_DIROPEN;
	  goto success;
	}
    }

  process_file_no = -1;
  for (int i = 0; procnet_tab[i].name; i++)
    {
      if (path_prefix_p (procnet_tab[i].name, path + 1,
			 strlen (procnet_tab[i].name), false))
	process_file_no = i;
    }
  if (process_file_no == -1)
    {
      if (flags & O_CREAT)
	{
	  set_errno (EROFS);
	  res = 0;
	  goto out;
	}
      else
	{
	  set_errno (ENOENT);
	  res = 0;
	  goto out;
	}
    }
  if (flags & O_WRONLY)
    {
      set_errno (EROFS);
      res = 0;
      goto out;
    }

  fileid = process_file_no;
  if (!fill_filebuf ())
	{
	  res = 0;
	  goto out;
	}

  if (flags & O_APPEND)
    position = filesize;
  else
    position = 0;

success:
  res = 1;
  set_flags ((flags & ~O_TEXT) | O_BINARY);
  set_open_status ();
out:
  syscall_printf ("%d = fhandler_proc::open (%p, %d)", res, flags, mode);
  return res;
}

bool
fhandler_procnet::fill_filebuf ()
{
  if (procnet_tab[fileid].format_func)
    {
      filesize = procnet_tab[fileid].format_func (NULL, filebuf);
      return true;
    }
  return false;
}

/* Return the same scope values as Linux. */
static unsigned int
get_scope (struct in6_addr *addr)
{
  if (IN6_IS_ADDR_LOOPBACK (addr))
    return 0x10;
  if (IN6_IS_ADDR_LINKLOCAL (addr))
    return 0x20;
  if (IN6_IS_ADDR_SITELOCAL (addr))
    return 0x40;
  if (IN6_IS_ADDR_V4COMPAT (addr))
    return 0x80;
  return 0x0;
}

/* Convert DAD state into Linux compatible values. */
static unsigned int dad_to_flags[] =
{
  0x02,		/* Invalid -> NODAD */
  0x40,		/* Tentative -> TENTATIVE */
  0xc0,		/* Duplicate -> PERMANENT | TENTATIVE */
  0x20,		/* Deprecated -> DEPRECATED */
  0x80		/* Preferred -> PERMANENT */
};

static _off64_t
format_procnet_ifinet6 (void *, char *&filebuf)
{
  PIP_ADAPTER_ADDRESSES pa0 = NULL, pap;
  PIP_ADAPTER_UNICAST_ADDRESS pua;
  ULONG alloclen;

  if (!wincap.has_gaa_prefixes ())
    return 0;
  _off64_t filesize = 0;
  if (!get_adapters_addresses (&pa0, AF_INET6))
    goto out;
  alloclen = 0;
  for (pap = pa0; pap; pap = pap->Next)
    for (pua = pap->FirstUnicastAddress; pua; pua = pua->Next)
      alloclen += 100;
  if (!alloclen)
    goto out;
  filebuf = (char *) crealloc (filebuf, alloclen);
  if (!filebuf)
    goto out;
  for (pap = pa0; pap; pap = pap->Next)
    for (pua = pap->FirstUnicastAddress; pua; pua = pua->Next)
      {
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)
				    pua->Address.lpSockaddr;
	for (int i = 0; i < 8; ++i)
	  /* __small_sprintf generates upper-case hex. */
	  filesize += sprintf (filebuf + filesize, "%04x",
			       ntohs (sin6->sin6_addr.s6_addr16[i]));
	filebuf[filesize++] = ' ';
	filesize += sprintf (filebuf + filesize,
			     "%02lx %02x %02x %02x %s\n",
			     pap->Ipv6IfIndex,
			     ip_addr_prefix (pua, pap->FirstPrefix),
			     get_scope (&((struct sockaddr_in6 *)
					pua->Address.lpSockaddr)->sin6_addr),
			     dad_to_flags [pua->DadState],
			     pap->AdapterName);
      }

out:
  if (pa0)
    free (pa0);
  return filesize;
}
