/* shared.cc: shared data area support.

   Copyright 1996, 1997, 1998, 1999, 2000, 2001 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <grp.h>
#include <pwd.h>
#include "sync.h"
#include "sigproc.h"
#include "pinfo.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "heap.h"
#include "shared_info.h"
#include "registry.h"
#include "cygwin_version.h"
#include "security.h"

#define SHAREDVER (unsigned)(cygwin_version.api_major << 16 | \
		   cygwin_version.api_minor)

shared_info NO_COPY *cygwin_shared = NULL;
mount_info NO_COPY *mount_table = NULL;
HANDLE cygwin_mount_h = NULL;

/* General purpose security attribute objects for global use. */
SECURITY_ATTRIBUTES NO_COPY sec_none;
SECURITY_ATTRIBUTES NO_COPY sec_none_nih;
SECURITY_ATTRIBUTES NO_COPY sec_all;
SECURITY_ATTRIBUTES NO_COPY sec_all_nih;

char * __stdcall
shared_name (const char *str, int num)
{
  static NO_COPY char buf[MAX_PATH] = {0};
  char envbuf[6];

  __small_sprintf (buf, "%s.%s.%d", cygwin_version.shared_id, str, num);
  if (GetEnvironmentVariable ("CYGWIN_TESTING", envbuf, 5))
    strcat (buf, cygwin_version.dll_build_date);
  return buf;
}

void * __stdcall
open_shared (const char *name, HANDLE &shared_h, DWORD size, void *addr)
{
  void *shared;

  if (!shared_h)
    {
      char *mapname;
      if (!name)
	mapname = NULL;
      else
	{
	  mapname = shared_name (name, 0);
	  shared_h = OpenFileMappingA (FILE_MAP_READ | FILE_MAP_WRITE,
				       TRUE, mapname);
	}
      if (!shared_h &&
	  !(shared_h = CreateFileMappingA (INVALID_HANDLE_VALUE,
					   &sec_all,
					   PAGE_READWRITE,
					   0,
					   size,
					   mapname)))
	api_fatal ("CreateFileMappingA, %E.  Terminating.");
    }

  shared = (shared_info *) MapViewOfFileEx (shared_h,
				       FILE_MAP_READ | FILE_MAP_WRITE,
				       0, 0, 0, addr);

  if (!shared)
    {
      /* Probably win95, so try without specifying the address.  */
      shared = (shared_info *) MapViewOfFileEx (shared_h,
				       FILE_MAP_READ|FILE_MAP_WRITE,
				       0,0,0,0);
    }

  if (!shared)
    api_fatal ("MapViewOfFileEx '%s'(%p), %E.  Terminating.", name, shared_h);

  debug_printf ("name %s, shared %p (wanted %p), h %p", name, shared, addr, shared_h);

  /* FIXME: I couldn't find anywhere in the documentation a note about
     whether the memory is initialized to zero.  The code assumes it does
     and since this part seems to be working, we'll leave it as is.  */
  return shared;
}

void
shared_info::initialize ()
{
  /* Ya, Win32 provides a way for a dll to watch when it's first loaded.
     We may eventually want to use it but for now we have this.  */
  if (inited)
    {
      if (inited != SHAREDVER)
	api_fatal ("Shared region version mismatch.  Version %x != %x.\n"
		   "Are you using multiple versions of cygwin1.dll?\n"
		   "Run 'cygcheck -r -s -v' to find out.",
		   inited, SHAREDVER);
      return;
    }

  /* Initialize the queue of deleted files.  */
  delqueue.init ();

  /* Initialize tty table.  */
  tty.init ();

  /* Fetch misc. registry entries.  */

  reg_key reg (KEY_READ, NULL);

  /* Note that reserving a huge amount of heap space does not result in
  the use of swap since we are not committing it. */
  /* FIXME: We should not be restricted to a fixed size heap no matter
  what the fixed size is. */

  heap_chunk_in_mb = reg.get_int ("heap_chunk_in_mb", 256);
  if (heap_chunk_in_mb < 4)
    {
      heap_chunk_in_mb = 4;
      reg.set_int ("heap_chunk_in_mb", heap_chunk_in_mb);
    }

  inited = SHAREDVER;
}

void __stdcall
memory_init ()
{
  /* Initialize general shared memory */
  HANDLE shared_h = cygheap ? cygheap->shared_h : NULL;
  cygwin_shared = (shared_info *) open_shared ("shared",
					       shared_h,
					       sizeof (*cygwin_shared),
					       cygwin_shared_address);

  cygwin_shared->initialize ();
  heap_init ();

  /* Allocate memory for the per-user mount table */
  char user_name[MAX_USER_NAME];
  DWORD user_name_len = MAX_USER_NAME;

  if (!GetUserName (user_name, &user_name_len))
    strcpy (user_name, "unknown");
  mount_table = (mount_info *) open_shared (user_name, cygwin_mount_h,
					    sizeof (mount_info), 0);
  debug_printf ("opening mount table for '%s' at %p", cygheap->user.name (),
		mount_table_address);
  ProtectHandle (cygwin_mount_h);
  debug_printf ("mount table version %x at %p", mount_table->version, mount_table);

  /* Initialize the Cygwin heap, if necessary */
  if (!cygheap)
    {
      cygheap_init ();
      cygheap->user.set_name (user_name);
    }
  cygheap->shared_h = shared_h;
  ProtectHandle (cygheap->shared_h);

  /* Initialize the Cygwin per-user mount table, if necessary */
  if (!mount_table->version)
    {
      mount_table->version = MOUNT_VERSION;
      debug_printf ("initializing mount table");
      mount_table->init ();	/* Initialize the mount table.  */
    }
}

void __stdcall
shared_terminate ()
{
  if (cygheap->shared_h)
    ForceCloseHandle (cygheap->shared_h);
  if (cygwin_mount_h)
    ForceCloseHandle (cygwin_mount_h);
}

unsigned
shared_info::heap_chunk_size ()
{
  return heap_chunk_in_mb << 20;
}

/* For apps that wish to access the shared data.  */

shared_info *
cygwin_getshared ()
{
  return cygwin_shared;
}

/*
 * Function to return a common SECURITY_DESCRIPTOR * that
 * allows all access.
 */

static NO_COPY SECURITY_DESCRIPTOR *null_sdp = 0;

SECURITY_DESCRIPTOR *__stdcall
get_null_sd ()
{
  static NO_COPY SECURITY_DESCRIPTOR sd;

  if (null_sdp == 0)
    {
      InitializeSecurityDescriptor (&sd, SECURITY_DESCRIPTOR_REVISION);
      SetSecurityDescriptorDacl (&sd, TRUE, 0, FALSE);
      null_sdp = &sd;
    }
  return null_sdp;
}

PSECURITY_ATTRIBUTES __stdcall
sec_user (PVOID sa_buf, PSID sid2, BOOL inherit)
{
  if (! sa_buf)
    return inherit ? &sec_none_nih : &sec_none;

  PSECURITY_ATTRIBUTES psa = (PSECURITY_ATTRIBUTES) sa_buf;
  PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)
			     ((char *) sa_buf + sizeof (*psa));
  PACL acl = (PACL) ((char *) sa_buf + sizeof (*psa) + sizeof (*psd));

  cygsid sid;

  if (cygheap->user.sid ())
    sid = cygheap->user.sid ();
  else if (! lookup_name (getlogin (), cygheap->user.logsrv (), sid))
    return inherit ? &sec_none_nih : &sec_none;

  size_t acl_len = sizeof (ACL)
		   + 4 * (sizeof (ACCESS_ALLOWED_ACE) - sizeof (DWORD))
		   + GetLengthSid (sid)
		   + GetLengthSid (get_admin_sid ())
		   + GetLengthSid (get_system_sid ())
		   + GetLengthSid (get_creator_owner_sid ());
  if (sid2)
    acl_len += sizeof (ACCESS_ALLOWED_ACE) - sizeof (DWORD)
	       + GetLengthSid (sid2);

  if (! InitializeAcl (acl, acl_len, ACL_REVISION))
    debug_printf ("InitializeAcl %E");

  if (! AddAccessAllowedAce (acl, ACL_REVISION,
			     SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL,
			     sid))
    debug_printf ("AddAccessAllowedAce(%s) %E", getlogin ());

  if (! AddAccessAllowedAce (acl, ACL_REVISION,
			     SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL,
			     get_admin_sid ()))
    debug_printf ("AddAccessAllowedAce(admin) %E");

  if (! AddAccessAllowedAce (acl, ACL_REVISION,
			     SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL,
			     get_system_sid ()))
    debug_printf ("AddAccessAllowedAce(system) %E");

  if (! AddAccessAllowedAce (acl, ACL_REVISION,
			     SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL,
			     get_creator_owner_sid ()))
    debug_printf ("AddAccessAllowedAce(creator_owner) %E");

  if (sid2)
    if (! AddAccessAllowedAce (acl, ACL_REVISION,
			       SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL,
			       sid2))
      debug_printf ("AddAccessAllowedAce(sid2) %E");

  if (! InitializeSecurityDescriptor (psd,
				      SECURITY_DESCRIPTOR_REVISION))
    debug_printf ("InitializeSecurityDescriptor %E");

/*
 * Setting the owner lets the created security attribute not work
 * on NT4 SP3 Server. Don't know why, but the function still does
 * what it should do also if the owner isn't set.
*/
#if 0
  if (! SetSecurityDescriptorOwner (psd, sid, FALSE))
    debug_printf ("SetSecurityDescriptorOwner %E");
#endif

  if (! SetSecurityDescriptorDacl (psd, TRUE, acl, FALSE))
    debug_printf ("SetSecurityDescriptorDacl %E");

  psa->nLength = sizeof (SECURITY_ATTRIBUTES);
  psa->lpSecurityDescriptor = psd;
  psa->bInheritHandle = inherit;
  return psa;
}

SECURITY_ATTRIBUTES *__stdcall
sec_user_nih (PVOID sa_buf, PSID sid2)
{
  return sec_user (sa_buf, sid2, FALSE);
}
