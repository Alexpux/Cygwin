/* sysconf.cc

   Copyright 1996, 1997, 1998, 1999, 2000, 2001 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <ntdef.h>
#include "security.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "cygerrno.h"
#include "ntdll.h"

/* sysconf: POSIX 4.8.1.1 */
/* Allows a portable app to determine quantities of resources or
   presence of an option at execution time. */
long int
sysconf (int in)
{
  switch (in)
    {
      case _SC_ARG_MAX:
	/* FIXME: what's the right value?  _POSIX_ARG_MAX is only 4K */
	return 1048576;
      case _SC_OPEN_MAX:
	return getdtablesize ();
      case _SC_PAGESIZE:
	return getpagesize ();
      case _SC_CLK_TCK:
	return CLOCKS_PER_SEC;
      case _SC_JOB_CONTROL:
	return _POSIX_JOB_CONTROL;
      case _SC_CHILD_MAX:
	return CHILD_MAX;
      case _SC_NGROUPS_MAX:
	return NGROUPS_MAX;
      case _SC_SAVED_IDS:
	return _POSIX_SAVED_IDS;
      case _SC_VERSION:
	return _POSIX_VERSION;
#if 0	/* FIXME -- unimplemented */
      case _SC_TZNAME_MAX:
	return _POSIX_TZNAME_MAX;
      case _SC_STREAM_MAX:
	return _POSIX_STREAM_MAX;
#endif
      case _SC_NPROCESSORS_CONF:
      case _SC_NPROCESSORS_ONLN:
	if (!iswinnt)
	  return 1;
	/*FALLTHRU*/
      case _SC_PHYS_PAGES:
      case _SC_AVPHYS_PAGES:
	{
	  NTSTATUS ret;
	  SYSTEM_BASIC_INFORMATION sbi;
	  if ((ret = NtQuerySystemInformation (SystemBasicInformation,
						 (PVOID) &sbi,
					       sizeof sbi, NULL))
		!= STATUS_SUCCESS)
	    {
	      __seterrno_from_win_error (RtlNtStatusToDosError (ret));
	      debug_printf("NtQuerySystemInformation: ret = %d, "
			   "Dos(ret) = %d",
			   ret, RtlNtStatusToDosError (ret));
	      return -1;
	    }
	  switch (in)
	    {
	    case _SC_NPROCESSORS_CONF:
	     return sbi.NumberProcessors;
	    case _SC_NPROCESSORS_ONLN:
	     return sbi.ActiveProcessors;
	    case _SC_PHYS_PAGES:
	      return sbi.NumberOfPhysicalPages;
	    case _SC_AVPHYS_PAGES:
	      return sbi.HighestPhysicalPage - sbi.LowestPhysicalPage + 1;
	    }
	}
    }

  /* Invalid input or unimplemented sysconf name */
  set_errno (EINVAL);
  return -1;
}
