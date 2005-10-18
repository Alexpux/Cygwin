/* sysconf.cc

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <ntdef.h>
#include "cygerrno.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
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
	{
	  long max = getdtablesize ();
	  if (max < OPEN_MAX)
	    max = OPEN_MAX;
	  return max;
	}
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
      case _SC_LOGIN_NAME_MAX:
	return LOGIN_NAME_MAX;
      case _SC_GETPW_R_SIZE_MAX:
      case _SC_GETGR_R_SIZE_MAX:
	return 16*1024;
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
	if (!wincap.supports_smp ())
	  return 1;
	/*FALLTHRU*/
      case _SC_PHYS_PAGES:
	if (wincap.supports_smp ())
	  {
	    NTSTATUS ret;
	    SYSTEM_BASIC_INFORMATION sbi;
	    if ((ret = NtQuerySystemInformation (SystemBasicInformation,
						   (PVOID) &sbi,
						 sizeof sbi, NULL))
		  != STATUS_SUCCESS)
	      {
		__seterrno_from_nt_status (ret);
		debug_printf ("NtQuerySystemInformation: ret %d, Dos(ret) %E",
			      ret);
		return -1;
	      }
	    switch (in)
	      {
	      case _SC_NPROCESSORS_CONF:
	       return sbi.NumberProcessors;
	      case _SC_NPROCESSORS_ONLN:
	       {
		 int i = 0;
		 do
		   if (sbi.ActiveProcessors & 1)
		     i++;
		 while (sbi.ActiveProcessors >>= 1);
		 return i;
	       }
	      case _SC_PHYS_PAGES:
		return sbi.NumberOfPhysicalPages;
	      }
	  }
	break;
      case _SC_AVPHYS_PAGES:
	if (wincap.supports_smp ())
	  {
	    NTSTATUS ret;
	    SYSTEM_PERFORMANCE_INFORMATION spi;
	    if ((ret = NtQuerySystemInformation (SystemPerformanceInformation,
						   (PVOID) &spi,
						 sizeof spi, NULL))
		  != STATUS_SUCCESS)
	      {
		__seterrno_from_nt_status (ret);
		debug_printf ("NtQuerySystemInformation: ret %d, Dos(ret) %E",
			      ret);
		return -1;
	      }
	    return spi.AvailablePages;
	  }
      case _SC_RTSIG_MAX:
	return RTSIG_MAX;
      case _SC_TTY_NAME_MAX:
	return TTY_NAME_MAX;
      case _SC_MEMLOCK_RANGE:
        return _POSIX_MEMLOCK_RANGE;
    }

  /* Invalid input or unimplemented sysconf name */
  set_errno (EINVAL);
  return -1;
}
