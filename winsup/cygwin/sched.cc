/* sched.cc: scheduler interface for Cygwin

   Copyright 2001, 2002  Red Hat, Inc.

   Written by Robert Collins <rbtcollins@hotmail.com>

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#define _WIN32_WINNT 0x300
#include "winsup.h"
#include <limits.h>
#include "cygerrno.h"
#include <assert.h>
#include <stdlib.h>
#include <syslog.h>
#include <sched.h>
#include "pinfo.h"
/* for getpid */
#include <unistd.h>
#include "registry.h"

extern "C" HWND WINAPI GetForegroundWindow();

/* Win32 priority to UNIX priority Mapping.
   For now, I'm just following the spec: any range of priorities is ok.
   There are probably many many issues with this...

   We don't want process's going realtime. Well, they probably could, but the issues
   with avoiding the priority values 17-22 and 27-30 (not supported before win2k)
   make that inefficient.
   However to complicate things most unixes use lower is better priorities.

   So we map -14 to 15, and 15 to 1 via (16- ((n+16) >> 1))
   we then map 1 to 15 to various process class and thread priority combinations

   Then we need to look at the threads vi process priority. As win95 98 and NT 4
   Don't support opening threads cross-process (unless a thread HANDLE is passed around)
   for now, we'll just use the priority class.

   The code and logic are present to calculate the priority for thread
   , if a thread handle can be obtained. Alternatively, if the symbols wouldn't be
   resolved until they are used
   we could support this on windows 2000 and ME now, and just fall back to the
   class only on pre win2000 machines.

   Lastly, because we can't assume that the pid we're given are Windows pids, we can't
   alter non-cygwin started programs.
*/

extern "C"
{

/* max priority for policy */
int
sched_get_priority_max (int policy)
{
  if (policy < 1 || policy > 3)
    {
      set_errno (EINVAL);
      return -1;
    }
  return -14;
}

/* min priority for policy */
int
sched_get_priority_min (int policy)
{
  if (policy < 1 || policy > 3)
    {
      set_errno (EINVAL);
      return -1;
    }
  return 15;
}

/* Check a scheduler parameter struct for valid settings */
int
valid_sched_parameters (const struct sched_param *param)
{
  if (param->sched_priority < -14 || param->sched_priority > 15)
    {
      return 0;
    }
  return -1;

}

/* get sched params for process

   Note, I'm never returning EPERM,
   Always ESRCH. This is by design (If cygwin ever looks at paranoid security
   Walking the pid values is a known hole in some os's)
*/
int
sched_getparam (pid_t pid, struct sched_param *param)
{
  pid_t localpid;
  int winpri;
  if (!param || pid < 0)
    {
      set_errno (EINVAL);
      return -1;
    }

  localpid = pid ? pid : getpid ();

  DWORD Class;
  int ThreadPriority;
  HANDLE process;
  pinfo p (localpid);

  /* get the class */

  if (!p)
    {
      set_errno (ESRCH);
      return -1;
    }
  process = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, p->dwProcessId);
  if (!process)
    {
      set_errno (ESRCH);
      return -1;
    }
  Class = GetPriorityClass (process);
  CloseHandle (process);
  if (!Class)
    {
      set_errno (ESRCH);
      return -1;
    }
  ThreadPriority = THREAD_PRIORITY_NORMAL;

  /* calculate the unix priority.

     FIXME: windows 2000 supports ABOVE_NORMAL and BELOW_NORMAL class's
     So this logic just defaults those class factors to NORMAL in the calculations */

  switch (Class)
    {
    case IDLE_PRIORITY_CLASS:
      switch (ThreadPriority)
	{
	case THREAD_PRIORITY_IDLE:
	  winpri = 1;
	  break;
	case THREAD_PRIORITY_LOWEST:
	  winpri = 2;
	  break;
	case THREAD_PRIORITY_BELOW_NORMAL:
	  winpri = 3;
	  break;
	case THREAD_PRIORITY_NORMAL:
	  winpri = 4;
	  break;
	case THREAD_PRIORITY_ABOVE_NORMAL:
	  winpri = 5;
	  break;
	case THREAD_PRIORITY_HIGHEST:
	default:
	  winpri = 6;
	  break;
	}
      break;
    case HIGH_PRIORITY_CLASS:
      switch (ThreadPriority)
	{
	case THREAD_PRIORITY_IDLE:
	  winpri = 1;
	  break;
	case THREAD_PRIORITY_LOWEST:
	  winpri = 11;
	  break;
	case THREAD_PRIORITY_BELOW_NORMAL:
	  winpri = 12;
	  break;
	case THREAD_PRIORITY_NORMAL:
	  winpri = 13;
	  break;
	case THREAD_PRIORITY_ABOVE_NORMAL:
	  winpri = 14;
	  break;
	case THREAD_PRIORITY_HIGHEST:
	default:
	  winpri = 15;
	  break;
	}
      break;
    case NORMAL_PRIORITY_CLASS:
    default:
      switch (ThreadPriority)
	{
	case THREAD_PRIORITY_IDLE:
	  winpri = 1;
	  break;
	case THREAD_PRIORITY_LOWEST:
	  winpri = 7;
	  break;
	case THREAD_PRIORITY_BELOW_NORMAL:
	  winpri = 8;
	  break;
	case THREAD_PRIORITY_NORMAL:
	  winpri = 9;
	  break;
	case THREAD_PRIORITY_ABOVE_NORMAL:
	  winpri = 10;
	  break;
	case THREAD_PRIORITY_HIGHEST:
	default:
	  winpri = 11;
	  break;
	}
      break;
    }

  /* reverse out winpri = (16- ((unixpri+16) >> 1)) */
  /*
     winpri-16 = -  (unixpri +16 ) >> 1

     -(winpri-16) = unixpri +16 >> 1
     (-(winpri-16)) << 1 = unixpri+16
     ((-(winpri - 16)) << 1) - 16 = unixpri
   */

  param->sched_priority = ((-(winpri - 16)) << 1) - 16;

  return 0;
}

/* get the scheduler for pid

   All process's on WIN32 run with SCHED_FIFO.
   So we just give an answer.
   (WIN32 uses a multi queue FIFO).
*/
int
sched_getscheduler (pid_t pid)
{
  if (pid < 0)
    return ESRCH;
  else
    return SCHED_FIFO;
}

/* get the time quantum for pid

   Implemented only for NT systems, it fails and sets errno to ESRCH
   for non-NT systems.
*/
int
sched_rr_get_interval (pid_t pid, struct timespec *interval)
{
  static const char quantable[2][2][3] =
    {{{12, 24, 36}, { 6, 12, 18}},
     {{36, 36, 36}, {18, 18, 18}}};
  /* FIXME: Clocktickinterval can be 15 ms for multi-processor system. */
  static const int clocktickinterval = 10;
  static const int quantapertick = 3;

  HWND forwin;
  DWORD forprocid;
  int vfindex, slindex, qindex, prisep;
  long nsec;

  if (!wincap.is_winnt ())
    {
      set_errno (ESRCH);
      return -1;
    }

  forwin = GetForegroundWindow ();
  if (!forwin)
    GetWindowThreadProcessId (forwin, &forprocid);
  else
    forprocid = 0;

  reg_key reg (HKEY_LOCAL_MACHINE, KEY_READ, "SYSTEM", "CurrentControlSet",
	       "Control", "PriorityControl", NULL);
  if (reg.error ())
    {
      set_errno (ESRCH);
      return -1;
    }
  prisep = reg.get_int ("Win32PrioritySeparation", 2);
  pinfo pi (pid ? pid : myself->pid);
  if (!pi)
    {
      set_errno (ESRCH);
      return -1;
    }

  if (pi->dwProcessId == forprocid)
    {
      qindex = prisep & 3;
      qindex = qindex == 3 ? 2 : qindex;
    }
  else
    qindex = 0;
  vfindex = ((prisep >> 2) & 3) % 3;
  if (vfindex == 0)
    vfindex = wincap.is_server () || prisep & 3 == 0 ? 1 : 0;
  else
    vfindex -= 1;
  slindex = ((prisep >> 4) & 3) % 3;
  if (slindex == 0)
    slindex = wincap.is_server () ? 1 : 0;
  else
    slindex -= 1;

  nsec = quantable[vfindex][slindex][qindex] / quantapertick
    * clocktickinterval * 1000000;
  interval->tv_sec = nsec / 1000000000;
  interval->tv_nsec = nsec % 1000000000;

  return 0;
}

/* set the scheduling parameters */
int
sched_setparam (pid_t pid, const struct sched_param *param)
{
  pid_t localpid;
  int winpri;
  DWORD Class;
  int ThreadPriority;
  HANDLE process;

  if (!param || pid < 0)
    {
      set_errno (EINVAL);
      return -1;
    }

  if (!valid_sched_parameters (param))
    {
      set_errno (EINVAL);
      return -1;
    }

  /*  winpri = (16- ((unixpri+16) >> 1)) */
  winpri = 16 - ((param->sched_priority + 16) >> 1);

  /* calculate our desired priority class and thread priority */

  if (winpri < 7)
    Class = IDLE_PRIORITY_CLASS;
  else if (winpri > 10)
    Class = HIGH_PRIORITY_CLASS;
  else
    Class = NORMAL_PRIORITY_CLASS;

  switch (Class)
    {
    case IDLE_PRIORITY_CLASS:
      switch (winpri)
	{
	case 1:
	  ThreadPriority = THREAD_PRIORITY_IDLE;
	  break;
	case 2:
	  ThreadPriority = THREAD_PRIORITY_LOWEST;
	  break;
	case 3:
	  ThreadPriority = THREAD_PRIORITY_BELOW_NORMAL;
	  break;
	case 4:
	  ThreadPriority = THREAD_PRIORITY_NORMAL;
	  break;
	case 5:
	  ThreadPriority = THREAD_PRIORITY_ABOVE_NORMAL;
	  break;
	case 6:
	  ThreadPriority = THREAD_PRIORITY_HIGHEST;
	  break;
	}
      break;
    case NORMAL_PRIORITY_CLASS:
      switch (winpri)
	{
	case 7:
	  ThreadPriority = THREAD_PRIORITY_LOWEST;
	  break;
	case 8:
	  ThreadPriority = THREAD_PRIORITY_BELOW_NORMAL;
	  break;
	case 9:
	  ThreadPriority = THREAD_PRIORITY_NORMAL;
	  break;
	case 10:
	  ThreadPriority = THREAD_PRIORITY_ABOVE_NORMAL;
	  break;
	case 11:
	  ThreadPriority = THREAD_PRIORITY_HIGHEST;
	  break;
	}
      break;
    case HIGH_PRIORITY_CLASS:
      switch (winpri)
	{
	case 12:
	  ThreadPriority = THREAD_PRIORITY_BELOW_NORMAL;
	  break;
	case 13:
	  ThreadPriority = THREAD_PRIORITY_NORMAL;
	  break;
	case 14:
	  ThreadPriority = THREAD_PRIORITY_ABOVE_NORMAL;
	  break;
	case 15:
	  ThreadPriority = THREAD_PRIORITY_HIGHEST;
	  break;
	}
      break;
    }

  localpid = pid ? pid : getpid ();

  pinfo p (localpid);

  /* set the class */

  if (!p)
    {
      set_errno (1);		//ESRCH);
      return -1;
    }
  process =
    OpenProcess (PROCESS_SET_INFORMATION, FALSE, (DWORD) p->dwProcessId);
  if (!process)
    {
      set_errno (2);		//ESRCH);
      return -1;
    }
  if (!SetPriorityClass (process, Class))
    {
      CloseHandle (process);
      set_errno (EPERM);
      return -1;
    }
  CloseHandle (process);

  return 0;
}

/* we map -14 to 15, and 15 to 1 via (16- ((n+16) >> 1)). This lines up with the allowed
 * valueswe return elsewhere in the sched* functions. We then map in groups of three to
 * allowed thread priority's. The reason for dropping accuracy while still returning
 * a wide range of values is to allow more flexible code in the future.
 */
int
sched_set_thread_priority (HANDLE thread, int priority)
{
  int real_pri;
  real_pri = 16 - ((priority + 16) >> 1);
  if (real_pri <1 || real_pri > 15)
    return EINVAL;

  if (real_pri < 4)
    real_pri = THREAD_PRIORITY_LOWEST;
  else if (real_pri < 7)
    real_pri = THREAD_PRIORITY_BELOW_NORMAL;
  else if (real_pri < 10)
    real_pri = THREAD_PRIORITY_NORMAL;
  else if (real_pri < 13)
    real_pri = THREAD_PRIORITY_ABOVE_NORMAL;
  else
    real_pri = THREAD_PRIORITY_HIGHEST;

  if (!SetThreadPriority (thread, real_pri))
    /* invalid handle, no access are the only expected errors. */
    return EPERM;
  return 0;
}

/* set the scheduler */
int
sched_setscheduler (pid_t pid, int policy,
		    const struct sched_param *param)
{
  /* on win32, you can't change the scheduler. Doh! */
  set_errno (ENOSYS);
  return -1;
}

/* yield the cpu */
int
sched_yield (void)
{
  low_priority_sleep (0);
  return 0;
}
}
