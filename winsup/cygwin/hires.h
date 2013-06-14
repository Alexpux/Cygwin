/* hires.h: Definitions for hires clock calculations

   Copyright 2002, 2003, 2004, 2005, 2009, 2010, 2011, 2012, 2013 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef __HIRES_H__
#define __HIRES_H__

#include <mmsystem.h>

/* Conversions for per-process and per-thread clocks */
#define PID_TO_CLOCKID(pid) (pid * 8 + CLOCK_PROCESS_CPUTIME_ID)
#define CLOCKID_TO_PID(cid) ((cid - CLOCK_PROCESS_CPUTIME_ID) / 8)
#define CLOCKID_IS_PROCESS(cid) ((cid % 8) == CLOCK_PROCESS_CPUTIME_ID)
#define THREADID_TO_CLOCKID(tid) (tid * 8 + CLOCK_THREAD_CPUTIME_ID)
#define CLOCKID_TO_THREADID(cid) ((cid - CLOCK_THREAD_CPUTIME_ID) / 8)
#define CLOCKID_IS_THREAD(cid) ((cid % 8) == CLOCK_THREAD_CPUTIME_ID)

/* Largest delay in ms for sleep and alarm calls.
   Allow actual delay to exceed requested delay by 10 s.
   Express as multiple of 1000 (i.e. seconds) + max resolution
   The tv_sec argument in timeval structures cannot exceed
   HIRES_DELAY_MAX / 1000 - 1, so that adding fractional part
   and rounding won't exceed HIRES_DELAY_MAX */
#define HIRES_DELAY_MAX ((((UINT_MAX - 10000) / 1000) * 1000) + 10)

/* 100ns difference between Windows and UNIX timebase. */
#define FACTOR (0x19db1ded53e8000LL)
/* # of 100ns intervals per second. */
#define NSPERSEC 10000000LL

class hires_base
{
 protected:
  int inited;
 public:
  void reset() {inited = false;}
};

class hires_ns : public hires_base
{
  LARGE_INTEGER primed_pc;
  double freq;
  void prime ();
 public:
  LONGLONG nsecs (bool monotonic = false);
  LONGLONG usecs () {return nsecs () / 1000LL;}
  LONGLONG resolution();
};

class hires_ms : public hires_base
{
 public:
  LONGLONG nsecs ();
  LONGLONG usecs () {return nsecs () / 10LL;}
  LONGLONG msecs () {return nsecs () / 10000LL;}
  UINT resolution ();
};

extern hires_ms gtod;
#endif /*__HIRES_H__*/
