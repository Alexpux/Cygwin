/* libc/sys/linux/time.c - Time-related system calls */

/* Written 2000 by Werner Almesberger */


#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <linux/times.h>
#include <machine/syscall.h>


_syscall1(time_t,time,time_t *,t)
_syscall1(clock_t,times,struct tms *,buf)
_syscall2(int,getitimer,int,type,struct itimerval *,old)
_syscall3(int,setitimer,int,type,const struct itimerval *,new,struct itimerval *,old)
_syscall2(int,gettimeofday,struct timeval *,tv,struct timezone *,tz)
_syscall2(int,settimeofday,const struct timeval *,tv,const struct timezone *,tz)
_syscall2(int,nanosleep,const struct timespec *,req,struct timespec *,rem)

weak_alias(__libc_gettimeofday,__gettimeofday);
