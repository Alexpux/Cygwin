/* types.h

   Copyright 2001, 2002, 2003 Red Hat Inc.
   Written by Robert Collins <rbtcollins@hotmail.com>

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _CYGWIN_TYPES_H
#define _CYGWIN_TYPES_H

#include <sys/sysmacros.h>

#ifndef __timespec_t_defined
#define __timespec_t_defined
typedef struct timespec timespec_t;
#endif /*__timespec_t_defined*/

#ifndef __timestruc_t_defined
#define __timestruc_t_defined
typedef struct timespec timestruc_t;
#endif /*__timestruc_t_defined*/

#ifndef __off_t_defined
#define __off_t_defined
typedef long __off32_t;
typedef long long __off64_t;
#ifdef __CYGWIN_USE_BIG_TYPES__
typedef __off64_t off_t;
#else
typedef __off32_t off_t;
#endif
#endif /*__off_t_defined*/

#ifndef __dev_t_defined
#define __dev_t_defined
typedef short __dev16_t;
typedef unsigned long __dev32_t;
#ifdef __CYGWIN_USE_BIG_TYPES__
typedef __dev32_t dev_t;
#else
typedef __dev16_t dev_t;
#endif
#endif /*__dev_t_defined*/

#ifndef __blksize_t_defined
#define __blksize_t_defined
typedef long blksize_t;
#endif /*__blksize_t_defined*/

#ifndef __blkcnt_t_defined
#define __blkcnt_t_defined
typedef long __blkcnt32_t;
typedef long long __blkcnt64_t;
#ifdef __CYGWIN_USE_BIG_TYPES__
typedef __blkcnt64_t  blkcnt_t;
#else
typedef __blkcnt32_t  blkcnt_t;
#endif
#endif /*__blkcnt_t_defined*/

#ifndef __uid_t_defined
#define __uid_t_defined
typedef unsigned short __uid16_t;
typedef unsigned long  __uid32_t;
#ifdef __CYGWIN_USE_BIG_TYPES__
typedef __uid32_t uid_t;
#else
typedef __uid16_t uid_t;
#endif
#endif /*__uid_t_defined*/

#ifndef __gid_t_defined
#define __gid_t_defined
typedef unsigned short __gid16_t;
typedef unsigned long  __gid32_t;
#ifdef __CYGWIN_USE_BIG_TYPES__
typedef __gid32_t gid_t;
#else
typedef __gid16_t gid_t;
#endif
#endif /*__gid_t_defined*/

#ifndef __ino_t_defined
#define __ino_t_defined
#ifdef __CYGWIN_USE_BIG_TYPES1__
typedef unsigned long long ino_t;
#else
typedef unsigned long ino_t;
#endif
#endif /*__ino_t_defined*/

#ifndef __BIT_TYPES_DEFINED
#define __BIT_TYPES_DEFINED__ 1

#ifndef __vm_offset_t
#define __vm_offset_t_defined
typedef unsigned long vm_offset_t;
#endif /*__vm_offset_t_defined*/

#ifndef __vm_size_t
#define __vm_size_t_defined
typedef unsigned long vm_size_t;
#endif /*__vm_size_t_defined*/

#ifndef __int8_t_defined
#define __int8_t_defined
typedef char int8_t;
#endif
#ifndef __int16_t_defined
#define __int16_t_defined
typedef __int16_t int16_t;
#endif
#ifndef __int32_t_defined
#define __int32_t_defined
typedef __int32_t int32_t;
#endif
#ifndef __int64_t_defined
#define __int64_t_defined
typedef __int64_t int64_t;
#endif

#ifndef __uint8_t_defined
#define __uint8_t_defined
typedef unsigned char uint8_t;
#endif
#ifndef __uint16_t_defined
#define __uint16_t_defined
typedef __uint16_t uint16_t;
#endif
#ifndef __uint32_t_defined
#define __uint32_t_defined
typedef __uint32_t uint32_t;
#endif
#ifndef __uint64_t_defined
#define __uint64_t_defined
typedef __uint64_t uint64_t;
#endif

#ifndef __uint8_t_defined
#define __uint8_t_defined
typedef unsigned char u_int8_t;
#endif
#ifndef __uint16_t_defined
#define __uint16_t_defined
typedef __uint16_t u_int16_t;
#endif
#ifndef __uint32_t_defined
#define __uint32_t_defined
typedef __uint32_t u_int32_t;
#endif
#ifndef __uint64_t_defined
#define __uint64_t_defined
typedef __uint64_t u_int64_t;
#endif

#ifndef __uintptr_t_defined
#define __uintptr_t_defined
typedef unsigned long uintptr_t;
#endif

#ifndef __intptr_t_defined
#define __intptr_t_defined
typedef long intptr_t;
#endif

#ifndef __register_t_defined
#define __register_t_defined
typedef __int32_t register_t;
#endif

#ifndef __addr_t_defined
#define __addr_t_defined
typedef char *addr_t;
#endif

#ifndef __mode_t_defined
#define __mode_t_defined
typedef unsigned mode_t;
#endif
#endif /*__BIT_TYPES_DEFINED*/

#if !defined(__INSIDE_CYGWIN__) || !defined(__cplusplus)

typedef struct __pthread_t {char __dummy;} *pthread_t;
typedef struct __pthread_mutex_t {char __dummy;} *pthread_mutex_t;

typedef struct __pthread_key_t {char __dummy;} *pthread_key_t;
typedef struct __pthread_attr_t {char __dummy;} *pthread_attr_t;
typedef struct __pthread_mutexattr_t {char __dummy;} *pthread_mutexattr_t;
typedef struct __pthread_condattr_t {char __dummy;} *pthread_condattr_t;
typedef struct __pthread_cond_t {char __dummy;} *pthread_cond_t;

  /* These variables are not user alterable. This means you!. */
typedef struct
{
  pthread_mutex_t mutex;
  int state;
}
pthread_once_t;
typedef struct __pthread_rwlock_t {char __dummy;} *pthread_rwlock_t;
typedef struct __pthread_rwlockattr_t {char __dummy;} *pthread_rwlockattr_t;

#else

/* pthreads types */

typedef class pthread *pthread_t;
typedef class pthread_mutex *pthread_mutex_t;
typedef class pthread_key *pthread_key_t;
typedef class pthread_attr *pthread_attr_t;
typedef class pthread_mutexattr *pthread_mutexattr_t;
typedef class pthread_condattr *pthread_condattr_t;
typedef class pthread_cond *pthread_cond_t;
typedef class pthread_once pthread_once_t;
typedef class pthread_rwlock *pthread_rwlock_t;
typedef class pthread_rwlockattr *pthread_rwlockattr_t;

/* semaphores types */
typedef class semaphore *sem_t;
#endif /* __INSIDE_CYGWIN__ */
#endif /* _CYGWIN_TYPES_H */

#ifdef __cplusplus
}
#endif
