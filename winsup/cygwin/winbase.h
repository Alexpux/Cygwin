#include_next "winbase.h"

#ifndef _WINBASE2_H
#define _WINBASE2_H

extern __inline__ long ilockincr (long *m)
{
  register int __res;
  __asm__ __volatile__ ("\n\
	movl	$1,%0\n\
	lock	xadd %0,(%1)\n\
	inc	%0\n\
	": "=a" (__res), "=r" (m): "1" (m));
  return __res;
}
extern __inline__ long ilockdecr (long *m)
{
  register int __res;
  __asm__ __volatile__ ("\n\
	movl	$0xffffffff,%0\n\
	lock	xadd %0,(%1)\n\
	dec	%0\n\
	": "=a" (__res), "=r" (m): "1" (m));
  return __res;
}
extern __inline__ long ilockexch (long *t, long v)
{
  register int __res;
  __asm__ __volatile__ ("\n\
	movl	(%2),%0\n\
1:	lock	cmpxchgl %3,(%1)\n\
	jne 1b\n\
 	": "=a" (__res), "=c" (t): "1" (t), "d" (v));
  return __res;
}

#undef InterlockedIncrement
#define InterlockedIncrement ilockincr
#undef InterlockedDecrement
#define InterlockedDecrement ilockdecr
#undef InterlockedExchange
#define InterlockedExchange ilockexch

extern long tls_ix;

extern __inline__ DWORD
my_tlsalloc ()
{
  return (DWORD) ilockincr (&tls_ix);
}

extern __inline__ BOOL
my_tlssetvalue (DWORD ix, void *val)
{
  char **stackbase;
  __asm__ volatile ("movl %%fs:4,%0": "=g" (stackbase));
  stackbase[-ix] = (char *) val;
  return 1;
}

extern __inline__ void *
my_tlsgetvalue (DWORD ix)
{
  char **stackbase;
  __asm__ volatile ("movl %%fs:4,%0": "=g" (stackbase));
  return stackbase[-ix];
}

extern __inline__ BOOL
my_tlsfree (DWORD ix)
{
  /* nothing for now */
  return 1;
}

#undef TlsAlloc
#define TlsAlloc my_tlsalloc
#undef TlsGetValue
#define TlsGetValue my_tlsgetvalue
#undef TlsSetValue
#define TlsSetValue my_tlssetvalue
#undef TlsFree
#define TlsFree my_tlsfree
#endif /*_WINBASE2_H*/
