#include <stdbool.h>
#include "cpu_features.h"

/* level 1 edx bits */
#define EDX_CX8 (1 << 8) /* CMPXCHG8B */
#define EDX_CMOV (1 << 15)
#define EDX_MMX (1 << 23)
#define EDX_FXSR (1 << 24) /* FXSAVE and FXRSTOR */
#define EDX_SSE (1 << 25)
#define EDX_SSE2 (1 << 26) 

/*  level 1 ecx bits */
#define ECX_SSE3 (1 << 0)
#define ECX_CX16 (1 << 13) /* CMPXCHG16B */

/* extended level 0x80000001 edx bits */
#define EDX_3DNOW (1 << 31)
#define EDX_3DNOWP (1 << 30)
#define EDX_LM (1 << 29) /*LONG MODE */

#define __cpuid(level,a,b,c,d)			 		\
  __asm__ __volatile__ ("cpuid;"				\
			: "=a" (a), "=b" (b), "=c" (c), "=d" (d)\
			: "0" (level))

/* Combine the different cpuid flags into a single bitmap.  */ 

unsigned int __cpu_features = 0;

void  __cpu_features_init (void)
{
  unsigned int eax, ebx, ecx, edx;
  /* Try to change the value of CPUID bit (bit 21) in EFLAGS.
     If the bit can be toggled, CPUID is supported.  */
  asm volatile ("pushfl; pushfl; popl %0;"
		"movl %0,%1; xorl %2,%0;"
		"pushl %0; popfl; pushfl; popl %0; popfl"
		: "=&r" (eax), "=&r" (ebx)
		: "i" (0x00200000));

  if (((eax ^ ebx) & 0x00200000) == 0)
    return;

  __cpuid (0, eax, ebx, ecx, edx);
  if (eax == 0)
    return;

  __cpuid (1, eax, ebx, ecx, edx);

  if (edx & EDX_CX8)
     __cpu_features |= _CRT_CMPXCHG8B;
  if (edx & EDX_CMOV)
     __cpu_features |= _CRT_CMOV;

  if (edx & EDX_MMX)
     __cpu_features |= _CRT_MMX;
  if (edx & EDX_FXSR)
     __cpu_features |= _CRT_FXSR; 
  if (edx & EDX_SSE)
     __cpu_features |= _CRT_SSE;
  if (edx & EDX_SSE2)
     __cpu_features |= _CRT_SSE2;


  if (ecx & ECX_SSE3)
     __cpu_features |= _CRT_SSE3;
  if (ecx & ECX_CX16)
     __cpu_features |= _CRT_CMPXCHG16B;

  __cpuid (0x80000000, eax, ebx, ecx, edx);
  if (eax < 0x80000001)
    return;
  __cpuid (0x80000001, eax, ebx, ecx, edx);
  if (edx & EDX_3DNOW);
    __cpu_features |= _CRT_3DNOW; 
  if (edx & EDX_3DNOWP)
    __cpu_features |= _CRT_3DNOWP; 

  return;
}

#ifdef TEST

#include <stdio.h>
#define report(feature) \
  if ((feature) & __cpu_features) printf( #feature " found\n")

int main()
{
  __cpu_features_init();

  report(_CRT_CMPXCHG8B);
  report(_CRT_CMOV);
  report(_CRT_MMX);
  report(_CRT_FXSR);
  report(_CRT_SSE);
  report(_CRT_SSE2);
  report(_CRT_SSE3);
  report(_CRT_CMPXCHG16B);
  report(_CRT_3DNOW);
  report(_CRT_3DNOWP);
 return 0;
}

#endif
