/*
 * Written by J.T. Conklin <jtc@netbsd.org>.
 * Public domain.
 *
 * Adapted for `long double' by Ulrich Drepper <drepper@cygnus.com>.
 */

/*
 * The 8087 method for the exponential function is to calculate
 *   exp(x) = 2^(x log2(e))
 * after separating integer and fractional parts
 *   x log2(e) = i + f, |f| <= .5
 * 2^i is immediate but f needs to be precise for long double accuracy.
 * Suppress range reduction error in computing f by the following.
 * Separate x into integer and fractional parts
 *   x = xi + xf, |xf| <= .5
 * Separate log2(e) into the sum of an exact number c0 and small part c1.
 *   c0 + c1 = log2(e) to extra precision
 * Then
 *   f = (c0 xi - i) + c0 xf + c1 x
 * where c0 xi is exact and so also is (c0 xi - i).
 * -- moshier@na-net.ornl.gov
 */

#include <math.h>
#include "cephes_mconf.h"  /* for max and min log thresholds */

static long double c0 = 1.44268798828125L;
static long double c1 = 7.05260771340735992468e-6L;

static long double
__expl (long double x)
{
  long double res;
  asm ("fldl2e\n\t"             /* 1  log2(e)         */
       "fmul %%st(1),%%st\n\t"  /* 1  x log2(e)       */
       "frndint\n\t"            /* 1  i               */
       "fld %%st(1)\n\t"        /* 2  x               */
       "frndint\n\t"            /* 2  xi              */
       "fld %%st(1)\n\t"        /* 3  i               */
       "fldt %2\n\t"            /* 4  c0              */
       "fld %%st(2)\n\t"        /* 5  xi              */
       "fmul %%st(1),%%st\n\t"  /* 5  c0 xi           */
       "fsubp %%st,%%st(2)\n\t" /* 4  f = c0 xi  - i  */
       "fld %%st(4)\n\t"        /* 5  x               */
       "fsub %%st(3),%%st\n\t"  /* 5  xf = x - xi     */
       "fmulp %%st,%%st(1)\n\t" /* 4  c0 xf           */
       "faddp %%st,%%st(1)\n\t" /* 3  f = f + c0 xf   */
       "fldt %3\n\t"            /* 4                  */
       "fmul %%st(4),%%st\n\t"  /* 4  c1 * x          */
       "faddp %%st,%%st(1)\n\t" /* 3  f = f + c1 * x  */
       "f2xm1\n\t"		/* 3 2^(fract(x * log2(e))) - 1 */
       "fld1\n\t"               /* 4 1.0              */
       "faddp\n\t"		/* 3 2^(fract(x * log2(e))) */
       "fstp	%%st(1)\n\t"    /* 2  */
       "fscale\n\t"	        /* 2 scale factor is st(1); e^x */
       "fstp	%%st(1)\n\t"    /* 1  */
       "fstp	%%st(1)\n\t"    /* 0  */
       : "=t" (res) : "0" (x), "m" (c0), "m" (c1) : "ax", "dx");
  return res;
}

long double expl (long double x)
{
  if (x > MAXLOGL)
    return INFINITY;
  else if (x < MINLOGL)
    return 0.0L;
  else
    return __expl (x);
}
