/*
 * Written by J.T. Conklin <jtc@netbsd.org>.
 * Changes for long double by Ulrich Drepper <drepper@cygnus.com>
 * Public domain.
 */

#include <math.h>

float
logbf (float x)
{
  float res;
  asm ("fxtract\n\t"
       "fstp	%%st" : "=t" (res) : "0" (x));
  return res;
}
