#include <fenv.h>

/* 7.6.4.4
   The feupdateenv function saves the currently raised exceptions in
   its automatic storage, installs the floating-point environment
   represented by the object pointed to by envp, and then raises the
   saved exceptions. The argument envp shall point to an object
   set by a call to feholdexcept or fegetenv, or equal the macro
   FE_DFL_ENV or an implementation-defined environment macro. */

/* FIXME: this works but surely there must be a better way.  */

int feupdateenv (const fenv_t * envp)
{
  unsigned int _fexcept = fetestexcept (FE_ALL_EXCEPT); /*save excepts */
  fesetenv (envp); /* install the env  */
  feraiseexcept (_fexcept); /* raise the execept */
  return 0;
}

