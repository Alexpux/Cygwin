/*
 * stdarg.h
 *
 * Provides facilities for stepping through a list of function arguments of
 * an unknown number and type.
 *
 * NOTE: Gcc should provide stdarg.h, and I believe their version will work
 *       with crtdll. If necessary I think you can replace this with the GCC
 *       stdarg.h.
 *
 * Note that the type used in va_arg is supposed to match the actual type
 * *after default promotions*. Thus, va_arg (..., short) is not valid.
 *
 * This file is part of the Mingw32 package.
 *
 * Contributors:
 *  Created by Colin Peters <colin@bird.fu.is.saga-u.ac.jp>
 *
 *  THIS SOFTWARE IS NOT COPYRIGHTED
 *
 *  This source code is offered for use in the public domain. You may
 *  use, modify or distribute it freely.
 *
 *  This code is distributed in the hope that it will be useful but
 *  WITHOUT ANY WARRANTY. ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 *  DISCLAMED. This includes but is not limited to warranties of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * $Revision$
 * $Author$
 * $Date$
 *
 */

#ifndef _STDARG_H_
#define _STDARG_H_

/* All the headers include this file. */
#include <_mingw.h>

/*
 * Don't do any of this stuff for the resource compiler.
 */
#ifndef RC_INVOKED

/* 
 * I was told that Win NT likes this.
 */
#ifndef _VA_LIST_DEFINED
#define _VA_LIST_DEFINED
#endif

#ifndef	_VA_LIST
#define _VA_LIST
#if defined __GNUC__ && __GNUC__ >= 3
typedef __builtin_va_list va_list;
#else
typedef char* va_list;
#endif
#endif

/*
 * Amount of space required in an argument list (ie. the stack) for an
 * argument of type t.
 */
#define __va_argsiz(t)	\
	(((sizeof(t) + sizeof(int) - 1) / sizeof(int)) * sizeof(int))


/*
 * Start variable argument list processing by setting AP to point to the
 * argument after pN.
 */
#ifdef	__GNUC__
/*
 * In GNU the stack is not necessarily arranged very neatly in order to
 * pack shorts and such into a smaller argument list. Fortunately a
 * neatly arranged version is available through the use of __builtin_next_arg.
 */
#define va_start(ap, pN)	\
	((ap) = ((va_list) __builtin_next_arg(pN)))
#else
/*
 * For a simple minded compiler this should work (it works in GNU too for
 * vararg lists that don't follow shorts and such).
 */
#define va_start(ap, pN)	\
	((ap) = ((va_list) (&pN) + __va_argsiz(pN)))
#endif


/*
 * End processing of variable argument list. In this case we do nothing.
 */
#define va_end(ap)	((void)0)


/*
 * Increment ap to the next argument in the list while returing a
 * pointer to what ap pointed to first, which is of type t.
 *
 * We cast to void* and then to t* because this avoids a warning about
 * increasing the alignment requirement.
 */

#define va_arg(ap, t)					\
	 (((ap) = (ap) + __va_argsiz(t)),		\
	  *((t*) (void*) ((ap) - __va_argsiz(t))))

#endif /* Not RC_INVOKED */

#endif /* not _STDARG_H_ */
