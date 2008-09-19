/*
 * stdio.h
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is a part of the mingw-runtime package.
 * No warranty is given; refer to the file DISCLAIMER within the package.
 *
 * Definitions of types and prototypes of functions for standard input and
 * output.
 *
 * NOTE: The file manipulation functions provided by Microsoft seem to
 * work with either slash (/) or backslash (\) as the directory separator.
 *
 */

#ifndef _STDIO_H_
#define	_STDIO_H_

/* All the headers include this file. */
#include <_mingw.h>

#ifndef RC_INVOKED
#define __need_size_t
#define __need_NULL
#define __need_wchar_t
#define	__need_wint_t
#include <stddef.h>
#define __need___va_list
#include <stdarg.h>
#endif	/* Not RC_INVOKED */


/* Flags for the iobuf structure  */
#define	_IOREAD	1 /* currently reading */
#define	_IOWRT	2 /* currently writing */
#define	_IORW	0x0080 /* opened as "r+w" */


/*
 * The three standard file pointers provided by the run time library.
 * NOTE: These will go to the bit-bucket silently in GUI applications!
 */
#define	STDIN_FILENO	0
#define	STDOUT_FILENO	1
#define	STDERR_FILENO	2

/* Returned by various functions on end of file condition or error. */
#define	EOF	(-1)

/*
 * The maximum length of a file name. You should use GetVolumeInformation
 * instead of this constant. But hey, this works.
 * Also defined in io.h.
 */
#ifndef FILENAME_MAX
#define	FILENAME_MAX	(260)
#endif

/*
 * The maximum number of files that may be open at once. I have set this to
 * a conservative number. The actual value may be higher.
 */
#define FOPEN_MAX	(20)

/* After creating this many names, tmpnam and tmpfile return NULL */
#define TMP_MAX	32767
/*
 * Tmpnam, tmpfile and, sometimes, _tempnam try to create
 * temp files in the root directory of the current drive
 * (not in pwd, as suggested by some older MS doc's).
 * Redefining these macros does not effect the CRT functions.
 */
#define _P_tmpdir   "\\"
#ifndef __STRICT_ANSI__
#define P_tmpdir _P_tmpdir
#endif
#define _wP_tmpdir  L"\\"

/*
 * The maximum size of name (including NUL) that will be put in the user
 * supplied buffer caName for tmpnam.
 * Inferred from the size of the static buffer returned by tmpnam
 * when passed a NULL argument. May actually be smaller.
 */
#define L_tmpnam (16)

#define _IOFBF    0x0000  /* full buffered */
#define _IOLBF    0x0040  /* line buffered */
#define _IONBF    0x0004  /* not buffered */

#define _IOMYBUF  0x0008  /* stdio malloc()'d buffer */
#define _IOEOF    0x0010  /* EOF reached on read */
#define _IOERR    0x0020  /* I/O error from system */
#define _IOSTRG   0x0040  /* Strange or no file descriptor */
#ifdef _POSIX_SOURCE
# define _IOAPPEND 0x0200
#endif
/*
 * The buffer size as used by setbuf such that it is equivalent to
 * (void) setvbuf(fileSetBuffer, caBuffer, _IOFBF, BUFSIZ).
 */
#define	BUFSIZ	512

/* Constants for nOrigin indicating the position relative to which fseek
 * sets the file position.  Defined unconditionally since ISO and POSIX
 * say they are defined here.  */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#ifndef	RC_INVOKED

#ifndef __VALIST
#ifdef __GNUC__
#define __VALIST __gnuc_va_list
#else
#define __VALIST char*
#endif
#endif /* defined __VALIST  */

/*
 * The structure underlying the FILE type.
 *
 * Some believe that nobody in their right mind should make use of the
 * internals of this structure. Provided by Pedro A. Aranda Gutiirrez
 * <paag@tid.es>.
 */
#ifndef _FILE_DEFINED
#define	_FILE_DEFINED
typedef struct _iobuf
{
	char*	_ptr;
	int	_cnt;
	char*	_base;
	int	_flag;
	int	_file;
	int	_charbuf;
	int	_bufsiz;
	char*	_tmpfname;
} FILE;
#endif	/* Not _FILE_DEFINED */


/*
 * The standard file handles
 */
#ifndef __DECLSPEC_SUPPORTED

extern FILE (*_imp___iob)[];	/* A pointer to an array of FILE */

#define _iob	(*_imp___iob)	/* An array of FILE */

#else /* __DECLSPEC_SUPPORTED */

__MINGW_IMPORT FILE _iob[];	/* An array of FILE imported from DLL. */

#endif /* __DECLSPEC_SUPPORTED */

#define stdin	(&_iob[STDIN_FILENO])
#define stdout	(&_iob[STDOUT_FILENO])
#define stderr	(&_iob[STDERR_FILENO])

#ifdef __cplusplus
extern "C" {
#endif

/*
 * File Operations
 */
_CRTIMP FILE* __cdecl __MINGW_NOTHROW fopen (const char*, const char*);
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	freopen (const char*, const char*, FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	fflush (FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	fclose (FILE*);
/* MS puts remove & rename (but not wide versions) in io.h  also */
_CRTIMP int __cdecl __MINGW_NOTHROW	remove (const char*);
_CRTIMP int __cdecl __MINGW_NOTHROW	rename (const char*, const char*);
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	tmpfile (void);
_CRTIMP char* __cdecl __MINGW_NOTHROW	tmpnam (char*);

#ifndef __STRICT_ANSI__
_CRTIMP char* __cdecl __MINGW_NOTHROW	_tempnam (const char*, const char*);
_CRTIMP int __cdecl __MINGW_NOTHROW	_rmtmp(void);
_CRTIMP int __cdecl __MINGW_NOTHROW	_unlink (const char*);

#ifndef	NO_OLDNAMES
_CRTIMP char* __cdecl __MINGW_NOTHROW	tempnam (const char*, const char*);
_CRTIMP int __cdecl __MINGW_NOTHROW	rmtmp(void);
_CRTIMP int __cdecl __MINGW_NOTHROW	unlink (const char*);
#endif
#endif /* __STRICT_ANSI__ */

_CRTIMP int __cdecl __MINGW_NOTHROW	setvbuf (FILE*, char*, int, size_t);

_CRTIMP void __cdecl __MINGW_NOTHROW	setbuf (FILE*, char*);

/*
 * Formatted Output
 *
 * MSVCRT implementations are not ANSI C99 conformant...
 * we offer these conforming alternatives from libmingwex.a
 */
#undef  __mingw_stdio_redirect__
#define __mingw_stdio_redirect__(F) __cdecl __MINGW_NOTHROW __mingw_##F

extern int __mingw_stdio_redirect__(fprintf)(FILE*, const char*, ...);
extern int __mingw_stdio_redirect__(printf)(const char*, ...);
extern int __mingw_stdio_redirect__(sprintf)(char*, const char*, ...);
extern int __mingw_stdio_redirect__(snprintf)(char*, size_t, const char*, ...);
extern int __mingw_stdio_redirect__(vfprintf)(FILE*, const char*, __VALIST);
extern int __mingw_stdio_redirect__(vprintf)(const char*, __VALIST);
extern int __mingw_stdio_redirect__(vsprintf)(char*, const char*, __VALIST);
extern int __mingw_stdio_redirect__(vsnprintf)(char*, size_t, const char*, __VALIST);

#if __USE_MINGW_ANSI_STDIO
/*
 * User has expressed a preference for C99 conformance...
 */
# undef __mingw_stdio_redirect__
# ifdef __cplusplus
/*
 * For C++ we use inline implementations, to avoid interference
 * with namespace qualification, which may result from using #defines.
 */
#  define __mingw_stdio_redirect__  static inline __cdecl __MINGW_NOTHROW

# elif defined __GNUC__
/*
 * FIXME: Is there any GCC version prerequisite here?
 *
 * We also prefer inline implementations for C, when we can be confident
 * that the GNU specific __inline__ mechanism is supported.
 */
#  define __mingw_stdio_redirect__  static __inline__ __cdecl __MINGW_NOTHROW

# else
/*
 * Can't use inlines; fall back on module local static stubs.
 */
#  define __mingw_stdio_redirect__  static __cdecl __MINGW_NOTHROW
# endif

__mingw_stdio_redirect__
int fprintf (FILE *__stream, const char *__format, ...)
{
  register int __retval;
  __builtin_va_list __local_argv; __builtin_va_start( __local_argv, __format );
  __retval = __mingw_vfprintf( __stream, __format, __local_argv );
  __builtin_va_end( __local_argv );
  return __retval;
}

__mingw_stdio_redirect__
int printf (const char *__format, ...)
{
  register int __retval;
  __builtin_va_list __local_argv; __builtin_va_start( __local_argv, __format );
  __retval = __mingw_vprintf( __format, __local_argv );
  __builtin_va_end( __local_argv );
  return __retval;
}

__mingw_stdio_redirect__
int sprintf (char *__stream, const char *__format, ...)
{
  register int __retval;
  __builtin_va_list __local_argv; __builtin_va_start( __local_argv, __format );
  __retval = __mingw_vsprintf( __stream, __format, __local_argv );
  __builtin_va_end( __local_argv );
  return __retval;
}

__mingw_stdio_redirect__
int vfprintf (FILE *__stream, const char *__format, __VALIST __local_argv)
{
  return __mingw_vfprintf( __stream, __format, __local_argv );
}

__mingw_stdio_redirect__
int vprintf (const char *__format, __VALIST __local_argv)
{
  return __mingw_vprintf( __format, __local_argv );
}

__mingw_stdio_redirect__
int vsprintf (char *__stream, const char *__format, __VALIST __local_argv)
{
  return __mingw_vsprintf( __stream, __format, __local_argv );
}

#else
/*
 * Default configuration: simply direct all calls to MSVCRT...
 */
_CRTIMP int __cdecl __MINGW_NOTHROW fprintf (FILE*, const char*, ...);
_CRTIMP int __cdecl __MINGW_NOTHROW printf (const char*, ...);
_CRTIMP int __cdecl __MINGW_NOTHROW sprintf (char*, const char*, ...);
_CRTIMP int __cdecl __MINGW_NOTHROW vfprintf (FILE*, const char*, __VALIST);
_CRTIMP int __cdecl __MINGW_NOTHROW vprintf (const char*, __VALIST);
_CRTIMP int __cdecl __MINGW_NOTHROW vsprintf (char*, const char*, __VALIST);

#endif
/*
 * Regardless of user preference, always offer these alternative
 * entry points, for direct access to the MSVCRT implementations.
 */
#undef  __mingw_stdio_redirect__
#define __mingw_stdio_redirect__(F) __cdecl __MINGW_NOTHROW __msvcrt_##F

_CRTIMP int __mingw_stdio_redirect__(fprintf)(FILE*, const char*, ...);
_CRTIMP int __mingw_stdio_redirect__(printf)(const char*, ...);
_CRTIMP int __mingw_stdio_redirect__(sprintf)(char*, const char*, ...);
_CRTIMP int __mingw_stdio_redirect__(vfprintf)(FILE*, const char*, __VALIST);
_CRTIMP int __mingw_stdio_redirect__(vprintf)(const char*, __VALIST);
_CRTIMP int __mingw_stdio_redirect__(vsprintf)(char*, const char*, __VALIST);

#undef  __mingw_stdio_redirect__

/* The following pair ALWAYS refer to the MSVCRT implementations...
 */
_CRTIMP int __cdecl __MINGW_NOTHROW _snprintf (char*, size_t, const char*, ...);
_CRTIMP int __cdecl __MINGW_NOTHROW _vsnprintf (char*, size_t, const char*, __VALIST);

#ifndef __NO_ISOCEXT  /* externs in libmingwex.a */
/*
 * Microsoft does not provide implementations for the following,
 * which are required by C99.  Note in particular that the corresponding
 * Microsoft implementations of _snprintf() and _vsnprintf() are *not*
 * compatible with C99, but the following are; if you want the MSVCRT
 * behaviour, you *must* use the Microsoft uglified names.
 */
int __cdecl __MINGW_NOTHROW snprintf (char *, size_t, const char *, ...);
int __cdecl __MINGW_NOTHROW vsnprintf (char *, size_t, const char *, __VALIST);

int __cdecl __MINGW_NOTHROW vscanf (const char * __restrict__, __VALIST);
int __cdecl __MINGW_NOTHROW vfscanf (FILE * __restrict__, const char * __restrict__,
		     __VALIST);
int __cdecl __MINGW_NOTHROW vsscanf (const char * __restrict__,
		     const char * __restrict__, __VALIST);

#endif  /* !__NO_ISOCEXT */

/*
 * Formatted Input
 */

_CRTIMP int __cdecl __MINGW_NOTHROW	fscanf (FILE*, const char*, ...);
_CRTIMP int __cdecl __MINGW_NOTHROW	scanf (const char*, ...);
_CRTIMP int __cdecl __MINGW_NOTHROW	sscanf (const char*, const char*, ...);
/*
 * Character Input and Output Functions
 */

_CRTIMP int __cdecl __MINGW_NOTHROW	fgetc (FILE*);
_CRTIMP char* __cdecl __MINGW_NOTHROW	fgets (char*, int, FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	fputc (int, FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	fputs (const char*, FILE*);
_CRTIMP char* __cdecl __MINGW_NOTHROW	gets (char*);
_CRTIMP int __cdecl __MINGW_NOTHROW	puts (const char*);
_CRTIMP int __cdecl __MINGW_NOTHROW	ungetc (int, FILE*);

/* Traditionally, getc and putc are defined as macros. but the
   standard doesn't say that they must be macros.
   We use inline functions here to allow the fast versions
   to be used in C++ with namespace qualification, eg., ::getc.

   _filbuf and _flsbuf  are not thread-safe. */
_CRTIMP int __cdecl __MINGW_NOTHROW	_filbuf (FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	_flsbuf (int, FILE*);

#if !defined _MT

__CRT_INLINE int __cdecl __MINGW_NOTHROW getc (FILE* __F)
{
  return (--__F->_cnt >= 0)
    ?  (int) (unsigned char) *__F->_ptr++
    : _filbuf (__F);
}

__CRT_INLINE int __cdecl __MINGW_NOTHROW putc (int __c, FILE* __F)
{
  return (--__F->_cnt >= 0)
    ?  (int) (unsigned char) (*__F->_ptr++ = (char)__c)
    :  _flsbuf (__c, __F);
}

__CRT_INLINE int __cdecl __MINGW_NOTHROW getchar (void)
{
  return (--stdin->_cnt >= 0)
    ?  (int) (unsigned char) *stdin->_ptr++
    : _filbuf (stdin);
}

__CRT_INLINE int __cdecl __MINGW_NOTHROW putchar(int __c)
{
  return (--stdout->_cnt >= 0)
    ?  (int) (unsigned char) (*stdout->_ptr++ = (char)__c)
    :  _flsbuf (__c, stdout);}

#else  /* Use library functions.  */

_CRTIMP int __cdecl __MINGW_NOTHROW	getc (FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	putc (int, FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	getchar (void);
_CRTIMP int __cdecl __MINGW_NOTHROW	putchar (int);

#endif

/*
 * Direct Input and Output Functions
 */

_CRTIMP size_t __cdecl __MINGW_NOTHROW	fread (void*, size_t, size_t, FILE*);
_CRTIMP size_t __cdecl __MINGW_NOTHROW	fwrite (const void*, size_t, size_t, FILE*);

/*
 * File Positioning Functions
 */

_CRTIMP int __cdecl __MINGW_NOTHROW	fseek (FILE*, long, int);
_CRTIMP long __cdecl __MINGW_NOTHROW	ftell (FILE*);
_CRTIMP void __cdecl __MINGW_NOTHROW	rewind (FILE*);

#if __MSVCRT_VERSION__ >= 0x800
_CRTIMP int __cdecl __MINGW_NOTHROW	_fseek_nolock (FILE*, long, int);
_CRTIMP long __cdecl __MINGW_NOTHROW	_ftell_nolock (FILE*);

_CRTIMP int __cdecl __MINGW_NOTHROW	_fseeki64 (FILE*, __int64, int);
_CRTIMP __int64 __cdecl __MINGW_NOTHROW	_ftelli64 (FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	_fseeki64_nolock (FILE*, __int64, int);
_CRTIMP __int64 __cdecl __MINGW_NOTHROW	_ftelli64_nolock (FILE*);
#endif

#ifdef __USE_MINGW_FSEEK  /* These are in libmingwex.a */
/*
 * Workaround for limitations on win9x where a file contents are
 * not zero'd out if you seek past the end and then write.
 */

int __cdecl __MINGW_NOTHROW __mingw_fseek (FILE *, long, int);
size_t __cdecl __MINGW_NOTHROW __mingw_fwrite (const void*, size_t, size_t, FILE*);
#define fseek(fp, offset, whence)  __mingw_fseek(fp, offset, whence)
#define fwrite(buffer, size, count, fp)  __mingw_fwrite(buffer, size, count, fp)
#endif /* __USE_MINGW_FSEEK */

/*
 * An opaque data type used for storing file positions... The contents of
 * this type are unknown, but we (the compiler) need to know the size
 * because the programmer using fgetpos and fsetpos will be setting aside
 * storage for fpos_t structres. Actually I tested using a byte array and
 * it is fairly evident that the fpos_t type is a long (in CRTDLL.DLL).
 * Perhaps an unsigned long? TODO? It's definitely a 64-bit number in
 * MSVCRT however, and for now `long long' will do.
 */
#ifdef __MSVCRT__
typedef long long fpos_t;
#else
typedef long	fpos_t;
#endif

_CRTIMP int __cdecl __MINGW_NOTHROW	fgetpos	(FILE*, fpos_t*);
_CRTIMP int __cdecl __MINGW_NOTHROW	fsetpos (FILE*, const fpos_t*);

/*
 * Error Functions
 */

_CRTIMP int __cdecl __MINGW_NOTHROW	feof (FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	ferror (FILE*);

#ifdef __cplusplus
inline int __cdecl __MINGW_NOTHROW feof (FILE* __F)
  { return __F->_flag & _IOEOF; }
inline int __cdecl __MINGW_NOTHROW ferror (FILE* __F)
  { return __F->_flag & _IOERR; }
#else
#define feof(__F)     ((__F)->_flag & _IOEOF)
#define ferror(__F)   ((__F)->_flag & _IOERR)
#endif

_CRTIMP void __cdecl __MINGW_NOTHROW	clearerr (FILE*);
_CRTIMP void __cdecl __MINGW_NOTHROW	perror (const char*);


#ifndef __STRICT_ANSI__
/*
 * Pipes
 */
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	_popen (const char*, const char*);
_CRTIMP int __cdecl __MINGW_NOTHROW	_pclose (FILE*);

#ifndef NO_OLDNAMES
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	popen (const char*, const char*);
_CRTIMP int __cdecl __MINGW_NOTHROW	pclose (FILE*);
#endif

/*
 * Other Non ANSI functions
 */
_CRTIMP int __cdecl __MINGW_NOTHROW	_flushall (void);
_CRTIMP int __cdecl __MINGW_NOTHROW	_fgetchar (void);
_CRTIMP int __cdecl __MINGW_NOTHROW	_fputchar (int);
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	_fdopen (int, const char*);
_CRTIMP int __cdecl __MINGW_NOTHROW	_fileno (FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	_fcloseall (void);
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	_fsopen (const char*, const char*, int);
#ifdef __MSVCRT__
_CRTIMP int __cdecl __MINGW_NOTHROW	_getmaxstdio (void);
_CRTIMP int __cdecl __MINGW_NOTHROW	_setmaxstdio (int);
#endif

#if __MSVCRT_VERSION__ >= 0x800
_CRTIMP unsigned int __cdecl __MINGW_NOTHROW _get_output_format (void);
_CRTIMP unsigned int __cdecl __MINGW_NOTHROW _set_output_format (unsigned int);

#define _TWO_DIGIT_EXPONENT  1

_CRTIMP int __cdecl __MINGW_NOTHROW _get_printf_count_output (void);
_CRTIMP int __cdecl __MINGW_NOTHROW _set_printf_count_output (int);
#endif

#ifndef _NO_OLDNAMES
_CRTIMP int __cdecl __MINGW_NOTHROW	fgetchar (void);
_CRTIMP int __cdecl __MINGW_NOTHROW	fputchar (int);
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	fdopen (int, const char*);
_CRTIMP int __cdecl __MINGW_NOTHROW	fileno (FILE*);
#endif	/* Not _NO_OLDNAMES */

#define _fileno(__F) ((__F)->_file)
#ifndef _NO_OLDNAMES
#define fileno(__F) ((__F)->_file)
#endif

#if defined (__MSVCRT__) && !defined (__NO_MINGW_LFS)
#include <sys/types.h>
__CRT_INLINE FILE* __cdecl __MINGW_NOTHROW fopen64 (const char* filename, const char* mode)
{
  return fopen (filename, mode); 
}

int __cdecl __MINGW_NOTHROW fseeko64 (FILE*, off64_t, int);

#ifdef __USE_MINGW_FSEEK
int __cdecl __MINGW_NOTHROW __mingw_fseeko64 (FILE *, off64_t, int);
#define fseeko64(fp, offset, whence)  __mingw_fseeko64(fp, offset, whence)
#endif

__CRT_INLINE off64_t __cdecl __MINGW_NOTHROW ftello64 (FILE * stream)
{
  fpos_t pos;
  if (fgetpos(stream, &pos))
    return  -1LL;
  else
   return ((off64_t) pos);
}
#endif /* __NO_MINGW_LFS */

#endif	/* Not __STRICT_ANSI__ */

/* Wide  versions */

#ifndef _WSTDIO_DEFINED
/*  also in wchar.h - keep in sync */
_CRTIMP int __cdecl __MINGW_NOTHROW	fwprintf (FILE*, const wchar_t*, ...);
_CRTIMP int __cdecl __MINGW_NOTHROW	wprintf (const wchar_t*, ...);
_CRTIMP int __cdecl __MINGW_NOTHROW	_snwprintf (wchar_t*, size_t, const wchar_t*, ...);
_CRTIMP int __cdecl __MINGW_NOTHROW	vfwprintf (FILE*, const wchar_t*, __VALIST);
_CRTIMP int __cdecl __MINGW_NOTHROW	vwprintf (const wchar_t*, __VALIST);
_CRTIMP int __cdecl __MINGW_NOTHROW	_vsnwprintf (wchar_t*, size_t, const wchar_t*, __VALIST);
_CRTIMP int __cdecl __MINGW_NOTHROW	fwscanf (FILE*, const wchar_t*, ...);
_CRTIMP int __cdecl __MINGW_NOTHROW	wscanf (const wchar_t*, ...);
_CRTIMP int __cdecl __MINGW_NOTHROW	swscanf (const wchar_t*, const wchar_t*, ...);
_CRTIMP wint_t __cdecl __MINGW_NOTHROW	fgetwc (FILE*);
_CRTIMP wint_t __cdecl __MINGW_NOTHROW	fputwc (wchar_t, FILE*);
_CRTIMP wint_t __cdecl __MINGW_NOTHROW	ungetwc (wchar_t, FILE*);

/* These differ from the ISO C prototypes, which have a maxlen parameter (like snprintf).  */
#ifndef __STRICT_ANSI__
_CRTIMP int __cdecl __MINGW_NOTHROW	swprintf (wchar_t*, const wchar_t*, ...);
_CRTIMP int __cdecl __MINGW_NOTHROW	vswprintf (wchar_t*, const wchar_t*, __VALIST);
#endif

#ifdef __MSVCRT__ 
_CRTIMP wchar_t* __cdecl __MINGW_NOTHROW fgetws (wchar_t*, int, FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	fputws (const wchar_t*, FILE*);
_CRTIMP wint_t __cdecl __MINGW_NOTHROW	getwc (FILE*);
_CRTIMP wint_t __cdecl __MINGW_NOTHROW	getwchar (void);
_CRTIMP wchar_t* __cdecl __MINGW_NOTHROW _getws (wchar_t*);
_CRTIMP wint_t __cdecl __MINGW_NOTHROW	putwc (wint_t, FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	_putws (const wchar_t*);
_CRTIMP wint_t __cdecl __MINGW_NOTHROW	putwchar (wint_t);
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	_wfdopen(int, const wchar_t *);
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	_wfopen (const wchar_t*, const wchar_t*);
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	_wfreopen (const wchar_t*, const wchar_t*, FILE*);
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	_wfsopen (const wchar_t*, const wchar_t*, int);
_CRTIMP wchar_t* __cdecl __MINGW_NOTHROW _wtmpnam (wchar_t*);
_CRTIMP wchar_t* __cdecl __MINGW_NOTHROW _wtempnam (const wchar_t*, const wchar_t*);
_CRTIMP int __cdecl __MINGW_NOTHROW	_wrename (const wchar_t*, const wchar_t*);
_CRTIMP int __cdecl __MINGW_NOTHROW	_wremove (const wchar_t*);
_CRTIMP void __cdecl __MINGW_NOTHROW	_wperror (const wchar_t*);
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	_wpopen (const wchar_t*, const wchar_t*);
#endif	/* __MSVCRT__ */

#ifndef __NO_ISOCEXT  /* externs in libmingwex.a */
int __cdecl __MINGW_NOTHROW snwprintf (wchar_t* s, size_t n, const wchar_t*  format, ...);
__CRT_INLINE int __cdecl __MINGW_NOTHROW
vsnwprintf (wchar_t* s, size_t n, const wchar_t* format, __VALIST arg)
  { return _vsnwprintf ( s, n, format, arg);}
int __cdecl __MINGW_NOTHROW vwscanf (const wchar_t * __restrict__, __VALIST);
int __cdecl __MINGW_NOTHROW vfwscanf (FILE * __restrict__,
		       const wchar_t * __restrict__, __VALIST);
int __cdecl __MINGW_NOTHROW vswscanf (const wchar_t * __restrict__,
		       const wchar_t * __restrict__, __VALIST);
#endif

#define _WSTDIO_DEFINED
#endif /* _WSTDIO_DEFINED */

#ifndef __STRICT_ANSI__
#ifdef __MSVCRT__
#ifndef NO_OLDNAMES
_CRTIMP FILE* __cdecl __MINGW_NOTHROW	wpopen (const wchar_t*, const wchar_t*);
#endif /* not NO_OLDNAMES */
#endif /* MSVCRT runtime */

/*
 * Other Non ANSI wide functions
 */
_CRTIMP wint_t __cdecl __MINGW_NOTHROW	_fgetwchar (void);
_CRTIMP wint_t __cdecl __MINGW_NOTHROW	_fputwchar (wint_t);
_CRTIMP int __cdecl __MINGW_NOTHROW	_getw (FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	_putw (int, FILE*);

#ifndef _NO_OLDNAMES
_CRTIMP wint_t __cdecl __MINGW_NOTHROW	fgetwchar (void);
_CRTIMP wint_t __cdecl __MINGW_NOTHROW	fputwchar (wint_t);
_CRTIMP int __cdecl __MINGW_NOTHROW	getw (FILE*);
_CRTIMP int __cdecl __MINGW_NOTHROW	putw (int, FILE*);
#endif	/* Not _NO_OLDNAMES */

#endif /* __STRICT_ANSI */

#ifdef __cplusplus
}
#endif

#endif	/* Not RC_INVOKED */

#endif /* _STDIO_H_ */
