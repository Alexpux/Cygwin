/*
 * DIRENT.H (formerly DIRLIB.H)
 *
 * by M. J. Weinstein   Released to public domain 1-Jan-89
 *
 * Because I have heard that this feature (opendir, readdir, closedir)
 * it so useful for programmers coming from UNIX or attempting to port
 * UNIX code, and because it is reasonably light weight, I have included
 * it in the Mingw32 package. I have also added an implementation of
 * rewinddir, seekdir and telldir.
 *   - Colin Peters <colin@bird.fu.is.saga-u.ac.jp>
 *
 *  This code is distributed in the hope that is will be useful but
 *  WITHOUT ANY WARRANTY. ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 *  DISCLAIMED. This includeds but is not limited to warranties of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * $Revision$
 * $Author$
 * $Date$
 *
 */
#ifndef _DIRENT_H_
#define _DIRENT_H_

/* All the headers include this file. */
#include <_mingw.h>

#include <io.h>

#ifndef RC_INVOKED

#ifdef __cplusplus
extern "C" {
#endif

struct dirent
{
	long		d_ino;		/* Always zero. */
	unsigned short	d_reclen;	/* Always zero. */
	unsigned short	d_namlen;	/* Length of name in d_name. */
	char		d_name[FILENAME_MAX]; /* File name. */
};

/*
 * This is an internal data structure. Good programmers will not use it
 * except as an argument to one of the functions below.
 * dd_stat field is now int (was short in older versions).
 */
typedef struct
{
	/* disk transfer area for this dir */
	struct _finddata_t	dd_dta;

	/* dirent struct to return from dir (NOTE: this makes this thread
	 * safe as long as only one thread uses a particular DIR struct at
	 * a time) */
	struct dirent		dd_dir;

	/* _findnext handle */
	long			dd_handle;

	/*
         * Status of search:
	 *   0 = not started yet (next entry to read is first entry)
	 *  -1 = off the end
	 *   positive = 0 based index of next entry
	 */
	int			dd_stat;

	/* given path for dir with search pattern (struct is extended) */
	char			dd_name[1];
} DIR;

DIR* __cdecl opendir (const char*);
struct dirent* __cdecl readdir (DIR*);
int __cdecl closedir (DIR*);
void __cdecl rewinddir (DIR*);
long __cdecl telldir (DIR*);
void __cdecl seekdir (DIR*, long);


/* wide char versions */

struct _wdirent
{
	long		d_ino;		/* Always zero. */
	unsigned short	d_reclen;	/* Always zero. */
	unsigned short	d_namlen;	/* Length of name in d_name. */
	wchar_t		d_name[FILENAME_MAX]; /* File name. */
	/* NOTE: The name in the dirent structure points to the name in the	 *       wfinddata_t structure in the _WDIR. */
};

/*
 * This is an internal data structure. Good programmers will not use it
 * except as an argument to one of the functions below.
 */
typedef struct
{
	/* disk transfer area for this dir */
	struct _wfinddata_t	dd_dta;

	/* dirent struct to return from dir (NOTE: this makes this thread
	 * safe as long as only one thread uses a particular DIR struct at
	 * a time) */
	struct _wdirent		dd_dir;

	/* _findnext handle */
	long			dd_handle;

	/*
         * Status of search:
	 *   0 = not started yet (next entry to read is first entry)
	 *  -1 = off the end
	 *   positive = 0 based index of next entry
	 */
	int			dd_stat;

	/* given path for dir with search pattern (struct is extended) */
	wchar_t			dd_name[1];
} _WDIR;



_WDIR* __cdecl _wopendir (const wchar_t*);
struct _wdirent*  __cdecl _wreaddir (_WDIR*);
int __cdecl _wclosedir (_WDIR*);
void __cdecl _wrewinddir (_WDIR*);
long __cdecl _wtelldir (_WDIR*);
void __cdecl _wseekdir (_WDIR*, long);


#ifdef	__cplusplus
}
#endif

#endif	/* Not RC_INVOKED */

#endif	/* Not _DIRENT_H_ */
