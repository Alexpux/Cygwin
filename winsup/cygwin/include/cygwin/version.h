/* version.h -- Cygwin version numbers and accompanying documentation.

   Copyright 1996, 1997, 1998, 1999 Cygnus Solutions.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

/* Cygwin versioning is relatively complicated because of its status
   as a shared library.  Let's start with how versioning used to be done.

   Historical versioning in Cygwin 16.0 to 19.5:

   In the olden days of Cygwin, we had a dll major and minor version
   and a registry version.  The major number started at 16 because the
   "b15" GNU-Win32 release of the compiler tools was out when this
   scheme was started.  We incremented the DLL name frequently (for
   every official release) and towards the end of this period every
   release used a different shared memory area to prevent DLLs from
   interfering with each other (embedding a build timestamp into the
   name of the shared memory area).  This turned out to be a Bad Idea
   (tm) because people needed to mingle separate releases and have
   them work together more than we thought they would.  This was
   especially problematic when tty info needed to be retained when an
   old Cygwin executable executed a newer one.

   In the old scheme, we incremented the major number whenever a
   change to the dll invalidated existing executables.  This can
   happen for a number of reasons, including when functions are
   removed from the export list of the dll.  The minor number was
   incremented when a change was made that we wanted to record, but
   that didn't invalidate existing executables.  Both numbers were
   recorded in the executable and in the dll.

   In October 1998 (starting with Cygwin 19.6), we started a new
   means of Cygwin versioning: */

      /* The DLL major and minor numbers correspond to the "version of
	 the Cygwin library".  This version is used to track important
	 changes to the DLL and is mainly informative in nature. */

  /* The current cygwin version is 1.1.0 */

#define CYGWIN_VERSION_DLL_MAJOR 1001
#define CYGWIN_VERSION_DLL_MINOR 0

      /* Major numbers before CYGWIN_VERSION_DLL_EPOCH are
	 incompatible. */

#define CYGWIN_VERSION_DLL_EPOCH 19

      /* CYGWIN_VERSION_DLL_COMBINED gives us a single number
	 representing the combined DLL major and minor numbers. */

#define CYGWIN_VERSION_DLL_MAKE_COMBINED(maj, min) (((maj) * 1000) + min)
#define CYGWIN_VERSION_DLL_COMBINED \
  CYGWIN_VERSION_DLL_MAKE_COMBINED (CYGWIN_DLL_VERSION_MAJOR, CYGWIN_DLL_VERSION_MINOR)

     /* Every version of cygwin <= this uses an old, incorrect method
	to determine signal masks. */

#define CYGWIN_VERSION_DLL_BAD_SIGNAL_MASK	19005

    /* API versions <= this had a termios structure whose members were
       too small to accomodate modern settings. */
#define CYGWIN_VERSION_DLL_OLD_TERMIOS		00005
#define CYGWIN_VERSION_DLL_IS_OLD_TERMIOS \
  (CYGWIN_VERSION_DLL_MAKE_COMBINED (user_data->api_major, user_data->api_minor) <= \
  CYGWIN_VERSION_DLL_OLD_TERMIOS)

     /* We used to use the DLL major/minor to track
	non-backward-compatible interface changes to the API.  Now we
	use an API major/minor number for this purpose. */

     /* API_MAJOR 0.0: Initial version.  API_MINOR changes:
	1: Export cygwin32_ calls as cygwin_ as well.
	2: Export j1, jn, y1, yn.
        3: Export dll_noncygwin_dllcrt0.
        4: New socket ioctls, revamped ifconf support.
        5: Thread support/exports.
        6: Change in termios handling.
        7: Export scandir and alphasort.
        8: Export _ctype_, _sys_errlist, _sys_nerr.
	9: Mount-related changes, new cygwin_umount export.
	   Raw device support (tape, floppies).
       10: Fast math routine support added.
       11: Export seekdir, telldir.
       12: Export pthread_join, pthread_detach.
       13: Export math funcs gamma and friends, also _j0, _j1, etc.
       14: Export snprintf and vnsprintf.
       15: Export glob
       16: Export cygwin_stackdump
       17: Export fast math stuff
     */

#define CYGWIN_VERSION_API_MAJOR 0
#define CYGWIN_VERSION_API_MINOR 17

     /* There is also a compatibity version number associated with the
	shared memory regions.  It is incremented when incompatible
	changes are made to the shared memory region *or* to any named
	shared mutexes, semaphores, etc.   The arbitrary starting
	version was 0 (cygwin release 98r2). */

#define CYGWIN_VERSION_SHARED_DATA 3

     /* An identifier used in the names used to create shared objects.
	The full names include the CYGWIN_VERSION_SHARED_DATA version
	as well as this identifier. */

#define CYGWIN_VERSION_DLL_IDENTIFIER	"cygwin1"

     /* The Cygwin mount table interface in the Win32 registry also
	has a version number associated with it in case that is
	changed in a non-backwards compatible fashion.  Increment this
	version number whenever incompatible changes in mount table
	registry usage are made.

	1: Original number version.
	2: New mount registry layout, system-wide mount accessibility.
     */

#define CYGWIN_VERSION_MOUNT_REGISTRY 2

     /* Identifiers used in the Win32 registry. */

#define CYGWIN_INFO_CYGNUS_REGISTRY_NAME "Cygnus Solutions"
#define CYGWIN_INFO_CYGWIN_REGISTRY_NAME "Cygwin"
#define CYGWIN_INFO_PROGRAM_OPTIONS_NAME "Program Options"
#define CYGWIN_INFO_CYGWIN_MOUNT_REGISTRY_NAME "mounts v2"

     /* In addition to the above version number strings, the build
	process adds some strings that may be useful in
	debugging/identifying a particular Cygwin DLL:

	The mkvers.sh script at the top level produces a .cc file
	which initializes a cygwin_version structure based on the
	above version information and creates a string table for
	grepping via "fgrep '%%%' cygwinwhatever.dll" if you are
	using GNU grep.  Otherwise you may want to do a
	"strings cygwinwhatever.dll | fgrep '%%%'" instead.

	This will produce output such as:

	%%% Cygwin dll_identifier: cygwin
	%%% Cygwin api_major: 0
	%%% Cygwin api_minor: 0
	%%% Cygwin dll_major: 19
	%%% Cygwin dll_minor: 6
	%%% Cygwin shared_data: 1
	%%% Cygwin registry: b15
	%%% Cygwin build date: Wed Oct 14 16:26:51 EDT 1998
	%%% Cygwin shared id: cygwinS1

	This information can also be obtained through a call to
	cygwin_internal (CW_GETVERSIONINFO).
     */

