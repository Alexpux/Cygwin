/* syslog.cc

   Copyright 1996, 1997, 1998 Cygnus Solutions.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>
#include "fhandler.h"
#include "dtable.h"
#include "cygerrno.h"
#include "cygheap.h"
#include "thread.h"

/* FIXME: These should probably be in the registry. */
/* FIXME: The Win95 path should be whatever slash is */

#define WIN95_EVENT_LOG_PATH "C:\\CYGWIN_SYSLOG.TXT"
#define CYGWIN_LOG_NAME "Cygwin"

/*
 * Utility function to help enable moving
 * WIN95_EVENT_LOG_PATH into registry later.
 */
static const char *
get_win95_event_log_path ()
{
  return WIN95_EVENT_LOG_PATH;
}

/* FIXME: For MT safe code these will need to be replaced */

#ifdef _MT_SAFE
#define process_ident  _reent_winsup()->_process_ident
#define process_logopt  _reent_winsup()->_process_logopt
#define process_facility  _reent_winsup()->_process_facility
  /* Default priority logmask */
#define process_logmask _reent_winsup()->_process_logmask
#else
static char *process_ident = 0;
static int process_logopt = 0;
static int process_facility = 0;

/* Default priority logmask */
static int process_logmask = LOG_UPTO (LOG_DEBUG);
#endif

/*
 * openlog: save the passed args. Don't open the
 * system log (NT) or log file (95) yet.
 */
extern "C"
void
openlog (const char *ident, int logopt, int facility)
{
    debug_printf ("openlog called with (%s, %d, %d)",
		       ident ? ident : "<NULL>", logopt, facility);

    if (process_ident != NULL)
      {
	free (process_ident);
	process_ident = 0;
      }
    if (ident)
      {
	process_ident = (char *) malloc (strlen (ident) + 1);
	if (process_ident == NULL)
	  {
	    debug_printf ("failed to allocate memory for process_ident");
	    return;
	  }
	strcpy (process_ident, ident);
      }
    process_logopt = logopt;
    process_facility = facility;
}

/* setlogmask: set the log priority mask and return previous mask.
   If maskpri is zero, just return previous. */
int
setlogmask (int maskpri)
{
  if (maskpri == 0)
    return process_logmask;

  int old_mask = process_logmask;
  process_logmask = maskpri & LOG_PRIMASK;

  return old_mask;
}

/* Private class used to handle formatting of syslog message */
/* It is named pass_handler because it does a two-pass handling of log
   strings.  The first pass counts the length of the string, and the second
   one builds the string. */

class pass_handler
{
  private:
    FILE *fp_;
    char *message_;
    int total_len_;

    void shutdown ();

    /* Explicitly disallow copies */
    pass_handler (const pass_handler &);
    pass_handler & operator = (const pass_handler &);

  public:
    pass_handler ();
    ~pass_handler ();

    int initialize (int);

    int print (const char *,...);
    int print_va (const char *, va_list);
    char *get_message () const { return message_; }
    void set_message (char *s) { message_ = s; *message_ = '\0'; }
};

pass_handler::pass_handler () : fp_ (0), message_ (0), total_len_ (0)
{
  ;
}

pass_handler::~pass_handler ()
{
  shutdown ();
}

void
pass_handler::shutdown ()
{
  if (fp_ != NULL)
    {
      fclose (fp_);
      fp_ = 0;
    }
}

int
pass_handler::initialize (int pass_number)
{
    shutdown ();
    if (pass_number)
      return total_len_ + 1;

    fp_ = fopen ("/dev/null", "wb");
    if (fp_ == NULL)
      {
	debug_printf ("failed to open /dev/null");
	return -1;
      }
    total_len_ = 0;
    return 0;
}

int
pass_handler::print (const char *fmt, ...)
{
    va_list ap;
    va_start (ap, fmt);
    int ret = print_va (fmt, ap);
    va_end (ap);
    return ret;
}

int
pass_handler::print_va (const char *fmt, va_list list)
{
    if (fp_ != NULL)
      {
	int len = vfprintf (fp_, fmt, list);
	if (len < 0)
	  return -1;
	total_len_ += len;
	return 0;
      }
    else if (message_ != NULL)
      {
	char *printpos = &message_[strlen (message_)];
	vsprintf (printpos, fmt, list);
	return 0;
      }
    debug_printf ("FAILURE ! fp_ and message_ both 0!! ");
    return -1;
}

/*
 * syslog: creates the log message and writes to system
 * log (NT) or log file (95). FIXME. WinNT log error messages
 * don't look pretty, but in order to fix this we have to
 * embed resources in the code and tell the NT registry
 * where we are, blech (what happens if we move ?).
 * We could, however, add the resources in Cygwin and
 * always point to that.
 */

extern "C"
void
syslog (int priority, const char *message, ...)
{
    debug_printf ("%x %s", priority, message);
    /* If the priority fails the current mask, reject */
    if (((priority & LOG_PRIMASK) & process_logmask) == 0)
      {
	debug_printf ("failing message %x due to priority mask %x",
		      priority, process_logmask);
	return;
      }

    /* Translate %m in the message to error text */
    char *errtext = strerror (get_errno ());
    int errlen = strlen (errtext);
    int numfound = 0;

    for (const char *cp = message; *cp; cp++)
      if (*cp == '%' && cp[1] == 'm')
	numfound++;

    char *newmessage = (char *) alloca (strlen (message) +
					(errlen * numfound) + 1);

    if (newmessage == NULL)
      {
	debug_printf ("failed to allocate newmessage");
	return;
      }

    char *dst = newmessage;
    for (const char *cp2 = message; *cp2; cp2++)
      if (*cp2 == '%' && cp2[1] == 'm')
	{
	  cp2++;
	  strcpy (dst, errtext);
	  while (*dst)
	    dst++;
	}
      else
	*dst++ = *cp2;

    *dst = '\0';
    message = newmessage;

    /* Work out the priority type - we ignore the facility for now.. */
    WORD eventType;
    switch (LOG_PRI (priority))
      {
      case LOG_ERR:
	eventType = EVENTLOG_ERROR_TYPE;
	break;
      case LOG_WARNING:
	eventType = EVENTLOG_WARNING_TYPE;
	break;
      case LOG_INFO:
	eventType = EVENTLOG_INFORMATION_TYPE;
	break;
      default:
	eventType = EVENTLOG_ERROR_TYPE;
	break;
      }

    /* We need to know how long the buffer needs to be.
       The only legal way I can see of doing this is to
       do a vfprintf to /dev/null, and count the bytes
       output, then do it again to a malloc'ed string. This
       is ugly, slow, but prevents core dumps :-).
     */
    va_list ap;

    pass_handler pass;
    for (int pass_number = 0; pass_number < 2; ++pass_number)
      {
	int n = pass.initialize (pass_number);
	if (n == -1)
	  return;
	else if (n > 0)
	  pass.set_message ((char *) alloca (n));

	/* Deal with ident_string */
	if (process_ident != NULL)
	  {
	    if (pass.print ("%s : ", process_ident) == -1)
	      return;
	  }
	if (process_logopt & LOG_PID)
	  {
	    if (pass.print ("Win32 Process Id = 0x%X : Cygwin Process Id = 0x%X : ",
			GetCurrentProcessId(),  getpid ()) == -1)
	      return;
	  }

	if (os_being_run != winNT)
	  {
	    /* Add a priority string - not needed for NT
	       as NT has its own priority codes. */
	    switch (LOG_PRI (priority))
	      {
	      case LOG_ERR:
		pass.print ("%s : ", "LOG_ERR");
		break;
	      case LOG_WARNING:
		pass.print ("%s : ", "LOG_WARNING");
		break;
	      case LOG_INFO:
		pass.print ("%s : ", "LOG_INFO");
		break;
	      default:
		pass.print ("%s : ", "LOG_ERR");
		break;
	      }
	  }

	/* Print out the variable part */
	va_start (ap, message);
	if (pass.print_va (message, ap) == -1)
	  return;
	va_end (ap);

      }
    const char *msg_strings[1];
    char *total_msg = pass.get_message ();
    int len = strlen (total_msg);
    if (len != 0 && (total_msg[len - 1] == '\n'))
      total_msg[len - 1] = '\0';

    msg_strings[0] = total_msg;

    if (os_being_run == winNT)
      {
	/* For NT, open the event log and send the message */
	HANDLE hEventSrc = RegisterEventSourceA (NULL, (process_ident != NULL) ?
					 process_ident : CYGWIN_LOG_NAME);
	if (hEventSrc == NULL)
	  {
	    debug_printf ("RegisterEventSourceA failed with %E");
	    return;
	  }
	ReportEventA (hEventSrc, eventType, 0, 0,
		      cygheap->user.sid (), 1, 0, msg_strings, NULL);
	DeregisterEventSource (hEventSrc);
      }
    else
      {
	/* Under Windows 95, append the message to the log file */
	FILE *fp = fopen (get_win95_event_log_path (), "a");
	if (fp == NULL)
	  {
	    debug_printf ("failed to open file %s",
			  get_win95_event_log_path ());
	    return;
	  }
	/* Now to prevent several syslog messages from being
	   interleaved, we must lock the first byte of the file
	   This works on Win32 even if we created the file above.
	*/
	HANDLE fHandle = cygheap->fdtab[fileno (fp)]->get_handle ();
	if (LockFile (fHandle, 0, 0, 1, 0) == FALSE)
	  {
	    debug_printf ("failed to lock file %s", get_win95_event_log_path());
	    fclose (fp);
	    return;
	  }
	fputs (msg_strings[0], fp);
	fputc ('\n', fp);
	UnlockFile (fHandle, 0, 0, 1, 0);
	if (ferror (fp))
	  {
	    debug_printf ("error in writing syslog");
	  }
	fclose (fp);
      }
}

extern "C"
void
closelog (void)
{
  ;
}
