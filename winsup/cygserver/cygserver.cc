/* cygserver.cc

   Copyright 2001, 2002, 2003, 2004, 2005 Red Hat Inc.

   Written by Egor Duda <deo@logos-m.ru>

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifdef __OUTSIDE_CYGWIN__
#include "woutsup.h"

#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cygwin_version.h"

#include "cygserver.h"
#include "process.h"
#include "transport.h"

#include "cygserver_ipc.h"
#include "cygserver_msg.h"
#include "cygserver_sem.h"

#define DEF_CONFIG_FILE	"" SYSCONFDIR "/cygserver.conf"

#define SERVER_VERSION	"1.12"

GENERIC_MAPPING access_mapping;

static bool
setup_privileges ()
{
  BOOL rc, ret_val;
  HANDLE hToken = NULL;
  TOKEN_PRIVILEGES sPrivileges;

  rc = OpenProcessToken (GetCurrentProcess () , TOKEN_ALL_ACCESS , &hToken) ;
  if (!rc)
    {
      debug ("error opening process token (%lu)", GetLastError ());
      return false;
    }
  rc = LookupPrivilegeValue (NULL, SE_DEBUG_NAME, &sPrivileges.Privileges[0].Luid);
  if (!rc)
    {
      debug ("error getting privilege luid (%lu)", GetLastError ());
      ret_val = false;
      goto out;
    }
  sPrivileges.PrivilegeCount = 1 ;
  sPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED ;
  rc = AdjustTokenPrivileges (hToken, FALSE, &sPrivileges, 0, NULL, NULL) ;
  if (!rc)
    {
      debug ("error adjusting privilege level. (%lu)", GetLastError ());
      ret_val = false;
      goto out;
    }

  access_mapping.GenericRead = FILE_READ_DATA;
  access_mapping.GenericWrite = FILE_WRITE_DATA;
  access_mapping.GenericExecute = 0;
  access_mapping.GenericAll = FILE_READ_DATA | FILE_WRITE_DATA;

  ret_val = true;

out:
  CloseHandle (hToken);
  return ret_val;
}

int
check_and_dup_handle (HANDLE from_process, HANDLE to_process,
		      HANDLE from_process_token,
		      DWORD access,
		      HANDLE from_handle,
		      HANDLE *to_handle_ptr, BOOL bInheritHandle = FALSE)
{
  HANDLE local_handle = NULL;
  int ret_val = EACCES;

  if (from_process != GetCurrentProcess ())
    {
      if (!DuplicateHandle (from_process, from_handle,
			    GetCurrentProcess (), &local_handle,
			    0, bInheritHandle,
			    DUPLICATE_SAME_ACCESS))
	{
	  log (LOG_ERR, "error getting handle(%u) to server (%lu)",
			 (unsigned int)from_handle, GetLastError ());
	  goto out;
	}
    } else
      local_handle = from_handle;

  if (!wincap.has_security ())
    assert (!from_process_token);
  else
    {
      char sd_buf [1024];
      PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR) &sd_buf;
      DWORD bytes_needed;
      PRIVILEGE_SET ps;
      DWORD ps_len = sizeof (ps);
      BOOL status;

      if (!GetKernelObjectSecurity (local_handle,
				    (OWNER_SECURITY_INFORMATION
				     | GROUP_SECURITY_INFORMATION
				     | DACL_SECURITY_INFORMATION),
				    sd, sizeof (sd_buf), &bytes_needed))
	{
	  log (LOG_ERR, "error getting handle SD (%lu)", GetLastError ());
	  goto out;
	}

      MapGenericMask (&access, &access_mapping);

      if (!AccessCheck (sd, from_process_token, access, &access_mapping,
			&ps, &ps_len, &access, &status))
	{
	  log (LOG_ERR, "error checking access rights (%lu)",
			 GetLastError ());
	  goto out;
	}

      if (!status)
	{
	  log (LOG_ERR, "access to object denied");
	  goto out;
	}
    }

  if (!DuplicateHandle (from_process, from_handle,
			to_process, to_handle_ptr,
			access, bInheritHandle, 0))
    {
      log (LOG_ERR, "error getting handle to client (%lu)", GetLastError ());
      goto out;
    }

  debug ("Duplicated %p to %p", from_handle, *to_handle_ptr);

  ret_val = 0;

 out:
  if (local_handle && from_process != GetCurrentProcess ())
    CloseHandle (local_handle);

  return (ret_val);
}

/*
 * client_request_attach_tty::serve ()
 */

void
client_request_attach_tty::serve (transport_layer_base *const conn,
				  process_cache *)
{
  assert (conn);

  assert (!error_code ());

  if (!wincap.has_security ())
    {
      log (LOG_NOTICE, "operation only supported on systems with security");
      error_code (EINVAL);
      msglen (0);
      return;
    }

  if (msglen () != sizeof (req))
    {
      log (LOG_ERR, "bad request body length: expecting %lu bytes, got %lu",
		      sizeof (req), msglen ());
      error_code (EINVAL);
      msglen (0);
      return;
    }

  msglen (0);			// Until we fill in some fields.

  debug ("pid %ld:(%p,%p) -> pid %ld", req.master_pid, req.from_master,
				       req.to_master, req.pid);

  debug ("opening process %ld", req.master_pid);

  const HANDLE from_process_handle =
    OpenProcess (PROCESS_DUP_HANDLE, FALSE, req.master_pid);

  if (!from_process_handle)
    {
      log (LOG_ERR, "error opening `from' process, error = %lu",
		     GetLastError ());
      error_code (EACCES);
      return;
    }

  debug ("opening process %ld", req.pid);

  const HANDLE to_process_handle =
    OpenProcess (PROCESS_DUP_HANDLE, FALSE, req.pid);

  if (!to_process_handle)
    {
      log (LOG_ERR, "error opening `to' process, error = %lu",
		     GetLastError ());
      CloseHandle (from_process_handle);
      error_code (EACCES);
      return;
    }

  debug ("Impersonating client");
  if (!conn->impersonate_client ())
    {
      CloseHandle (from_process_handle);
      CloseHandle (to_process_handle);
      error_code (EACCES);
      return;
    }

  HANDLE token_handle = NULL;

  debug ("about to open thread token");
  const DWORD rc = OpenThreadToken (GetCurrentThread (),
				    TOKEN_QUERY,
				    TRUE,
				    &token_handle);

  debug ("opened thread token, rc=%lu", rc);
  if (!conn->revert_to_self ())
    {
      CloseHandle (from_process_handle);
      CloseHandle (to_process_handle);
      error_code (EACCES);
      return;
    }

  if (!rc)
    {
      log (LOG_ERR, "error opening thread token, error = %lu",
		     GetLastError ());
      CloseHandle (from_process_handle);
      CloseHandle (to_process_handle);
      error_code (EACCES);
      return;
    }

  // From this point on, a reply body is returned to the client.

  const HANDLE from_master = req.from_master;
  const HANDLE to_master = req.to_master;

  req.from_master = NULL;
  req.to_master = NULL;

  msglen (sizeof (req));

  if (from_master)
    if (check_and_dup_handle (from_process_handle, to_process_handle,
			      token_handle,
			      GENERIC_READ,
			      from_master,
			      &req.from_master, TRUE) != 0)
      {
	log (LOG_ERR, "error duplicating from_master handle, error = %lu",
		       GetLastError ());
	error_code (EACCES);
      }

  if (to_master)
    if (check_and_dup_handle (from_process_handle, to_process_handle,
			      token_handle,
			      GENERIC_WRITE,
			      to_master,
			      &req.to_master, TRUE) != 0)
      {
	log (LOG_ERR, "error duplicating to_master handle, error = %lu",
		       GetLastError ());
	error_code (EACCES);
      }

  CloseHandle (from_process_handle);
  CloseHandle (to_process_handle);
  CloseHandle (token_handle);

  debug ("%lu(%lu, %lu) -> %lu(%lu,%lu)",
		req.master_pid, from_master, to_master,
		req.pid, req.from_master, req.to_master);

  return;
}

void
client_request_get_version::serve (transport_layer_base *, process_cache *)
{
  assert (!error_code ());

  if (msglen ())
    log (LOG_ERR, "unexpected request body ignored: %lu bytes", msglen ());

  msglen (sizeof (version));

  version.major = CYGWIN_SERVER_VERSION_MAJOR;
  version.api   = CYGWIN_SERVER_VERSION_API;
  version.minor = CYGWIN_SERVER_VERSION_MINOR;
  version.patch = CYGWIN_SERVER_VERSION_PATCH;
}

class server_request : public queue_request
{
public:
  server_request (transport_layer_base *const conn, process_cache *const cache)
    : _conn (conn), _cache (cache)
  {}

  virtual ~server_request ()
  {
    delete _conn;
  }

  virtual void process ()
  {
    client_request::handle_request (_conn, _cache);
  }

private:
  transport_layer_base *const _conn;
  process_cache *const _cache;
};

class server_submission_loop : public queue_submission_loop
{
public:
  server_submission_loop (threaded_queue *const queue,
			  transport_layer_base *const transport,
			  process_cache *const cache)
    : queue_submission_loop (queue, false),
      _transport (transport),
      _cache (cache)
  {
    assert (_transport);
    assert (_cache);
  }

private:
  transport_layer_base *const _transport;
  process_cache *const _cache;

  virtual void request_loop ();
};

/* FIXME: this is a little ugly.  What we really want is to wait on
 * two objects: one for the pipe/socket, and one for being told to
 * shutdown.  Otherwise this will stay a problem (we won't actually
 * shutdown until the request _AFTER_ the shutdown request.  And
 * sending ourselves a request is ugly
 */
void
server_submission_loop::request_loop ()
{
  /* I'd like the accepting thread's priority to be above any "normal"
   * thread in the system to avoid overflowing the listen queue (for
   * sockets; similar issues exist for named pipes); but, for example,
   * a normal priority thread in a foregrounded process is boosted to
   * THREAD_PRIORITY_HIGHEST (AFAICT).  Thus try to set the current
   * thread's priority to a level one above that.  This fails on
   * win9x/ME so assume any failure in that call is due to that and
   * simply call again at one priority level lower.
   */
  if (!SetThreadPriority (GetCurrentThread (), THREAD_PRIORITY_HIGHEST + 1))
    if (!SetThreadPriority (GetCurrentThread (), THREAD_PRIORITY_HIGHEST))
      debug ("failed to raise accept thread priority, error = %lu",
	     GetLastError ());

  while (_running)
    {
      bool recoverable = false;
      transport_layer_base *const conn = _transport->accept (&recoverable);
      if (!conn && !recoverable)
	{
	  log (LOG_ERR, "fatal error on IPC transport: closing down");
	  return;
	}
      // EINTR probably implies a shutdown request; so back off for a
      // moment to let the main thread take control, otherwise the
      // server spins here receiving EINTR repeatedly since the signal
      // handler in the main thread doesn't get a chance to be called.
      if (!conn && errno == EINTR)
	{
	  if (!SetThreadPriority (GetCurrentThread (), THREAD_PRIORITY_NORMAL))
	    debug ("failed to reset thread priority, error = %lu",
		   GetLastError ());

	  Sleep (0);
	  if (!SetThreadPriority (GetCurrentThread (),
				  THREAD_PRIORITY_HIGHEST + 1))
	    if (!SetThreadPriority (GetCurrentThread (),
				    THREAD_PRIORITY_HIGHEST))
	      debug ("failed to raise thread priority, error = %lu",
		     GetLastError ());
	}
      if (conn)
	_queue->add (new server_request (conn, _cache));
    }
}

client_request_shutdown::client_request_shutdown ()
  : client_request (CYGSERVER_REQUEST_SHUTDOWN)
{
}

void
client_request_shutdown::serve (transport_layer_base *, process_cache *)
{
  assert (!error_code ());

  if (msglen ())
    log (LOG_ERR, "unexpected request body ignored: %lu bytes", msglen ());

  /* FIXME: link upwards, and then this becomes a trivial method call to
   * only shutdown _this queue_
   */

  kill (getpid (), SIGINT);

  msglen (0);
}

static sig_atomic_t shutdown_server = false;

static void
handle_signal (const int signum)
{
  /* any signal makes us die :} */

  shutdown_server = true;
}

/*
 * print_usage ()
 */

static void
print_usage (const char *const pgm)
{
  log (LOG_NOTICE, "Usage: %s [OPTIONS]\n"
"Configuration option:\n"
"  -f, --config-file <file>      Use <file> as config file.  Default is\n"
"                                " DEF_CONFIG_FILE "\n"
"\n"
"Performance options:\n"
"  -c, --cleanup-threads <num>   Number of cleanup threads to use.\n"
"  -r, --request-threads <num>   Number of request threads to use.\n"
"\n"
"Logging options:\n"
"  -d, --debug                   Log debug messages to stderr.\n"
"  -e, --stderr                  Log to stderr (default if stderr is a tty).\n"
"  -E, --no-stderr               Don't log to stderr (see -y, -Y options).\n"
"  -l, --log-level <level>       Verbosity of logging (1..7).  Default: 6\n"
"  -y, --syslog                  Log to syslog (default if stderr is no tty).\n"
"  -Y, --no-syslog               Don't log to syslog (See -e, -E options).\n"
"\n"
"Support options:\n"
"  -m, --no-sharedmem            Don't start XSI Shared Memory support.\n"
"  -q, --no-msgqueues            Don't start XSI Message Queue support.\n"
"  -s, --no-semaphores           Don't start XSI Semaphore support.\n"
"\n"
"Miscellaneous:\n"
"  -S, --shutdown                Shutdown the daemon.\n"
"  -h, --help                    Output usage information and exit.\n"
"  -v, --version                 Output version information and exit."
, pgm);
}

/*
 * print_version ()
 */

static void
print_version ()
{
  char buf[200];
  snprintf (buf, sizeof (buf), "%d.%d.%d(%d.%d/%d/%d)-(%d.%d.%d.%d) %s",
	    cygwin_version.dll_major / 1000,
	    cygwin_version.dll_major % 1000,
	    cygwin_version.dll_minor,
	    cygwin_version.api_major,
	    cygwin_version.api_minor,
	    cygwin_version.shared_data,
	    CYGWIN_SERVER_VERSION_MAJOR,
	    CYGWIN_SERVER_VERSION_API,
	    CYGWIN_SERVER_VERSION_MINOR,
	    CYGWIN_SERVER_VERSION_PATCH,
	    cygwin_version.mount_registry,
	    cygwin_version.dll_build_date);

  log (LOG_INFO, "(cygwin) %s\n"
		  "API version %s\n"
		  "Copyright 2001, 2002, 2003, 2004, 2005 Red Hat, Inc.\n"
		  "Compiled on %s\n"
		  "Default configuration file is %s",
		  SERVER_VERSION, buf, __DATE__, DEF_CONFIG_FILE);
}

/*
 * main ()
 */

int
main (const int argc, char *argv[])
{
  const struct option longopts[] = {
    {"cleanup-threads", required_argument, NULL, 'c'},
    {"debug", no_argument, NULL, 'd'},
    {"stderr", no_argument, NULL, 'e'},
    {"no-stderr", no_argument, NULL, 'E'},
    {"config-file", required_argument, NULL, 'f'},
    {"help", no_argument, NULL, 'h'},
    {"log-level", required_argument, NULL, 'l'},
    {"no-sharedmem", no_argument, NULL, 'm'},
    {"no-msgqueues", no_argument, NULL, 'q'},
    {"request-threads", required_argument, NULL, 'r'},
    {"no-semaphores", no_argument, NULL, 's'},
    {"shutdown", no_argument, NULL, 'S'},
    {"version", no_argument, NULL, 'v'},
    {"syslog", no_argument, NULL, 'y'},
    {"no-syslog", no_argument, NULL, 'Y'},
    {0, no_argument, NULL, 0}
  };

  const char opts[] = "c:deEf:hl:mqr:sSvyY";

  long cleanup_threads = 0;
  long request_threads = 0;
  bool shutdown = false;
  const char *config_file = DEF_CONFIG_FILE;
  bool force_config_file = false;
  tun_bool_t option_log_stderr = TUN_UNDEF;
  tun_bool_t option_log_syslog = TUN_UNDEF;

  char *c = NULL;

  /* Check if we have a terminal.  If so, default to stderr logging,
     otherwise default to syslog logging.  This must be done early
     to allow default logging already in option processing state. */
  openlog ("cygserver", LOG_PID, LOG_KERN);
  if (isatty (2))
    log_stderr = TUN_TRUE;
  else
    log_syslog = TUN_TRUE;

  int opt;

  opterr = 0;
  while ((opt = getopt_long (argc, argv, opts, longopts, NULL)) != EOF)
    switch (opt)
      {
      case 'c':
	c = NULL;
	cleanup_threads = strtol (optarg, &c, 10);
	if (cleanup_threads <= 0 || cleanup_threads > 16 || (c && *c))
	  panic ("Number of cleanup threads must be between 1 and 16");
	break;

      case 'd':
        log_debug = TUN_TRUE;
	break;

      case 'e':
        option_log_stderr = TUN_TRUE;
	break;

      case 'E':
        option_log_stderr = TUN_FALSE;
	break;

      case 'f':
	config_file = optarg;
	force_config_file = true;
        break;

      case 'h':
	print_usage (getprogname ());
	return 0;

      case 'l':
        c = NULL;
	log_level = strtoul (optarg, &c, 10);
	if (!log_level || log_level > 7 || (c && *c))
	  panic ("Log level must be between 1 and 7");
	break;
        
      case 'm':
        support_sharedmem = TUN_FALSE;
	break;

      case 'q':
        support_msgqueues = TUN_FALSE;
	break;

      case 'r':
	c = NULL;
	request_threads = strtol (optarg, &c, 10);
	if (request_threads <= 0 || request_threads > 64 || (c && *c))
	  panic ("Number of request threads must be between 1 and 64");
	break;

      case 's':
        support_semaphores = TUN_FALSE;
	break;

      case 'S':
	shutdown = true;
	break;

      case 'v':
	print_version ();
	return 0;

      case 'y':
        option_log_syslog = TUN_TRUE;
	break;

      case 'Y':
        option_log_syslog = TUN_FALSE;
	break;

      case '?':
	panic ("unknown option -- %c\n"
	       "Try `%s --help' for more information.", optopt, getprogname ());
      }

  if (optind != argc)
    panic ("Too many arguments");

  if (shutdown)
    {
      /* Setting `cygserver_running' stops the request code making a
       * version request, which is not much to the point.
       */
      cygserver_running = CYGSERVER_OK;

      client_request_shutdown req;

      if (req.make_request () == -1 || req.error_code ())
	panic("Shutdown request failed: %s", strerror (req.error_code ()));

      // FIXME: It would be nice to wait here for the daemon to exit.

      return 0;
    }

  SIGHANDLE (SIGHUP);
  SIGHANDLE (SIGINT);
  SIGHANDLE (SIGTERM);

  tunable_param_init (config_file, force_config_file);

  loginit (option_log_stderr, option_log_syslog);

  log (LOG_INFO, "daemon starting up");

  if (!cleanup_threads)
    TUNABLE_INT_FETCH ("kern.srv.cleanup_threads", &cleanup_threads);
  if (!cleanup_threads)
    cleanup_threads = 2;

  if (!request_threads)
    TUNABLE_INT_FETCH ("kern.srv.request_threads", &request_threads);
  if (!request_threads)
    request_threads = 10;

  if (support_sharedmem == TUN_UNDEF)
    TUNABLE_BOOL_FETCH ("kern.srv.sharedmem", &support_sharedmem);
  if (support_sharedmem == TUN_UNDEF)
    support_sharedmem = TUN_TRUE;

  if (support_msgqueues == TUN_UNDEF)
    TUNABLE_BOOL_FETCH ("kern.srv.msgqueues", &support_msgqueues);
  if (support_msgqueues == TUN_UNDEF)
    support_msgqueues = TUN_TRUE;

  if (support_semaphores == TUN_UNDEF)
    TUNABLE_BOOL_FETCH ("kern.srv.semaphores", &support_semaphores);
  if (support_semaphores == TUN_UNDEF)
    support_semaphores = TUN_TRUE;

  wincap.init ();
  if (wincap.has_security () && !setup_privileges ())
    panic ("Setting process privileges failed.");

  ipcinit ();

  /*XXXXX*/
  threaded_queue request_queue (request_threads);

  transport_layer_base *const transport = create_server_transport ();
  assert (transport);

  process_cache cache (cleanup_threads);

  server_submission_loop submission_loop (&request_queue, transport, &cache);

  request_queue.add_submission_loop (&submission_loop);

  if (transport->listen () == -1)
    return 1;

  cache.start ();

  request_queue.start ();

  log (LOG_NOTICE, "Initialization complete.  Waiting for requests.");

  /* TODO: wait on multiple objects - the thread handle for each
   * request loop + all the process handles. This should be done by
   * querying the request_queue and the process cache for all their
   * handles, and then waiting for (say) 30 seconds.  after that we
   * recreate the list of handles to wait on, and wait again.  the
   * point of all this abstraction is that we can trivially server
   * both sockets and pipes simply by making a new transport, and then
   * calling request_queue.process_requests (transport2);
   */
  /* WaitForMultipleObjects abort && request_queue && process_queue && signal
     -- if signal event then retrigger it
  */
  while (!shutdown_server && request_queue.running () && cache.running ())
    {
      pause ();
      if (ipcunload ())
	{
	  shutdown_server = false;
	  log (LOG_WARNING, "Shutdown request received but ignored.  "
			     "Dependent processes still running.");
	}
    }

  log (LOG_INFO, "Shutdown request received - new requests will be denied");
  request_queue.stop ();
  log (LOG_INFO, "All pending requests processed");
  delete transport;
  log (LOG_INFO, "No longer accepting requests - cygwin will operate in daemonless mode");
  cache.stop ();
  log (LOG_INFO, "All outstanding process-cache activities completed");
  log (LOG_NOTICE, "Shutdown finished.");

  return 0;
}
#endif /* __OUTSIDE_CYGWIN__ */
