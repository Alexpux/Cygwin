/* thread.cc: Locking and threading module functions

   Copyright 1998, 1999, 2000, 2001, 2002 Red Hat, Inc.

   Originally written by Marco Fuykschot <marco@ddi.nl>
   Substantialy enhanced by Robert Collins <rbtcollins@hotmail.com>

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

/* Implementation overview and caveats:

   Win32 puts some contraints on what can and cannot be implemented.  Where
   possible we work around those contrainsts.  Where we cannot work around
   the constraints we either pretend to be conformant, or return an error
   code.

   Some caveats: PROCESS_SHARED objects while they pretend to be process
   shared, may not actually work.  Some test cases are needed to determine
   win32's behaviour.  My suspicion is that the win32 handle needs to be
   opened with different flags for proper operation.

   R.Collins, April 2001.  */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef _MT_SAFE
#include "winsup.h"
#include <limits.h>
#include <errno.h>
#include "cygerrno.h"
#include <assert.h>
#include <stdlib.h>
#include <syslog.h>
#include "pinfo.h"
#include "perprocess.h"
#include "security.h"
#include <semaphore.h>
#include <stdio.h>
#include <sys/timeb.h>

extern int threadsafe;

#define MT_INTERFACE user_data->threadinterface

struct _reent *
_reent_clib ()
{
  int tmp = GetLastError ();
  struct __reent_t *_r =
    (struct __reent_t *) TlsGetValue (MT_INTERFACE->reent_index);

#ifdef _CYG_THREAD_FAILSAFE
  if (_r == 0)
    system_printf ("local thread storage not inited");
#endif

  SetLastError (tmp);
  return _r->_clib;
}

struct _winsup_t *
_reent_winsup ()
{
  int tmp = GetLastError ();
  struct __reent_t *_r;
  _r = (struct __reent_t *) TlsGetValue (MT_INTERFACE->reent_index);
#ifdef _CYG_THREAD_FAILSAFE
  if (_r == 0)
    system_printf ("local thread storage not inited");
#endif
  SetLastError (tmp);
  return _r->_winsup;
}

inline LPCRITICAL_SECTION
ResourceLocks::Lock (int _resid)
{
#ifdef _CYG_THREAD_FAILSAFE
  if (!inited)
    system_printf ("lock called before initialization");

  thread_printf
    ("Get Resource lock %d ==> %p for %p , real : %d , threadid %d ", _resid,
     &lock, user_data, myself->pid, GetCurrentThreadId ());
#endif
  return &lock;
}

void
SetResourceLock (int _res_id, int _mode, const char *_function)
{
#ifdef _CYG_THREAD_FAILSAFE
  thread_printf ("Set resource lock %d mode %d for %s start",
		 _res_id, _mode, _function);
#endif
  EnterCriticalSection (user_data->resourcelocks->Lock (_res_id));

#ifdef _CYG_THREAD_FAILSAFE
  user_data->resourcelocks->owner = GetCurrentThreadId ();
  user_data->resourcelocks->count++;
#endif
}

void
ReleaseResourceLock (int _res_id, int _mode, const char *_function)
{
#ifdef _CYG_THREAD_FAILSAFE
  thread_printf ("Release resource lock %d mode %d for %s done", _res_id,
		 _mode, _function);

  AssertResourceOwner (_res_id, _mode);
  user_data->resourcelocks->count--;
  if (user_data->resourcelocks->count == 0)
    user_data->resourcelocks->owner = 0;
#endif

  LeaveCriticalSection (user_data->resourcelocks->Lock (_res_id));
}

#ifdef _CYG_THREAD_FAILSAFE
void
AssertResourceOwner (int _res_id, int _mode)
{

  thread_printf
    ("Assert Resource lock %d ==> for %p , real : %d , threadid %d count %d owner %d",
     _res_id, user_data, myself->pid, GetCurrentThreadId (),
     user_data->resourcelocks->count, user_data->resourcelocks->owner);
  if (user_data && (user_data->resourcelocks->owner != GetCurrentThreadId ()))
    system_printf ("assertion failed, not the resource owner");
}

#endif

void
ResourceLocks::Init ()
{
  InitializeCriticalSection (&lock);
  inited = true;

#ifdef _CYG_THREAD_FAILSAFE
  owner = 0;
  count = 0;
#endif

  thread_printf ("lock %p inited by %p , %d", &lock, user_data, myself->pid);
}

void
ResourceLocks::Delete ()
{
  if (inited)
    {
      thread_printf ("Close Resource Locks %p ", &lock);
      DeleteCriticalSection (&lock);
      inited = false;
    }
}

void
MTinterface::Init (int forked)
{

  reent_index = TlsAlloc ();
  reents._clib = _impure_ptr;
  reents._winsup = &winsup_reent;

  winsup_reent._process_logmask = LOG_UPTO (LOG_DEBUG);

  TlsSetValue (reent_index, &reents);
  // the static reent_data will be used in the main thread

  if (!indexallocated)
    {
      thread_self_dwTlsIndex = TlsAlloc ();
      if (thread_self_dwTlsIndex == TLS_OUT_OF_INDEXES)
	system_printf
	  ("local storage for thread couldn't be set\nThis means that we are not thread safe!");
      else
	indexallocated = (-1);
    }

  concurrency = 0;
  threadcount = 1; /*1 current thread when Init occurs.*/

  pthread::initMainThread (&mainthread, myself->hProcess);

  if (forked)
    return;

  mutexs = NULL;
  conds  = NULL;
  semaphores = NULL;

}

void
MTinterface::fixup_before_fork (void)
{
  pthread_key::fixup_before_fork ();
}

/* This function is called from a single threaded process */
void
MTinterface::fixup_after_fork (void)
{
  pthread_key::fixup_after_fork ();
  pthread_mutex *mutex = mutexs;
  debug_printf ("mutexs is %x",mutexs);
  while (mutex)
    {
      mutex->fixup_after_fork ();
      mutex = mutex->next;
    }
  pthread_cond *cond = conds;
  debug_printf ("conds is %x",conds);
  while (cond)
    {
      cond->fixup_after_fork ();
      cond = cond->next;
    }
  semaphore *sem = semaphores;
  debug_printf ("semaphores is %x",semaphores);
  while (sem)
    {
      sem->fixup_after_fork ();
      sem = sem->next;
    }
}

/* pthread calls */

/* static methods */
void
pthread::initMainThread (pthread *mainThread, HANDLE win32_obj_id)
{
  mainThread->win32_obj_id = win32_obj_id;
  mainThread->setThreadIdtoCurrent ();
  setTlsSelfPointer (mainThread);
}

pthread *
pthread::self ()
{
  pthread *temp = (pthread *) TlsGetValue (MT_INTERFACE->thread_self_dwTlsIndex);
  if (temp)
      return temp;
  temp = new pthread ();
  temp->precreate (NULL);
  if (!temp->magic) {
      delete temp;
      return pthreadNull::getNullpthread ();
  }
  temp->postcreate ();
  return temp;
}

void
pthread::setTlsSelfPointer (pthread *thisThread)
{
  /*the OS doesn't check this for <= 64 Tls entries (pre win2k) */
  TlsSetValue (MT_INTERFACE->thread_self_dwTlsIndex, thisThread);
}



/* member methods */
pthread::pthread ():verifyable_object (PTHREAD_MAGIC), win32_obj_id (0),
                    cancelstate (0), canceltype (0), cancel_event (0),
                    joiner (NULL), cleanup_stack (NULL)
{
}

pthread::~pthread ()
{
  if (win32_obj_id)
    CloseHandle (win32_obj_id);
  if (cancel_event)
    CloseHandle (cancel_event);
}

void
pthread::setThreadIdtoCurrent ()
{
  thread_id = GetCurrentThreadId ();
}

void
pthread::precreate (pthread_attr *newattr)
{
  pthread_mutex *verifyable_mutex_obj = &mutex;

  /*already running ? */
  if (win32_obj_id)
    return;

  if (newattr)
    {
      attr.joinable = newattr->joinable;
      attr.contentionscope = newattr->contentionscope;
      attr.inheritsched = newattr->inheritsched;
      attr.stacksize = newattr->stacksize;
    }

  if (!pthread_mutex::isGoodObject (&verifyable_mutex_obj))
    {
      thread_printf ("New thread object access mutex is not valid. this %p",
		     this);
      magic = 0;
      return;
    }

  cancel_event = ::CreateEvent (NULL,TRUE,FALSE,NULL);
  if (!cancel_event)
    {
      system_printf ("couldn't create cancel event, this %p LastError %d", this, GetLastError () );
      /*we need the event for correct behaviour */
      magic = 0;
      return;
    }
}

void
pthread::create (void *(*func) (void *), pthread_attr *newattr,
		 void *threadarg)
{
  precreate (newattr);
  if (!magic)
      return;
   function = func;
   arg = threadarg;

  win32_obj_id = ::CreateThread (&sec_none_nih, attr.stacksize,
				(LPTHREAD_START_ROUTINE) thread_init_wrapper,
				this, CREATE_SUSPENDED, &thread_id);

  if (!win32_obj_id)
    {
      thread_printf ("CreateThread failed: this %p LastError %E", this);
      magic = 0;
    }
  else {
      postcreate ();
      ResumeThread (win32_obj_id);
  }
}

void
pthread::postcreate ()
{
    InterlockedIncrement (&MT_INTERFACE->threadcount);
    /*FIXME: set the priority appropriately for system contention scope */
    if (attr.inheritsched == PTHREAD_EXPLICIT_SCHED)
      {
	/*FIXME: set the scheduling settings for the new thread */
	/*sched_thread_setparam (win32_obj_id, attr.schedparam); */
      }
}

void
pthread::exit (void *value_ptr)
{
  class pthread *thread = this;

  // run cleanup handlers
  pop_all_cleanup_handlers ();

  pthread_key::runAllDestructors ();

  mutex.Lock ();
  // cleanup if thread is in detached state and not joined
  if (__pthread_equal (&joiner, &thread ) )
    delete this;
  else
    {
      return_ptr = value_ptr;
      mutex.UnLock ();
    }

  /* Prevent DLL_THREAD_DETACH Attempting to clean us up */
  setTlsSelfPointer (0);

  if (InterlockedDecrement (&MT_INTERFACE->threadcount) == 0)
    ::exit (0);
  else
    ExitThread (0);
}

int
pthread::cancel (void)
{
  class pthread *thread = this;
  class pthread *self = pthread::self ();

  mutex.Lock ();

  if (canceltype == PTHREAD_CANCEL_DEFERRED ||
      cancelstate == PTHREAD_CANCEL_DISABLE)
    {
      // cancel deferred
      mutex.UnLock ();
      SetEvent (cancel_event);
      return 0;
    }

  else if (__pthread_equal (&thread, &self))
    {
      mutex.UnLock ();
      cancel_self ();
      return 0; // Never reached
    }

  // cancel asynchronous
  SuspendThread (win32_obj_id);
  if (WaitForSingleObject (win32_obj_id, 0) == WAIT_TIMEOUT)
    {
      CONTEXT context;
      context.ContextFlags = CONTEXT_CONTROL;
      GetThreadContext (win32_obj_id, &context);
      context.Eip = (DWORD) pthread::static_cancel_self;
      SetThreadContext (win32_obj_id, &context);
    }
  mutex.UnLock ();
  ResumeThread (win32_obj_id);

  return 0;
/*
  TODO: insert  pthread_testcancel into the required functions
  the required function list is: *indicates done, X indicates not present in cygwin.
aio_suspend ()
*close ()
*creat ()
fcntl ()
fsync ()
getmsg ()
getpmsg ()
lockf ()
mq_receive ()
mq_send ()
msgrcv ()
msgsnd ()
msync ()
nanosleep ()
open ()
pause ()
poll ()
pread ()
pthread_cond_timedwait ()
pthread_cond_wait ()
*pthread_join ()
pthread_testcancel ()
putmsg ()
putpmsg ()
pwrite ()
read ()
readv ()
select ()
sem_wait ()
sigpause ()
sigsuspend ()
sigtimedwait ()
sigwait ()
sigwaitinfo ()
*sleep ()
system ()
tcdrain ()
*usleep ()
wait ()
wait3()
waitid ()
waitpid ()
write ()
writev ()

the optional list is:
catclose ()
catgets ()
catopen ()
closedir ()
closelog ()
ctermid ()
dbm_close ()
dbm_delete ()
dbm_fetch ()
dbm_nextkey ()
dbm_open ()
dbm_store ()
dlclose ()
dlopen ()
endgrent ()
endpwent ()
endutxent ()
fclose ()
fcntl ()
fflush ()
fgetc ()
fgetpos ()
fgets ()
fgetwc ()
fgetws ()
fopen ()
fprintf ()
fputc ()
fputs ()
fputwc ()
fputws ()
fread ()
freopen ()
fscanf ()
fseek ()
fseeko ()
fsetpos ()
ftell ()
ftello ()
ftw ()
fwprintf ()
fwrite ()
fwscanf ()
getc ()
getc_unlocked ()
getchar ()
getchar_unlocked ()
getcwd ()
getdate ()
getgrent ()
getgrgid ()
getgrgid_r ()
getgrnam ()
getgrnam_r ()
getlogin ()
getlogin_r ()
getpwent ()
*getpwnam ()
*getpwnam_r ()
*getpwuid ()
*getpwuid_r ()
gets ()
getutxent ()
getutxid ()
getutxline ()
getw ()
getwc ()
getwchar ()
getwd ()
glob ()
iconv_close ()
iconv_open ()
ioctl ()
lseek ()
mkstemp ()
nftw ()
opendir ()
openlog ()
pclose ()
perror ()
popen ()
printf ()
putc ()
putc_unlocked ()
putchar ()
putchar_unlocked ()
puts ()
pututxline ()
putw ()
putwc ()
putwchar ()
readdir ()
readdir_r ()
remove ()
rename ()
rewind ()
rewinddir ()
scanf ()
seekdir ()
semop ()
setgrent ()
setpwent ()
setutxent ()
strerror ()
syslog ()
tmpfile ()
tmpnam ()
ttyname ()
ttyname_r ()
ungetc ()
ungetwc ()
unlink ()
vfprintf ()
vfwprintf ()
vprintf ()
vwprintf ()
wprintf ()
wscanf ()

Note, that for fcntl (), for any value of the cmd argument.

And we must not introduce cancellation points anywhere else that's part of the posix or
opengroup specs.
 */
}

void
pthread::testcancel (void)
{
  if (cancelstate == PTHREAD_CANCEL_DISABLE)
    return;

  if (WAIT_OBJECT_0 == WaitForSingleObject (cancel_event, 0 ) )
    cancel_self ();
}

void
pthread::static_cancel_self (void)
{
  pthread::self ()->cancel_self ();
}


int
pthread::setcancelstate (int state, int *oldstate)
{
  int result = 0;

  mutex.Lock ();

  if (state != PTHREAD_CANCEL_ENABLE && state != PTHREAD_CANCEL_DISABLE)
    result = EINVAL;
  else
    {
      if (oldstate)
	*oldstate = cancelstate;
      cancelstate = state;
    }

  mutex.UnLock ();

  return result;
}

int
pthread::setcanceltype (int type, int *oldtype)
{
  int result = 0;

  mutex.Lock ();

  if (type != PTHREAD_CANCEL_DEFERRED && type != PTHREAD_CANCEL_ASYNCHRONOUS)
    result = EINVAL;
  else
    {
      if (oldtype)
	*oldtype = canceltype;
      canceltype = type;
    }

  mutex.UnLock ();

  return result;
}

void
pthread::push_cleanup_handler (__pthread_cleanup_handler *handler)
{
  if (this != self ())
    // TODO: do it?
    api_fatal ("Attempt to push a cleanup handler across threads");
  handler->next = cleanup_stack;
  InterlockedExchangePointer (&cleanup_stack, handler );
}

void
pthread::pop_cleanup_handler (int const execute)
{
  if (this != self ())
    // TODO: send a signal or something to the thread ?
    api_fatal ("Attempt to execute a cleanup handler across threads");

  mutex.Lock ();

  if (cleanup_stack != NULL)
    {
      __pthread_cleanup_handler *handler = cleanup_stack;

      if (execute)
	(*handler->function) (handler->arg);
      cleanup_stack = handler->next;
    }

  mutex.UnLock ();
}

void
pthread::pop_all_cleanup_handlers ()
{
  while (cleanup_stack != NULL)
    pop_cleanup_handler (1);
}

void
pthread::cancel_self ()
{
  exit (PTHREAD_CANCELED);
}

DWORD
pthread::getThreadId ()
{
  return thread_id;
}

/* static members */
bool
pthread_attr::isGoodObject (pthread_attr_t const *attr)
{
  if (verifyable_object_isvalid (attr, PTHREAD_ATTR_MAGIC) != VALID_OBJECT)
    return false;
  return true;
}

/* instance members */

pthread_attr::pthread_attr ():verifyable_object (PTHREAD_ATTR_MAGIC),
joinable (PTHREAD_CREATE_JOINABLE), contentionscope (PTHREAD_SCOPE_PROCESS),
inheritsched (PTHREAD_INHERIT_SCHED), stacksize (0)
{
  schedparam.sched_priority = 0;
}

pthread_attr::~pthread_attr ()
{
}

bool
pthread_condattr::isGoodObject (pthread_condattr_t const *attr)
{
  if (verifyable_object_isvalid (attr, PTHREAD_CONDATTR_MAGIC) != VALID_OBJECT)
    return false;
  return true;
}

pthread_condattr::pthread_condattr ():verifyable_object
  (PTHREAD_CONDATTR_MAGIC), shared (PTHREAD_PROCESS_PRIVATE)
{
}

pthread_condattr::~pthread_condattr ()
{
}

pthread_cond::pthread_cond (pthread_condattr *attr):verifyable_object (PTHREAD_COND_MAGIC)
{
  int temperr;
  this->shared = attr ? attr->shared : PTHREAD_PROCESS_PRIVATE;
  this->mutex = NULL;
  this->waiting = 0;

  this->win32_obj_id = ::CreateEvent (&sec_none_nih, false,	/*auto signal reset - which I think is pthreads like ? */
				     false,	/*start non signaled */
				     NULL /*no name */);
  /*TODO: make a shared mem mutex if out attributes request shared mem cond */
  cond_access = NULL;
  if ((temperr = pthread_mutex_init (&this->cond_access, NULL)))
    {
      system_printf ("couldn't init mutex, this %p errno %d", this, temperr);
      /*we need the mutex for correct behaviour */
      magic = 0;
    }

  if (!this->win32_obj_id)
    magic = 0;
  /* threadsafe addition is easy */
  next = (pthread_cond *) InterlockedExchangePointer (&MT_INTERFACE->conds, this);
}

pthread_cond::~pthread_cond ()
{
  if (win32_obj_id)
    CloseHandle (win32_obj_id);
  pthread_mutex_destroy (&cond_access);
  /* I'm not 100% sure the next bit is threadsafe. I think it is... */
  if (MT_INTERFACE->conds == this)
    InterlockedExchangePointer (&MT_INTERFACE->conds, this->next);
  else
    {
      pthread_cond *tempcond = MT_INTERFACE->conds;
      while (tempcond->next && tempcond->next != this)
	tempcond = tempcond->next;
      /* but there may be a race between the loop above and this statement */
      InterlockedExchangePointer (&tempcond->next, this->next);
    }
}

void
pthread_cond::BroadCast ()
{
  /* TODO: implement the same race fix as Signal has */
  if (pthread_mutex_lock (&cond_access))
    system_printf ("Failed to lock condition variable access mutex, this %p", this);
  int count = waiting;
  if (!pthread_mutex::isGoodObject (&mutex))
    {
      if (pthread_mutex_unlock (&cond_access))
	system_printf ("Failed to unlock condition variable access mutex, this %p", this);
      /*This isn't and API error - users are allowed to call this when no threads
	 are waiting
	 system_printf ("Broadcast called with invalid mutex");
      */
      return;
    }
  while (count--)
    PulseEvent (win32_obj_id);
  if (pthread_mutex_unlock (&cond_access))
    system_printf ("Failed to unlock condition variable access mutex, this %p", this);
}

void
pthread_cond::Signal ()
{
  if (pthread_mutex_lock (&cond_access))
    system_printf ("Failed to lock condition variable access mutex, this %p", this);
  if (!pthread_mutex::isGoodObject (&mutex))
    {
      if (pthread_mutex_unlock (&cond_access))
	system_printf ("Failed to unlock condition variable access mutex, this %p",
		       this);
      return;
    }
  int temp = waiting;
  if (!temp)
    /* nothing to signal */
    {
      if (pthread_mutex_unlock (&cond_access))
	system_printf ("Failed to unlock condition variable access mutex, this %p", this);
      return;
    }
  /* Prime the detection flag */
  ExitingWait = 1;
  /* Signal any waiting thread */
  PulseEvent (win32_obj_id);
  /* No one can start waiting until we release the condition access mutex */
  /* The released thread will decrement waiting when it gets a time slice...
     without waiting for the access mutex
   * InterLockedIncrement on 98 +, NT4 + returns the incremented value.
   * On 95, nt 3.51 < it returns a sign correct number - 0=0, + for greater than 0, -
   * for less than 0.
   * Because of this we cannot spin on the waiting count, but rather we need a
   * dedicated flag for a thread exiting the Wait function.
   * Also not that Interlocked* sync CPU caches with memory.
   */
  int spins = 10;
  /* When ExitingWait is nonzero after a decrement, the leaving thread has
   * done it's thing
   */
  while (InterlockedDecrement (&ExitingWait) == 0 && spins)
    {
      InterlockedIncrement (&ExitingWait);
      /* give up the cpu to force a context switch. */
      Sleep (0);
      if (spins == 5)
	/* we've had 5 timeslices, and the woken thread still hasn't done it's
	 * thing - maybe we raced it with the event? */
	PulseEvent (win32_obj_id);
      spins--;
    }
  if (waiting + 1 != temp)
    system_printf ("Released too many threads - %d now %d originally", waiting, temp);
  if (pthread_mutex_unlock (&cond_access))
    system_printf ("Failed to unlock condition variable access mutex, this %p", this);
}

int
pthread_cond::TimedWait (DWORD dwMilliseconds)
{
  DWORD rv;
  if (!wincap.has_signal_object_and_wait ())
    {
      // FIXME: race condition (potentially drop events
      // Possible solution (single process only) - place this in a critical section.
      ReleaseMutex (mutex->win32_obj_id);
      rv = WaitForSingleObject (win32_obj_id, dwMilliseconds);
    }
  else
    {
      LeaveCriticalSection (&mutex->criticalsection);
      rv = WaitForSingleObject (win32_obj_id, dwMilliseconds);
#if 0
    /* we need to use native win32 mutex's here, because the cygwin ones now use
     * critical sections, which are faster, but introduce a race _here_. Until then
     * The NT variant of the code is redundant.
     */

    rv = SignalObjectAndWait (mutex->win32_obj_id, win32_obj_id, dwMilliseconds,
			 false);
#endif
    }
  switch (rv)
    {
    case WAIT_FAILED:
      return 0;			/*POSIX doesn't allow errors after we modify the mutex state */
    case WAIT_ABANDONED:
    case WAIT_TIMEOUT:
      return ETIMEDOUT;
    case WAIT_OBJECT_0:
      return 0;			/*we have been signaled */
    default:
      return 0;
    }
}

void
pthread_cond::fixup_after_fork ()
{
  debug_printf ("cond %x in fixup_after_fork", this);
  if (shared != PTHREAD_PROCESS_PRIVATE)
    api_fatal ("doesn't understand PROCESS_SHARED condition variables");
  /* FIXME: duplicate code here and in the constructor. */
  this->win32_obj_id = ::CreateEvent (&sec_none_nih, false, false, NULL);
  if (!win32_obj_id)
    api_fatal ("failed to create new win32 mutex");
#if DETECT_BAD_APPS
  if (waiting)
    api_fatal ("Forked () while a condition variable has waiting threads.\nReport to cygwin@cygwin.com");
#else
  waiting = 0;
  mutex = NULL;
#endif
}

/* pthread_key */
/* static members */
List<pthread_key> pthread_key::keys;

void
pthread_key::saveAKey (pthread_key *key)
{
  key->saveKeyToBuffer ();
}

void
pthread_key::fixup_before_fork ()
{
  keys.forEach (saveAKey);
}

void
pthread_key::restoreAKey (pthread_key *key)
{
  key->recreateKeyFromBuffer ();
}

void
pthread_key::fixup_after_fork ()
{
  keys.forEach (restoreAKey);
}

void
pthread_key::destroyAKey (pthread_key *key)
{
  key->run_destructor ();
}

void
pthread_key::runAllDestructors ()
{
  keys.forEach (destroyAKey);
}

bool
pthread_key::isGoodObject (pthread_key_t const *key)
{
  if (verifyable_object_isvalid (key, PTHREAD_KEY_MAGIC) != VALID_OBJECT)
    return false;
  return true;
}

/* non-static members */

pthread_key::pthread_key (void (*aDestructor) (void *)):verifyable_object (PTHREAD_KEY_MAGIC), destructor (aDestructor)
{
  dwTlsIndex = TlsAlloc ();
  if (dwTlsIndex == TLS_OUT_OF_INDEXES)
    magic = 0;
  else
    keys.Insert (this);
}

pthread_key::~pthread_key ()
{
  /* We may need to make the list code lock the list during operations
   */
  if (magic != 0) 
    {
      keys.Remove (this);
      TlsFree (dwTlsIndex);
    }
}

int
pthread_key::set (const void *value)
{
  /*the OS function doesn't perform error checking */
  TlsSetValue (dwTlsIndex, (void *) value);
  return 0;
}

void *
pthread_key::get () const
{
  int savedError = ::GetLastError ();
  void *result = TlsGetValue (dwTlsIndex);
  ::SetLastError (savedError);
  return result;
}

void
pthread_key::saveKeyToBuffer ()
{
  fork_buf = get ();
}

void
pthread_key::recreateKeyFromBuffer ()
{
  dwTlsIndex = TlsAlloc ();
  if (dwTlsIndex == TLS_OUT_OF_INDEXES)
    api_fatal ("pthread_key::recreateKeyFromBuffer () failed to reallocate Tls storage");
  set (fork_buf);
}

void
pthread_key::run_destructor () const
{
  if (destructor)
    destructor (get ());
}

/*pshared mutexs:

 * REMOVED FROM CURRENT. These can be reinstated with the daemon, when all the
 gymnastics can be a lot easier.

 *the mutex_t (size 4) is not used as a verifyable object because we cannot
 *guarantee the same address space for all processes.
 *we use the following:
 *high bit set (never a valid address).
 *second byte is reserved for the priority.
 *third byte is reserved
 *fourth byte is the mutex id. (max 255 cygwin mutexs system wide).
 *creating mutex's does get slower and slower, but as creation is a one time
 *job, it should never become an issue
 *
 *And if you're looking at this and thinking, why not an array in cygwin for all mutexs,
 *- you incur a penalty on _every_ mutex call and you have toserialise them all.
 *... Bad karma.
 *
 *option 2? put everything in userspace and update the ABI?
 *- bad karma as well - the HANDLE, while identical across process's,
 *Isn't duplicated, it's reopened.
 */

/* static members */
bool
pthread_mutex::isGoodObject (pthread_mutex_t const *mutex)
{
  if (verifyable_object_isvalid (mutex, PTHREAD_MUTEX_MAGIC) != VALID_OBJECT)
    return false;
  return true;
}

bool
pthread_mutex::isGoodInitializer (pthread_mutex_t const *mutex)
{
  if (verifyable_object_isvalid (mutex, PTHREAD_MUTEX_MAGIC, PTHREAD_MUTEX_INITIALIZER) != VALID_STATIC_OBJECT)
    return false;
  return true;
}

bool
pthread_mutex::isGoodInitializerOrObject (pthread_mutex_t const *mutex)
{
  if (verifyable_object_isvalid (mutex, PTHREAD_MUTEX_MAGIC, PTHREAD_MUTEX_INITIALIZER) == INVALID_OBJECT)
    return false;
  return true;
}

pthread_mutex::pthread_mutex (pthread_mutexattr *attr):verifyable_object (PTHREAD_MUTEX_MAGIC)
{
  /*attr checked in the C call */
  if (attr && attr->pshared == PTHREAD_PROCESS_SHARED)
    {
      // fail
      magic = 0;
      return;
    }
  if (wincap.has_try_enter_critical_section ())
    InitializeCriticalSection (&criticalsection);
  else
    {
      this->win32_obj_id = ::CreateMutex (&sec_none_nih, false, NULL);
      if (!win32_obj_id)
	magic = 0;
    }
  condwaits = 0;
  pshared = PTHREAD_PROCESS_PRIVATE;
  /* threadsafe addition is easy */
  next = (pthread_mutex *) InterlockedExchangePointer (&MT_INTERFACE->mutexs, this);
}

pthread_mutex::~pthread_mutex ()
{
  if (wincap.has_try_enter_critical_section ())
    DeleteCriticalSection (&criticalsection);
  else
    {
      if (win32_obj_id)
	CloseHandle (win32_obj_id);
      win32_obj_id = NULL;
    }
  /* I'm not 100% sure the next bit is threadsafe. I think it is... */
  if (MT_INTERFACE->mutexs == this)
    /* TODO: printf an error if the return value != this */
    InterlockedExchangePointer (&MT_INTERFACE->mutexs, next);
  else
    {
      pthread_mutex *tempmutex = MT_INTERFACE->mutexs;
      while (tempmutex->next && tempmutex->next != this)
	tempmutex = tempmutex->next;
      /* but there may be a race between the loop above and this statement */
      /* TODO: printf an error if the return value != this */
      InterlockedExchangePointer (&tempmutex->next, this->next);
    }
}

int
pthread_mutex::Lock ()
{
  if (wincap.has_try_enter_critical_section ())
    {
      EnterCriticalSection (&criticalsection);
      return 0;
    }
  /* FIXME: Return 0 on success */
  return WaitForSingleObject (win32_obj_id, INFINITE);
}

/* returns non-zero on failure */
int
pthread_mutex::TryLock ()
{
  if (wincap.has_try_enter_critical_section ())
    return (!TryEnterCriticalSection (&criticalsection));
  return (WaitForSingleObject (win32_obj_id, 0) == WAIT_TIMEOUT);
}

int
pthread_mutex::UnLock ()
{
  if (wincap.has_try_enter_critical_section ())
    {
      LeaveCriticalSection (&criticalsection);
      return 0;
    }
  return (!ReleaseMutex (win32_obj_id));
}

void
pthread_mutex::fixup_after_fork ()
{
  debug_printf ("mutex %x in fixup_after_fork", this);
  if (pshared != PTHREAD_PROCESS_PRIVATE)
    api_fatal ("pthread_mutex::fixup_after_fork () doesn'tunderstand PROCESS_SHARED mutex's");
  /* FIXME: duplicate code here and in the constructor. */
  if (wincap.has_try_enter_critical_section ())
    InitializeCriticalSection (&criticalsection);
  else
    {
      win32_obj_id = ::CreateMutex (&sec_none_nih, false, NULL);
      if (!win32_obj_id)
	api_fatal ("pthread_mutex::fixup_after_fork () failed to create new win32 mutex");
    }
#if DETECT_BAD_APPS
  if (condwaits)
    api_fatal ("Forked () while a mutex has condition variables waiting on it.\nReport to cygwin@cygwin.com");
#else
  condwaits = 0;
#endif
}

bool
pthread_mutexattr::isGoodObject (pthread_mutexattr_t const * attr)
{
  if (verifyable_object_isvalid (attr, PTHREAD_MUTEXATTR_MAGIC) != VALID_OBJECT)
    return false;
  return true;
}

pthread_mutexattr::pthread_mutexattr ():verifyable_object (PTHREAD_MUTEXATTR_MAGIC),
pshared (PTHREAD_PROCESS_PRIVATE), mutextype (PTHREAD_MUTEX_DEFAULT)
{
}

pthread_mutexattr::~pthread_mutexattr ()
{
}

semaphore::semaphore (int pshared, unsigned int value):verifyable_object (SEM_MAGIC)
{
  this->win32_obj_id = ::CreateSemaphore (&sec_none_nih, value, LONG_MAX,
					 NULL);
  if (!this->win32_obj_id)
    magic = 0;
  this->shared = pshared;
  currentvalue = value;
  /* threadsafe addition is easy */
  next = (semaphore *) InterlockedExchangePointer (&MT_INTERFACE->semaphores, this);
}

semaphore::~semaphore ()
{
  if (win32_obj_id)
    CloseHandle (win32_obj_id);
  /* I'm not 100% sure the next bit is threadsafe. I think it is... */
  if (MT_INTERFACE->semaphores == this)
    InterlockedExchangePointer (&MT_INTERFACE->semaphores, this->next);
  else
    {
      semaphore *tempsem = MT_INTERFACE->semaphores;
      while (tempsem->next && tempsem->next != this)
	tempsem = tempsem->next;
      /* but there may be a race between the loop above and this statement */
      InterlockedExchangePointer (&tempsem->next, this->next);
    }
}

void
semaphore::Post ()
{
  /* we can't use the currentvalue, because the wait functions don't let us access it */
  ReleaseSemaphore (win32_obj_id, 1, NULL);
  currentvalue++;
}

int
semaphore::TryWait ()
{
  /*FIXME: signals should be able to interrupt semaphores...
   *We probably need WaitForMultipleObjects here.
   */
  if (WaitForSingleObject (win32_obj_id, 0) == WAIT_TIMEOUT)
    {
      set_errno (EAGAIN);
      return -1;
    }
  currentvalue--;
  return 0;
}

void
semaphore::Wait ()
{
  WaitForSingleObject (win32_obj_id, INFINITE);
  currentvalue--;
}

void
semaphore::fixup_after_fork ()
{
  debug_printf ("sem %x in fixup_after_fork", this);
  if (shared != PTHREAD_PROCESS_PRIVATE)
    api_fatal ("doesn't understand PROCESS_SHARED semaphores variables");
  /* FIXME: duplicate code here and in the constructor. */
  this->win32_obj_id = ::CreateSemaphore (&sec_none_nih, currentvalue, LONG_MAX, NULL);
  if (!win32_obj_id)
    api_fatal ("failed to create new win32 semaphore");
}

verifyable_object::verifyable_object (long verifyer):
magic (verifyer)
{
}

verifyable_object::~verifyable_object ()
{
  magic = 0;
}

/*Generic memory acccess routine - where should it live ? */
int __stdcall
check_valid_pointer (void const *pointer)
{
  if (!pointer || IsBadWritePtr ((void *) pointer, sizeof (verifyable_object)))
    return EFAULT;
  return 0;
}

verifyable_object_state
verifyable_object_isvalid (void const * objectptr, long magic, void *static_ptr)
{
  verifyable_object **object = (verifyable_object **)objectptr;
  if (check_valid_pointer (object))
    return INVALID_OBJECT;
  if (!*object)
    return INVALID_OBJECT;
  if (static_ptr && *object == static_ptr)
    return VALID_STATIC_OBJECT;
  if (check_valid_pointer (*object))
    return INVALID_OBJECT;
  if ((*object)->magic != magic)
    return INVALID_OBJECT;
  return VALID_OBJECT;
}

verifyable_object_state
verifyable_object_isvalid (void const * objectptr, long magic)
{
  return verifyable_object_isvalid (objectptr, magic, NULL);
}

/* Pthreads */
void *
pthread::thread_init_wrapper (void *_arg)
{
  // Setup the local/global storage of this thread

  pthread *thread = (pthread *) _arg;
  struct __reent_t local_reent;
  struct _winsup_t local_winsup;
  struct _reent local_clib = _REENT_INIT (local_clib);

  struct sigaction _sigs[NSIG];
  sigset_t _sig_mask;		/*one set for everything to ignore. */
  LONG _sigtodo[NSIG + __SIGOFFSET];

  // setup signal structures
  thread->sigs = _sigs;
  thread->sigmask = &_sig_mask;
  thread->sigtodo = _sigtodo;

  memset (&local_winsup, 0, sizeof (struct _winsup_t));

  local_reent._clib = &local_clib;
  local_reent._winsup = &local_winsup;

  local_winsup._process_logmask = LOG_UPTO (LOG_DEBUG);

  /*This is not checked by the OS !! */
  if (!TlsSetValue (MT_INTERFACE->reent_index, &local_reent))
    system_printf ("local storage for thread couldn't be set");

  setTlsSelfPointer (thread);

  thread->mutex.Lock ();
  // if thread is detached force cleanup on exit
  if (thread->attr.joinable == PTHREAD_CREATE_DETACHED && thread->joiner == NULL)
    thread->joiner = pthread::self ();
  thread->mutex.UnLock ();

#ifdef _CYG_THREAD_FAILSAFE
  if (_REENT == _impure_ptr)
    system_printf ("local storage for thread isn't setup correctly");
#endif

  thread_printf ("started thread %p %p %p %p %p %p", _arg, &local_clib,
		 _impure_ptr, thread, thread->function, thread->arg);

  // call the user's thread
  void *ret = thread->function (thread->arg);

  thread->exit (ret);

#if 0
// ??? This code only runs if the thread exits by returning.
// it's all now in __pthread_exit ();
#endif
  /*never reached */
  return 0;
}

bool
pthread::isGoodObject (pthread_t const *thread)
{
  if (verifyable_object_isvalid (thread, PTHREAD_MAGIC) != VALID_OBJECT)
    return false;
  return true;
}

unsigned long
pthread::getsequence_np ()
{
  return getThreadId ();
}

int
pthread::create (pthread_t *thread, const pthread_attr_t *attr,
		  void *(*start_routine) (void *), void *arg)
{
  DECLARE_TLS_STORAGE;
  if (attr && !pthread_attr::isGoodObject (attr))
    return EINVAL;

  *thread = new pthread ();
  (*thread)->create (start_routine, attr ? *attr : NULL, arg);
  if (!isGoodObject (thread))
    {
      delete (*thread);
      *thread = NULL;
      return EAGAIN;
    }

  return 0;
}

int
pthread::once (pthread_once_t *once_control, void (*init_routine) (void))
{
  // already done ?
  if (once_control->state)
    return 0;

  pthread_mutex_lock (&once_control->mutex);
  /*Here we must set a cancellation handler to unlock the mutex if needed */
  /*but a cancellation handler is not the right thing. We need this in the thread
   *cleanup routine. Assumption: a thread can only be in one pthread_once routine
   *at a time. Stote a mutex_t *in the pthread_structure. if that's non null unlock
   *on pthread_exit ();
   */
  if (!once_control->state)
    {
      init_routine ();
      once_control->state = 1;
    }
  /*Here we must remove our cancellation handler */
  pthread_mutex_unlock (&once_control->mutex);
  return 0;
}

int
pthread::cancel (pthread_t thread)
{
  if (!isGoodObject (&thread))
    return ESRCH;

  return thread->cancel ();
}

/*
 *Races in pthread_atfork:
 *We are race safe in that any additions to the lists are made via
 *InterlockedExchangePointer.
 *However, if the user application doesn't perform syncronisation of some sort
 *It's not guaranteed that a near simultaneous call to pthread_atfork and fork
 *will result in the new atfork handlers being calls.
 *More rigorous internal syncronisation isn't needed as the user program isn't
 *guaranteeing their own state.
 *
 *as far as multiple calls to pthread_atfork, the worst case is simultaneous calls
 *will result in an indeterminate order for parent and child calls (what gets inserted
 *first isn't guaranteed.)
 *
 *There is one potential race... Does the result of InterlockedExchangePointer
 *get committed to the return location _before_ any context switches can occur?
 *If yes, we're safe, if no, we're not.
 */
void
pthread::atforkprepare (void)
{
  MT_INTERFACE->fixup_before_fork ();

  callback *cb = MT_INTERFACE->pthread_prepare;
  while (cb)
    {
      cb->cb ();
      cb = cb->next;
    }
}

void
pthread::atforkparent (void)
{
  callback *cb = MT_INTERFACE->pthread_parent;
  while (cb)
    {
      cb->cb ();
      cb = cb->next;
    }
}

void
pthread::atforkchild (void)
{
  MT_INTERFACE->fixup_after_fork ();

  callback *cb = MT_INTERFACE->pthread_child;
  while (cb)
    {
      cb->cb ();
      cb = cb->next;
    }
}

/*Register a set of functions to run before and after fork.
 *prepare calls are called in LI-FC order.
 *parent and child calls are called in FI-FC order.
 */
int
pthread::atfork (void (*prepare)(void), void (*parent)(void), void (*child)(void))
{
  callback *prepcb = NULL, *parentcb = NULL, *childcb = NULL;
  if (prepare)
    {
      prepcb = new callback;
      if (!prepcb)
	return ENOMEM;
    }
  if (parent)
    {
      parentcb = new callback;
      if (!parentcb)
	{
	  if (prepcb)
	    delete prepcb;
	  return ENOMEM;
	}
    }
  if (child)
    {
      childcb = new callback;
      if (!childcb)
	{
	  if (prepcb)
	    delete prepcb;
	  if (parentcb)
	    delete parentcb;
	  return ENOMEM;
	}
    }

  if (prepcb)
  {
    prepcb->cb = prepare;
    prepcb->next = (callback *) InterlockedExchangePointer ((LONG *) &MT_INTERFACE->pthread_prepare, (long int) prepcb);
  }
  if (parentcb)
  {
    parentcb->cb = parent;
    callback **t = &MT_INTERFACE->pthread_parent;
    while (*t)
      t = &(*t)->next;
    /*t = pointer to last next in the list */
    parentcb->next = (callback *) InterlockedExchangePointer ((LONG *) t, (long int) parentcb);
  }
  if (childcb)
  {
    childcb->cb = child;
    callback **t = &MT_INTERFACE->pthread_child;
    while (*t)
      t = &(*t)->next;
    /*t = pointer to last next in the list */
    childcb->next = (callback *) InterlockedExchangePointer ((LONG *) t, (long int) childcb);
  }
  return 0;
}

int
__pthread_attr_init (pthread_attr_t *attr)
{
  if (check_valid_pointer (attr))
    return EINVAL;
  *attr = new pthread_attr;
  if (!pthread_attr::isGoodObject (attr))
    {
      delete (*attr);
      *attr = NULL;
      return EAGAIN;
    }
  return 0;
}

int
__pthread_attr_getinheritsched (const pthread_attr_t *attr,
				int *inheritsched)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  *inheritsched = (*attr)->inheritsched;
  return 0;
}

int
__pthread_attr_getschedparam (const pthread_attr_t *attr,
			      struct sched_param *param)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  *param = (*attr)->schedparam;
  return 0;
}

/*From a pure code point of view, this should call a helper in sched.cc,
 *to allow for someone adding scheduler policy changes to win32 in the future.
 *However that's extremely unlikely, so short and sweet will do us
 */
int
__pthread_attr_getschedpolicy (const pthread_attr_t *attr, int *policy)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  *policy = SCHED_FIFO;
  return 0;
}


int
__pthread_attr_getscope (const pthread_attr_t *attr, int *contentionscope)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  *contentionscope = (*attr)->contentionscope;
  return 0;
}

int
__pthread_attr_setdetachstate (pthread_attr_t *attr, int detachstate)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  if (detachstate < 0 || detachstate > 1)
    return EINVAL;
  (*attr)->joinable = detachstate;
  return 0;
}

int
__pthread_attr_getdetachstate (const pthread_attr_t *attr, int *detachstate)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  *detachstate = (*attr)->joinable;
  return 0;
}

int
__pthread_attr_setinheritsched (pthread_attr_t *attr, int inheritsched)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  if (inheritsched != PTHREAD_INHERIT_SCHED
      && inheritsched != PTHREAD_EXPLICIT_SCHED)
    return ENOTSUP;
  (*attr)->inheritsched = inheritsched;
  return 0;
}

int
__pthread_attr_setschedparam (pthread_attr_t *attr,
			      const struct sched_param *param)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  if (!valid_sched_parameters (param))
    return ENOTSUP;
  (*attr)->schedparam = *param;
  return 0;
}

/*See __pthread_attr_getschedpolicy for some notes */
int
__pthread_attr_setschedpolicy (pthread_attr_t *attr, int policy)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  if (policy != SCHED_FIFO)
    return ENOTSUP;
  return 0;
}

int
__pthread_attr_setscope (pthread_attr_t *attr, int contentionscope)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  if (contentionscope != PTHREAD_SCOPE_SYSTEM
      && contentionscope != PTHREAD_SCOPE_PROCESS)
    return EINVAL;
  /*In future, we may be able to support system scope by escalating the thread
   *priority to exceed the priority class. For now we only support PROCESS scope. */
  if (contentionscope != PTHREAD_SCOPE_PROCESS)
    return ENOTSUP;
  (*attr)->contentionscope = contentionscope;
  return 0;
}

int
__pthread_attr_setstacksize (pthread_attr_t *attr, size_t size)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  (*attr)->stacksize = size;
  return 0;
}

int
__pthread_attr_getstacksize (const pthread_attr_t *attr, size_t *size)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  *size = (*attr)->stacksize;
  return 0;
}

int
__pthread_attr_destroy (pthread_attr_t *attr)
{
  if (!pthread_attr::isGoodObject (attr))
    return EINVAL;
  delete (*attr);
  *attr = NULL;
  return 0;
}

int
pthread::join (pthread_t *thread, void **return_val)
{
   pthread_t joiner = self ();

   // Initialize return val with NULL
   if (return_val)
     *return_val = NULL;

  /*FIXME: wait on the thread cancellation event as well - we are a cancellation point*/
  if (!isGoodObject (thread))
    return ESRCH;

  if (__pthread_equal (thread,&joiner))
    return EDEADLK;

  (*thread)->mutex.Lock ();

  if ((*thread)->attr.joinable == PTHREAD_CREATE_DETACHED)
    {
      (*thread)->mutex.UnLock ();
      return EINVAL;
    }
  else
    {
      (*thread)->joiner = joiner;
      (*thread)->attr.joinable = PTHREAD_CREATE_DETACHED;
      (*thread)->mutex.UnLock ();
      WaitForSingleObject ((*thread)->win32_obj_id, INFINITE);
      if (return_val)
	 *return_val = (*thread)->return_ptr;
      // cleanup
      delete (*thread);
    }	/*End if */

  pthread_testcancel ();

  return 0;
}

int
pthread::detach (pthread_t *thread)
{
  if (!isGoodObject (thread))
    return ESRCH;

  (*thread)->mutex.Lock ();
  if ((*thread)->attr.joinable == PTHREAD_CREATE_DETACHED)
    {
      (*thread)->mutex.UnLock ();
      return EINVAL;
    }

  // check if thread is still alive
  if (WAIT_TIMEOUT == WaitForSingleObject ((*thread)->win32_obj_id, 0) )
    {
      // force cleanup on exit
      (*thread)->joiner = *thread;
      (*thread)->attr.joinable = PTHREAD_CREATE_DETACHED;
      (*thread)->mutex.UnLock ();
    }
  else
    {
      // thread has already terminated.
      (*thread)->mutex.UnLock ();
      delete (*thread);
    }

  return 0;
}

int
pthread::suspend (pthread_t *thread)
{
  if (!isGoodObject (thread))
    return ESRCH;

  if ((*thread)->suspended == false)
    {
      (*thread)->suspended = true;
      SuspendThread ((*thread)->win32_obj_id);
    }

  return 0;
}


int
pthread::resume (pthread_t *thread)
{
  if (!isGoodObject (thread))
    return ESRCH;

  if ((*thread)->suspended == true)
    ResumeThread ((*thread)->win32_obj_id);
  (*thread)->suspended = false;

  return 0;
}

/*provided for source level compatability.
 *See http://www.opengroup.org/onlinepubs/007908799/xsh/pthread_getconcurrency.html
 */
int
__pthread_getconcurrency (void)
{
  return MT_INTERFACE->concurrency;
}

/*keep this in sync with sched.cc */
int
__pthread_getschedparam (pthread_t thread, int *policy,
			 struct sched_param *param)
{
  if (!pthread::isGoodObject (&thread))
    return ESRCH;
  *policy = SCHED_FIFO;
  /*we don't return the current effective priority, we return the current requested
   *priority */
  *param = thread->attr.schedparam;
  return 0;
}

/*Thread SpecificData */
int
__pthread_key_create (pthread_key_t *key, void (*destructor) (void *))
{
  /*The opengroup docs don't define if we should check this or not,
   *but creation is relatively rare..
   */
  if (pthread_key::isGoodObject (key))
    return EBUSY;

  *key = new pthread_key (destructor);

  if (!pthread_key::isGoodObject (key))
    {
      delete (*key);
      *key = NULL;
      return EAGAIN;
    }
  return 0;
}

int
__pthread_key_delete (pthread_key_t key)
{
  if (!pthread_key::isGoodObject (&key))
    return EINVAL;

  delete (key);
  return 0;
}

/*provided for source level compatability.
 *See http://www.opengroup.org/onlinepubs/007908799/xsh/pthread_getconcurrency.html
 */
int
__pthread_setconcurrency (int new_level)
{
  if (new_level < 0)
    return EINVAL;
  MT_INTERFACE->concurrency = new_level;
  return 0;
}

/*keep syncronised with sched.cc */
int
__pthread_setschedparam (pthread_t thread, int policy,
			 const struct sched_param *param)
{
  if (!pthread::isGoodObject (&thread))
    return ESRCH;
  if (policy != SCHED_FIFO)
    return ENOTSUP;
  if (!param)
    return EINVAL;
  int rv =
    sched_set_thread_priority (thread->win32_obj_id, param->sched_priority);
  if (!rv)
    thread->attr.schedparam.sched_priority = param->sched_priority;
  return rv;
}


int
__pthread_setspecific (pthread_key_t key, const void *value)
{
  if (!pthread_key::isGoodObject (&key))
    return EINVAL;
  (key)->set (value);
  return 0;
}

void *
__pthread_getspecific (pthread_key_t key)
{
  if (!pthread_key::isGoodObject (&key))
    return NULL;

  return (key)->get ();

}

/*Thread synchronisation */
bool
pthread_cond::isGoodObject (pthread_cond_t const *cond)
{
  if (verifyable_object_isvalid (cond, PTHREAD_COND_MAGIC) != VALID_OBJECT)
    return false;
  return true;
}

bool
pthread_cond::isGoodInitializer (pthread_cond_t const *cond)
{
  if (verifyable_object_isvalid (cond, PTHREAD_COND_MAGIC, PTHREAD_COND_INITIALIZER) != VALID_STATIC_OBJECT)
    return false;
  return true;
}

bool
pthread_cond::isGoodInitializerOrObject (pthread_cond_t const *cond)
{
  if (verifyable_object_isvalid (cond, PTHREAD_COND_MAGIC, PTHREAD_COND_INITIALIZER) == INVALID_OBJECT)
    return false;
  return true;
}

int
__pthread_cond_destroy (pthread_cond_t *cond)
{
  if (pthread_cond::isGoodInitializer (cond))
    return 0;
  if (!pthread_cond::isGoodObject (cond))
    return EINVAL;

  /*reads are atomic */
  if ((*cond)->waiting)
    return EBUSY;

  delete (*cond);
  *cond = NULL;

  return 0;
}

int
__pthread_cond_init (pthread_cond_t *cond, const pthread_condattr_t *attr)
{
  if (attr && !pthread_condattr::isGoodObject (attr))
    return EINVAL;

  if (pthread_cond::isGoodObject (cond))
    return EBUSY;

  *cond = new pthread_cond (attr ? (*attr) : NULL);

  if (!pthread_cond::isGoodObject (cond))
    {
      delete (*cond);
      *cond = NULL;
      return EAGAIN;
    }

  return 0;
}

int
__pthread_cond_broadcast (pthread_cond_t *cond)
{
  if (pthread_cond::isGoodInitializer (cond))
    __pthread_cond_init (cond, NULL);
  if (!pthread_cond::isGoodObject (cond))
    return EINVAL;

  (*cond)->BroadCast ();

  return 0;
}

int
__pthread_cond_signal (pthread_cond_t *cond)
{
  if (pthread_cond::isGoodInitializer (cond))
    __pthread_cond_init (cond, NULL);
  if (!pthread_cond::isGoodObject (cond))
    return EINVAL;

  (*cond)->Signal ();

  return 0;
}

int
__pthread_cond_dowait (pthread_cond_t *cond, pthread_mutex_t *mutex,
		       long waitlength)
{
// and yes cond_access here is still open to a race. (we increment, context swap,
// broadcast occurs -  we miss the broadcast. the functions aren't split properly.
  int rv;
  pthread_mutex **themutex = NULL;
  if (*mutex == PTHREAD_MUTEX_INITIALIZER)
    __pthread_mutex_init (mutex, NULL);
  themutex = mutex;
  if (pthread_cond::isGoodInitializer (cond))
    __pthread_cond_init (cond, NULL);

  if (!pthread_mutex::isGoodObject (themutex))
    return EINVAL;
  if (!pthread_cond::isGoodObject (cond))
    return EINVAL;

  /*if the cond variable is blocked, then the above timer test maybe wrong. *shrug**/
  if (pthread_mutex_lock (&(*cond)->cond_access))
    system_printf ("Failed to lock condition variable access mutex, this %p", *cond);

  if ((*cond)->waiting)
    if ((*cond)->mutex && ((*cond)->mutex != (*themutex)))
      {
	if (pthread_mutex_unlock (&(*cond)->cond_access))
	  system_printf ("Failed to unlock condition variable access mutex, this %p", *cond);
	return EINVAL;
      }
  InterlockedIncrement (&((*cond)->waiting));

  (*cond)->mutex = (*themutex);
  InterlockedIncrement (&((*themutex)->condwaits));
  if (pthread_mutex_unlock (&(*cond)->cond_access))
    system_printf ("Failed to unlock condition variable access mutex, this %p", *cond);
  /* At this point calls to Signal will progress evebn if we aren' yet waiting
   * However, the loop there should allow us to get scheduled and call wait,
   * and have them call PulseEvent again if we dont' respond.
   */
  rv = (*cond)->TimedWait (waitlength);
  /* this may allow a race on the mutex acquisition and waits..
   * But doing this within the cond access mutex creates a different race
   */
  InterlockedDecrement (&((*cond)->waiting));
  /* Tell Signal that we have been released */
  InterlockedDecrement (&((*cond)->ExitingWait));
  (*themutex)->Lock ();
  if (pthread_mutex_lock (&(*cond)->cond_access))
    system_printf ("Failed to lock condition variable access mutex, this %p", *cond);
  if ((*cond)->waiting == 0)
    (*cond)->mutex = NULL;
  InterlockedDecrement (&((*themutex)->condwaits));
  if (pthread_mutex_unlock (&(*cond)->cond_access))
    system_printf ("Failed to unlock condition variable access mutex, this %p", *cond);

  return rv;
}

extern "C" int
pthread_cond_timedwait (pthread_cond_t *cond, pthread_mutex_t *mutex,
			const struct timespec *abstime)
{
  if (check_valid_pointer (abstime))
    return EINVAL;
  struct timeb currSysTime;
  long waitlength;
  ftime (&currSysTime);
  waitlength = (abstime->tv_sec - currSysTime.time) *1000;
  if (waitlength < 0)
    return ETIMEDOUT;
  return __pthread_cond_dowait (cond, mutex, waitlength);
}

extern "C" int
pthread_cond_wait (pthread_cond_t *cond, pthread_mutex_t *mutex)
{
  return __pthread_cond_dowait (cond, mutex, INFINITE);
}

int
__pthread_condattr_init (pthread_condattr_t *condattr)
{
  /* FIXME: we dereference blindly! */
  *condattr = new pthread_condattr;
  if (!pthread_condattr::isGoodObject (condattr))
    {
      delete (*condattr);
      *condattr = NULL;
      return EAGAIN;
    }
  return 0;
}

int
__pthread_condattr_getpshared (const pthread_condattr_t *attr, int *pshared)
{
  if (!pthread_condattr::isGoodObject (attr))
    return EINVAL;
  *pshared = (*attr)->shared;
  return 0;
}

int
__pthread_condattr_setpshared (pthread_condattr_t *attr, int pshared)
{
  if (!pthread_condattr::isGoodObject (attr))
    return EINVAL;
  if ((pshared < 0) || (pshared > 1))
    return EINVAL;
  /*shared cond vars not currently supported */
  if (pshared != PTHREAD_PROCESS_PRIVATE)
    return EINVAL;
  (*attr)->shared = pshared;
  return 0;
}

int
__pthread_condattr_destroy (pthread_condattr_t *condattr)
{
  if (!pthread_condattr::isGoodObject (condattr))
    return EINVAL;
  delete (*condattr);
  *condattr = NULL;
  return 0;
}

/*Thread signal */
int
__pthread_kill (pthread_t thread, int sig)
{
// lock myself, for the use of thread2signal
  // two different kills might clash: FIXME

  if (!pthread::isGoodObject (&thread))
    return EINVAL;

  if (thread->sigs)
    myself->setthread2signal (thread);

  int rval = _kill (myself->pid, sig);

  // unlock myself
  return rval;
}

int
__pthread_sigmask (int operation, const sigset_t *set, sigset_t *old_set)
{
  pthread *thread = pthread::self ();

  // lock this myself, for the use of thread2signal
  // two differt kills might clash: FIXME

  if (thread->sigs)
    myself->setthread2signal (thread);

  int rval = sigprocmask (operation, set, old_set);

  // unlock this myself

  return rval;
}

/* ID */

int
__pthread_equal (pthread_t *t1, pthread_t *t2)
{
  return (*t1 == *t2);
}

/*Mutexes  */

/*FIXME: there's a potential race with PTHREAD_MUTEX_INITALIZER:
 *the mutex is not actually inited until the first use.
 *So two threads trying to lock/trylock may collide.
 *Solution: we need a global mutex on mutex creation, or possibly simply
 *on all constructors that allow INITIALIZER macros.
 *the lock should be very small: only around the init routine, not
 *every test, or all mutex access will be synchronised.
 */

int
__pthread_mutex_init (pthread_mutex_t *mutex,
		      const pthread_mutexattr_t *attr)
{
  if (attr && !pthread_mutexattr::isGoodObject (attr) || check_valid_pointer (mutex))
    return EINVAL;

  /* FIXME: bugfix: we should check *mutex being a valid address */
  if (pthread_mutex::isGoodObject (mutex))
    return EBUSY;

  *mutex = new pthread_mutex (attr ? (*attr) : NULL);
  if (!pthread_mutex::isGoodObject (mutex))
    {
      delete (*mutex);
      *mutex = NULL;
      return EAGAIN;
    }
  return 0;
}

int
__pthread_mutex_getprioceiling (const pthread_mutex_t *mutex,
				int *prioceiling)
{
  pthread_mutex_t *themutex = (pthread_mutex_t *) mutex;
  if (pthread_mutex::isGoodInitializer (mutex))
    __pthread_mutex_init ((pthread_mutex_t *) mutex, NULL);
  if (!pthread_mutex::isGoodObject (themutex))
    return EINVAL;
  /*We don't define _POSIX_THREAD_PRIO_PROTECT because we do't currently support
   *mutex priorities.
   *
   *We can support mutex priorities in the future though:
   *Store a priority with each mutex.
   *When the mutex is optained, set the thread priority as appropriate
   *When the mutex is released, reset the thread priority.
   */
  return ENOSYS;
}

int
__pthread_mutex_lock (pthread_mutex_t *mutex)
{
  pthread_mutex_t *themutex = mutex;
  /* This could be simplified via isGoodInitializerOrObject 
     and isGoodInitializer, but in a performance critical call like this....
     no.
     */
  switch (verifyable_object_isvalid (themutex, PTHREAD_MUTEX_MAGIC, PTHREAD_MUTEX_INITIALIZER))
    {
    case INVALID_OBJECT:
      return EINVAL;
      break;
    case VALID_STATIC_OBJECT:
      if (pthread_mutex::isGoodInitializer (mutex))
	{
	  int rv = __pthread_mutex_init (mutex, NULL);
	  if (rv)
	    return rv;
	}
      break;
    case VALID_OBJECT:
      break;
    }
  (*themutex)->Lock ();
  return 0;
}

int
__pthread_mutex_trylock (pthread_mutex_t *mutex)
{
  pthread_mutex_t *themutex = mutex;
  if (pthread_mutex::isGoodInitializer (mutex))
    __pthread_mutex_init (mutex, NULL);
  if (!pthread_mutex::isGoodObject (themutex))
    return EINVAL;
  if ((*themutex)->TryLock ())
    return EBUSY;
  return 0;
}

int
__pthread_mutex_unlock (pthread_mutex_t *mutex)
{
  if (pthread_mutex::isGoodInitializer (mutex))
    __pthread_mutex_init (mutex, NULL);
  if (!pthread_mutex::isGoodObject (mutex))
    return EINVAL;
  (*mutex)->UnLock ();
  return 0;
}

int
__pthread_mutex_destroy (pthread_mutex_t *mutex)
{
  if (pthread_mutex::isGoodInitializer (mutex))
    return 0;
  if (!pthread_mutex::isGoodObject (mutex)) 
    return EINVAL;

  /*reading a word is atomic */
  if ((*mutex)->condwaits)
    return EBUSY;

  delete (*mutex);
  *mutex = NULL;
  return 0;
}

int
__pthread_mutex_setprioceiling (pthread_mutex_t *mutex, int prioceiling,
				int *old_ceiling)
{
  pthread_mutex_t *themutex = mutex;
  if (pthread_mutex::isGoodInitializer (mutex))
    __pthread_mutex_init (mutex, NULL);
  if (!pthread_mutex::isGoodObject (themutex))
    return EINVAL;
  return ENOSYS;
}

/*Win32 doesn't support mutex priorities - see __pthread_mutex_getprioceiling
 *for more detail */
int
__pthread_mutexattr_getprotocol (const pthread_mutexattr_t *attr,
				 int *protocol)
{
  if (!pthread_mutexattr::isGoodObject (attr))
    return EINVAL;
  return ENOSYS;
}

int
__pthread_mutexattr_getpshared (const pthread_mutexattr_t *attr,
				int *pshared)
{
  if (!pthread_mutexattr::isGoodObject (attr))
    return EINVAL;
  *pshared = (*attr)->pshared;
  return 0;
}

/*Win32 mutex's are equivalent to posix RECURSIVE mutexs.
 *We need to put glue in place to support other types of mutex's. We map
 *PTHREAD_MUTEX_DEFAULT to PTHREAD_MUTEX_RECURSIVE and return EINVAL for other types.
 */
int
__pthread_mutexattr_gettype (const pthread_mutexattr_t *attr, int *type)
{
  if (!pthread_mutexattr::isGoodObject (attr))
    return EINVAL;
  *type = (*attr)->mutextype;
  return 0;
}

/*Currently pthread_mutex_init ignores the attr variable, this is because
 *none of the variables have any impact on it's behaviour.
 *
 *FIXME: write and test process shared mutex's.
 */
int
__pthread_mutexattr_init (pthread_mutexattr_t *attr)
{
  if (pthread_mutexattr::isGoodObject (attr))
    return EBUSY;

  *attr = new pthread_mutexattr ();
  if (!pthread_mutexattr::isGoodObject (attr))
    {
      delete (*attr);
      *attr = NULL;
      return ENOMEM;
    }
  return 0;
}

int
__pthread_mutexattr_destroy (pthread_mutexattr_t *attr)
{
  if (!pthread_mutexattr::isGoodObject (attr))
    return EINVAL;
  delete (*attr);
  *attr = NULL;
  return 0;
}


/*Win32 doesn't support mutex priorities */
int
__pthread_mutexattr_setprotocol (pthread_mutexattr_t *attr, int protocol)
{
  if (!pthread_mutexattr::isGoodObject (attr))
    return EINVAL;
  return ENOSYS;
}

/*Win32 doesn't support mutex priorities */
int
__pthread_mutexattr_setprioceiling (pthread_mutexattr_t *attr,
				    int prioceiling)
{
  if (!pthread_mutexattr::isGoodObject (attr))
    return EINVAL;
  return ENOSYS;
}

int
__pthread_mutexattr_getprioceiling (const pthread_mutexattr_t *attr,
				    int *prioceiling)
{
  if (!pthread_mutexattr::isGoodObject (attr))
    return EINVAL;
  return ENOSYS;
}

int
__pthread_mutexattr_setpshared (pthread_mutexattr_t *attr, int pshared)
{
  if (!pthread_mutexattr::isGoodObject (attr))
    return EINVAL;
  /*we don't use pshared for anything as yet. We need to test PROCESS_SHARED
   *functionality
   */
  if (pshared != PTHREAD_PROCESS_PRIVATE)
    return EINVAL;
  (*attr)->pshared = pshared;
  return 0;
}

/*see __pthread_mutex_gettype */
int
__pthread_mutexattr_settype (pthread_mutexattr_t *attr, int type)
{
  if (!pthread_mutexattr::isGoodObject (attr))
    return EINVAL;
  if (type != PTHREAD_MUTEX_RECURSIVE)
    return EINVAL;
  (*attr)->mutextype = type;
  return 0;
}

/*Semaphores */

/* static members */
bool
semaphore::isGoodObject (sem_t const * sem)
{
  if (verifyable_object_isvalid (sem, SEM_MAGIC) != VALID_OBJECT)
    return false;
  return true;
}

int
semaphore::init (sem_t *sem, int pshared, unsigned int value)
{
  /*opengroup calls this undefined */
  if (isGoodObject (sem))
    return EBUSY;

  if (value > SEM_VALUE_MAX)
    return EINVAL;

  *sem = new semaphore (pshared, value);

  if (!isGoodObject (sem))
    {
      delete (*sem);
      *sem = NULL;
      return EAGAIN;
    }
  return 0;
}

int
semaphore::destroy (sem_t *sem)
{
  if (!isGoodObject (sem))
    return EINVAL;

  /*FIXME - new feature - test for busy against threads... */

  delete (*sem);
  *sem = NULL;
  return 0;
}

int
semaphore::wait (sem_t *sem)
{
  if (!isGoodObject (sem))
    {
      set_errno (EINVAL);
      return -1;
    }

  (*sem)->Wait ();
  return 0;
}

int
semaphore::trywait (sem_t *sem)
{
  if (!isGoodObject (sem))
    {
      set_errno (EINVAL);
      return -1;
    }

  return (*sem)->TryWait ();
}

int
semaphore::post (sem_t *sem)
{
  if (!isGoodObject (sem))
    return EINVAL;

  (*sem)->Post ();
  return 0;
}

/* pthreadNull */
pthread *
pthreadNull::getNullpthread ()
{
  /* because of weird entry points */
  _instance.magic = 0;
  return &_instance;
}

pthreadNull::pthreadNull ()
{
  /* Mark ourselves as invalid */
  magic = 0;
}

pthreadNull::~pthreadNull ()
{
}

void
pthreadNull::create (void *(*)(void *), pthread_attr *, void *)
{
}

void
pthreadNull::exit (void *value_ptr)
{
}

int
pthreadNull::cancel ()
{
  return 0;
}

void
pthreadNull::testcancel ()
{
}

int
pthreadNull::setcancelstate (int state, int *oldstate)
{
  return EINVAL;
}

int
pthreadNull::setcanceltype (int type, int *oldtype)
{
  return EINVAL;
}

void
pthreadNull::push_cleanup_handler (__pthread_cleanup_handler *handler)
{
}

void
pthreadNull::pop_cleanup_handler (int const execute)
{
}
unsigned long
pthreadNull::getsequence_np ()
{
  return 0;
}

pthreadNull pthreadNull::_instance = pthreadNull ();

#endif // MT_SAFE
