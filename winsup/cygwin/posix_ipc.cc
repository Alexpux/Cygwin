/* posix_ipc.cc: POSIX IPC API for Cygwin.

   Copyright 2007 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

/* TODO: POSIX semaphores are implemented in thread.cc right now.  The
	 implementation in thread.cc disallows implementing kernel
	 persistent semaphores, so in the long run we should move the
	 implementation here, using file based shared memory instead. */

#include "winsup.h"
#include "path.h"
#include "cygerrno.h"
#include "cygtls.h"
#include "security.h"
#include "sigproc.h"
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <stdarg.h>
#include <mqueue.h>

struct
{
  const char *prefix;
  const char *description;
} ipc_names[] = {
  { "/dev/shm", "POSIX shared memory object" },
  { "/dev/mqueue", "POSIX message queue" },
  { "/dev/sem", "POSIX semaphore" }
};

enum ipc_type_t
{
  shmem,
  mqueue,
  sem
};

static bool
check_path (char *res_name, ipc_type_t type, const char *name)
{
  /* Note that we require the existance of the apprpriate /dev subdirectories
     for POSIX IPC object support, similar to Linux (which supports the
     directories, but doesn't require to mount them).  We don't create
     these directory here, that's the task of the installer.  But we check
     for existance and give ample warning. */
  path_conv path (ipc_names[type].prefix, PC_SYM_NOFOLLOW);
  if (path.error || !path.exists () || !path.isdir ())
    {
      small_printf (
	"Warning: '%s' does not exists or is not a directory.\n\n"
	"%ss require the existance of this directory.\n"
	"Create the directory '%s' and set the permissions to 01777.\n"
	"For instance on the command line: mkdir -m 01777 %s\n",
	ipc_names[type].prefix, ipc_names[type].description,
	ipc_names[type].prefix, ipc_names[type].prefix);
      set_errno (EINVAL);
      return false;
    }
  /* Name must start with a single slash. */
  if (!name || name[0] != '/' || name[1] == '/')
    {
      debug_printf ("Invalid %s name '%s'", ipc_names[type].description, name);
      set_errno (EINVAL);
      return false;
    }
  if (strlen (name) > CYG_MAX_PATH - sizeof (ipc_names[type].prefix))
    {
      debug_printf ("%s name '%s' too long", ipc_names[type].description, name);
      set_errno (ENAMETOOLONG);
      return false;
    }
  strcpy (res_name, ipc_names[type].prefix);
  strcat (res_name, name);
  return true;
}

static int
ipc_mutex_init (HANDLE *pmtx, const char *name)
{
  char buf[CYG_MAX_PATH];
  __small_sprintf (buf, "%scyg_pmtx/%s",
		   wincap.has_terminal_services () ? "Global\\" : "", name);
  *pmtx = CreateMutex (&sec_all, FALSE, buf);
  if (!*pmtx)
    debug_printf ("failed: %E\n");
  return *pmtx ? 0 : geterrno_from_win_error ();
}

static int
ipc_mutex_lock (HANDLE mtx)
{
  HANDLE h[2] = { mtx, signal_arrived };

  switch (WaitForMultipleObjects (2, h, FALSE, INFINITE))
    {     
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED_0:
      return 0;
    case WAIT_OBJECT_0 + 1:
      set_errno (EINTR);
      return 1;
    default:
      break;
    }     
  return geterrno_from_win_error ();
}

static inline int
ipc_mutex_unlock (HANDLE mtx)
{
  return ReleaseMutex (mtx) ? 0 : geterrno_from_win_error ();
}

static inline int
ipc_mutex_close (HANDLE mtx)
{
  return CloseHandle (mtx) ? 0 : geterrno_from_win_error ();
}

static int
ipc_cond_init (HANDLE *pevt, const char *name)
{
  char buf[CYG_MAX_PATH];
  strcpy (buf, wincap.has_terminal_services () ? "Global\\" : "");
  __small_sprintf (buf, "%scyg_pevt/%s",
		   wincap.has_terminal_services () ? "Global\\" : "", name);
  *pevt = CreateEvent (&sec_all, TRUE, FALSE, buf);
  if (!*pevt)
    debug_printf ("failed: %E\n");
  return *pevt ? 0 : geterrno_from_win_error ();
}

static int
ipc_cond_timedwait (HANDLE evt, HANDLE mtx, const struct timespec *abstime)
{
  struct timeval tv;
  DWORD timeout;
  HANDLE h[2] = { mtx, evt };

  if (!abstime)
    timeout = INFINITE;
  else if (abstime->tv_sec < 0
	   || abstime->tv_nsec < 0
	   || abstime->tv_nsec > 999999999)
    return EINVAL;
  else
    {
      gettimeofday (&tv, NULL);
      /* Check for immediate timeout. */
      if (tv.tv_sec > abstime->tv_sec
	  || (tv.tv_sec == abstime->tv_sec
	      && tv.tv_usec > abstime->tv_nsec / 1000))
	return ETIMEDOUT;
      timeout = (abstime->tv_sec - tv.tv_sec) * 1000;
      timeout += (abstime->tv_nsec / 1000 - tv.tv_usec) / 1000;
    }
  if (ipc_mutex_unlock (mtx))
    return -1;
  switch (WaitForMultipleObjects (2, h, TRUE, timeout))
    {     
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED_0:
      ResetEvent (evt);
      return 0;
    case WAIT_TIMEOUT:
      ipc_mutex_lock (mtx);
      return ETIMEDOUT;
    default:
      break;
    }     
  return geterrno_from_win_error ();
}

static inline int
ipc_cond_signal (HANDLE evt)
{
  return SetEvent (evt) ? 0 : geterrno_from_win_error ();
}

static inline int
ipc_cond_close (HANDLE evt)
{
  return CloseHandle (evt) ? 0 : geterrno_from_win_error ();
}

/* POSIX shared memory object implementation. */

extern "C" int
shm_open (const char *name, int oflag, mode_t mode)
{
  char shmname[CYG_MAX_PATH];

  if (!check_path (shmname, shmem, name))
    return -1;

  /* Check for valid flags. */
  if (((oflag & O_ACCMODE) != O_RDONLY && (oflag & O_ACCMODE) != O_RDWR)
      || (oflag & ~(O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC)))
    {
      debug_printf ("Invalid oflag 0%o", oflag);
      set_errno (EINVAL);
      return -1;
    }

  return open (shmname, oflag, mode & 0777);
}

extern "C" int
shm_unlink (const char *name)
{
  char shmname[CYG_MAX_PATH];

  if (!check_path (shmname, shmem, name))
    return -1;

  return unlink (shmname);
}

/* The POSIX message queue implementation is based on W. Richard STEVENS
   implementation, just tweaked for Cygwin.  The main change is
   the usage of Windows mutexes and events instead of using the pthread
   synchronization objects.  The pathname is massaged so that the
   files are created under /dev/mqueue.  mq_timedsend and mq_timedreceive
   are implemented additionally. */

struct mq_hdr
{
  struct mq_attr  mqh_attr;	 /* the queue's attributes */
  long            mqh_head;	 /* index of first message */
  long            mqh_free;	 /* index of first free message */
  long            mqh_nwait;	 /* #threads blocked in mq_receive() */
  pid_t           mqh_pid;	 /* nonzero PID if mqh_event set */
  char            mqh_uname[20]; /* unique name used to identify synchronization
  				    objects connected to this queue */
  struct sigevent mqh_event;	 /* for mq_notify() */
};

struct msg_hdr
{
  long            msg_next;	 /* index of next on linked list */
  ssize_t         msg_len;	 /* actual length */
  unsigned int    msg_prio;	 /* priority */
};

struct mq_info
{
  struct mq_hdr  *mqi_hdr;	 /* start of mmap'ed region */
  unsigned long   mqi_magic;	 /* magic number if open */
  int             mqi_flags;	 /* flags for this process */
  HANDLE          mqi_lock;	 /* mutex lock */
  HANDLE          mqi_wait;	 /* and condition variable */
};

#define MQI_MAGIC	0x98765432UL

#define MSGSIZE(i)	roundup((i), sizeof(long))

#define	 MAX_TRIES	10	/* for waiting for initialization */

struct mq_attr defattr = { 0, 10, 8192, 0 };	/* Linux defaults. */

extern "C" _off64_t lseek64 (int, _off64_t, int);
extern "C" void *mmap64 (void *, size_t, int, int, int, _off64_t);

extern "C" mqd_t
mq_open (const char *name, int oflag, ...)
{
  int i, fd, nonblock, created;
  long msgsize, index;
  _off64_t filesize;
  va_list ap;
  mode_t mode;
  int8_t *mptr;
  struct __stat64 statbuff;
  struct mq_hdr *mqhdr;
  struct msg_hdr *msghdr;
  struct mq_attr *attr;
  struct mq_info *mqinfo;
  char mqname[CYG_MAX_PATH];

  if (!check_path (mqname, mqueue, name))
    return (mqd_t) -1;

  myfault efault;
  if (efault.faulted (EFAULT))
      return (mqd_t) -1;

  created = 0;
  nonblock = oflag & O_NONBLOCK;
  oflag &= ~O_NONBLOCK;
  mptr = (int8_t *) MAP_FAILED;
  mqinfo = NULL;

again:
  if (oflag & O_CREAT)
    {
      va_start (ap, oflag);		/* init ap to final named argument */
      mode = va_arg (ap, mode_t) & ~S_IXUSR;
      attr = va_arg (ap, struct mq_attr *);
      va_end (ap);

      /* Open and specify O_EXCL and user-execute */
      fd = open (mqname, oflag | O_EXCL | O_RDWR, mode | S_IXUSR);
      if (fd < 0)
        {
	  if (errno == EEXIST && (oflag & O_EXCL) == 0)
	    goto exists;		/* already exists, OK */
	  return (mqd_t) -1;
	}
      created = 1;
      /* First one to create the file initializes it */
      if (attr == NULL)
	attr = &defattr;
      else if (attr->mq_maxmsg <= 0 || attr->mq_msgsize <= 0)
	{
	  set_errno (EINVAL);
	  goto err;
	}
      /* Calculate and set the file size */
      msgsize = MSGSIZE (attr->mq_msgsize);
      filesize = sizeof (struct mq_hdr)
      		 + (attr->mq_maxmsg * (sizeof (struct msg_hdr) + msgsize));
      if (lseek64 (fd, filesize - 1, SEEK_SET) == -1)
	goto err;
      if (write (fd, "", 1) == -1)
	goto err;

      /* Memory map the file */
      mptr = (int8_t *) mmap64 (NULL, (size_t) filesize, PROT_READ | PROT_WRITE,
				MAP_SHARED, fd, 0);
      if (mptr == (int8_t *) MAP_FAILED)
	goto err;

      /* Allocate one mq_info{} for the queue */
      if (!(mqinfo = (struct mq_info *) malloc (sizeof (struct mq_info))))
	goto err;
      mqinfo->mqi_hdr = mqhdr = (struct mq_hdr *) mptr;
      mqinfo->mqi_magic = MQI_MAGIC;
      mqinfo->mqi_flags = nonblock;

      /* Initialize header at beginning of file */
      /* Create free list with all messages on it */
      mqhdr->mqh_attr.mq_flags = 0;
      mqhdr->mqh_attr.mq_maxmsg = attr->mq_maxmsg;
      mqhdr->mqh_attr.mq_msgsize = attr->mq_msgsize;
      mqhdr->mqh_attr.mq_curmsgs = 0;
      mqhdr->mqh_nwait = 0;
      mqhdr->mqh_pid = 0;
      __small_sprintf (mqhdr->mqh_uname, "cyg%016X", hash_path_name (0,mqname));
      mqhdr->mqh_head = 0;
      index = sizeof (struct mq_hdr);
      mqhdr->mqh_free = index;
      for (i = 0; i < attr->mq_maxmsg - 1; i++)
	{
	  msghdr = (struct msg_hdr *) &mptr[index];
	  index += sizeof (struct msg_hdr) + msgsize;
	  msghdr->msg_next = index;
	}
      msghdr = (struct msg_hdr *) &mptr[index];
      msghdr->msg_next = 0;		/* end of free list */

      /* Initialize mutex & condition variable */
      i = ipc_mutex_init (&mqinfo->mqi_lock, mqhdr->mqh_uname);
      if (i != 0)
	goto pthreaderr;

      i = ipc_cond_init (&mqinfo->mqi_wait, mqhdr->mqh_uname);
      if (i != 0)
	goto pthreaderr;

      /* Initialization complete, turn off user-execute bit */
      if (fchmod (fd, mode) == -1)
	goto err;
      close (fd);
      return ((mqd_t) mqinfo);
    }

exists:
  /* Open the file then memory map */
  if ((fd = open (mqname, O_RDWR)) < 0)
    {
      if (errno == ENOENT && (oflag & O_CREAT))
	goto again;
      goto err;
    }
  /* Make certain initialization is complete */
  for (i = 0; i < MAX_TRIES; i++)
    {
      if (stat64 (mqname, &statbuff) == -1)
	{
	  if (errno == ENOENT && (oflag & O_CREAT))
	    {
	      close(fd);
	      goto again;
	    }
	  goto err;
	}
      if ((statbuff.st_mode & S_IXUSR) == 0)
	break;
      sleep (1);
    }
  if (i == MAX_TRIES)
    {
      set_errno (ETIMEDOUT);
      goto err;
    }

  filesize = statbuff.st_size;
  mptr = (int8_t *) mmap64 (NULL, (size_t) filesize, PROT_READ | PROT_WRITE,
			    MAP_SHARED, fd, 0);
  if (mptr == (int8_t *) MAP_FAILED)
    goto err;
  close (fd);

  /* Allocate one mq_info{} for each open */
  if (!(mqinfo = (struct mq_info *) malloc (sizeof (struct mq_info))))
    goto err;
  mqinfo->mqi_hdr = (struct mq_hdr *) mptr;
  mqinfo->mqi_magic = MQI_MAGIC;
  mqinfo->mqi_flags = nonblock;

  /* Initialize mutex & condition variable */
  i = ipc_mutex_init (&mqinfo->mqi_lock, mqhdr->mqh_uname);
  if (i != 0)
    goto pthreaderr;

  i = ipc_cond_init (&mqinfo->mqi_wait, mqhdr->mqh_uname);
  if (i != 0)
    goto pthreaderr;

  return (mqd_t) mqinfo;

pthreaderr:
  errno = i;
err:
  /* Don't let following function calls change errno */
  save_errno save;

  if (created)
    unlink (mqname);
  if (mptr != (int8_t *) MAP_FAILED)
    munmap((void *) mptr, (size_t) filesize);
  if (mqinfo)
    free (mqinfo);
  close (fd);
  return (mqd_t) -1;
}

extern "C" int
mq_getattr (mqd_t mqd, struct mq_attr *mqstat)
{
  int n;
  struct mq_hdr *mqhdr;
  struct mq_attr *attr;
  struct mq_info *mqinfo;
  
  myfault efault;
  if (efault.faulted (EBADF))
      return -1;

  mqinfo = (struct mq_info *) mqd;
  if (mqinfo->mqi_magic != MQI_MAGIC)
    {
      set_errno (EBADF);
      return -1;
    }
  mqhdr = mqinfo->mqi_hdr;
  attr = &mqhdr->mqh_attr;
  if ((n = ipc_mutex_lock (mqinfo->mqi_lock)) != 0)
    {
      errno = n;
      return -1;
    }       
  mqstat->mq_flags = mqinfo->mqi_flags;   /* per-open */
  mqstat->mq_maxmsg = attr->mq_maxmsg;    /* remaining three per-queue */
  mqstat->mq_msgsize = attr->mq_msgsize;
  mqstat->mq_curmsgs = attr->mq_curmsgs;

  ipc_mutex_unlock (mqinfo->mqi_lock);
  return 0;
}               

extern "C" int
mq_setattr (mqd_t mqd, const struct mq_attr *mqstat, struct mq_attr *omqstat)
{
  int n;
  struct mq_hdr *mqhdr; 
  struct mq_attr *attr;
  struct mq_info *mqinfo;

  myfault efault;
  if (efault.faulted (EBADF))
      return -1;

  mqinfo = (struct mq_info *) mqd;
  if (mqinfo->mqi_magic != MQI_MAGIC)
    {
      set_errno (EBADF);
      return -1;
    }
  mqhdr = mqinfo->mqi_hdr;
  attr = &mqhdr->mqh_attr;
  if ((n = ipc_mutex_lock (mqinfo->mqi_lock)) != 0)
    {
      errno = n;
      return -1;
    }

  if (omqstat != NULL)
    {
      omqstat->mq_flags = mqinfo->mqi_flags;  /* previous attributes */
      omqstat->mq_maxmsg = attr->mq_maxmsg;
      omqstat->mq_msgsize = attr->mq_msgsize;
      omqstat->mq_curmsgs = attr->mq_curmsgs; /* and current status */
    }

  if (mqstat->mq_flags & O_NONBLOCK)
    mqinfo->mqi_flags |= O_NONBLOCK;
  else
    mqinfo->mqi_flags &= ~O_NONBLOCK;

  ipc_mutex_unlock (mqinfo->mqi_lock);
  return 0;
}

extern "C" int
mq_notify (mqd_t mqd, const struct sigevent *notification)
{
  int n;
  pid_t pid;
  struct mq_hdr *mqhdr;
  struct mq_info *mqinfo;
  
  myfault efault;
  if (efault.faulted (EBADF))
      return -1;

  mqinfo = (struct mq_info *) mqd;
  if (mqinfo->mqi_magic != MQI_MAGIC)
    {
      set_errno (EBADF);  
      return -1;
    }
  mqhdr = mqinfo->mqi_hdr; 
  if ((n = ipc_mutex_lock (mqinfo->mqi_lock)) != 0)
    {
      errno = n;
      return -1;
    }
  
  pid = getpid ();
  if (!notification)
    {
      if (mqhdr->mqh_pid == pid)
	  mqhdr->mqh_pid = 0;     /* unregister calling process */
    }
  else
    {
      if (mqhdr->mqh_pid != 0)
	{
	  if (kill (mqhdr->mqh_pid, 0) != -1 || errno != ESRCH)
	    {
	      set_errno (EBUSY);
	      ipc_mutex_unlock (mqinfo->mqi_lock);
	      return -1;
	    }
	}
      mqhdr->mqh_pid = pid;
      mqhdr->mqh_event = *notification;
    }                                        
  ipc_mutex_unlock (mqinfo->mqi_lock);
  return 0;
}                       

static int
_mq_send (mqd_t mqd, const char *ptr, size_t len, unsigned int prio,
	  const struct timespec *abstime)
{
  int n;
  long index, freeindex;
  int8_t *mptr;
  struct sigevent *sigev;
  struct mq_hdr *mqhdr;
  struct mq_attr *attr;
  struct msg_hdr *msghdr, *nmsghdr, *pmsghdr;
  struct mq_info *mqinfo;

  myfault efault;
  if (efault.faulted (EBADF))
      return -1;

  mqinfo = (struct mq_info *) mqd;
  if (mqinfo->mqi_magic != MQI_MAGIC)
    {
      set_errno (EBADF);
      return -1;
    }
  if (prio > MQ_PRIO_MAX)
    {
      set_errno (EINVAL);
      return -1;
    }

  mqhdr = mqinfo->mqi_hdr;        /* struct pointer */
  mptr = (int8_t *) mqhdr;        /* byte pointer */
  attr = &mqhdr->mqh_attr;
  if ((n = ipc_mutex_lock (mqinfo->mqi_lock)) != 0)
    {
      errno = n;
      return -1;
    }

  if (len > (size_t) attr->mq_msgsize)
    {
      set_errno (EMSGSIZE);
      goto err;
    }
  if (attr->mq_curmsgs == 0)
    {
      if (mqhdr->mqh_pid != 0 && mqhdr->mqh_nwait == 0)
	{
	  sigev = &mqhdr->mqh_event;
	  if (sigev->sigev_notify == SIGEV_SIGNAL)
	    sigqueue (mqhdr->mqh_pid, sigev->sigev_signo, sigev->sigev_value);
	  mqhdr->mqh_pid = 0;             /* unregister */
	}
    }
  else if (attr->mq_curmsgs >= attr->mq_maxmsg)
    {
      /* Queue is full */
      if (mqinfo->mqi_flags & O_NONBLOCK)
	{
	  set_errno (EAGAIN);
	  goto err;
	}
      /* Wait for room for one message on the queue */
      while (attr->mq_curmsgs >= attr->mq_maxmsg)
	ipc_cond_timedwait (mqinfo->mqi_wait, mqinfo->mqi_lock, abstime);
    }

  /* nmsghdr will point to new message */
  if ((freeindex = mqhdr->mqh_free) == 0)
    api_fatal ("mq_send: curmsgs = %ld; free = 0", attr->mq_curmsgs);

  nmsghdr = (struct msg_hdr *) &mptr[freeindex];
  nmsghdr->msg_prio = prio;
  nmsghdr->msg_len = len;
  memcpy (nmsghdr + 1, ptr, len);          /* copy message from caller */
  mqhdr->mqh_free = nmsghdr->msg_next;    /* new freelist head */

  /* Find right place for message in linked list */
  index = mqhdr->mqh_head;
  pmsghdr = (struct msg_hdr *) &(mqhdr->mqh_head);
  while (index)
    {
      msghdr = (struct msg_hdr *) &mptr[index];
      if (prio > msghdr->msg_prio)
	{
	  nmsghdr->msg_next = index;
	  pmsghdr->msg_next = freeindex;
	  break;
	}
      index = msghdr->msg_next;
      pmsghdr = msghdr;
    }
  if (index == 0)
    {
      /* Queue was empty or new goes at end of list */
      pmsghdr->msg_next = freeindex;
      nmsghdr->msg_next = 0;
    }
  /* Wake up anyone blocked in mq_receive waiting for a message */
  if (attr->mq_curmsgs == 0)
    ipc_cond_signal (mqinfo->mqi_wait);
  attr->mq_curmsgs++;

  ipc_mutex_unlock (mqinfo->mqi_lock);
  return 0;

err:
  ipc_mutex_unlock (mqinfo->mqi_lock);
  return -1;
}

extern "C" int
mq_send (mqd_t mqd, const char *ptr, size_t len, unsigned int prio)
{
  return _mq_send (mqd, ptr, len, prio, NULL);
}

extern "C" int
mq_timedsend (mqd_t mqd, const char *ptr, size_t len, unsigned int prio,
	      const struct timespec *abstime)
{
  return _mq_send (mqd, ptr, len, prio, abstime);
}

static ssize_t
_mq_receive (mqd_t mqd, char *ptr, size_t maxlen, unsigned int *priop,
	     const struct timespec *abstime)
{
  int n;
  long index;
  int8_t *mptr;
  ssize_t len;
  struct mq_hdr *mqhdr; 
  struct mq_attr *attr;
  struct msg_hdr *msghdr;
  struct mq_info *mqinfo;

  myfault efault;
  if (efault.faulted (EBADF))
      return -1;

  mqinfo = (struct mq_info *) mqd;
  if (mqinfo->mqi_magic != MQI_MAGIC)
    {
      set_errno (EBADF);
      return -1;
    }
  mqhdr = mqinfo->mqi_hdr;        /* struct pointer */
  mptr = (int8_t *) mqhdr;        /* byte pointer */
  attr = &mqhdr->mqh_attr;
  if ((n = ipc_mutex_lock (mqinfo->mqi_lock)) != 0)
    {
      errno = n;
      return -1;
    }

  if (maxlen < (size_t) attr->mq_msgsize)
    {
      set_errno (EMSGSIZE);
      goto err;
    }
  if (attr->mq_curmsgs == 0)	/* queue is empty */
    {
      if (mqinfo->mqi_flags & O_NONBLOCK)
	{
	  set_errno (EAGAIN);
	  goto err;
	}
      /* Wait for a message to be placed onto queue */
      mqhdr->mqh_nwait++;
      while (attr->mq_curmsgs == 0)
	ipc_cond_timedwait (mqinfo->mqi_wait, mqinfo->mqi_lock, abstime);
      mqhdr->mqh_nwait--;
    }

  if ((index = mqhdr->mqh_head) == 0)
    api_fatal ("mq_receive: curmsgs = %ld; head = 0", attr->mq_curmsgs);

  msghdr = (struct msg_hdr *) &mptr[index];
  mqhdr->mqh_head = msghdr->msg_next;     /* new head of list */
  len = msghdr->msg_len;
  memcpy(ptr, msghdr + 1, len);           /* copy the message itself */
  if (priop != NULL)
    *priop = msghdr->msg_prio;

  /* Just-read message goes to front of free list */
  msghdr->msg_next = mqhdr->mqh_free;
  mqhdr->mqh_free = index;

  /* Wake up anyone blocked in mq_send waiting for room */
  if (attr->mq_curmsgs == attr->mq_maxmsg)
    ipc_cond_signal (mqinfo->mqi_wait);
  attr->mq_curmsgs--;

  ipc_mutex_unlock (mqinfo->mqi_lock);
  return len;

err:
  ipc_mutex_unlock (mqinfo->mqi_lock);
  return -1;
}

extern "C" ssize_t
mq_receive (mqd_t mqd, char *ptr, size_t maxlen, unsigned int *priop)
{
  return _mq_receive (mqd, ptr, maxlen, priop, NULL);
}

extern "C" ssize_t
mq_timedreceive (mqd_t mqd, char *ptr, size_t maxlen, unsigned int *priop,
		 const struct timespec *abstime)
{
  return _mq_receive (mqd, ptr, maxlen, priop, abstime);
}

extern "C" int
mq_close (mqd_t mqd)
{
  long msgsize, filesize;
  struct mq_hdr *mqhdr;
  struct mq_attr *attr;
  struct mq_info *mqinfo;

  myfault efault;
  if (efault.faulted (EBADF))
      return -1;

  mqinfo = (struct mq_info *) mqd;
  if (mqinfo->mqi_magic != MQI_MAGIC)
    {
      set_errno (EBADF);
      return -1;
    }
  mqhdr = mqinfo->mqi_hdr;
  attr = &mqhdr->mqh_attr;

  if (mq_notify (mqd, NULL))	/* unregister calling process */
    return -1;

  msgsize = MSGSIZE (attr->mq_msgsize);
  filesize = sizeof (struct mq_hdr)
	     + (attr->mq_maxmsg * (sizeof (struct msg_hdr) + msgsize));
  if (munmap (mqinfo->mqi_hdr, filesize) == -1)
    return -1;

  mqinfo->mqi_magic = 0;          /* just in case */
  ipc_cond_close (mqinfo->mqi_wait);
  ipc_mutex_close (mqinfo->mqi_lock);
  free (mqinfo);
  return 0;
}

extern "C" int
mq_unlink (const char *name)
{
  char mqname[CYG_MAX_PATH];

  if (!check_path (mqname, mqueue, name))
    return -1;
  if (unlink (mqname) == -1)
    return -1;
  return 0;
}

