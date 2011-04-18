/* poll.cc. Implements poll(2) via usage of select(2) call.

   Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
   2011 Red Hat, Inc.

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

#define  __INSIDE_CYGWIN_NET__

#define FD_SETSIZE 16384		// lots of fds
#include "winsup.h"
#include <sys/poll.h>
#include <stdlib.h>
#define USE_SYS_TYPES_FD_SET
#include "cygerrno.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "pinfo.h"
#include "sigproc.h"

extern "C" int
poll (struct pollfd *fds, nfds_t nfds, int timeout)
{
  int max_fd = 0;
  fd_set *read_fds, *write_fds, *except_fds;
  struct timeval tv = { timeout / 1000, (timeout % 1000) * 1000 };

  for (unsigned int i = 0; i < nfds; ++i)
    if (fds[i].fd > max_fd)
      max_fd = fds[i].fd;

  size_t fds_size = howmany (max_fd + 1, NFDBITS) * sizeof (fd_mask);

  read_fds = (fd_set *) alloca (fds_size);
  write_fds = (fd_set *) alloca (fds_size);
  except_fds = (fd_set *) alloca (fds_size);

  if (!read_fds || !write_fds || !except_fds)
    {
      set_errno (EINVAL);	/* According to SUSv3. */
      return -1;
    }

  memset (read_fds, 0, fds_size);
  memset (write_fds, 0, fds_size);
  memset (except_fds, 0, fds_size);

  int invalid_fds = 0;
  for (unsigned int i = 0; i < nfds; ++i)
    {
      fds[i].revents = 0;
      if (!cygheap->fdtab.not_open (fds[i].fd))
	{
	  if (fds[i].events & POLLIN)
	    FD_SET(fds[i].fd, read_fds);
	  if (fds[i].events & POLLOUT)
	    FD_SET(fds[i].fd, write_fds);
	  if (fds[i].events & POLLPRI)
	    FD_SET(fds[i].fd, except_fds);
	}
      else if (fds[i].fd >= 0)
	{
	  ++invalid_fds;
	  fds[i].revents = POLLNVAL;
	}
    }

  if (invalid_fds)
    return invalid_fds;

  int ret = cygwin_select (max_fd + 1, read_fds, write_fds, except_fds,
			   timeout < 0 ? NULL : &tv);
  if (ret <= 0)
    return ret;

  /* Set revents fields and count fds with non-zero revents fields for
     return value. */
  ret = 0;
  for (unsigned int i = 0; i < nfds; ++i)
    {
      if (fds[i].fd >= 0)
	{
	  fhandler_socket *sock;

	  /* Check if the descriptor has been closed, or if shutdown for the
	     read side has been called on a socket. */
	  if (cygheap->fdtab.not_open (fds[i].fd)
	      || ((sock = cygheap->fdtab[fds[i].fd]->is_socket ())
		  && sock->saw_shutdown_read ()))
	    fds[i].revents = POLLHUP;
	  else
	    {
	      if (FD_ISSET(fds[i].fd, read_fds))
		/* This should be sufficient for sockets, too.  Using
		   MSG_PEEK, as before, can be considered dangerous at
		   best.  Quote from W. Richard Stevens: "The presence
		   of an error can be considered either normal data or
		   an error (POLLERR).  In either case, a subsequent read
		   will return -1 with errno set to the appropriate value."
		   So it looks like there's actually no good reason to
		   return POLLERR. */
		fds[i].revents |= POLLIN;
	      /* Handle failed connect. */
	      if (FD_ISSET(fds[i].fd, write_fds)
		  && (sock = cygheap->fdtab[fds[i].fd]->is_socket ())
		  && sock->connect_state () == connect_failed)
		fds[i].revents |= (POLLIN | POLLERR);
	      else
		{
		  if (FD_ISSET(fds[i].fd, write_fds))
		    fds[i].revents |= POLLOUT;
		  if (FD_ISSET(fds[i].fd, except_fds))
		    fds[i].revents |= POLLPRI;
		}
	    }
	  if (fds[i].revents)
	    ++ret;
	}
    }

  return ret;
}

extern "C" int
ppoll (struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts,
       const sigset_t *sigmask)
{
  int timeout;
  sigset_t oldset = _my_tls.sigmask;

  myfault efault;
  if (efault.faulted (EFAULT))
    return -1;
  timeout = (timeout_ts == NULL)
	    ? -1
	    : (timeout_ts->tv_sec * 1000 + timeout_ts->tv_nsec / 1000000);
  if (sigmask)
    set_signal_mask (*sigmask, _my_tls.sigmask);
  int ret = poll (fds, nfds, timeout);
  if (sigmask)
    set_signal_mask (oldset, _my_tls.sigmask);
  return ret;
}
