/* cygserver_shm.h

   Copyright 2001 Red Hat Inc.
   Written by Robert Collins <rbtcollins@hotmail.com>

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include <sys/types.h>
#include "cygwin/cygserver_transport.h"
#include "cygwin/cygserver.h"

#define SHM_CREATE 0
#define SHM_REATTACH 1
#define SHM_ATTACH 2
#define SHM_DETACH 3
#define SHM_DEL    4


class client_request_shm : public client_request
{
  public:
#ifndef __INSIDE_CYGWIN__
  virtual void serve (transport_layer_base *conn, process_cache *cache);
#endif
  client_request_shm (key_t, size_t, int, char psdbuf[4096], pid_t);
  client_request_shm ();
  client_request_shm (int, int, pid_t);
  client_request_shm (int, int);
  union {
   struct {int type; pid_t pid; int shm_id; key_t key; size_t size; int shmflg; char sd_buf[4096];} in;
   struct {int shm_id; HANDLE filemap; HANDLE attachmap; key_t key;} out;
  } parameters;
};

#ifndef __INSIDE_CYGWIN__
class shm_cleanup : cleanup_routine
{
public:
  virtual void cleanup (long winpid);
};
#endif
#if 0
class _shmattach {
public:
  void *data;
  class _shmattach *next;
};

class shmid_ds {
public:
  struct   ipc_perm shm_perm;
  size_t   shm_segsz;
  pid_t    shm_lpid;
  pid_t    shm_cpid;
  shmatt_t shm_nattch;
  time_t   shm_atime;
  time_t   shm_dtime;
  time_t   shm_ctime;
  HANDLE filemap;
  HANDLE attachmap;
  void *mapptr;
  class _shmattach *attachhead;
};

class shmnode {
public:
  class shmid_ds * shmid;
  class shmnode *next;
  key_t key;
};
//....
struct shmid_ds {
  struct   ipc_perm shm_perm;
  size_t   shm_segsz;
  pid_t    shm_lpid;
  pid_t    shm_cpid;
  shmatt_t shm_nattch;
  time_t   shm_atime;
  time_t   shm_dtime;
  time_t   shm_ctime;
};

void *shmat(int, const void *, int);
int   shmctl(int, int, struct shmid_ds *);
int   shmdt(const void *);
int   shmget(key_t, size_t, int);

#endif
