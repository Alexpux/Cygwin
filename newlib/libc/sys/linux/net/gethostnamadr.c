/*-
 * Copyright (c) 1994, Garrett Wollman
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/types.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <nsswitch.h>
#include <arpa/nameser.h>		/* XXX hack for _res */
#include <resolv.h>			/* XXX hack for _res */
#include <dirent.h>

extern int _ht_gethostbyname(void *, void *, va_list);
extern int _dns_gethostbyname(void *, void *, va_list);
extern int _nis_gethostbyname(void *, void *, va_list);
extern int _ht_gethostbyaddr(void *, void *, va_list);
extern int _dns_gethostbyaddr(void *, void *, va_list);
extern int _nis_gethostbyaddr(void *, void *, va_list);

/* Host lookup order if nsswitch.conf is broken or nonexistant */
static const ns_src default_src[] = { 
	{ NSSRC_FILES, NS_SUCCESS },
	{ NSSRC_DNS, NS_SUCCESS },
	{ 0 }
};

__LOCK_INIT(static, name_lock);
__LOCK_INIT(static, addr_lock);

struct hostent *
gethostbyname(const char *name)
{
  struct hostent *hp = NULL;

  if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
    h_errno = NETDB_INTERNAL;
    return (NULL);
  }
  if (_res.options & RES_USE_INET6) {		/* XXX */
    hp = gethostbyname2(name, AF_INET6);	/* XXX */
    if (hp)					/* XXX */
      return (hp);			        /* XXX */
  }						/* XXX */
  return (gethostbyname2(name, AF_INET));
}

struct hostent *
gethostbyname2(const char *name, int type)
{
  static struct hostent host, *hp;
  static char hostbuf[BUFSIZ];
  static int herr;
  int rval;

  static const ns_dtab dtab[] = {
    NS_FILES_CB(_ht_gethostbyname, NULL)
    { NSSRC_DNS, _dns_gethostbyname, NULL },
    NS_NIS_CB(_nis_gethostbyname, NULL) /* force -DHESIOD */
    { 0 }
  };

#ifdef HAVE_DD_LOCK
  __lock_acquire(name_lock);
#endif
  rval = nsdispatch((void *)&hp, dtab, NSDB_HOSTS, "gethostbyname",
                    default_src, name, type, &host, hostbuf, BUFSIZ, &herr);

#ifdef HAVE_DD_LOCK
  __lock_release(name_lock);
#endif
  if (rval != NS_SUCCESS)
    return NULL;
  else
    return hp;
}

int
__gethostbyname_r(const char *name, struct hostent *result,
	void *buffer, int buflen, struct hostent **hp, int *herr)
{
  int rval;
  int type;

  static const ns_dtab dtab[] = {
    NS_FILES_CB(_ht_gethostbyname, NULL)
    { NSSRC_DNS, _dns_gethostbyname, NULL },
    NS_NIS_CB(_nis_gethostbyname, NULL) /* force -DHESIOD */
    { 0 }
  };

  if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
    h_errno = NETDB_INTERNAL;
    return HOST_NOT_FOUND;
  }

  if (_res.options & RES_USE_INET6)
    type = AF_INET6;
  else
    type = AF_INET;

  rval = nsdispatch((void *)hp, dtab, NSDB_HOSTS, "gethostbyname",
                    default_src, name, type, result, buffer, buflen, herr);

  if (rval != NS_SUCCESS)
    return rval;
  else
    return 0;
}

struct hostent *
gethostbyaddr(const char *addr, int len, int type)
{
  static struct hostent host, *hp;
  static char hostbuf[BUFSIZ];
  static int herr;
  int rval;

  static const ns_dtab dtab[] = {
    NS_FILES_CB(_ht_gethostbyaddr, NULL)
    { NSSRC_DNS, _dns_gethostbyaddr, NULL },
    NS_NIS_CB(_nis_gethostbyaddr, NULL) /* force -DHESIOD */
    { 0 }
  };       

#ifdef HAVE_DD_LOCK
  __lock_acquire(addr_lock);
#endif
  rval = nsdispatch((void *)&hp, dtab, NSDB_HOSTS, "gethostbyaddr",
			  default_src, addr, len, type, &host, hostbuf, BUFSIZ, &herr);

#ifdef HAVE_DD_LOCK
  __lock_release(addr_lock);
#endif
  if (rval != NS_SUCCESS)
    return NULL;
  else
    return hp;
}

int
__gethostbyaddr_r (const char *addr, int len, int type,
                     struct hostent *result, void *buffer, int buflen,
                     struct hostent **hp, int *herr)
{
  int rval;

  static const ns_dtab dtab[] = {
    NS_FILES_CB(_ht_gethostbyaddr, NULL)
    { NSSRC_DNS, _dns_gethostbyaddr, NULL },
    NS_NIS_CB(_nis_gethostbyaddr, NULL) /* force -DHESIOD */
    { 0 }
  };       

  rval = nsdispatch((void *)hp, dtab, NSDB_HOSTS, "gethostbyaddr",
                    default_src, addr, len, type, result, buffer, buflen, herr);

  if(rval != NS_SUCCESS)
    return rval;
  else
    return 0;
}

void
sethostent(stayopen)
	int stayopen;
{
	_sethosthtent(stayopen);
	_sethostdnsent(stayopen);
}

void
endhostent()
{
	_endhosthtent();
	_endhostdnsent();
}

void
sethostent_r(int f, FILE **hostfile, int *stayopen)
{
  _sethosthtent_r(f, hostfile, stayopen);
  _sethostdnsent(f);
}

void
endhostent_r(FILE **hostfile, int *stayopen)
{
  _endhosthtent_r(hostfile, stayopen);
  _endhostdnsent();
}
