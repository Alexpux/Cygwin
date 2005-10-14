/*
 * ++Copyright++ 1985, 1988, 1993
 * -
 * Copyright (c) 1985, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
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
 * -
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * -
 * --Copyright--
 */


#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)gethostnamadr.c	8.1 (Berkeley) 6/4/93";
static char fromrcsid[] = "From: Id: gethnamaddr.c,v 8.23 1998/04/07 04:59:46 vixie Exp $";
#endif /* LIBC_SCCS and not lint */
#include <sys/cdefs.h>

#include <sys/types.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <resolv.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <nsswitch.h>

#include "res_config.h"

#define SPRINTF(x) ((size_t)sprintf x)

static const char AskedForGot[] =
		"gethostby*.gethostanswer: asked for \"%s\", got \"%s\"";

#ifdef RESOLVSORT
static void addrsort(char **, int);
#endif

u_int32_t _getlong(const u_char *src);
u_int16_t _getshort(const u_char *src);

#ifdef DEBUG
static void dbgprintf(char *, int);
#endif

#if PACKETSZ > 1024
#define	MAXPACKET	PACKETSZ
#else
#define	MAXPACKET	1024
#endif

typedef union {
    HEADER hdr;
    u_char buf[MAXPACKET];
} querybuf;

typedef union {
    int32_t al;
    char ac;
} align;

extern int h_errno;
int _dns_ttl_;

#ifdef DEBUG
static void
dbgprintf(msg, num)
	char *msg;
	int num;
{
	if (_res.options & RES_DEBUG) {
		int save = errno;

		printf(msg, num);
		errno = save;
	}
}
#else
# define dbgprintf(msg, num) /*nada*/
#endif

#define BOUNDED_INCR(x) \
	do { \
		cp += x; \
		if (cp > eom) { \
			*herr = NO_RECOVERY; \
			return (NULL); \
		} \
	} while (0)

#define BOUNDS_CHECK(ptr, count) \
	do { \
		if ((ptr) + (count) > eom) { \
			*herr = NO_RECOVERY; \
			return (NULL); \
		} \
	} while (0)

static struct hostent *
gethostanswer(answer, anslen, qname, qtype, host, hostbuf, hostbuflen, herr)
	const querybuf *answer;
	int anslen;
	const char *qname;
	int qtype;
        struct hostent *host;
        char *hostbuf;
        int hostbuflen;
        int *herr;
{
	const HEADER *hp;
	const u_char *cp;
	int n;
	const u_char *eom, *erdata;
	char *bp, **ap, **hap;
	int type, class, buflen, ancount, qdcount;
	int haveanswer, had_error;
	int toobig = 0;
	char tbuf[MAXDNAME];
	const char *tname;
	int (*name_ok)(const char *);

	tname = qname;
	host->h_name = NULL;
	eom = answer->buf + anslen;
	switch (qtype) {
	case T_A:
	case T_AAAA:
		name_ok = res_hnok;
		break;
	case T_PTR:
		name_ok = res_dnok;
		break;
	default:
		*herr = NO_RECOVERY;
		return (NULL);	/* XXX should be abort(); */
	}
	/*
	 * find first satisfactory answer
	 */
	hp = &answer->hdr;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	bp = hostbuf;
	buflen = hostbuflen;
	cp = answer->buf;
	BOUNDED_INCR(HFIXEDSZ);
	if (qdcount != 1) {
		*herr = NO_RECOVERY;
		return (NULL);
	}
	n = dn_expand(answer->buf, eom, cp, bp, buflen);
	if ((n < 0) || !(*name_ok)(bp)) {
		*herr = NO_RECOVERY;
		return (NULL);
	}
	BOUNDED_INCR(n + QFIXEDSZ);
	if (qtype == T_A || qtype == T_AAAA) {
		/* res_send() has already verified that the query name is the
		 * same as the one we sent; this just gets the expanded name
		 * (i.e., with the succeeding search-domain tacked on).
		 */
		n = strlen(bp) + 1;		/* for the \0 */
		if (n >= MAXHOSTNAMELEN) {
			*herr = NO_RECOVERY;
			return (NULL);
		}
		host->h_name = bp;
		bp += n;
		buflen -= n;
		/* The qname can be abbreviated, but h_name is now absolute. */
		qname = host->h_name;
	}
	ap = host->__host_aliases;
	*ap = NULL;
	host->h_aliases = host->__host_aliases;
	hap = host->__host_addrs;
	*hap = NULL;
	host->h_addr_list = host->__host_addrs;
	haveanswer = 0;
	had_error = 0;
	_dns_ttl_ = -1;
	while (ancount-- > 0 && cp < eom && !had_error) {
		n = dn_expand(answer->buf, eom, cp, bp, buflen);
		if ((n < 0) || !(*name_ok)(bp)) {
			had_error++;
			continue;
		}
		cp += n;			/* name */
		BOUNDS_CHECK(cp, 3 * INT16SZ + INT32SZ);
		type = _getshort(cp);
 		cp += INT16SZ;			/* type */
		class = _getshort(cp);
 		cp += INT16SZ;			/* class */
		if (qtype == T_A  && type == T_A)
			_dns_ttl_ = _getlong(cp);
		cp += INT32SZ;			/* TTL */
		n = _getshort(cp);
		cp += INT16SZ;			/* len */
		BOUNDS_CHECK(cp, n);
		erdata = cp + n;
		if (class != C_IN) {
			/* XXX - debug? syslog? */
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		if ((qtype == T_A || qtype == T_AAAA) && type == T_CNAME) {
			if (ap >= &host->__host_aliases[MAXALIASES-1])
				continue;
			n = dn_expand(answer->buf, eom, cp, tbuf, sizeof tbuf);
			if ((n < 0) || !(*name_ok)(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			if (cp != erdata) {
				*herr = NO_RECOVERY;
				return (NULL);
			}
			/* Store alias. */
			*ap++ = bp;
			n = strlen(bp) + 1;	/* for the \0 */
			if (n >= MAXHOSTNAMELEN) {
				had_error++;
				continue;
			}
			bp += n;
			buflen -= n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > buflen || n >= MAXHOSTNAMELEN) {
				had_error++;
				continue;
			}
			strcpy(bp, tbuf);
			host->h_name = bp;
			bp += n;
			buflen -= n;
			continue;
		}
		if (qtype == T_PTR && type == T_CNAME) {
			n = dn_expand(answer->buf, eom, cp, tbuf, sizeof tbuf);
			if (n < 0 || !res_dnok(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			if (cp != erdata) {
				*herr = NO_RECOVERY;
				return (NULL);
			}
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > buflen || n >= MAXHOSTNAMELEN) {
				had_error++;
				continue;
			}
			strcpy(bp, tbuf);
			tname = bp;
			bp += n;
			buflen -= n;
			continue;
		}
		if (type != qtype) {
			if (type != T_SIG)
				syslog(LOG_NOTICE|LOG_AUTH,
	"gethostby*.gethostanswer: asked for \"%s %s %s\", got type \"%s\"",
				       qname, p_class(C_IN), p_type(qtype),
				       p_type(type));
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		switch (type) {
		case T_PTR:
			if (strcasecmp(tname, bp) != 0) {
				syslog(LOG_NOTICE|LOG_AUTH,
				       AskedForGot, qname, bp);
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
			n = dn_expand(answer->buf, eom, cp, bp, buflen);
			if ((n < 0) || !res_hnok(bp)) {
				had_error++;
				break;
			}
#if MULTI_PTRS_ARE_ALIASES
			cp += n;
			if (cp != erdata) {
				*herr = NO_RECOVERY;
				return (NULL);
			}
			if (!haveanswer)
				host->h_name = bp;
			else if (ap < &host->__host_aliases[MAXALIASES-1])
				*ap++ = bp;
			else
				n = -1;
			if (n != -1) {
				n = strlen(bp) + 1;	/* for the \0 */
				if (n >= MAXHOSTNAMELEN) {
					had_error++;
					break;
				}
				bp += n;
				buflen -= n;
			}
			break;
#else
			host->h_name = bp;
			if (_res.options & RES_USE_INET6) {
				n = strlen(bp) + 1;	/* for the \0 */
				if (n >= MAXHOSTNAMELEN) {
					had_error++;
					break;
				}
				bp += n;
				buflen -= n;
				_map_v4v6_hostent(host, &bp, &buflen);
			}
			*herr = NETDB_SUCCESS;
			return host;
#endif
		case T_A:
		case T_AAAA:
			if (strcasecmp(host->h_name, bp) != 0) {
				syslog(LOG_NOTICE|LOG_AUTH,
				       AskedForGot, host->h_name, bp);
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
			if (n != host->h_length) {
				cp += n;
				continue;
			}
			if (!haveanswer) {
				int nn;

				host->h_name = bp;
				nn = strlen(bp) + 1;	/* for the \0 */
				bp += nn;
				buflen -= nn;
			}

			bp += sizeof(align) - ((u_long)bp % sizeof(align));

			if (bp + n >= &hostbuf[hostbuflen]) {
				dbgprintf("size (%d) too big\n", n);
				had_error++;
				continue;
			}
			if (hap >= &host->__host_addrs[MAXADDRS-1]) {
				if (!toobig++)
					dbgprintf("Too many addresses (%d)\n",
						MAXADDRS);
				cp += n;
				continue;
			}
			bcopy(cp, *hap++ = bp, n);
			bp += n;
			buflen -= n;
			cp += n;
			if (cp != erdata) {
				*herr = NO_RECOVERY;
				return (NULL);
			}
			break;
		default:
			dbgprintf("Impossible condition (type=%d)\n", type);
			*herr = NO_RECOVERY;
			return (NULL);
			/* BIND has abort() here, too risky on bad data */
		}
		if (!had_error)
			haveanswer++;
	}
	if (haveanswer) {
		*ap = NULL;
		*hap = NULL;
# if defined(RESOLVSORT)
		/*
		 * Note: we sort even if host can take only one address
		 * in its return structures - should give it the "best"
		 * address in that case, not some random one
		 */
		if (_res.nsort && haveanswer > 1 && qtype == T_A)
			addrsort(host->__host_addrs, haveanswer);
# endif /*RESOLVSORT*/
		if (!host->h_name) {
			n = strlen(qname) + 1;	/* for the \0 */
			if (n > buflen || n >= MAXHOSTNAMELEN)
				goto no_recovery;
			strcpy(bp, qname);
			host->h_name = bp;
			bp += n;
			buflen -= n;
		}
		if (_res.options & RES_USE_INET6)
			_map_v4v6_hostent(host, &bp, &buflen);
		*herr = NETDB_SUCCESS;
		return host;
	}
 no_recovery:
	*herr = NO_RECOVERY;
	return (NULL);
}

struct hostent *
__dns_getanswer(answer, anslen, qname, qtype, host, hostbuf, hostbuflen, herr)
	const char *answer;
	int anslen;
	const char *qname;
	int qtype;
        struct hostent *host;
        char *hostbuf;
        int hostbuflen;
        int *herr;
{
	switch(qtype) {
	case T_AAAA:
		host->h_addrtype = AF_INET6;
		host->h_length = IN6ADDRSZ;
		break;
	case T_A:
	default:
		host->h_addrtype = AF_INET;
		host->h_length = INADDRSZ;
		break;
	}

	return(gethostanswer((const querybuf *)answer, anslen, qname, qtype, host, hostbuf, hostbuflen, herr));
}

int
_dns_gethostbyname(void *rval, void *cb_data, va_list ap)
{
	const char *name;
	int af;
	querybuf buf;
	const char *cp;
	char *bp;
	int n, size, type, len;
        struct hostent *resultbuf;
        char *hostbuf;
        int buflen;
        int *herr;

	name = va_arg(ap, const char *);
	af = va_arg(ap, int);
        resultbuf = va_arg(ap, struct hostent *);
        hostbuf = va_arg(ap, char *);
        buflen = va_arg(ap, int);
        herr = va_arg(ap, int *);

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		*herr = NETDB_INTERNAL;
		return NS_UNAVAIL;
	}

	switch (af) {
	case AF_INET:
		size = INADDRSZ;
		type = T_A;
		break;
	case AF_INET6:
		size = IN6ADDRSZ;
		type = T_AAAA;
		break;
	default:
		*herr = NETDB_INTERNAL;
		errno = EAFNOSUPPORT;
		return NS_UNAVAIL;
	}

	resultbuf->h_addrtype = af;
	resultbuf->h_length = size;

	/*
	 * if there aren't any dots, it could be a user-level alias.
	 * this is also done in res_query() since we are not the only
	 * function that looks up host names.
	 */
	if (!strchr(name, '.') && (cp = __hostalias(name)))
		name = cp;

	/*
	 * disallow names consisting only of digits/dots, unless
	 * they end in a dot.
	 */
	if (isdigit((unsigned char)name[0]))
		for (cp = name;; ++cp) {
			if (!*cp) {
				if (*--cp == '.')
					break;
				/*
				 * All-numeric, no dot at the end.
				 * Fake up a hostent as if we'd actually
				 * done a lookup.
				 */
				if (inet_pton(af, name, resultbuf->__host_addr) <= 0) {
					*herr = HOST_NOT_FOUND;
					return NS_NOTFOUND;
				}
				strncpy(hostbuf, name, MAXDNAME);
				hostbuf[MAXDNAME] = '\0';
				bp = hostbuf + MAXDNAME;
				len = buflen - MAXDNAME;
				resultbuf->h_name = hostbuf;
				resultbuf->h_aliases = resultbuf->__host_aliases;
				resultbuf->__host_aliases[0] = NULL;
				resultbuf->__host_addrs[0] = (char *)resultbuf->__host_addr;
				resultbuf->__host_addrs[1] = NULL;
				resultbuf->h_addr_list = resultbuf->__host_addrs;
				if (_res.options & RES_USE_INET6)
					_map_v4v6_hostent(resultbuf, &bp, &len);
				*herr = NETDB_SUCCESS;
				*(struct hostent **)rval = resultbuf;
				return NS_SUCCESS;
			}
			if (!isdigit((unsigned char)*cp) && *cp != '.')
				break;
		}
	if ((isxdigit((unsigned char)name[0]) && strchr(name, ':') != NULL) ||
	    name[0] == ':')
		for (cp = name;; ++cp) {
			if (!*cp) {
				if (*--cp == '.')
					break;
				/*
				 * All-IPv6-legal, no dot at the end.
				 * Fake up a hostent as if we'd actually
				 * done a lookup.
				 */
				if (inet_pton(af, name, resultbuf->__host_addr) <= 0) {
					*herr = HOST_NOT_FOUND;
					return NS_NOTFOUND;
				}
				strncpy(hostbuf, name, MAXDNAME);
				hostbuf[MAXDNAME] = '\0';
				bp = hostbuf + MAXDNAME;
				len = buflen - MAXDNAME;
				resultbuf->h_name = hostbuf;
				resultbuf->h_aliases = resultbuf->__host_aliases;
				resultbuf->__host_aliases[0] = NULL;
				resultbuf->__host_addrs[0] = (char *)resultbuf->__host_addr;
				resultbuf->__host_addrs[1] = NULL;
				resultbuf->h_addr_list = resultbuf->__host_addrs;
				*herr = NETDB_SUCCESS;
				*(struct hostent **)rval = resultbuf;
				return NS_SUCCESS;
			}
			if (!isxdigit((unsigned char)*cp) && *cp != ':' && *cp != '.')
				break;
		}

	if ((n = res_search(name, C_IN, type, buf.buf, sizeof(buf))) < 0) {
		dbgprintf("res_search failed (%d)\n", n);
		return NS_UNAVAIL;
	}
	*(struct hostent **)rval = gethostanswer(&buf, n, name, type, resultbuf, hostbuf, buflen, herr);
	return (*(struct hostent **)rval != NULL) ? NS_SUCCESS : NS_NOTFOUND;
}

int
_dns_gethostbyaddr(void *rval, void *cb_data, va_list ap)
{
	const char *addr;	/* XXX should have been def'd as u_char! */
	int len, af;
	const u_char *uaddr;
	static const u_char mapped[] = { 0,0, 0,0, 0,0, 0,0, 0,0, 0xff,0xff };
	static const u_char tunnelled[] = { 0,0, 0,0, 0,0, 0,0, 0,0, 0,0 };
	int n, size;
	querybuf buf;
	struct hostent *hp;
	char qbuf[MAXDNAME+1], *qp;
#ifdef SUNSECURITY
	struct hostent *rhp;
	char **haddr;
	u_long old_options;
	char hname2[MAXDNAME+1];
#endif /*SUNSECURITY*/
        struct hostent *resultbuf;
        char *hostbuf;
        int buflen;
        int *herr;

	addr = va_arg(ap, const char *);
	uaddr = (const u_char *)addr;
	len = va_arg(ap, int);
	af = va_arg(ap, int);
        resultbuf = va_arg(ap, struct hostent *);
        hostbuf = va_arg(ap, char *);
        buflen = va_arg(ap, int);
        herr = va_arg(ap, int *);

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		*herr = NETDB_INTERNAL;
		return NS_UNAVAIL;
	}
	if (af == AF_INET6 && len == IN6ADDRSZ &&
	    (!memcmp(uaddr, mapped, sizeof mapped) ||
	     !memcmp(uaddr, tunnelled, sizeof tunnelled))) {
		/* Unmap. */
		addr += sizeof mapped;
		uaddr += sizeof mapped;
		af = AF_INET;
		len = INADDRSZ;
	}
	switch (af) {
	case AF_INET:
		size = INADDRSZ;
		break;
	case AF_INET6:
		size = IN6ADDRSZ;
		break;
	default:
		errno = EAFNOSUPPORT;
		*herr = NETDB_INTERNAL;
		return NS_UNAVAIL;
	}
	if (size != len) {
		errno = EINVAL;
		*herr = NETDB_INTERNAL;
		return NS_UNAVAIL;
	}
	switch (af) {
	case AF_INET:
		(void) sprintf(qbuf, "%u.%u.%u.%u.in-addr.arpa",
			       (uaddr[3] & 0xff),
			       (uaddr[2] & 0xff),
			       (uaddr[1] & 0xff),
			       (uaddr[0] & 0xff));
		break;
	case AF_INET6:
		qp = qbuf;
		for (n = IN6ADDRSZ - 1; n >= 0; n--) {
			qp += SPRINTF((qp, "%x.%x.",
				       uaddr[n] & 0xf,
				       (uaddr[n] >> 4) & 0xf));
		}
		strcpy(qp, "ip6.int");
		break;
	default:
		abort();
	}
	n = res_query(qbuf, C_IN, T_PTR, (u_char *)buf.buf, sizeof buf.buf);
	if (n < 0) {
		dbgprintf("res_query failed (%d)\n", n);
		return NS_UNAVAIL;
	}
	if (n > sizeof buf.buf) {
		dbgprintf("static buffer is too small (%d)\n", n);
		return NS_UNAVAIL;
	}
	if (!(hp = gethostanswer(&buf, n, qbuf, T_PTR, resultbuf, hostbuf, buflen, herr)))
		return NS_NOTFOUND;   /* *herr was set by gethostanswer() */
#ifdef SUNSECURITY
	if (af == AF_INET) {
	    /*
	     * turn off search as the name should be absolute,
	     * 'localhost' should be matched by defnames
	     */
	    strncpy(hname2, hp->h_name, MAXDNAME);
	    hname2[MAXDNAME] = '\0';
	    old_options = _res.options;
	    _res.options &= ~RES_DNSRCH;
	    _res.options |= RES_DEFNAMES;
	    if (!(rhp = gethostbyname(hname2))) {
		syslog(LOG_NOTICE|LOG_AUTH,
		       "gethostbyaddr: No A record for %s (verifying [%s])",
		       hname2, inet_ntoa(*((struct in_addr *)addr)));
		_res.options = old_options;
		*herr = HOST_NOT_FOUND;
		return NS_NOTFOUND;
	    }
	    _res.options = old_options;
	    for (haddr = rhp->h_addr_list; *haddr; haddr++)
		if (!memcmp(*haddr, addr, INADDRSZ))
			break;
	    if (!*haddr) {
		syslog(LOG_NOTICE|LOG_AUTH,
		       "gethostbyaddr: A record of %s != PTR record [%s]",
		       hname2, inet_ntoa(*((struct in_addr *)addr)));
		*herr = HOST_NOT_FOUND;
		return NS_NOTFOUND;
	    }
	}
#endif /*SUNSECURITY*/
	hp->h_addrtype = af;
	hp->h_length = len;
	bcopy(addr, resultbuf->__host_addr, len);
	resultbuf->__host_addrs[0] = (char *)resultbuf->__host_addr;
	resultbuf->__host_addrs[1] = NULL;
	if (af == AF_INET && (_res.options & RES_USE_INET6)) {
		_map_v4v6_address((char*)resultbuf->__host_addr, (char*)resultbuf->__host_addr);
		hp->h_addrtype = AF_INET6;
		hp->h_length = IN6ADDRSZ;
	}
	*herr = NETDB_SUCCESS;
	*(struct hostent **)rval = hp;
	return (hp != NULL) ? NS_SUCCESS : NS_NOTFOUND;
}

#ifdef RESOLVSORT
static void
addrsort(ap, num)
	char **ap;
	int num;
{
	int i, j;
	char **p;
	short aval[MAXADDRS];
	int needsort = 0;

	p = ap;
	for (i = 0; i < num; i++, p++) {
	    for (j = 0 ; (unsigned)j < _res.nsort; j++)
		if (_res.sort_list[j].addr.s_addr == 
		    (((struct in_addr *)(*p))->s_addr & _res.sort_list[j].mask))
			break;
	    aval[i] = j;
	    if (needsort == 0 && i > 0 && j < aval[i-1])
		needsort = i;
	}
	if (!needsort)
	    return;

	while (needsort < num) {
	    for (j = needsort - 1; j >= 0; j--) {
		if (aval[j] > aval[j+1]) {
		    char *hp;

		    i = aval[j];
		    aval[j] = aval[j+1];
		    aval[j+1] = i;

		    hp = ap[j];
		    ap[j] = ap[j+1];
		    ap[j+1] = hp;

		} else
		    break;
	    }
	    needsort++;
	}
}
#endif
void
_sethostdnsent(stayopen)
	int stayopen;
{
	if ((_res.options & RES_INIT) == 0 && res_init() == -1)
		return;
	if (stayopen)
		_res.options |= RES_STAYOPEN | RES_USEVC;
}

void
_endhostdnsent()
{
	_res.options &= ~(RES_STAYOPEN | RES_USEVC);
	res_close();
}
