/*
 * if_pppvar.h - private structures and declarations for PPP.
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * $FreeBSD: src/sys/net/if_pppvar.h,v 1.19 2002/03/24 09:34:04 bde Exp $
 */

/*
 * Supported network protocols.  These values are used for
 * indexing sc_npmode.
 */
#define NP_IP	0		/* Internet Protocol */
#define NUM_NP	1		/* Number of NPs. */

/*
 * Structure describing each ppp unit.
 */
struct ppp_softc {
	struct	ifnet sc_if;		/* network-visible interface */
/*hi*/	u_int	sc_flags;		/* control/status bits; see if_ppp.h */
	struct	callout_handle sc_ch;	/* Used for scheduling timeouts */
	void	*sc_devp;		/* pointer to device-dep structure */
	void	(*sc_start)(struct ppp_softc *);	/* start output proc */
	void	(*sc_ctlp)(struct ppp_softc *); /* rcvd control pkt */
	void	(*sc_relinq)(struct ppp_softc *); /* relinquish ifunit */
	void	(*sc_setmtu)(struct ppp_softc *); /* set mtu */
	short	sc_mru;			/* max receive unit */
	pid_t	sc_xfer;		/* used in transferring unit */
/*hi*/	struct	ifqueue sc_rawq;	/* received packets */
/*net*/	struct	ifqueue sc_inq;		/* queue of input packets for daemon */
/*net*/	struct	ifqueue sc_fastq;	/* interactive output packet q */
	struct	mbuf *sc_npqueue;	/* output packets not to be sent yet */
	struct	mbuf **sc_npqtail;	/* ptr to last next ptr in npqueue */
	struct	pppstat sc_stats;	/* count of bytes/pkts sent/rcvd */
	enum	NPmode sc_npmode[NUM_NP]; /* what to do with each NP */
	struct	compressor *sc_xcomp;	/* transmit compressor */
	void	*sc_xc_state;		/* transmit compressor state */
	struct	compressor *sc_rcomp;	/* receive decompressor */
	void	*sc_rc_state;		/* receive decompressor state */
	time_t	sc_last_sent;		/* time (secs) last NP pkt sent */
	time_t	sc_last_recv;		/* time (secs) last NP pkt rcvd */
#ifdef PPP_FILTER
	struct	bpf_program sc_pass_filt;   /* filter for packets to pass */
	struct	bpf_program sc_active_filt; /* filter for "non-idle" packets */
#endif /* PPP_FILTER */
#ifdef	VJC
	struct	slcompress *sc_comp; 	/* vjc control buffer */
#endif

	/* Device-dependent part for async lines. */
	ext_accm sc_asyncmap;		/* async control character map */
	u_long	sc_rasyncmap;		/* receive async control char map */
	struct	mbuf *sc_outm;		/* mbuf chain currently being output */
	struct	mbuf *sc_m;		/* pointer to input mbuf chain */
	struct	mbuf *sc_mc;		/* pointer to current input mbuf */
	char	*sc_mp;			/* ptr to next char in input mbuf */
	short	sc_ilen;		/* length of input packet so far */
	u_short	sc_fcs;			/* FCS so far (input) */
	u_short	sc_outfcs;		/* FCS so far for output packet */
	u_char	sc_rawin[16];		/* chars as received */
	int	sc_rawin_count;		/* # in sc_rawin */
};

struct	ppp_softc *pppalloc(pid_t pid);
void	pppdealloc(struct ppp_softc *sc);
int	pppioctl(struct ppp_softc *sc, u_long cmd, caddr_t data, int flag,
	    struct thread *td);
int	pppoutput(struct ifnet *ifp, struct mbuf *m0, struct sockaddr *dst,
	    struct rtentry *rtp);
void	ppp_restart(struct ppp_softc *sc);
void	ppppktin(struct ppp_softc *sc, struct mbuf *m, int lost);
struct	mbuf *ppp_dequeue(struct ppp_softc *sc);
