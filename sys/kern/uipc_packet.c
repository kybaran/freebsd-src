/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2023 Dell Technologies Inc
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/socket.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_var.h>
#include <net/af_packet.h>
#include <net/uipc_packet.h>

#include <sys/domain.h>
#include <sys/epoch.h>
#include <sys/eventhandler.h>
#include <sys/mbuf.h>
#include <sys/priv.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <vm/uma.h>

#include <netinet/in.h>


VNET_DEFINE(struct af_packet_filters, af_packet_filters_global);

#define PACKETPCB_LOCK(packetpcb)         mtx_lock(&(packetpcb)->packetpcb_mtx)
#define PACKETPCB_UNLOCK(packetpcb)       mtx_unlock(&(packetpcb)->packetpcb_mtx)
#define PACKETPCB_LOCK_ASSERT(packetpcb)  mtx_assert(&(packetpcb)->packetpcb_mtx, MA_OWNED)

#define PACKETPCB_FILTER_ENABLED  0x0001

static void packet_init(void);
static void packet_abort(struct socket *so);
static int packet_attach(struct socket *so, int proto, struct thread *td);
static int packet_bind(struct socket *so, struct sockaddr *nam,
  struct thread *td);
static void packet_detach(struct socket *so);
static int	packet_send(struct socket *so, int flags, struct mbuf *m,
  struct sockaddr *addr, struct mbuf *control, struct thread *td);
static void packet_close(struct socket *so);

static struct pr_usrreqs packet_usrreqs = {
  .pru_abort =  packet_abort,
  .pru_attach = packet_attach,
  .pru_bind =   packet_bind,
  .pru_detach = packet_detach,
  .pru_send =   packet_send,
  .pru_close =  packet_close,
};

static struct domain packetdomain;

static struct protosw packetsw[] = {
{
	.pr_type = SOCK_RAW,
	.pr_domain = &packetdomain,
	.pr_flags = PR_ATOMIC | PR_ADDR | PR_ANYPROTO,
	.pr_usrreqs = &packet_usrreqs,
},
{
	.pr_type = SOCK_DGRAM,
	.pr_domain = &packetdomain,
	.pr_flags = PR_ATOMIC | PR_ADDR | PR_ANYPROTO,
	.pr_usrreqs = &packet_usrreqs,
},
};

static struct domain packetdomain = {
	.dom_family = AF_PACKET,
	.dom_name = "packet",
	.dom_protosw = packetsw,
	.dom_protoswNPROTOSW = &packetsw[nitems(packetsw)],
};
DOMAIN_SET(packet);

struct packetpcb {
	struct mtx packetpcb_mtx;
	struct socket *packet_socket;
	int ethertype;
	int flags;
	CK_LIST_ENTRY(packetpcb) filter_list;
};

static uma_zone_t packet_zone;

static u_long	packetraw_sendspace = ETHER_MAX_LEN_JUMBO;
static u_long	packetraw_recvspace = 16 * ETHER_MAX_LEN_JUMBO;

static u_long	packetdg_sendspace = 9216;
static u_long	packetdg_recvspace = 40 * (1024 +
#ifdef INET6
		sizeof(struct sockaddr_in6)
#else
		sizeof(struct sockaddr_in)
#endif
);	/* 40 1K datagrams */


static void
packet_zone_change(void *tag)
{
  uma_zone_set_max(packet_zone, maxsockets);
}

static void
packet_filter_insert(struct packetpcb_list *list, struct packetpcb *packetpcb)
{
  PACKETPCB_LOCK_ASSERT(packetpcb);
  KASSERT(!(packetpcb->flags & PACKETPCB_FILTER_ENABLED),
    ("packetpcb is already inserted in the list"));

  CK_LIST_INSERT_HEAD(list, packetpcb, filter_list);
  packetpcb->flags |= PACKETPCB_FILTER_ENABLED;
}

static void
packet_filter_remove(struct packetpcb *packetpcb)
{
  PACKETPCB_LOCK_ASSERT(packetpcb);

  if (packetpcb->flags & PACKETPCB_FILTER_ENABLED)
  {
    CK_LIST_REMOVE(packetpcb, filter_list);
    packetpcb->flags &= ~PACKETPCB_FILTER_ENABLED;
  }

}

static void
packet_init(void)
{
  packet_zone = uma_zcreate("packetpcb", sizeof(struct packetpcb), NULL, NULL,
    NULL, NULL, UMA_ALIGN_CACHE, 0);
  uma_zone_set_max(packet_zone, maxsockets);
  uma_zone_set_warning(packet_zone, "kern.ipc.maxsockets limit reached");

  EVENTHANDLER_REGISTER(maxsockets_change, packet_zone_change,
    NULL, EVENTHANDLER_PRI_ANY);
}
SYSINIT(packet_init, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY, packet_init, NULL);

static void
packet_vnet_init(void *arg __unused)
{
  CK_LIST_INIT(&V_af_packet_filters_global.in4_packetpcbs);
  CK_LIST_INIT(&V_af_packet_filters_global.in6_packetpcbs);
  CK_LIST_INIT(&V_af_packet_filters_global.misc_packetpcbs);
}
VNET_SYSINIT(packet_vnet_init, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY,
  packet_vnet_init, NULL);

static void
packet_abort(struct socket *so)
{
  struct packetpcb *packetpcb;


  packetpcb = so->so_pcb;

  PACKETPCB_LOCK(packetpcb);
  packet_filter_remove(packetpcb);
  PACKETPCB_UNLOCK(packetpcb);
}

static int
packet_attach(struct socket *so, int proto, struct thread *td)
{
  int error;
  u_long sendspace, recvspace;
  struct packetpcb *packetpcb;
  struct packetpcb_list *filter;


  KASSERT(so->so_pcb == NULL, ("packet_attach: so_pcb != NULL"));
  error = priv_check(td, PRIV_NET_PACKET);
  if (error != 0)
  {
    return error;
  }

  if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0)
  {
    switch (so->so_type)
    {
      case SOCK_RAW:
      {
        sendspace = packetraw_sendspace;
        recvspace = packetraw_recvspace;
        break;
      }
      case SOCK_DGRAM:
      {
        sendspace = packetdg_sendspace;
        recvspace = packetdg_recvspace;
        break;
      }
      default:
      {
        panic("packet_attach");
      }

    }
    error = soreserve(so, sendspace, recvspace);
    if (error)
    {
      return (error);
    }

  }

  packetpcb = uma_zalloc(packet_zone, M_NOWAIT | M_ZERO);
  if (packetpcb == NULL)
  {
    return (ENOBUFS);
  }

  mtx_init(&packetpcb->packetpcb_mtx, "packetpcb", NULL, MTX_DEF);
  packetpcb->packet_socket = so;
  packetpcb->ethertype = ntohs(proto);
  packetpcb->flags = 0;

  so->so_pcb = packetpcb;

  if (packetpcb->ethertype != 0)
  {
    PACKETPCB_LOCK(packetpcb);
    filter = packet_filter_get(&V_af_packet_filters_global,
      packetpcb->ethertype);
    packet_filter_insert(filter, packetpcb);
    PACKETPCB_UNLOCK(packetpcb);
  }


  return (0);
}

static int
packet_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
  struct sockaddr_ll *sll;
  struct ifnet *ifp;
  struct packetpcb *packetpcb;
  struct packetpcb_list *filter;


  if (nam->sa_family != AF_PACKET || nam->sa_len != sizeof(*sll))
  {
    return (EINVAL);
  }

  sll = (struct sockaddr_ll *)nam;
  if ( (sll->sll_ifindex == 0) ||
       (sll->sll_halen > nitems(sll->sll_addr)) )
  {
    return (EINVAL);
  }

  ifp = ifnet_byindex(sll->sll_ifindex);
  if (ifp == NULL)
  {
    return(EHOSTUNREACH);
  }

  packetpcb = so->so_pcb;
  KASSERT(packetpcb != NULL, ("packet_bind: packetpcb == NULL"));

  PACKETPCB_LOCK(packetpcb);
  packetpcb->ethertype = sll->sll_protocol;
  packet_filter_remove(packetpcb);
  filter = packet_filter_get(&(ifp->if_packet_filters),
    packetpcb->ethertype);
  packet_filter_insert(filter, packetpcb);
  PACKETPCB_UNLOCK(packetpcb);


  return (0);
}

static void
packet_detach(struct socket *so)
{
  struct packetpcb *packetpcb;


  packetpcb = so->so_pcb;

  NET_EPOCH_WAIT();
  KASSERT(!(packetpcb->flags & PACKETPCB_FILTER_ENABLED),
    ("packetpcb is still in filter list"));
  mtx_destroy(&packetpcb->packetpcb_mtx);
  uma_zfree(packet_zone, packetpcb);

  so->so_pcb = NULL;
}

static int
pack_prepend_hdr(struct ifnet *ifp, struct mbuf **mbufpp,
  struct sockaddr_ll *sll)
{
  int error;
  struct if_encap_req req;


  if (sll->sll_halen != ifp->if_addrlen)
  {
    return (EINVAL);
  }

  req.mb = *mbufpp;
  req.rtype = IFENCAP_LL_MBUF;
  req.flags = 0;
  req.family = AF_PACKET;
  req.lladdr_len = sll->sll_halen;
  req.lladdr = (char *)sll->sll_addr;
  req.hdata = NULL;
  req.proto = sll->sll_protocol;

  error = ifp->if_requestencap(ifp, &req);
  *mbufpp = req.mb;


  return (error);
}

static int
packet_send(struct socket *so, int flags, struct mbuf *m,
	struct sockaddr *addr, struct mbuf *control, struct thread *td)
{
  struct epoch_tracker et;
  struct sockaddr_ll *sll;
  struct ifnet *ifp;
  int error;


  if ( (control != NULL) ||
       (addr->sa_family != AF_PACKET || addr->sa_len != sizeof(*sll)) )
  {
    error = EINVAL;
    goto out;
  }

  sll = (struct sockaddr_ll *)addr;
  if ( (sll->sll_ifindex == 0) ||
       (sll->sll_halen > nitems(sll->sll_addr)) )
  {
    error = EINVAL;
    goto out;
  }

  NET_EPOCH_ENTER_ET(et);

  ifp = ifnet_byindex(sll->sll_ifindex);
  if (ifp == NULL)
  {
    error = EHOSTUNREACH;
    goto out_epoch;
  }

  if (so->so_type == SOCK_DGRAM)
  {
    error = pack_prepend_hdr(ifp, &m, sll);
    if (error != 0)
    {
      goto out_epoch;
    }

  }

  if (m->m_pkthdr.len > ifp->if_mtu)
  {
    error = EMSGSIZE;
    goto out_epoch;
  }

  /* XXX this bypasses outgoing pfil hooks */
  error = ifp->if_transmit(ifp, m);

  /* ifnet has taken ownership of the mbuf */
  m = NULL;

out_epoch:
  NET_EPOCH_EXIT_ET(et);
out:
  m_freem(m);
  m_freem(control);


  return (error);
}

static void
packet_close(struct socket *so)
{
  struct packetpcb *packetpcb;


  packetpcb = so->so_pcb;

  PACKETPCB_LOCK(packetpcb);
  packet_filter_remove(packetpcb);
  PACKETPCB_UNLOCK(packetpcb);
}

static void
packet_input(struct packetpcb *packetpcb, struct mbuf *m, uint16_t ethertype)
{
  struct socket *so;
  struct ether_header *eh;
  struct ifnet *ifp;
  struct sockaddr_ll addr;
  struct mbuf *mPacket;
  int queued;


  mPacket = m_dup(m, M_NOWAIT);
  if (mPacket == NULL)
  {
    return;
  }

  so = packetpcb->packet_socket;
  eh = mtod(mPacket, struct ether_header *);
  ifp = mPacket->m_pkthdr.rcvif;

  bzero(&addr, sizeof(addr));
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = ethertype;
  addr.sll_ifindex = ifp->if_index;
  addr.sll_hatype = 0; /* XXX Linuxism */

  if (mPacket->m_flags & M_BCAST)
  {
    addr.sll_pkttype = PACKET_BROADCAST;
  }
  else if (mPacket->m_flags & M_MCAST)
  {
    addr.sll_pkttype = PACKET_MULTICAST;
  }
  else if (bcmp(IF_LLADDR(ifp), eh->ether_dhost, ETHER_ADDR_LEN) != 0)
  {
    /* Can't depend on M_PROMISC as that is set after our hook. */
    addr.sll_pkttype = PACKET_OTHERHOST;
  }
  else
  {
    addr.sll_pkttype = PACKET_HOST;
  }

  addr.sll_halen = ETHER_ADDR_LEN;
  memcpy(addr.sll_addr, eh->ether_shost, ETHER_ADDR_LEN);

  if (so->so_type == SOCK_DGRAM)
  {
    m_adj(mPacket, ETHER_HDR_LEN);
  }

  SOCKBUF_LOCK(&so->so_rcv);
  queued = sbappendaddr_locked(&so->so_rcv, (struct sockaddr *)&addr, mPacket, NULL);
  if (queued == 0)
  {
    SOCKBUF_UNLOCK(&so->so_rcv);
    m_freem(mPacket);
  }
  else
  {
    sorwakeup_locked(so);
  }

}

static __inline bool
packetpcb_is_wildcard(struct packetpcb *packetpcb)
{
  return (packetpcb->ethertype == ETHERTYPE_ALL);
}

static __inline bool
packet_ethertype_matches(struct packetpcb *packetpcb, uint16_t ethertype)
{
  return (packetpcb->ethertype == ethertype || packetpcb_is_wildcard(packetpcb));
}

void
packet_input_list(struct mbuf *m, struct packetpcb_list *list,
  uint16_t ethertype)
{
  struct packetpcb *packetpcb;


  CK_LIST_FOREACH(packetpcb, list, filter_list)
  {
    if (packet_ethertype_matches(packetpcb, ethertype))
    {
      packet_input(packetpcb, m, ethertype);
    }

  }

}
