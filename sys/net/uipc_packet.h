/*
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

#ifndef _NET_UIPC_PACKET_H_
#define _NET_UIPC_PACKET_H_

#include <net/af_packet.h>


void packet_input_list(struct mbuf *m, struct packetpcb_list *list,
  uint16_t ethertype);

static __inline struct packetpcb_list *
packet_filter_get(struct af_packet_filters *filters, uint16_t ethertype)
{
  switch (ethertype)
  {
    case ETHERTYPE_ALL:
    {
      return (&filters->all_packetpcbs);
    }
    case ETHERTYPE_IP:
    {
      return (&filters->in4_packetpcbs);
    }
    case ETHERTYPE_IPV6:
    {
      return (&filters->in6_packetpcbs);
    }
    default:
    {
      return (&filters->misc_packetpcbs);
    }

  }

}

static __inline void
packet_filter_try(struct mbuf *m, struct packetpcb_list *list, uint16_t etype)
{
  if (__predict_false(!CK_LIST_EMPTY(list)))
  {
    packet_input_list(m, list, etype);
  }
}

static __inline void
packet_filters_process(struct mbuf *m, struct af_packet_filters *filters,
  uint16_t etype)
{
  struct packetpcb_list *filter;


  if (filters == NULL)
  {
    return;
  }

  filter = packet_filter_get(filters, etype);
  packet_filter_try(m, filter, etype);
}

static __inline void
packet_input_check(struct mbuf *m, struct ifnet *ifp, uint16_t etype)
{
  packet_filters_process(m, &V_af_packet_filters_global, ETHERTYPE_ALL);
  packet_filters_process(m, &(ifp->if_packet_filters), ETHERTYPE_ALL);

  packet_filters_process(m, &V_af_packet_filters_global, etype);
  packet_filters_process(m, &(ifp->if_packet_filters), etype);
}

#endif /* _NET_UIPC_PACKET_H_ */
