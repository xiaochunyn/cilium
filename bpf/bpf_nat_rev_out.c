/*
 *  Copyright (C) 2016-2017 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <node_config.h>
#include <netdev_config.h>

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#ifndef CONNTRACK
#define CONNTRACK
#endif

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/l4.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/drop.h"
#include "lib/lb.h"
#include "lib/conntrack.h"

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	__u16 revnat = skb->mark & 0xFFFF;

	/* The skb->mark contains the service ID (RevNAT ID). It was preserved
	 * from when the request entered the node. */
	if (!revnat)
		return TC_ACT_OK;

	switch (skb->protocol) {
	case bpf_htons(ETH_P_IPV6):
		/* FIXME */
		break;

#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (1) {
			struct iphdr *ip4 = data + ETH_HLEN;
			struct ipv4_ct_tuple tuple = {};
			struct csum_offset csum_off = {};
			int l4_off;

			data = (void *) (long) skb->data;
			data_end = (void *) (long) skb->data_end;
			ip4 = data + ETH_HLEN;
			if (data + sizeof(*ip4) + ETH_HLEN > data_end)
				return DROP_INVALID;

			l4_off = ct_extract_tuple4(&tuple, ip4, ETH_HLEN, CT_EGRESS);
			csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

			lb4_rev_nat(skb, ETH_HLEN, l4_off, &csum_off, 0, &tuple, revnat, 0);
		}
		break;
#endif /* ENABLE_IPV4 */
	}

	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
