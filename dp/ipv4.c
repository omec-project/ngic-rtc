/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include "ipv4.h"

/**
 * Function to update ipv4 ckcum.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	None
 */
static void update_ckcum(struct rte_mbuf *m)
{
	struct ipv4_hdr *ipv4_hdr;

	/* update Ip checksum */
	ipv4_hdr = get_mtoip(m);
	ipv4_hdr->hdr_checksum = 0;
	ipv4_hdr->hdr_checksum = rte_ipv4_cksum((struct ipv4_hdr *)ipv4_hdr);
}

void
construct_ipv4_hdr(struct rte_mbuf *m, uint16_t len, uint8_t protocol,
		   uint32_t src_ip, uint32_t dst_ip)
{
	build_ipv4_default_hdr(m);

	set_ipv4_hdr(m, len, protocol, src_ip, dst_ip);

	update_ckcum(m);
}
