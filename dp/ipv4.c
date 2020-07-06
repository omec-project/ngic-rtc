/*
 * Copyright (c) 2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ipv4.h"

/**
 * @brief  : Function to update ipv4 ckcum.
 * @param  : m, mbuf pointer
 * @return : Returns nothing
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
