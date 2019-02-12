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

#include <arpa/inet.h>

#include "util.h"

void
construct_udp_hdr(struct rte_mbuf *m, uint16_t len,
		  uint16_t sport, uint16_t dport)
{
	struct udp_hdr *udp_hdr;

	udp_hdr = get_mtoudp(m);
	udp_hdr->src_port = htons(sport);
	udp_hdr->dst_port = htons(dport);
	udp_hdr->dgram_len = htons(len);

	/* update Udp checksum */
	udp_hdr->dgram_cksum = 0;
}
