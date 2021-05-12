/*
 * Copyright (c) 2020 T-Mobile
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

#include "ipv6.h"

/**
 * @brief  : Function to construct ipv6 header.
 * @param  : m, mbuf pointer
 * @param  : len, len of header
 * @param  : protocol, next protocol id
 * @param  : src_ip, Source ip address
 * @param  : dst_ip, destination ip address
 * @return : Returns nothing
 */
void
construct_ipv6_hdr(struct rte_mbuf *m, uint16_t len, uint8_t protocol,
		   struct in6_addr *src_ip, struct in6_addr *dst_ip)
{
	build_ipv6_default_hdr(m);

	set_ipv6_hdr(m, len, protocol, src_ip, dst_ip);
}
