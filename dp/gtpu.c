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
#include <rte_ip.h>

#include "up_main.h"
#include "gtpu.h"
#include "gw_adapter.h"
extern int clSystemLog;

int (*fp_decap_gtpu_hdr)(struct rte_mbuf *m, uint8_t ip_type);
int (*fp_encap_gtpu_hdr)(struct rte_mbuf *m, uint32_t teid, uint8_t ip_type);
uint32_t (*fp_gtpu_inner_src_ip)(struct rte_mbuf *m);
struct in6_addr (*fp_gtpu_inner_src_ipv6)(struct rte_mbuf *m);
void (*fp_gtpu_get_inner_src_dst_ip)(struct rte_mbuf *m, uint32_t *src_ip, uint32_t *dst_ip);

static uint16_t gtpu_seqnb = 0;

/**
 * @brief  : Function to construct gtpu header.
 * @param  : m,  mbuf pointer
 * @param  : teid, tunnel endpoint id
 * @param  : tpdu_len, length of tunneled pdu
 * @return : Returns nothing
 */
static inline void
construct_gtpu_hdr_with_seqnb(struct rte_mbuf *m, uint32_t teid, uint16_t tpdu_len,
		uint8_t ip_type)
{
	uint8_t *gpdu_hdr;

	/* Construct GPDU header. */
	if (ip_type) {
		gpdu_hdr = (uint8_t *) get_mtogtpu_v6(m);
	} else {
		gpdu_hdr = (uint8_t *) get_mtogtpu(m);
	}
	*(gpdu_hdr++) = (GTPU_VERSION << 5) |
					(GTP_PROTOCOL_TYPE_GTP << 4) |
					(GTP_FLAG_SEQNB);
	*(gpdu_hdr++) = GTP_GPDU;
	tpdu_len = tpdu_len + sizeof(GTPU_STATIC_SEQNB);
	*((uint16_t *) gpdu_hdr) = htons(tpdu_len);
	gpdu_hdr += 2;
	*((uint32_t *) gpdu_hdr) = htonl(teid);
	gpdu_hdr +=sizeof(teid);
	*((uint32_t *) gpdu_hdr) = GTPU_STATIC_SEQNB |
								htons(gtpu_seqnb);
	gtpu_seqnb++;
}

/**
 * @brief  : Function to construct gtpu header without sequence number
 * @param  : m,  mbuf pointer
 * @param  : teid, tunnel endpoint id
 * @param  : tpdu_len, length of tunneled pdu
 * @return : Returns nothing
 */
static inline void
construct_gtpu_hdr_without_seqnb(struct rte_mbuf *m, uint32_t teid, uint16_t tpdu_len,
			uint8_t ip_type)
{
	uint8_t *gpdu_hdr;

	/* Construct GPDU header. */
	if (ip_type) {
		gpdu_hdr = (uint8_t *) get_mtogtpu_v6(m);
	} else {
		gpdu_hdr = (uint8_t *) get_mtogtpu(m);
	}
	*(gpdu_hdr++) = (GTPU_VERSION << 5) | (GTP_PROTOCOL_TYPE_GTP << 4);
	*(gpdu_hdr++) = GTP_GPDU;
	*((uint16_t *) gpdu_hdr) = htons(tpdu_len);
	gpdu_hdr += 2;
	*((uint32_t *) gpdu_hdr) = htonl(teid);
}

int decap_gtpu_hdr_dynamic_seqnb(struct rte_mbuf *m, uint8_t ip_type)
{
	void *ret;
	uint8_t *pkt_ptr;
	/* If IP_Type set to 1, i.e IPv6 packet, and set to 0 i.e. IPv4 Pkt */
	if (ip_type) {
		/* Remove the GPDU hdr = 8 Bytes, IPv6 hdr= 40 Bytes, UDP = 8 Bytes
		 *  from the tunneled packet.
		 * Note: the ether header must be updated before tx.
		 */
		pkt_ptr = (uint8_t *) get_mtogtpu_v6(m);
		ret = rte_pktmbuf_adj(m, GPDU_HDR_SIZE_DYNAMIC(*pkt_ptr) + UDP_HDR_SIZE + IPv6_HDR_SIZE);
	} else {
		/* Remove the GPDU hdr = 8 Bytes, IPv4 hdr= 20 Bytes, UDP = 8 Bytes
		 *  from the tunneled packet.
		 * Note: the ether header must be updated before tx.
		 */
		pkt_ptr = (uint8_t *) get_mtogtpu(m);
		ret = rte_pktmbuf_adj(m, GPDU_HDR_SIZE_DYNAMIC(*pkt_ptr) + UDP_HDR_SIZE + IPv4_HDR_SIZE);
	}
	if (ret == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Error: Failed to remove GTPU header\n", LOG_VALUE);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Decap: modified mbuf offset %d, data len %d, pkt len%u\n",
			LOG_VALUE, m->data_off, m->data_len, m->pkt_len);
	return 0;
}

int decap_gtpu_hdr_with_seqnb(struct rte_mbuf *m, uint8_t ip_type)
{
	void *ret;

	/* If IP_Type set to 1, i.e IPv6 packet, and set to 0 i.e. IPv4 Pkt */
	if (ip_type) {
		/* Remove the GPDU hdr = 12 Bytes, IPv6 hdr= 40 Bytes, UDP = 8 Bytes
		 *  from the tunneled packet.
		 * Note: the ether header must be updated before tx.
		 */
		ret = rte_pktmbuf_adj(m, GPDU_HDR_SIZE_WITH_SEQNB + UDP_HDR_SIZE + IPv6_HDR_SIZE);
	} else {
		/* Remove the GPDU hdr = 12 Bytes, IPv4 hdr= 20 Bytes, UDP = 8 Bytes
		 *  from the tunneled packet.
		 * Note: the ether header must be updated before tx.
		 */
		ret = rte_pktmbuf_adj(m, GPDU_HDR_SIZE_WITH_SEQNB + UDP_HDR_SIZE + IPv4_HDR_SIZE);
	}
	if (ret == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Failed to remove GTPU header\n", LOG_VALUE);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			"Decap: modified mbuf offset %d, data_len %d, pkt_len%u\n",
			m->data_off, m->data_len, m->pkt_len);
	return 0;
}

int decap_gtpu_hdr_without_seqnb(struct rte_mbuf *m, uint8_t ip_type)
{
	void *ret;

	/* If IP_Type set to 1, i.e IPv6 packet, and set to 0 i.e. IPv4 Pkt */
	if (ip_type) {
		/* Remove the GPDU hdr = 8 Bytes, IPv6 hdr= 40 Bytes, UDP = 8 Bytes
		 *  from the tunneled packet.
		 * Note: the ether header must be updated before tx.
		 */
		ret = rte_pktmbuf_adj(m, GPDU_HDR_SIZE_WITHOUT_SEQNB + UDP_HDR_SIZE + IPv6_HDR_SIZE);
	} else {
		/* Remove the GPDU hdr = 8 Bytes, IPv4 hdr= 20 Bytes, UDP = 8 Bytes
		 *  from the tunneled packet.
		 * Note: the ether header must be updated before tx.
		 */
		ret = rte_pktmbuf_adj(m, GPDU_HDR_SIZE_WITHOUT_SEQNB + UDP_HDR_SIZE + IPv4_HDR_SIZE);
	}
	if (ret == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Failed to remove GTPU header\n", LOG_VALUE);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			"Decap: modified mbuf offset %d, data_len %d, pkt_len%u\n",
			m->data_off, m->data_len, m->pkt_len);
	return 0;
}

int encap_gtpu_hdr_with_seqnb(struct rte_mbuf *m, uint32_t teid, uint8_t ip_type)
{
	uint8_t *pkt_ptr;
	uint16_t tpdu_len;

	tpdu_len = rte_pktmbuf_data_len(m);
	tpdu_len -= ETH_HDR_SIZE;
	/* If IP_Type set to 1, i.e IPv6 packet, and set to 0 i.e. IPv4 Pkt */
	if (ip_type) {
		/* Prepend GPDU hdr = 8 Bytes, IPv6 hdr= 40 Bytes,
		 * UDP = 8 Bytes to mbuf data in headroom.
		 */
		pkt_ptr =
			(uint8_t *) rte_pktmbuf_prepend(m,
					GPDU_HDR_SIZE_WITH_SEQNB +
					UDP_HDR_SIZE + IPv6_HDR_SIZE);
	} else {
		/* Prepend GPDU hdr = 8 Bytes, IPv4 hdr= 20 Bytes,
		 * UDP = 8 Bytes to mbuf data in headroom.
		 */
		pkt_ptr =
			(uint8_t *) rte_pktmbuf_prepend(m,
					GPDU_HDR_SIZE_WITH_SEQNB +
					UDP_HDR_SIZE + IPv4_HDR_SIZE);
	}
	if (pkt_ptr == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Error: Failed to add GTPU header\n", LOG_VALUE);
		return -1;
	}
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Encap: modified mbuf offset %d, data len %d, PKT len %u\n",
			LOG_VALUE, m->data_off, m->data_len, m->pkt_len);

	construct_gtpu_hdr_with_seqnb(m, teid, tpdu_len, ip_type);

	return 0;
}

int encap_gtpu_hdr_without_seqnb(struct rte_mbuf *m, uint32_t teid, uint8_t ip_type)
{
	uint8_t *pkt_ptr;
	uint16_t tpdu_len;

	tpdu_len = rte_pktmbuf_data_len(m);
	tpdu_len -= ETH_HDR_SIZE;
	/* If IP_Type set to 1, i.e IPv6 packet, and set to 0 i.e. IPv4 Pkt */
	if (ip_type) {
		/* Prepend GPDU hdr = 8 Bytes, IPv6 hdr= 40 Bytes,
		 * UDP = 8 Bytes to mbuf data in headroom.
		 */
		pkt_ptr =
			(uint8_t *) rte_pktmbuf_prepend(m,
					GPDU_HDR_SIZE_WITHOUT_SEQNB +
					UDP_HDR_SIZE + IPv6_HDR_SIZE);
	} else {
		/* Prepend GPDU hdr = 8 Bytes, IPv4 hdr= 20 Bytes,
		 * UDP = 8 Bytes to mbuf data in headroom.
		 */
		pkt_ptr =
			(uint8_t *) rte_pktmbuf_prepend(m,
					GPDU_HDR_SIZE_WITHOUT_SEQNB +
					UDP_HDR_SIZE + IPv4_HDR_SIZE);
	}

	if (pkt_ptr == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Failed to add GTPU header\n", LOG_VALUE);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			"Encap: modified mbuf offset %d, data_len %d, pkt_len %u\n",
			m->data_off, m->data_len, m->pkt_len);

	construct_gtpu_hdr_without_seqnb(m, teid, tpdu_len, ip_type);

	return 0;
}

uint32_t gtpu_inner_src_ip_dynamic_seqnb(struct rte_mbuf *m)
{
	uint8_t *pkt_ptr;
	struct ipv4_hdr *inner_ipv4_hdr;

	pkt_ptr = (uint8_t *) get_mtogtpu(m);
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"IPv4:VS-GPDU HDR SIZE: %u\n",
			LOG_VALUE, GPDU_HDR_SIZE_DYNAMIC(*pkt_ptr));

	pkt_ptr += GPDU_HDR_SIZE_DYNAMIC(*pkt_ptr);
	inner_ipv4_hdr = (struct ipv4_hdr *)pkt_ptr;

	return inner_ipv4_hdr->src_addr;
}

uint32_t gtpu_inner_src_ip_with_seqnb(struct rte_mbuf *m)
{
	uint8_t *pkt_ptr;
	struct ipv4_hdr *inner_ipv4_hdr;

	pkt_ptr = (uint8_t *) get_mtogtpu(m);
	clLog(clSystemLog, eCLSeverityDebug, "IPv4:VS-gtpu.c: GPDU_HDR_SIZE %u\n",
			GPDU_HDR_SIZE_WITH_SEQNB);

	pkt_ptr += GPDU_HDR_SIZE_WITH_SEQNB;
	inner_ipv4_hdr = (struct ipv4_hdr *)pkt_ptr;

	return inner_ipv4_hdr->src_addr;
}

uint32_t gtpu_inner_src_ip_without_seqnb(struct rte_mbuf *m)
{
	uint8_t *pkt_ptr;
	struct ipv4_hdr *inner_ipv4_hdr;

	pkt_ptr = (uint8_t *) get_mtogtpu(m);
	clLog(clSystemLog, eCLSeverityDebug, "IPv4:VS-gtpu.c: GPDU_HDR_SIZE %u\n",
			GPDU_HDR_SIZE_WITHOUT_SEQNB);

	pkt_ptr += GPDU_HDR_SIZE_WITHOUT_SEQNB;
	inner_ipv4_hdr = (struct ipv4_hdr *)pkt_ptr;

	return inner_ipv4_hdr->src_addr;
}

void gtpu_get_inner_src_dst_ip_dynamic_seqnb(struct rte_mbuf *m,
		uint32_t *src_ip, uint32_t *dst_ip)
{
	uint8_t *pkt_ptr = NULL;
	struct ipv4_hdr *inner_ipv4_hdr = NULL;

	pkt_ptr = (uint8_t *) get_mtogtpu(m);

	pkt_ptr += GPDU_HDR_SIZE_DYNAMIC(*pkt_ptr);
	inner_ipv4_hdr = (struct ipv4_hdr *)pkt_ptr;

	*src_ip = inner_ipv4_hdr->src_addr;
	*dst_ip = inner_ipv4_hdr->dst_addr;
}

void gtpu_get_inner_src_dst_ip_with_seqnb(struct rte_mbuf *m,
		uint32_t *src_ip, uint32_t *dst_ip)
{
	uint8_t *pkt_ptr = NULL;
	struct ipv4_hdr *inner_ipv4_hdr = NULL;

	pkt_ptr = (uint8_t *) get_mtogtpu(m);

	pkt_ptr += GPDU_HDR_SIZE_WITH_SEQNB;
	inner_ipv4_hdr = (struct ipv4_hdr *)pkt_ptr;

	*src_ip = inner_ipv4_hdr->src_addr;
	*dst_ip = inner_ipv4_hdr->dst_addr;
}

void gtpu_get_inner_src_dst_ip_without_seqnb(struct rte_mbuf *m,
		uint32_t *src_ip, uint32_t *dst_ip)
{
	uint8_t *pkt_ptr = NULL;
	struct ipv4_hdr *inner_ipv4_hdr = NULL;

	pkt_ptr = (uint8_t *) get_mtogtpu(m);

	pkt_ptr += GPDU_HDR_SIZE_WITHOUT_SEQNB;
	inner_ipv4_hdr = (struct ipv4_hdr *)pkt_ptr;

	*src_ip = inner_ipv4_hdr->src_addr;
	*dst_ip = inner_ipv4_hdr->dst_addr;
}

/* VS: IPv6*/
struct in6_addr gtpu_inner_src_ipv6_with_seqnb(struct rte_mbuf *m)
{
	uint8_t *pkt_ptr;
	struct ipv6_hdr *inner_ipv6_hdr;

	pkt_ptr = (uint8_t *) get_mtogtpu_v6(m);
	clLog(clSystemLog, eCLSeverityDebug, "IPv6:VS-gtpu.c: GPDU_HDR_SIZE %u\n",
			GPDU_HDR_SIZE_WITH_SEQNB);

	pkt_ptr += GPDU_HDR_SIZE_WITH_SEQNB;
	inner_ipv6_hdr = (struct ipv6_hdr *)pkt_ptr;

	return *(struct in6_addr *)inner_ipv6_hdr->src_addr;
}

struct in6_addr gtpu_inner_src_ipv6_without_seqnb(struct rte_mbuf *m)
{
	uint8_t *pkt_ptr;
	struct ipv6_hdr *inner_ipv6_hdr;

	pkt_ptr = (uint8_t *) get_mtogtpu_v6(m);
	clLog(clSystemLog, eCLSeverityDebug, "IPv6:VS-gtpu.c: GPDU_HDR_SIZE %u\n",
			GPDU_HDR_SIZE_WITHOUT_SEQNB);

	pkt_ptr += GPDU_HDR_SIZE_WITHOUT_SEQNB;
	inner_ipv6_hdr = (struct ipv6_hdr *)pkt_ptr;

	return *(struct in6_addr *)inner_ipv6_hdr->src_addr;
}

struct in6_addr gtpu_inner_src_ipv6_dynamic_seqnb(struct rte_mbuf *m)
{
	uint8_t *pkt_ptr;
	struct ipv6_hdr *inner_ipv6_hdr;

	pkt_ptr = (uint8_t *) get_mtogtpu_v6(m);
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"IPv6:VS-GPDU HDR SIZE: %u\n",
			LOG_VALUE, GPDU_HDR_SIZE_DYNAMIC(*pkt_ptr));

	pkt_ptr += GPDU_HDR_SIZE_DYNAMIC(*pkt_ptr);
	inner_ipv6_hdr = (struct ipv6_hdr *)pkt_ptr;

	return *(struct in6_addr *)inner_ipv6_hdr->src_addr;
}

