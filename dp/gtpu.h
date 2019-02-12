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

#ifndef _GTPU_H_
#define _GTPU_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of GTPU header parsing and constructor.
 */
#include "util.h"

#define GTPU_VERSION		0x01
#define GTP_PROTOCOL_TYPE_GTP	0x01

#define GTP_FLAG_EXTHDR		0x04
#define GTP_FLAG_SEQNB		0x02
#define GTP_FLAG_NPDU		0x01

/* GTPU_STATIC_SEQNB 0x00001122::On Wire 22 11 00 00
 * Last two SEQNB bytes should be 00 00
 * */
#define GTPU_STATIC_SEQNB (uint32_t)0x00000000


#define GPDU_HDR_SIZE_WITHOUT_SEQNB	8
#define GPDU_HDR_SIZE_WITH_SEQNB	12

#define GPDU_HDR_SIZE_DYNAMIC(flags) ((uint32_t)(GPDU_HDR_SIZE_WITHOUT_SEQNB + ((flags) & GTP_FLAG_SEQNB ? sizeof(GTPU_STATIC_SEQNB) : 0)))

#define GTP_GPDU		0xff

/* GTPU-Echo defines*/
#define GTPU_ECHO_RECOVERY			(14)
#define GTPU_ECHO_REQUEST			(0x01)
#define GTPU_ECHO_RESPONSE			(0x02)
#define GTPU_HDR_SIZE				(8)

#define UDP_PORT_GTPU_NW_ORDER 26632 /* GTP UDP port(2152) in NW order */
/**
 * Gpdu header structure .
 */

#pragma pack(1)
struct gtpu_hdr {
	uint8_t pdn:1;		/**< n-pdn number present ? */
	uint8_t seq:1;		/**< sequence no. */
	uint8_t ex:1;		/**< next extersion hdr present? */
	uint8_t spare:1;	/**< reserved */
	uint8_t pt:1;		/**< protocol type */
	uint8_t version:3;	/**< version */
	uint8_t msgtype;	/**< message type */
	uint16_t msglen;	/**< message length */
	uint32_t teid;		/**< tunnel endpoint id */
	uint32_t seqnb;		/**< sequence number */
};
#pragma pack()

/**
 * Function to return pointer to gtpu headers.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	pointer to udp headers
 */
static inline struct gtpu_hdr *get_mtogtpu(struct rte_mbuf *m)
{
	return (struct gtpu_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) +
			ETH_HDR_SIZE + IPv4_HDR_SIZE + UDP_HDR_SIZE);
}

/**
 * Function for decapsulation of gtpu headers.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
extern int (*fp_decap_gtpu_hdr)(struct rte_mbuf *m);
int decap_gtpu_hdr_dynamic_seqnb(struct rte_mbuf *m);
int decap_gtpu_hdr_with_seqnb(struct rte_mbuf *m);
int decap_gtpu_hdr_without_seqnb(struct rte_mbuf *m);
#define DECAP_GTPU_HDR(a) (*fp_decap_gtpu_hdr)(a)

/**
 * Function for encapsulation of gtpu headers.
 *
 * @param m
 *	mbuf pointer
 * @param teid
 *	tunnel endpoint id to be set in gtpu header.
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
extern int (*fp_encap_gtpu_hdr)(struct rte_mbuf *m, uint32_t teid);
int encap_gtpu_hdr_with_seqnb(struct rte_mbuf *m, uint32_t teid);
int encap_gtpu_hdr_without_seqnb(struct rte_mbuf *m, uint32_t teid);
#define ENCAP_GTPU_HDR(a,b) (*fp_encap_gtpu_hdr)(a,b)

/**
 * Function to get inner dst ip of tunneled packet.
 *
 * @param m
 *	mbuf of the incoming packet.
 *
 * @return
 *	 inner dst ip
 */
extern uint32_t (*fp_gtpu_inner_src_ip)(struct rte_mbuf *m);
uint32_t gtpu_inner_src_ip_dynamic_seqnb(struct rte_mbuf *m);
uint32_t gtpu_inner_src_ip_with_seqnb(struct rte_mbuf *m);
uint32_t gtpu_inner_src_ip_without_seqnb(struct rte_mbuf *m);
#define GTPU_INNER_SRC_IP(a) (*fp_gtpu_inner_src_ip)(a)

/**
 * Function to get inner src and dst ip of tunneled packet.
 *
 * @param m
 *	mbuf of the incoming packet.
 * @param src_ip
 *	source ip.
 * @param dst_ip
 *	destination ip.
 *
 * @return
 *	 inner dst ip
 */
extern void (*fp_gtpu_get_inner_src_dst_ip)(struct rte_mbuf *m, uint32_t *src_ip, uint32_t *dst_ip);
void gtpu_get_inner_src_dst_ip_dynamic_seqnb(struct rte_mbuf *m, uint32_t *src_ip, uint32_t *dst_ip);
void gtpu_get_inner_src_dst_ip_with_seqnb(struct rte_mbuf *m, uint32_t *src_ip, uint32_t *dst_ip);
void gtpu_get_inner_src_dst_ip_without_seqnb(struct rte_mbuf *m, uint32_t *src_ip, uint32_t *dst_ip);
#define GTPU_GET_INNER_SRC_DST_IP(a,b,c) (*fp_gtpu_get_inner_src_dst)(a,b,c)

/**
 * Function to process GTPU Echo request
 *  @param echo_pkt
 *  mbuf of the incoming packet.
 *
 * @return
 * void
 */
void process_echo_request(struct rte_mbuf *echo_pkt);
#endif	/* _GTPU_H_ */
