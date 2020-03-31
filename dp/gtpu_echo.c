
#include <rte_log.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "ipv4.h"
#include "gtpu.h"
//#include "gtpu_echo.h"
#include "util.h"

/* VS: TODO*/
//static uint8_t resp_cnt = 1;

/* Brief: Function to set echo request as echo response
 * @ Input param: echo_pkt rte_mbuf pointer
 * @ Output param: none
 * Return: void
 */
static void reset_req_pkt_as_resp(struct rte_mbuf *echo_pkt) {
	/* Swap src and destination mac addresses */
	struct ether_hdr *eth_h = rte_pktmbuf_mtod(echo_pkt, struct ether_hdr *);
	struct ether_addr tmp_mac;
	ether_addr_copy(&eth_h->d_addr, &tmp_mac);
	ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
	ether_addr_copy(&tmp_mac, &eth_h->s_addr);

	/* Swap src and dst IP addresses */
	struct ipv4_hdr *ip_hdr = get_mtoip(echo_pkt);
	uint32_t tmp_ip = ip_hdr->dst_addr;
	ip_hdr->dst_addr = ip_hdr->src_addr;
	ip_hdr->src_addr = tmp_ip;
	ip_hdr->total_length = htons(ntohs(ip_hdr->total_length)+
			sizeof(gtpu_recovery_ie));

	/* Swap src and dst UDP ports */
	struct udp_hdr *udphdr = get_mtoudp(echo_pkt);
	uint16_t tmp_port = udphdr->dst_port;
	udphdr->dst_port = udphdr->src_port;
	udphdr->src_port = tmp_port;
	udphdr->dgram_len = htons(ntohs(udphdr->dgram_len)+
			sizeof(gtpu_recovery_ie));
}
/* Brief: Function to set recovery IE
 * @ Input param: echo_pkt rte_mbuf pointer
 * @ Output param: none
 * Return: void
 */
static int set_recovery(struct rte_mbuf *echo_pkt, uint8_t port_id) {
	struct ipv4_hdr *ip_hdr = get_mtoip(echo_pkt);
	struct gtpu_hdr *gtpu_hdr = get_mtogtpu(echo_pkt);
	gtpu_recovery_ie *recovery_ie = NULL;

	/* Get the extra len bytes for recovery */
	uint16_t extra_len = echo_pkt->pkt_len - (ETHER_HDR_LEN + ntohs(ip_hdr->total_length));

	if (extra_len < sizeof(gtpu_recovery_ie)) {
		recovery_ie = (gtpu_recovery_ie *)rte_pktmbuf_append(echo_pkt, (sizeof(gtpu_recovery_ie) - extra_len));
		/* Checking the sufficient header room lenght for the recovery */
		if ((echo_pkt->pkt_len - (ETHER_HDR_LEN + ntohs(ip_hdr->total_length)) <  sizeof(gtpu_recovery_ie))) {
			fprintf(stderr, "ERROR: For recovery there is not sufficient lenght is allocated\n");
			return -1;
		}
	}
	/* Point to the current location of the recovery ie */
	recovery_ie = (gtpu_recovery_ie*)((char*)gtpu_hdr + GTPU_HDR_SIZE + ntohs(gtpu_hdr->msglen));

	if (recovery_ie == NULL) {
		RTE_LOG_DP(ERR, DP, "Couldn't append %lu bytes to mbuf",
				sizeof(gtpu_recovery_ie));
		 return -1;
	}

	gtpu_hdr->msgtype = GTPU_ECHO_RESPONSE;
	gtpu_hdr->msglen = htons(ntohs(gtpu_hdr->msglen)+
		sizeof(gtpu_recovery_ie));
	recovery_ie->type = GTPU_ECHO_RECOVERY;
	//recovery_ie->restart_cntr = resp_cnt;
	recovery_ie->restart_cntr = 0;
	return 0;
}

/* Brief: Function to set checksum of IPv4 and UDP header
 * @ Input param: echo_pkt rte_mbuf pointer
 * @ Output param: none
 * Return: void
 */
static void set_checksum(struct rte_mbuf *echo_pkt) {
	struct ipv4_hdr *ipv4hdr = get_mtoip(echo_pkt);
	ipv4hdr->hdr_checksum = 0;
	struct udp_hdr *udphdr = get_mtoudp(echo_pkt);
	udphdr->dgram_cksum = 0;
	udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4hdr, udphdr);
	ipv4hdr->hdr_checksum = rte_ipv4_cksum(ipv4hdr);
}

/* Brief: Function to process GTP-U echo request
 * @ Input param: echo_pkt rte_mbuf pointer
 * @ Output param: none
 * Return: void
 */
void process_echo_request(struct rte_mbuf *echo_pkt, uint8_t port_id) {
	int ret;
	ret = set_recovery(echo_pkt, port_id);
	if (ret < 0) {
		fprintf(stderr, "Failed to create echo response..\n");
		return;
	}

	reset_req_pkt_as_resp(echo_pkt);
	set_checksum(echo_pkt);
}
