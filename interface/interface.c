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

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>

#include "util.h"
#include "interface.h"
#include "dp_ipc_api.h"
#include "clogger.h"

//#include "acl_dp.h"
//#include "meter.h"
//#include "gtpv2c_ie.h"

#ifdef SDN_ODL_BUILD
#include "zmqsub.h"
#include "zmqpub.h"
#ifdef CP_BUILD
#include "nb.h"
#endif
#endif

#ifndef CP_BUILD
#include "up_acl.h"
#else
#include "gtpv2c.h"
#include "ipc_api.h"
#endif /* CP_BULID */

#ifdef SGX_CDR
	#define DEALERIN_IP "dealer_in_ip"
	#define DEALERIN_PORT "dealer_in_port"
	#define DEALERIN_MRENCLAVE "dealer_in_mrenclave"
	#define DEALERIN_MRSIGNER "dealer_in_mrsigner"
	#define DEALERIN_ISVSVN "dealer_in_isvsvn"
	#define DP_CERT_PATH "dp_cert_path"
	#define DP_PKEY_PATH "dp_pkey_path"
#endif /* SGX_CDR */

#ifdef CP_BUILD
#ifdef GX_BUILD
extern int gx_app_sock;
#endif /* GX_BUILD */
#endif /* CP_BUILD */

/*
 * UDP Setup
 */
udp_sock_t my_sock;

/* VS: ROUTE DISCOVERY */
extern int route_sock;


struct in_addr dp_comm_ip;
struct in_addr cp_comm_ip;
uint16_t dp_comm_port;
uint16_t cp_comm_port;

#ifdef SDN_ODL_BUILD
struct in_addr fpc_ip;
uint16_t fpc_port;
uint16_t fpc_topology_port;

struct in_addr cp_nb_ip;
uint16_t cp_nb_port;
#endif

#ifdef TIMER_STATS
#ifdef AUTO_ANALYSIS
extern void print_perf_statistics(void);
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */

extern struct ipc_node *basenode;
extern struct rte_hash *heartbeat_recovery_hash;

struct rte_hash *node_id_hash;

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

void register_comm_msg_cb(enum cp_dp_comm id,
		int (*init)(void),
		int (*send)(void *msg_payload, uint32_t size),
		int (*recv)(void *msg_payload, uint32_t size),
		int (*destroy)(void))
{
	struct comm_node *node;

	node = &comm_node[id];
	node->init = init;
	node->send = send;
	node->recv = recv;
	node->destroy = destroy;
	node->status = 0;
	node->init();
}

int set_comm_type(enum cp_dp_comm id)
{
	if (comm_node[id].status == 0 && comm_node[id].init != NULL) {
		active_comm_msg = &comm_node[id];
		comm_node[id].status = 1;
	} else {
		clLog(clSystemLog, eCLSeverityCritical,"Error: Cannot set communication type\n");
		return -1;
	}
	return 0;
}

int unset_comm_type(enum cp_dp_comm id)
{
	if (comm_node[id].status) {
		active_comm_msg->destroy();
		comm_node[id].status = 0;
	} else {
		clLog(clSystemLog, eCLSeverityCritical,"Error: Cannot unset communication type\n");
		return -1;
	}
	return 0;
}

int process_comm_msg(void *buf)
{
	struct msgbuf *rbuf = (struct msgbuf *)buf;
	struct ipc_node *cb;

	if (rbuf->mtype >= MSG_END)
		return -1;

	/* Callback APIs */
	cb = &basenode[rbuf->mtype];

	return cb->msg_cb(rbuf);
}

#ifdef CP_BUILD
#ifdef SDN_ODL_BUILD
/**
 * @brief  : send data on udp interface
 * @param  : msg_payload, buffer holds data to be sent
 * @param  : size, total size of data
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
udp_send_socket(void *msg_payload, uint32_t size)
{
	if (__send_udp_packet(&my_sock, msg_payload, size) < 0)
		clLog(clSystemLog, eCLSeverityCritical, "Failed to send msg !!!\n");

	/* Workaround to avoid out of order packets on DP. In case of load it
	 * is observed that packets are received out of order at DP e.g. MB is
	 * received before CS, hence causing issue in session establishment */
	usleep(50);
	return 0;
}

/**
 * @brief  : Init listen socket.
 * @param  : No param
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
udp_init_cp_socket(void)
{
	/*
	 * UDP init
	 */
	/* TODO IP and port parameters */
	if (__create_udp_socket(dp_comm_ip, dp_comm_port, cp_comm_port,
				&my_sock) < 0)
		rte_exit(EXIT_FAILURE, "Create CP UDP Socket Failed "
				"for IP %s:%u!!!\n",
				inet_ntoa(dp_comm_ip), dp_comm_port);

	return 0;
}

#endif /* CP_BUILD */
#endif /* SDN_ODL_BUILD */

#ifndef CP_BUILD
/**
 * @brief  : Init listen socket.
 * @param  : No param
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
udp_init_dp_socket(void)
{
	if (__create_udp_socket(cp_comm_ip, cp_comm_port, dp_comm_port,
				&my_sock) < 0)
		rte_exit(EXIT_FAILURE, "Create DP UDP Socket "
				"Failed for IP %s:%d!!!\n",
				inet_ntoa(cp_comm_ip), cp_comm_port);
	return 0;
}

#ifdef SDN_ODL_BUILD
/**
 * Code Rel. Jan 30, 2017
 * UDP recvfrom used for PCC, ADC, Session table initialization.
 * Needs to be from SDN controller as code & data models evolve.
 */

/**
 * @brief  : Init zmq socket.
 * @param  : No param
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
zmq_init_socket(void)
{
	/*
	 * zmqsub init
	 */
	zmq_pubsocket_create();
	return zmq_subsocket_create();
}

/**
 * @brief  : send data on zmq interface
 * @param  : zmqmsgbuf, buffer holds data to be sent
 * @param  : zmqmsgbufsz, total size of data
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
zmq_send_socket(void *zmqmsgbuf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqsub recv
	 */
	return zmq_mbuf_send(zmqmsgbuf, sizeof(struct zmqbuf));
}

/**
 * @brief  : Receive data on udp interface
 * @param  : buf, buffer to store incoming data
 * @param  : zmqmsgbufsz, total size of received data
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
zmq_recv_socket(void *buf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqsub recv
	 */
	int zmqmsglen = zmq_mbuf_rcv(buf, zmqmsgbufsz);

	if (zmqmsglen > 0) {
		clLog(clSystemLog, eCLSeverityDebug,
				"Rcvd zmqmsglen= %d:\t zmqmsgbufsz= %u\n",
				zmqmsglen, zmqmsgbufsz);
	}
	return zmqmsglen;
}

//#ifdef PRINT_NEW_RULE_ENTRY
///**
// * @brief  : Function to print ADC rules values.
// * @param  : [In] pointer to adc rule structure element
// * @return : Returns nothing
// */
//static void
//print_sel_type_val(struct adc_rules *adc)
//{
//	if (NULL != adc) {
//		switch (adc->sel_type) {
//			case DOMAIN_NAME:
//				clLog(clSystemLog, eCLSeverityDebug, " ---> Domain Name :%s\n",
//						adc->u.domain_name);
//				break;
//
//			case DOMAIN_IP_ADDR:
//				clLog(clSystemLog, eCLSeverityDebug, " ---> Domain Ip :%d\n",
//						(adc->u.domain_ip.u.ipv4_addr));
//				break;
//
//			case DOMAIN_IP_ADDR_PREFIX:
//				clLog(clSystemLog, eCLSeverityDebug, " ---> Domain Ip :%d\n",
//						(adc->u.domain_ip.u.ipv4_addr));
//				clLog(clSystemLog, eCLSeverityDebug, " ---> Domain Prefix :%d\n",
//						adc->u.domain_prefix.prefix);
//				break;
//
//			default:
//				clLog(clSystemLog, eCLSeverityCritical, "UNKNOWN Selector Type: %d\n",
//						adc->sel_type);
//				break;
//		}
//	}
//}
//
///**
// * @brief  : Function to print ADC rules values.
// * @param  : [In] pointer to adc rule structure element
// * @return : Returns nothing
// */
//static void
//print_adc_val(struct adc_rules *adc)
//{
//	if (NULL != adc) {
//		clLog(clSystemLog, eCLSeverityDebug, "=========================================\n");
//		clLog(clSystemLog, eCLSeverityDebug, " ---> ADC Rule Method ::\n");
//		clLog(clSystemLog, eCLSeverityDebug, "=========================================\n");
//		clLog(clSystemLog, eCLSeverityDebug, " ---> Rule id : %d\n", adc->rule_id);
//
//		print_sel_type_val(adc);
//
//		clLog(clSystemLog, eCLSeverityDebug, "=========================================\n\n");
//	}
//}
//
///**
// * @brief  : Function to print PCC rules values.
// * @param  : [In] pointer to pcc rule structure element
// * @return : Returns nothing
// */
//static void
//print_pcc_val(struct pcc_rules *pcc)
//{
//	if (NULL != pcc) {
//		clLog(clSystemLog, eCLSeverityDebug, "=========================================\n");
//		clLog(clSystemLog, eCLSeverityDebug, " ---> PCC Rule Method ::\n");
//		clLog(clSystemLog, eCLSeverityDebug, "=========================================\n");
//		clLog(clSystemLog, eCLSeverityDebug, " ---> Rule id : %d\n", pcc->rule_id);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> metering_method :%d\n",
//				pcc->metering_method);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> charging_mode :%d\n",
//				pcc->charging_mode);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> rating_group :%d\n",
//				pcc->rating_group);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> rule_status :%d\n",
//				pcc->rule_status);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> gate_status :%d\n",
//				pcc->gate_status);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> session_cont :%d\n",
//				pcc->session_cont);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> monitoring_key :%d\n",
//				pcc->monitoring_key);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> precedence :%d\n",
//				pcc->precedence);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> level_of_report :%d\n",
//				pcc->report_level);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> mute_status :%d\n",
//				pcc->mute_notify);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> drop_pkt_count :%ld\n",
//				pcc->drop_pkt_count);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> redirect_info :%d\n",
//				pcc->redirect_info.info);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> ul_mbr_mtr_profile_idx :%d\n",
//				pcc->qos.ul_mtr_profile_index);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> dl_mbr_mtr_profile_idx :%d\n",
//				pcc->qos.dl_mtr_profile_index);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> ADC Index :%d\n",
//				pcc->adc_idx);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> SDF Index count:%d\n",
//				pcc->sdf_idx_cnt);
//		for(int i =0; i< pcc->sdf_idx_cnt; ++i)
//			clLog(clSystemLog, eCLSeverityDebug, " ---> SDF IDx [%d]:%d\n",
//					i, pcc->sdf_idx[i]);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> rule_name:%s\n", pcc->rule_name);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> sponsor_id:%s\n", pcc->sponsor_id);
//		clLog(clSystemLog, eCLSeverityDebug, "=========================================\n\n");
//	}
//}
//
///**
// * @brief  : Function to print METER rules values.
// * @param  : [In] pointer to mtr entry structure element
// * @return : Returns nothing
// */
//static void
//print_mtr_val(struct mtr_entry *mtr)
//{
//	if (NULL != mtr) {
//		clLog(clSystemLog, eCLSeverityDebug, "=========================================\n");
//		clLog(clSystemLog, eCLSeverityDebug, " ---> Meter Rule Method ::\n");
//		clLog(clSystemLog, eCLSeverityDebug, "=========================================\n");
//		clLog(clSystemLog, eCLSeverityDebug, " ---> Meter profile index :%d\n",
//				mtr->mtr_profile_index);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> Meter CIR :%ld\n",
//				mtr->mtr_param.cir);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> Meter CBS :%ld\n",
//				mtr->mtr_param.cbs);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> Meter EBS :%ld\n",
//				mtr->mtr_param.ebs);
//		clLog(clSystemLog, eCLSeverityDebug, " ---> Metering Method :%d\n",
//				mtr->metering_method);
//		clLog(clSystemLog, eCLSeverityDebug, "=========================================\n\n");
//	}
//}
//
///**
// * @brief  : Function to print SDF rules values.
// * @param  : [In] pointer to pkt_filter structure element
// * @return : Returns nothing
// */
//static void
//print_sdf_val(struct pkt_filter *sdf)
//{
//	if (NULL != sdf) {
//		clLog(clSystemLog, eCLSeverityDebug, "==========================================\n");
//		clLog(clSystemLog, eCLSeverityDebug, " ---> SDF Rule Method ::\n");
//		clLog(clSystemLog, eCLSeverityDebug, "==========================================\n");
//
//		switch (sdf->sel_rule_type) {
//			case RULE_STRING:
//				clLog(clSystemLog, eCLSeverityDebug, " ---> pcc_rule_id :%d\n",
//						sdf->pcc_rule_id);
//				clLog(clSystemLog, eCLSeverityDebug, " ---> rule_type :%d\n",
//						sdf->sel_rule_type);
//				clLog(clSystemLog, eCLSeverityDebug, " ---> rule_str : %s\n",
//						sdf->u.rule_str);
//				clLog(clSystemLog, eCLSeverityDebug, "====================================\n\n");
//				break;
//
//			case FIVE_TUPLE:
//				/*TODO: rule should be in struct
//				 * five_tuple_rule
//				 * This field is currently not used
//				 */
//				break;
//
//			default:
//				clLog(clSystemLog, eCLSeverityCritical, "UNKNOWN Rule Type: %d\n",
//						sdf->sel_rule_type);
//				break;
//		}
//	}
//}
//#endif /*PRINT_NEW_RULE_ENTRY*/
//
///**
// * @brief  : Function to parse adc rules values into adc_rules struct.
// *           Here parse values as per selector type (DOMAIN_NAME,
// *           DOMAIN_IP_ADDR, and DOMAIN_IP_ADDR_PREFIX), domain name,
// *           domain ip addr, domain prefix parameters values from recv buf and
// *           stored into adc_rules struct.
// *           ref.doc: message_sdn.docx
// *           section : Table No.11 ADC Rules
// * @param  : sel_type, selctor type pointed to adc rule type
// * @param  : [In] pointer (arm) to zmq rcv structure element
// * @param  : [Out] pointer (adc) to adc rules structure element
// * @return : Returns 0 in case of success , -1 otherwise
// */
//static int
//parse_adc_buf(int sel_type, char *arm, struct adc_rules *adc)
//{
//		if (arm != NULL) {
//			switch (sel_type) {
//				case DOMAIN_NAME:
//					strncpy(adc->u.domain_name, (char *)((arm)+1),
//							*(uint8_t *)(arm));
//
//#ifdef PRINT_NEW_RULE_ENTRY
//					print_adc_val(adc);
//#endif
//					return 0;
//
//				case DOMAIN_IP_ADDR_PREFIX:
//					adc->u.domain_ip.u.ipv4_addr =
//						ntohl(*(uint32_t *)(arm));
//					adc->u.domain_prefix.prefix =
//						rte_bswap16(*(uint16_t *)((arm) + 4));
//#ifdef PRINT_NEW_RULE_ENTRY
//					print_adc_val(adc);
//#endif  /* PRINT_NEW_RULE_ENTRY */
//					return 0;
//
//				case DOMAIN_IP_ADDR:
//					adc->u.domain_ip.u.ipv4_addr =
//						ntohl(*(uint32_t *)(arm));
//#ifdef PRINT_NEW_RULE_ENTRY
//					print_adc_val(adc);
//#endif  /* PRINT_NEW_RULE_ENTRY */
//					return 0;
//
//				default:
//					clLog(clSystemLog, eCLSeverityCritical, "UNKNOWN Selector Type: %d\n",
//							sel_type);
//					return -1;
//			}
//		}
//		return -1;
//}
//
///**
// * @brief  : Convert sdf_idx array in to array of integers for SDF index values.
// *           Sample input : "[0, 1, 2, 3]"
// * @param  : [IN] sdf_idx : String containing comma separater SDF index values
// * @param  : [OUT] out_sdf_idx : Array of integers converted from sdf_idx
// * @return : Returns 0 in case of success , -1 otherwise
// */
//static uint32_t
//get_sdf_indices(char *sdf_idx, uint32_t *out_sdf_idx)
//{
//	char *tmp = strtok (sdf_idx,",");
//	int i = 0;
//
//	while ((NULL != tmp) && (i < MAX_SDF_IDX_COUNT)) {
//		out_sdf_idx[i++] = atoi(tmp);
//		tmp = strtok (NULL, ",");
//	}
//	return i;
//}

/**
 * @brief  : Converts zmq message type to session_info or
 *           respective rules info
 * @param  : [IN] zmqmsgbuf_rx : Pointer to received zmq buffer
 * @param  : [IN] zmqmsglen : Length of the zmq buffer
 * @return : Returns 0 in case of success , -1 otherwise
 */

int
zmq_mbuf_process(struct zmqbuf *zmqmsgbuf_rx, int zmqmsglen)
{
	int ret;
	struct msgbuf buf = {0};
	struct zmqbuf zmqmsgbuf_tx;
	struct msgbuf *rbuf = &buf;
	struct session_info *sess = &rbuf->msg_union.sess_entry;

	memset(sess, 0, sizeof(*sess));

	rbuf->mtype = MSG_END;

	switch (zmqmsgbuf_rx->type) {
		case CREATE_SESSION: {
				struct create_session_t *csm =
				    &zmqmsgbuf_rx->msg_union.create_session_msg;

				rbuf->mtype = MSG_SESS_CRE;
				rbuf->dp_id.id = DPN_ID;

				sess->ue_addr.iptype = IPTYPE_IPV4;
				sess->ue_addr.u.ipv4_addr = ntohl(csm->ue_ipv4);
				sess->ul_s1_info.enb_addr.u.ipv4_addr = 0;
				sess->ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
				sess->ul_s1_info.sgw_addr.u.ipv4_addr =
				    ntohl(csm->s1u_sgw_ipv4);
				sess->ul_s1_info.sgw_teid = csm->s1u_sgw_teid;
				sess->dl_s1_info.enb_addr.u.ipv4_addr = 0;
				sess->dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
				sess->dl_s1_info.sgw_addr.u.ipv4_addr =
				    ntohl(csm->s1u_sgw_ipv4);
				sess->dl_s1_info.enb_teid = 0;

				switch(app.spgw_cfg) {
				    case SGWU:
				        /* Configure PGWU IP addr */
				        sess->ul_s1_info.s5s8_pgwu_addr.iptype = IPTYPE_IPV4;
				        sess->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr = ntohl(csm->s5s8_ipv4);
				        break;

				    case PGWU:
				        /* Configure SGWU IP addr */
				        sess->dl_s1_info.s5s8_sgwu_addr.iptype = IPTYPE_IPV4;
				        sess->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr = ntohl(csm->s5s8_ipv4);
				        sess->dl_s1_info.enb_teid = csm->s1u_sgw_teid;

				        /* Add default pcc rule entry for dl */
				        sess->num_dl_pcc_rules = 1;
				        sess->dl_pcc_rule_id[0] = 1;
				        break;

				    default:
				        break;
				}

				sess->num_ul_pcc_rules = 1;
				sess->ul_pcc_rule_id[0] = 1;

				sess->sess_id = rte_bswap64(csm->session_id);
				sess->client_id = csm->client_id;
				zmqmsgbuf_tx.msg_union.dpn_response.client_id = csm->client_id;
				zmqmsgbuf_tx.msg_union.dpn_response.op_id = csm->op_id;
				zmqmsgbuf_tx.topic_id = csm->controller_topic;
				break;
			}

		case MODIFY_BEARER: {
				struct modify_bearer_t *mbm =
				    &zmqmsgbuf_rx->msg_union.modify_bearer_msg;
				rbuf->mtype = MSG_SESS_MOD;
				rbuf->dp_id.id = DPN_ID;

				sess->ue_addr.u.ipv4_addr = 0;
				sess->ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
				sess->ul_s1_info.enb_addr.u.ipv4_addr =
				    ntohl(mbm->s1u_enodeb_ipv4);
				sess->ul_s1_info.sgw_addr.u.ipv4_addr = 0;
				sess->ul_s1_info.sgw_teid = 0;
				sess->dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
				sess->dl_s1_info.enb_addr.u.ipv4_addr =
				    ntohl(mbm->s1u_enodeb_ipv4);
				sess->dl_s1_info.sgw_addr.u.ipv4_addr = 0;
				sess->dl_s1_info.enb_teid = mbm->s1u_enodeb_teid;

				sess->num_ul_pcc_rules = 1;
				sess->ul_pcc_rule_id[0] = 1;
				sess->num_dl_pcc_rules = 1;
				sess->dl_pcc_rule_id[0] = 1;

				sess->sess_id = rte_bswap64(mbm->session_id);
				zmqmsgbuf_tx.msg_union.dpn_response.client_id = mbm->client_id;
				zmqmsgbuf_tx.msg_union.dpn_response.op_id = mbm->op_id;
				zmqmsgbuf_tx.topic_id = mbm->controller_topic;
				break;
			}

		case DELETE_SESSION: {
				struct delete_session_t *dsm =
				    &zmqmsgbuf_rx->msg_union.delete_session_msg;
				rbuf->mtype = MSG_SESS_DEL;
				rbuf->dp_id.id = DPN_ID;

				sess->ue_addr.u.ipv4_addr = 0;
				sess->ul_s1_info.enb_addr.u.ipv4_addr = 0;
				sess->ul_s1_info.sgw_addr.u.ipv4_addr = 0;
				sess->ul_s1_info.sgw_teid = 0;
				sess->dl_s1_info.enb_addr.u.ipv4_addr = 0;
				sess->dl_s1_info.sgw_addr.u.ipv4_addr = 0;
				sess->dl_s1_info.enb_teid = 0;

				sess->sess_id = rte_bswap64(dsm->session_id);

				zmqmsgbuf_tx.msg_union.dpn_response.client_id = dsm->client_id;
				zmqmsgbuf_tx.msg_union.dpn_response.op_id = dsm->op_id;
				zmqmsgbuf_tx.topic_id = dsm->controller_topic;
				break;
			}

		case ADC_RULE: {
				/*
				* @brief Coverts zmq message into ADC Rules info
				* ref.Doc : message_sdn_dp.docx
				* section : Table No.11 ADC Table
				*/
				static uint8_t rule_num = 1;
				uint8_t *buf = (uint8_t *)&(zmqmsgbuf_rx->msg_union.adc_rule_m);
				struct adc_rules *adc =
				    &(rbuf->msg_union.adc_filter_entry);

				rbuf->mtype = MSG_ADC_TBL_ADD;
				rbuf->dp_id.id = DPN_ID;

				adc->sel_type = *(uint8_t *)(buf);

				adc->rule_id = rule_num++;

				ret = parse_adc_buf(adc->sel_type, (((char *)(buf) + 1)), adc);

				if (ret < 0){
				    clLog(clSystemLog, eCLSeverityCritical, "Failed to filled adc structure\n");
				}
				break;
			}

		case PCC_RULE: {
				/**
				* @brief Coverts zmq message into PCC Rules info
				* ref.Doc : message_sdn_dp.docx
				* section : Table No.12 PCC Table
				*/
				static uint8_t rule_id_t = 1;
				struct pcc_rules_t *pcc_t =
				    &(zmqmsgbuf_rx->msg_union.pcc_rules_m);
				struct pcc_rules *pcc = &(rbuf->msg_union.pcc_entry);
				uint8_t sdf_idx[MAX_SDF_STR_LEN]={0};
				uint8_t len=0, offset = 0;

				rbuf->mtype = MSG_PCC_TBL_ADD;
				rbuf->dp_id.id = DPN_ID;

				pcc->rule_id = rule_id_t++;
				pcc->metering_method = pcc_t->metering_method;
				pcc->charging_mode = pcc_t->charging_mode;
				pcc->rating_group = rte_bswap16(pcc_t->rating_group);
				pcc->rule_status = pcc_t->rule_status;
				pcc->gate_status = pcc_t->gate_status;
				pcc->session_cont = pcc_t->session_cont;
				pcc->monitoring_key = rte_bswap32(pcc_t->monitoring_key);
				pcc->precedence = rte_bswap32(pcc_t->precedence);
				pcc->report_level = pcc_t->level_of_report;
				pcc->mute_notify = pcc_t->mute_status;
				pcc->drop_pkt_count = rte_bswap64(pcc_t->drop_pkt_count);
				pcc->qos.ul_mtr_profile_index = rte_bswap16(pcc_t->ul_mtr_profile_idx);
				pcc->qos.dl_mtr_profile_index = rte_bswap16(pcc_t->dl_mtr_profile_idx);
				pcc->redirect_info.info = pcc_t->redirect_info;
				pcc->adc_idx = rte_bswap32(pcc_t->adc_idx);

				/**
				* ref.table no 12 PCC table info will help know the code
				* len(SDF_FILTER_IDX), 0 : [0-4]
				* SDF_FILTER_IDX, 5: [5 - len1]
				* len(RULE_NAME), 5 + len1 :
				* RULE_NAME, [5+len1] + 5
				* len(SPONSOR_ID),  [5+len1] + [ 5 + len2]
				* SPONSOR_ID) [5+len1] + [5+len2] + 5
				*/
				strncpy(sdf_idx, ((char *)(&(pcc_t->adc_idx))+5),
				        *(uint8_t *)(&(pcc_t->adc_idx)+1));

				offset = *(uint8_t *)((char *)(&(pcc_t->adc_idx))+ 5 +
				        *(uint8_t *)(&(pcc_t->adc_idx)+1));

				strncpy(pcc->rule_name, ((char *)(&(pcc_t->adc_idx)) + 6 +
						*(uint8_t *)(&(pcc_t->adc_idx)+1)), offset);

				strncpy(pcc->sponsor_id, ((char *)(&(pcc_t->adc_idx)) + 7 +
						offset + *(uint8_t *)(&(pcc_t->adc_idx)+1)), MAX_LEN);

				len = *(uint8_t *)(&(pcc_t->adc_idx)+1);

				/**sdf indices are present only if adc is not present*/
				if(-1 == pcc->adc_idx){
				    /* Convert array of sdf index value to integers */
				    pcc->sdf_idx_cnt = get_sdf_indices(sdf_idx, pcc->sdf_idx);
				}
#ifdef PRINT_NEW_RULE_ENTRY
				print_pcc_val(pcc);
#endif  /* PRINT_NEW_RULE_ENTRY */
				break;
			}

		case METER_RULE: {
				/**
				 * @brief Coverts zmq message into Meter Rules info
				 * ref.Doc : message_sdn_dp.docx
				 * section : Table No.13 Meter Table
				 */
				struct mtr_entry_t *mtr_t =
				    &(zmqmsgbuf_rx->msg_union.mtr_entry_m);
				struct mtr_entry *mtr = &(rbuf->msg_union.mtr_entry);

				rbuf->mtype = MSG_MTR_ADD;
				rbuf->dp_id.id = DPN_ID;

				mtr->mtr_profile_index =
				    rte_bswap16(mtr_t->meter_profile_index);
				mtr->mtr_param.cir = rte_bswap64(mtr_t->cir);
				mtr->mtr_param.cbs = rte_bswap64(mtr_t->cbs);
				mtr->mtr_param.ebs = rte_bswap64(mtr_t->ebs);
				mtr->metering_method = mtr_t->metering_method;
#ifdef PRINT_NEW_RULE_ENTRY
				print_mtr_val(mtr);
#endif  /* PRINT_NEW_RULE_ENTRY */
				break;
			}

		case SDF_RULE: {
				/**
				* @brief Coverts zmq message into SDF Rules info
				* ref.Doc : Message_sdn.docx
				* section : Table No.14 SDF Table
				*/
				static uint8_t rule_id_t = 1;
				struct sdf_entry_t *sdf_t =
				    &(zmqmsgbuf_rx->msg_union.sdf_entry_m);
				struct pkt_filter *sdf = &(rbuf->msg_union.pkt_filter_entry);

				rbuf->mtype = MSG_SDF_ADD;
				rbuf->dp_id.id = DPN_ID;

				sdf->pcc_rule_id = rule_id_t++;
				sdf->sel_rule_type = sdf_t->rule_type;

				switch (sdf->sel_rule_type) {
				    case RULE_STRING:
						strncpy(sdf->u.rule_str,
						(char *)(&(sdf_t->rule_type) + 5),
						MAX_LEN);
				        break;

				    case FIVE_TUPLE:
				        /*TODO: rule should be in struct five_tuple_rule
				        * This field is currently not used
				        */
				        break;

				    default:
				        clLog(clSystemLog, eCLSeverityCritical, "UNKNOWN Rule Type: %d\n",
						sdf_t->rule_type);
				        break;
				}
#ifdef PRINT_NEW_RULE_ENTRY
				print_sdf_val(sdf);
#endif  /* PRINT_NEW_RULE_ENTRY */
				break;
			}

		case DDN_ACK: {
				rbuf->mtype = MSG_DDN_ACK;
				rbuf->dp_id.id = DPN_ID;

				clLog(clSystemLog, eCLSeverityDebug,"ACK received from FPC..\n");
				break;
			}

		default:
			    clLog(clSystemLog, eCLSeverityCritical, "UNKNOWN Message Type: %d\n", zmqmsgbuf_rx->type);
			    break;

	}

	ret = process_comm_msg((void *)rbuf);
	if (ret < 0)
		zmqmsgbuf_tx.msg_union.dpn_response.cause =
			GTPV2C_CAUSE_SYSTEM_FAILURE;
	else
		zmqmsgbuf_tx.msg_union.dpn_response.cause =
			GTPV2C_CAUSE_REQUEST_ACCEPTED;

	zmqmsgbuf_tx.type = DPN_RESPONSE;
	ret = do_zmq_mbuf_send(&zmqmsgbuf_tx);

	if (ret < 0)
		clLog(clSystemLog, eCLSeverityDebug, "do_zmq_mbuf_send failed for type: %"PRIu8"\n",
				zmqmsgbuf_rx->type);

	return ret;
}

/**
 * @brief  : Closes zmq socket
 * @param  : No param
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
zmq_destroy(void)
{
	/*
	 * zmqsub destroy
	 */
	zmq_subsocket_destroy();
	return 0;
}

#endif /* DP: SDN_ODL_BUILD */
#endif /* !CP_BUILD*/

#define IFACE_FILE "../config/interface.cfg"
#define SET_CONFIG_IP(ip, file, section, entry) \
do {\
	entry = rte_cfgfile_get_entry(file, section, #ip);\
	if (entry == NULL)\
	rte_panic("%s not found in %s", #ip, IFACE_FILE);\
	if (inet_aton(entry, &ip) == 0)\
	rte_panic("Invalid %s in %s", #ip, IFACE_FILE);\
} while (0)
#define SET_CONFIG_PORT(port, file, section, entry) \
do {\
	entry = rte_cfgfile_get_entry(file, section, #port);\
	if (entry == NULL)\
	rte_panic("%s not found in %s", #port, IFACE_FILE);\
	if (sscanf(entry, "%"SCNu16, &port) != 1)\
	rte_panic("Invalid %s in %s", #port, IFACE_FILE);\
} while (0)

/**
 * @brief  : Read interface configuration form config file
 * @param  : No param
 * @return : Returns nothing
 */
static
void read_interface_config(void)
{
		struct rte_cfgfile *file = rte_cfgfile_load(IFACE_FILE, 0);
		const char *file_entry;

		if (file == NULL)
			rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n",
					IFACE_FILE);

#ifndef SDN_ODL_BUILD /* Communication over the UDP */
		SET_CONFIG_IP(dp_comm_ip, file, "0", file_entry);
		SET_CONFIG_PORT(dp_comm_port, file, "0", file_entry);

		SET_CONFIG_IP(cp_comm_ip, file, "0", file_entry);
		SET_CONFIG_PORT(cp_comm_port, file, "0", file_entry);

#else   /* Communication over the ZMQ */

		const char *zmq_proto = "tcp";
		struct in_addr zmq_sub_ip;
		struct in_addr zmq_pub_ip;
		uint16_t zmq_sub_port;
		uint16_t zmq_pub_port;

		SET_CONFIG_IP(fpc_ip, file, "0", file_entry);
		SET_CONFIG_PORT(fpc_port, file, "0", file_entry);
		SET_CONFIG_PORT(fpc_topology_port, file, "0", file_entry);

		SET_CONFIG_IP(cp_nb_ip, file, "0", file_entry);
		SET_CONFIG_PORT(cp_nb_port, file, "0", file_entry);

		SET_CONFIG_IP(zmq_sub_ip, file, "0", file_entry);
		SET_CONFIG_PORT(zmq_sub_port, file, "0", file_entry);

		SET_CONFIG_IP(zmq_pub_ip, file, "0", file_entry);
		SET_CONFIG_PORT(zmq_pub_port, file, "0", file_entry);

		snprintf(zmq_sub_ifconnect, sizeof(zmq_sub_ifconnect),
				"%s://%s:%u", zmq_proto, inet_ntoa(zmq_sub_ip), zmq_sub_port);
		snprintf(zmq_pub_ifconnect, sizeof(zmq_pub_ifconnect),
				"%s://%s:%u", zmq_proto, inet_ntoa(zmq_pub_ip), zmq_pub_port);

#endif

#ifdef SGX_CDR
		app.dealer_in_ip = rte_cfgfile_get_entry(file, "0",
				DEALERIN_IP);
		app.dealer_in_port = rte_cfgfile_get_entry(file, "0",
				DEALERIN_PORT);
		app.dealer_in_mrenclave = rte_cfgfile_get_entry(file, "0",
				DEALERIN_MRENCLAVE);
		app.dealer_in_mrsigner = rte_cfgfile_get_entry(file, "0",
				DEALERIN_MRSIGNER);
		app.dealer_in_isvsvn = rte_cfgfile_get_entry(file, "0",
				DEALERIN_ISVSVN);
		app.dp_cert_path = rte_cfgfile_get_entry(file, "0",
				DP_CERT_PATH);
		app.dp_pkey_path = rte_cfgfile_get_entry(file, "0",
				DP_PKEY_PATH);
#endif /* SGX_CDR */
}


/**
 * @brief Initialize iface message passing
 *
 * This function is not thread safe and should only be called once by DP.
 */
void iface_module_constructor(void)
{
		/* Read and store ip and port for socket communication between cp and
		 * dp*/
		read_interface_config();

#ifdef CP_BUILD
		clLog(clSystemLog, eCLSeverityDebug,"IFACE: CP Initialization\n");
#ifdef SDN_ODL_BUILD
		register_comm_msg_cb(COMM_SOCKET,
				udp_init_cp_socket,
				udp_send_socket,
				NULL,
				NULL);
		set_comm_type(COMM_SOCKET);
#endif  /* SDN_ODL_BUILD  */
#else   /* CP_BUILD */
#ifndef SDN_ODL_BUILD

		clLog(clSystemLog, eCLSeverityMajor, "IFACE: DP Initialization\n");
		create_udp_socket(dp_comm_ip, dp_comm_port, &my_sock);

#else
		/* Code Rel. Jan 30, 2017
		 * Note: PCC, ADC, Session table initial creation on the DP sent over UDP by CP
		 * Needs to be from SDN controller as code & data models evolve
		 * For Jan 30, 2017 release, for flow updates over SDN controller
		 * register ZMQSUB socket after dp_session_table_create.
		 */
		register_comm_msg_cb(COMM_ZMQ,
				zmq_init_socket,
				zmq_send_socket,
				zmq_recv_socket,
				zmq_destroy);
#endif  /* SDN_ODL_BUILD */
#endif  /* !CP_BUILD */
}

void sig_handler(int signo)
{
		if (signo == SIGINT) {
#ifdef SDN_ODL_BUILD
#ifdef CP_BUILD
			close_nb();
#else
			zmq_status_goodbye();
#endif
#endif

#ifdef CP_BUILD
#ifdef GX_BUILD
			if (gx_app_sock > 0)
				close_ipc_channel(gx_app_sock);
#endif /* GX_BUILD */
#ifdef SYNC_STATS
			retrive_stats_entry();
			close_stats();
#endif /* SYNC_STATS */
#endif

#ifdef USE_REST
			gst_deinit();
#endif /* USE_REST */

#ifndef CP_BUILD
			close(route_sock);
#endif
#ifdef TIMER_STATS
#ifdef AUTO_ANALYSIS
			print_perf_statistics();
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */
			rte_exit(EXIT_SUCCESS, "received SIGINT\n");
		}
}

