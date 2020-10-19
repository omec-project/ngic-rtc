/*
 * Copyright (c) 2019 Sprint
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

/**
 * pkt_handler.c: Main processing for uplink and downlink packets.
 * Also process any notification coming from interface core for
 * messages from CP for modifications to an active session.
 * This is done by the worker core in the pipeline.
 */

#include <unistd.h>
#include <locale.h>

#include "gtpu.h"
#include "util.h"
#include "up_acl.h"
#include "up_main.h"
#include "up_ether.h"
#include "pfcp_up_llist.h"
#include "pfcp_up_struct.h"
#include "clogger.h"
#include "pfcp_set_ie.h"
#include "pfcp_up_sess.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"
#include "pfcp_util.h"
#include "../cp_dp_api/tcp_client.h"

#ifdef EXTENDED_CDR
uint64_t s1u_non_gtp_pkts_mask;
#endif

extern pcap_dumper_t *pcap_dumper_east;
extern pcap_dumper_t *pcap_dumper_west;
extern udp_sock_t my_sock;
extern struct rte_ring *li_dl_ring;
extern struct rte_ring *li_ul_ring;

char CDR_FILE_PATH[CDR_BUFF_SIZE];


int
notification_handler(struct rte_mbuf **pkts,
	uint32_t n)
{
	uint16_t tx_cnt = 0;
	unsigned int *ring_entry = NULL;
	struct rte_ring *ring = NULL;
	struct rte_mbuf *buf_pkt = NULL;
	pfcp_session_datat_t *data = NULL;
	pdr_info_t *pdr[MAX_BURST_SZ] = {NULL};
	pfcp_session_datat_t *sess_info[MAX_BURST_SZ] = {NULL};
	uint64_t pkts_mask = 0, pkts_queue_mask = 0, fwd_pkts_mask = 0;
	uint32_t *key = NULL;
	unsigned int ret = 32, num = 32, i;

	pfcp_session_datat_t *sess_data[MAX_BURST_SZ] = {NULL};

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Notification handler resolving the buffer packets, count:%u\n",
		LOG_VALUE, n);

	for (i = 0; i < n; ++i) {
		buf_pkt = pkts[i];
		key = rte_pktmbuf_mtod(buf_pkt, uint32_t *);
		/* TODO: Temp Solution */
		uint8_t find_teid_key = 0;

		/* Check key is not NULL or Zero */
		if (key == NULL) {
			continue;
		}

		/* Add the handling of the session */
		data = get_sess_by_teid_entry(*key, NULL, SESS_MODIFY);
		if (data == NULL) {
			data = get_sess_by_ueip_entry(*key, NULL, SESS_MODIFY);
			if (data == NULL) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Session entry not found for TEID/UE_IP: %u\n",
					LOG_VALUE, *key);
				continue;
			}
		} else {
			/* if SGWU find the key */
			find_teid_key = PRESENT;
		}
		/* Set the packet mask */
		SET_BIT(fwd_pkts_mask, i);

		rte_ctrlmbuf_free(buf_pkt);
		ring = data->dl_ring;
		if (data->sess_state != CONNECTED) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Update the State to CONNECTED\n", LOG_VALUE);
			data->sess_state = CONNECTED;
		}

		if (!ring) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"No DL Ring is found\n", LOG_VALUE);
			continue; /* No dl ring*/
		}

		/* de-queue this ring and send the downlink pkts*/
		while (ret) {
			ret = rte_ring_sc_dequeue_burst(ring,
					(void **)pkts, num, ring_entry);
			pkts_mask = (1 << ret) - 1;

			for (i = 0; i < ret; ++i)
				sess_info[i] = data;

			for (i = 0; i < ret; ++i)
				pdr[i] = sess_info[i]->pdrs;

			if(!find_teid_key) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"SAEGWU: Encap the GTPU Pkts...\n",
						LOG_VALUE);
				/* Encap GTPU header*/
				gtpu_encap(&pdr[0], &sess_info[0], (struct rte_mbuf **)pkts, ret,
						&pkts_mask, &fwd_pkts_mask, &pkts_queue_mask);
			} else {
				/* Get downlink session info */
				dl_sess_info_get((struct rte_mbuf **)pkts, ret, &pkts_mask,
						&sess_data[0],
						&pkts_queue_mask);
			}

			if (pkts_queue_mask != 0)
			    clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Something is wrong, the session still doesnt hv "
			        "enb teid\n", LOG_VALUE);

			if(find_teid_key) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Update the Next Hop eNB ipv4 frame info\n", LOG_VALUE);
				/* Update nexthop L3 header*/
				update_enb_info(pkts, num, &pkts_mask, &fwd_pkts_mask, &sess_data[0], &pdr[0]);
			}

			/* Update nexthop L2 header*/
			update_nexthop_info((struct rte_mbuf **)pkts, num, &pkts_mask,
					app.wb_port, &pdr[0]);


			uint32_t pkt_indx = 0;
#ifdef STATS
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Resolved the Buffer packets Pkts:%u\n", LOG_VALUE, ret);
			epc_app.dl_params[SGI_PORT_ID].pkts_in += ret;
			epc_app.dl_params[SGI_PORT_ID].ddn_buf_pkts -= ret;
#endif /* STATS */


			/* Capture the GTPU packets.*/
			up_pcap_dumper(pcap_dumper_east, pkts, ret);

			while (ret) {
				uint16_t pkt_cnt = PKT_BURST_SZ;

				if (ret < PKT_BURST_SZ)
					pkt_cnt = ret;

				tx_cnt = rte_eth_tx_burst(S1U_PORT_ID,
						0, &pkts[pkt_indx], pkt_cnt);
				ret -= tx_cnt;
				pkt_indx += tx_cnt;
			}
		}

		if (rte_ring_enqueue(dl_ring_container, ring) ==
				ENOBUFS) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Can't put ring back, so free it\n", LOG_VALUE);
			rte_ring_free(ring);
		}
	}

	return 0;
}

int
cdr_cause_code(pfcp_usage_rpt_trig_ie_t *usage_rpt_trig, char *buf) {

	if(usage_rpt_trig->volth == 1) {
		strncpy(buf, VOLUME_LIMIT, CDR_BUFF_SIZE);
		return 0;
	}

	if(usage_rpt_trig->timth == 1) {
		strncpy(buf, TIME_LIMIT, CDR_BUFF_SIZE);
		return 0;
	}

	if(usage_rpt_trig->termr == 1) {
		strncpy(buf, CDR_TERMINATION, CDR_BUFF_SIZE);
		return 0;
	}

	return -1;
}

int
get_seq_no_of_cdr(char *buffer, char *seq_no) {

	int cnt = 0;
	int i = 0;
	if (buffer == NULL)
		return -1;

	for(i=0; i<MAX_SEQ_NO_LEN; i++) {
		if (buffer[i] == ',') {
			seq_no[i] = buffer[i];
			cnt++;
		} else {
			seq_no[i] = buffer[i];
		}

		if(cnt == 2)
			break;
	}

	seq_no[i] = '\0';

	clLog(clSystemLog, eCLSeverityDebug,
			"CDR_SEQ_NO: %s\n", seq_no);
	return 0;
}

int
remove_cdr_entry(uint32_t seq_no, uint64_t up_seid) {

	char buffer[CDR_BUFF_SIZE] = {0};
	char seq_buff[CDR_BUFF_SIZE] = {0};
	char seq_no_of_cdr[CDR_BUFF_SIZE] = {0};

	snprintf(seq_buff, CDR_BUFF_SIZE, "%u,%lx", seq_no, up_seid);
	clLog(clSystemLog, eCLSeverityDebug,
			"Recived seq buff for deletion : %s\n", seq_buff);

	FILE *file = fopen(CDR_FILE_PATH, "r+");
	if(file == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Error while opening file\n");
		return -1;
	}

	FILE *file_1 = fopen(PATH_TEMP, "w");
	if(file_1 == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Error while opening file\n");
		return -1;
	}

	while(fgets(buffer,sizeof(buffer),file)!=NULL) {

		memset(seq_no_of_cdr, 0, sizeof(seq_no_of_cdr));
		get_seq_no_of_cdr(buffer, seq_no_of_cdr);

		if((strncmp(seq_no_of_cdr, seq_buff, strlen(seq_buff))) == 0) {
			clLog(clSystemLog, eCLSeverityDebug,
					"Remove CDR asst with seq_no : %u\n", seq_no);
			continue;
		} else {
			fputs(buffer,file_1);
		}
	}

	fclose(file);
	fclose(file_1);

	if((remove(CDR_FILE_PATH))!=0) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Error while deleting\n");
		return -1;
	}

	rename(PATH_TEMP, CDR_FILE_PATH);

	return 0;
}


int
generate_cdr(cdr_t *dp_cdr, uint64_t up_seid, char *trigg_buff,
									uint32_t seq_no, uint32_t ue_ip_addr, char *CDR_BUFF) {
	struct timeval epoc_start_time;
	struct timeval epoc_end_time;
	struct timeval epoc_data_start_time;
	struct timeval epoc_data_end_time;
	char ue_addr_buff[CDR_BUFF_SIZE] = {0};
	char dp_ip_addr_buff[CDR_BUFF_SIZE] = {0};
	char cp_ip_addr_buff[CDR_BUFF_SIZE] = {0};
	char start_time_buff[CDR_TIME_BUFF] = {0};
	char end_time_buff[CDR_TIME_BUFF] = {0};
	char data_start_time_buff[CDR_TIME_BUFF] = {0};
	char data_end_time_buff[CDR_TIME_BUFF] = {0};
	pfcp_session_t *sess = NULL;
	pfcp_session_datat_t *sessions = NULL;
	uint32_t cp_ip;
	uint32_t dp_ip;

	if (dp_cdr == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				"usage report is NULL\n");
		return -1;
	}

	sess = get_sess_info_entry(up_seid, SESS_MODIFY);
	if(sess == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to Retrieve Session Info\n\n", LOG_VALUE);
		return -1;
	}

	if(sess->sessions == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Sessions not found\n");
		return -1;
	}

	sessions = sess->sessions;

	if ( ue_ip_addr == 0 && sessions->next != NULL) {
		ue_ip_addr = sessions->next->ue_ip_addr;
	}

	if (ue_ip_addr == 0) {
		snprintf(ue_addr_buff, CDR_BUFF_SIZE,"%s","NULL");
	} else {
		ue_ip_addr = ntohl(ue_ip_addr);
		snprintf(ue_addr_buff, CDR_BUFF_SIZE,"%s",
				inet_ntoa(*((struct in_addr *)&(ue_ip_addr))));
	}

	dp_ip = htonl(dp_comm_ip.s_addr);
	snprintf(dp_ip_addr_buff, CDR_BUFF_SIZE,"%s",
			inet_ntoa(*((struct in_addr *)&(dp_ip))));

	cp_ip = htonl(cp_comm_ip.s_addr);
	snprintf(cp_ip_addr_buff, CDR_BUFF_SIZE,"%s",
			inet_ntoa(*((struct in_addr *)&(cp_ip))));

	ntp_to_unix_time(&dp_cdr->start_time, &epoc_start_time);
	snprintf(start_time_buff,CDR_TIME_BUFF, "%lu", epoc_start_time.tv_sec);

	ntp_to_unix_time(&dp_cdr->end_time, &epoc_end_time);
	snprintf(end_time_buff, CDR_TIME_BUFF, "%lu", epoc_end_time.tv_sec);

	ntp_to_unix_time(&dp_cdr->time_of_frst_pckt, &epoc_data_start_time);
	snprintf(data_start_time_buff, CDR_TIME_BUFF, "%lu", epoc_data_start_time.tv_sec);

	ntp_to_unix_time(&dp_cdr->time_of_lst_pckt, &epoc_data_end_time);
	snprintf(data_end_time_buff, CDR_TIME_BUFF, "%lu", epoc_data_end_time.tv_sec);

	snprintf(CDR_BUFF, CDR_BUFF_SIZE,
			"%u,%lx,%lx,""""%"PRIu64",%s,%s,%s,%s,%lu,%lu,%lu,%u,%s,%s,%s,%s\n" ,
			               seq_no,
						   sess->up_seid,
					       sess->cp_seid,
						   sess->imsi,
						   dp_ip_addr_buff,
						   cp_ip_addr_buff,
						   ue_addr_buff,
						   trigg_buff,
						   dp_cdr->uplink_volume,
						   dp_cdr->downlink_volume,
						   dp_cdr->total_volume,
						   dp_cdr->duration_value,
						   start_time_buff,
						   end_time_buff,
						   data_start_time_buff,
						   data_end_time_buff);
	clLog(clSystemLog, eCLSeverityDebug,
			"CDR : %s\n", CDR_BUFF);
	return 0;
}

int
store_cdr_into_file_pfcp_sess_rpt_req(pfcp_usage_rpt_sess_rpt_req_ie_t *usage_report,
										uint64_t  up_seid, uint32_t trig,
													uint32_t seq_no) {

	FILE *file = NULL;
	char CDR_BUFF[CDR_BUFF_SIZE] = {0};
	char TRIGG_BUFF[CDR_BUFF_SIZE] = {0};
	cdr_t dp_cdr = {0};

	file = fopen(CDR_FILE_PATH, "r");
	if(file == NULL) {
		file = fopen(CDR_FILE_PATH, "w");
		if(file == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					"Error while creating file CDR.csv\n");
			return -1;
		}
		fputs(CDR_HEADER, file);
		clLog(clSystemLog, eCLSeverityDebug,
				"Adding header in file CDR.csv\n");
	}
	fclose(file);

	file = fopen(CDR_FILE_PATH, "a");
	if(file == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Failed to create/open CDR.csv file\n");
		return -1;
	}

	dp_cdr.uplink_volume = usage_report->vol_meas.uplink_volume;
	dp_cdr.downlink_volume = usage_report->vol_meas.downlink_volume;
	dp_cdr.total_volume = usage_report->vol_meas.total_volume;

	dp_cdr.duration_value = usage_report->dur_meas.duration_value;

	dp_cdr.start_time = usage_report->start_time.start_time;
	dp_cdr.end_time = usage_report->end_time.end_time;
	dp_cdr.time_of_frst_pckt = usage_report->time_of_frst_pckt.time_of_frst_pckt;
	dp_cdr.time_of_lst_pckt = usage_report->time_of_lst_pckt.time_of_lst_pckt;
	cdr_cause_code(&usage_report->usage_rpt_trig, TRIGG_BUFF);

	generate_cdr(&dp_cdr, up_seid, TRIGG_BUFF, seq_no, 0, CDR_BUFF);

	fputs(CDR_BUFF, file);

	fclose(file);

	return 0;
}

int
store_cdr_for_restoration(pfcp_usage_rpt_sess_del_rsp_ie_t *usage_report,
								uint64_t  up_seid, uint32_t trig,
								uint32_t seq_no, uint32_t ue_ip_addr) {

	FILE *file = NULL;
	char CDR_BUFF[CDR_BUFF_SIZE] = {0};
	char TRIGG_BUFF[CDR_BUFF_SIZE] = {0};
	cdr_t dp_cdr = {0};

	file = fopen(CDR_FILE_PATH, "r");
	if(file == NULL) {
		file = fopen(CDR_FILE_PATH, "w");
		if(file == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					"Error while creating file CDR.csv\n");
			return -1;
		}
		fputs(CDR_HEADER, file);
		clLog(clSystemLog, eCLSeverityDebug,
				"Adding header in file CDR.csv\n");
	}
	fclose(file);

	file = fopen(CDR_FILE_PATH, "a");
	if(file == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Failed to create/open CDR.csv file\n");
		return -1;
	}

	dp_cdr.uplink_volume = usage_report->vol_meas.uplink_volume;
	dp_cdr.downlink_volume = usage_report->vol_meas.downlink_volume;
	dp_cdr.total_volume = usage_report->vol_meas.total_volume;

	dp_cdr.duration_value = usage_report->dur_meas.duration_value;

	dp_cdr.start_time = usage_report->start_time.start_time;
	dp_cdr.end_time = usage_report->end_time.end_time;
	dp_cdr.time_of_frst_pckt = usage_report->time_of_frst_pckt.time_of_frst_pckt;
	dp_cdr.time_of_lst_pckt = usage_report->time_of_lst_pckt.time_of_lst_pckt;
	cdr_cause_code(&usage_report->usage_rpt_trig, TRIGG_BUFF);

	generate_cdr(&dp_cdr, up_seid, TRIGG_BUFF, seq_no, ue_ip_addr, CDR_BUFF);

	fputs(CDR_BUFF, file);

	fclose(file);

	return 0;
}

int send_usage_report_req(urr_info_t *urr, uint64_t cp_seid, uint64_t up_seid, uint32_t trig){

	int encoded = 0;
	static uint32_t seq = 1;
	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	pfcp_sess_rpt_req_t pfcp_sess_rep_req = {0};
	memset(pfcp_msg, 0, sizeof(pfcp_msg));

	/* Fill the Sequence number in PFCP header */
	seq = get_pfcp_sequence_number(PFCP_SESSION_REPORT_REQUEST, seq);

	/* Set the Sequence number flag in header */
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_rep_req.header),
		PFCP_SESSION_REPORT_REQUEST, HAS_SEID, seq, NO_CP_MODE_REQUIRED);

	/* Fill the CP Seid into header */
	pfcp_sess_rep_req.header.seid_seqno.has_seid.seid = cp_seid;

	/* Setting Report Types in the PKT */
	set_sess_report_type(&pfcp_sess_rep_req.report_type);
	pfcp_sess_rep_req.report_type.dldr = 0;
	pfcp_sess_rep_req.report_type.usar = 1;


	/* Fill the Session Usage report info into Report Request message */
	fill_sess_rep_req_usage_report(
			&pfcp_sess_rep_req.usage_report[pfcp_sess_rep_req.usage_report_count],
			urr, trig);

	store_cdr_into_file_pfcp_sess_rpt_req(&pfcp_sess_rep_req.usage_report[pfcp_sess_rep_req.usage_report_count++],
							up_seid, trig, seq);

	/* Encode the PFCP Session Report Request */
	encoded = encode_pfcp_sess_rpt_req_t(&pfcp_sess_rep_req, pfcp_msg);
	pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
	pfcp_hdr->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"sending PFCP_SESSION_REPORT_REQUEST [%d] from dp\n",
		LOG_VALUE, pfcp_hdr->message_type);
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"length[%d]\n", LOG_VALUE, htons(pfcp_hdr->message_len));

	/* Send the PFCP Session Report Request to CP*/
	if (encoded != 0) {
		if(pfcp_send(my_sock.sock_fd,
					(char *)pfcp_msg, encoded, &dest_addr_t, SENT) < 0) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Error Sending in PFCP Session Report Request: %i\n",
				LOG_VALUE, errno);
		}
	}

	/* retrive the session Info */
	pfcp_session_t *sess = NULL;
	sess = get_sess_info_entry(up_seid, SESS_MODIFY);
	if(sess == NULL) {
               clLog(clSystemLog, eCLSeverityCritical,
			   	LOG_FORMAT"Failed to Retrieve Session Info\n\n", LOG_VALUE);
    }

    process_event_li(sess, NULL, 0, pfcp_msg, encoded,
                     dest_addr_t.sin_addr.s_addr, dest_addr_t.sin_port);
	return 0;
}

/**
 * @brief  : Update the Usage Report structre as per data recived
 * @param  : pkts, pkts recived
 * @param  : n, no of pkts recived
 * @param  : pkts_mask, packet  mask
 * @param  : pdr, structure for pdr info for pkts
 * @return : Returns 0 for succes and -1 failure
 */
static
int update_usage(struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask,
										pdr_info_t **pdr, uint16_t flow)
{
	for(int i = 0; i < n; i++){
		if (ISSET_BIT(*pkts_mask, i)) {
			/* Get the linked URRs from the PDR */
			if(pdr[i] != NULL) {
				if(pdr[i]->urr_count){
					/* Check the Flow Direction */
					if(flow == DOWNLINK){
						if(!pdr[i]->urr->first_pkt_time)
							pdr[i]->urr->first_pkt_time = current_ntp_timestamp();

						/* Get System Current TimeStamp */
						pdr[i]->urr->last_pkt_time = current_ntp_timestamp();
						/* Retrive the data from the packet */
						pdr[i]->urr->dwnlnk_data += rte_pktmbuf_data_len(pkts[i]);

						if((pdr[i]->urr->rept_trigg == VOL_TIME_BASED
									|| pdr[i]->urr->rept_trigg == VOL_BASED) &&
								(pdr[i]->urr->dwnlnk_data >= pdr[i]->urr->vol_thes_dwnlnk)) {
							clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"Downlink Volume threshol reached\n", LOG_VALUE);
							/* Send Session Usage Report for Downlink*/
							send_usage_report_req(pdr[i]->urr, pdr[i]->session->cp_seid,
								pdr[i]->session->up_seid,VOL_BASED);
							/* Reset the DL data */
							pdr[i]->urr->dwnlnk_data = 0;
						}
					}else if(flow == UPLINK){
						/* Retrive the data from the packet */
						pdr[i]->urr->uplnk_data += rte_pktmbuf_data_len(pkts[i]);
						if(!pdr[i]->urr->first_pkt_time)
							pdr[i]->urr->first_pkt_time = current_ntp_timestamp();

						/* Get System Current TimeStamp */
						pdr[i]->urr->last_pkt_time = current_ntp_timestamp();
						if((pdr[i]->urr->rept_trigg == VOL_TIME_BASED ||
									pdr[i]->urr->rept_trigg == VOL_BASED) &&
								(pdr[i]->urr->uplnk_data >= pdr[i]->urr->vol_thes_uplnk)) {
							clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"Ulink Volume threshol reached\n", LOG_VALUE);
							/* Send Session Usage Report for Uplink*/
							send_usage_report_req(pdr[i]->urr, pdr[i]->session->cp_seid,
								pdr[i]->session->up_seid, VOL_BASED);
							/* Reset the UL data */
							pdr[i]->urr->uplnk_data = 0;
						}
					}
				}
			}
		}
	}
	return 0;
}

/**
 * @Brief  : Function to fill pdrs from sess data
 * @param  : n, number of packets
 * @param  : sess_data, session data
 * @param  : pdr, packet detection rule
 * @param  : pkts_mask
 * @return : Returns nothing
 */
static void
get_pdr_from_sess_data(uint32_t n, pfcp_session_datat_t **sess_data,
		pdr_info_t **pdr, uint64_t *pkts_mask, uint64_t *pkts_queue_mask)
{

	uint32_t i;

	for (i = 0; i < n; i++) {
		if ((ISSET_BIT(*pkts_mask, i)) || (ISSET_BIT(*pkts_queue_mask, i))) {
			/* Fill the PDR info form the session data */
			if (sess_data[i] != NULL) {
				if (sess_data[i]->pdrs == NULL) {
					/* PDR is NULL, Reset the pkts mask */
					RESET_BIT(*pkts_mask, i);
					continue;
				}
				pdr[i] = sess_data[i]->pdrs;
			}
		}
	}
}

/**
 * @Brief  : Function to calculate gtpu header length
 * @param  : pkts, rte_mbuf packet
 * @return : Returns length of gtpu header length
 */
static uint8_t
calc_gtpu_len(struct rte_mbuf *pkts)
{
	uint8_t gtpu_len = 0;
	uint8_t *pkt_ptr = NULL;

	if (1 == app.gtpu_seqnb_in) {
		gtpu_len = GPDU_HDR_SIZE_WITH_SEQNB;
	} else if (2 == app.gtpu_seqnb_in) {
		gtpu_len = GPDU_HDR_SIZE_WITHOUT_SEQNB;
	} else {
		pkt_ptr = (uint8_t *) get_mtogtpu(pkts);
		gtpu_len = GPDU_HDR_SIZE_DYNAMIC(*pkt_ptr);
	}

	return gtpu_len;
}

/**
 * @Brief  : Function to fillup ethernet information
 * @param  : intfc, interface name
 * @param  : dir, packet direction
 * @param  : *src, source
 * @param  : *dst, destination
 * @return : Returns nothing
 */
static void
fill_ether_info(uint8_t intfc, uint8_t dir, int32_t *src, int32_t *dst) {
	*src = -1;
	*dst = -1;

	if (WEST_INTFC == intfc) {
		if (UPLINK_DIRECTION == dir) {
			*dst = app.wb_port;
		} else {
			*src = app.wb_port;
		}
	} else if (EAST_INTFC == intfc) {
		if (UPLINK_DIRECTION == dir) {
			*src = app.eb_port;
		} else {
			*dst = app.eb_port;
		}
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"intfc(%u) dir(%u) src(%d) dst(%d)\n", LOG_VALUE,
			intfc, dir, *src, *dst);

	return;
}

/**
 * @Brief  : Function to update sgi pkts for LI as per LI configuration
 * @param  : pkts, mbuf packets
 * @param  : li_data, li_data_t structure
 * @param  : content, packet content
 * @return : Returns nothing
 */
static void
update_li_sgi_pkts(struct rte_mbuf *pkts, li_data_t *li_data, uint8_t content)
{
	uint8_t *tmp_pkt = NULL;
	uint8_t *tmp_buf = NULL;
	struct udp_hdr *udp_ptr = NULL;
	struct ipv4_hdr *ipv4_ptr = NULL;

	switch (content) {
	case COPY_HEADER_ONLY:

		tmp_pkt = rte_pktmbuf_mtod(pkts, uint8_t *);
		li_data->size = rte_pktmbuf_data_len(pkts);

		/* copy data packet in temporary buffer */
		tmp_buf = rte_malloc(NULL, li_data->size, 0);
		if (NULL == tmp_buf) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR: Memory"
				" allocation for pkts failed", LOG_VALUE);
			return;
		}

		memcpy(tmp_buf, tmp_pkt, li_data->size);

		/* Update length in udp packet */
		udp_ptr = (struct udp_hdr *)
			&tmp_buf[ETH_HDR_SIZE + IPv4_HDR_SIZE];
		udp_ptr->dgram_len = htons(UDP_HDR_SIZE);

		/* Update length in ipv4 packet */
		ipv4_ptr = (struct ipv4_hdr *)
			&tmp_buf[ETH_HDR_SIZE];
		ipv4_ptr->total_length = htons(IPv4_HDR_SIZE + UDP_HDR_SIZE);

		/* set length of packet */
		li_data->size = ETH_HDR_SIZE + IPv4_HDR_SIZE + UDP_HDR_SIZE;

		/* copy only header in li packet not modify original packet */
		li_data->pkts = rte_malloc(NULL, (li_data->size + sizeof(li_header_t)), 0);
		if (NULL == li_data->pkts) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR: Memory"
				" allocation for pkts failed", LOG_VALUE);
			rte_free(tmp_buf);
			tmp_buf = NULL;
			return;
		}

		memcpy(li_data->pkts, tmp_buf, li_data->size);

		/* free temporary allocated buffer */
		rte_free(tmp_buf);
		tmp_buf = NULL;

		break;

	case COPY_HEADER_DATA_ONLY:
	case COPY_DATA_ONLY:

		/* copy entire packet and set size */
		li_data->size = rte_pktmbuf_data_len(pkts);
		tmp_pkt = rte_pktmbuf_mtod(pkts, uint8_t *);
		li_data->pkts = rte_malloc(NULL, (li_data->size + sizeof(li_header_t)), 0);
		if (NULL == li_data->pkts) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR: Memory"
				" allocation for pkts failed", LOG_VALUE);
			return;
		}

		memcpy(li_data->pkts, tmp_pkt, li_data->size);

		break;
	}

	return;
}

/**
 * @Brief  : Function to update pkts for LI as per LI configurations
 * @param  : pkts, mbuf packets
 * @param  : li_data, li_data_t structure
 * @param  : intfc, interface name
 * @param  : dir, packet direction
 * @param  : content, packet content
 * @return : Returns nothing
 */
static void
update_li_pkts(struct rte_mbuf *pkts, li_data_t *li_data, uint8_t intfc,
	uint8_t dir, uint8_t content)
{
	uint32_t i = 0;
	size_t len = 0;
	uint32_t cntr = 0;
	uint8_t gtpu_len = 0;
	int32_t src_ether = -1;
	int32_t dst_ether = -1;
	uint8_t *tmp_pkt = NULL;
	uint8_t *tmp_buf = NULL;
	struct udp_hdr *udp_ptr = NULL;
	struct ipv4_hdr *ipv4_ptr = NULL;
	struct ether_hdr *eth_ptr = NULL;

	switch (content) {
	case COPY_HEADER_ONLY:

		tmp_pkt = rte_pktmbuf_mtod(pkts, uint8_t *);
		li_data->size = rte_pktmbuf_data_len(pkts);

		/* copy data packet in temporary buffer */
		tmp_buf = rte_malloc(NULL, li_data->size, 0);
		if (NULL == tmp_buf) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR: Memory"
				" allocation for pkts failed", LOG_VALUE);
			return;
		}

		memcpy(tmp_buf, tmp_pkt, li_data->size);

		/* set gtpu length as per configuration */
		gtpu_len = calc_gtpu_len(pkts);

		/* Update length in udp packet */
		udp_ptr = (struct udp_hdr *)
			&tmp_buf[ETH_HDR_SIZE + IPv4_HDR_SIZE];
		udp_ptr->dgram_len = htons(UDP_HDR_SIZE + gtpu_len);

		/* Update length in ipv4 packet */
		ipv4_ptr = (struct ipv4_hdr *)
			&tmp_buf[ETH_HDR_SIZE];
		ipv4_ptr->total_length = htons(IPv4_HDR_SIZE + UDP_HDR_SIZE +
			gtpu_len);

		/* set length of packet */
		len = ETH_HDR_SIZE + IPv4_HDR_SIZE + UDP_HDR_SIZE +
			gtpu_len;
		li_data->size = len;

		/* copy only header in li packet not modify original packet */
		li_data->pkts = rte_malloc(NULL, (len + sizeof(li_header_t)), 0);
		if (NULL == li_data->pkts) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR: Memory"
				" allocation for pkts failed", LOG_VALUE);
			rte_free(tmp_buf);
			tmp_buf = NULL;
			return;
		}

		memcpy(li_data->pkts, tmp_buf, len);

		/* free temporary allocated buffer */
		rte_free(tmp_buf);
		tmp_buf = NULL;

		break;

	case COPY_HEADER_DATA_ONLY:

		/* copy entire packet and set size */
		li_data->size = rte_pktmbuf_data_len(pkts);
		tmp_pkt = rte_pktmbuf_mtod(pkts, uint8_t *);
		li_data->pkts = rte_malloc(NULL, (li_data->size + sizeof(li_header_t)), 0);
		if (NULL == li_data->pkts) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR: Memory"
				" allocation for pkts failed", LOG_VALUE);
			return;
		}

		memcpy(li_data->pkts, tmp_pkt, li_data->size);

		break;

	case COPY_DATA_ONLY:

		tmp_pkt = rte_pktmbuf_mtod(pkts, uint8_t *);
		li_data->size = rte_pktmbuf_data_len(pkts);

		/* copy data packet in temporary buffer */
		tmp_buf = rte_malloc(NULL, li_data->size, 0);
		if (NULL == tmp_buf) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR: Memory"
				" allocation for pkts failed", LOG_VALUE);
			return;
		}

		memcpy(tmp_buf, tmp_pkt, li_data->size);

		/* set gtpu length as per configuration */
		gtpu_len = calc_gtpu_len(pkts);

		/*
		 * set len parameter that much bytes we are going to remove
		 * from start of buffer which is gtpu header
		 */
		len = gtpu_len + UDP_HDR_SIZE + IPv4_HDR_SIZE;

		/* allocate memory for li packet */
		li_data->pkts = rte_malloc(NULL, ((li_data->size - len) + sizeof(li_header_t)), 0);
		if (NULL == li_data->pkts) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR: Memory"
				" allocation for pkts failed", LOG_VALUE);
			rte_free(tmp_buf);
			tmp_buf = NULL;
			return;
		}

		/* copy data to li packet without gtpu header */
		for (cntr = len; cntr < li_data->size; ++cntr) {
			li_data->pkts[i++] = tmp_buf[cntr];
		}

		/* update li data size */
		li_data->size -= len;

		/* Update ether header with available mac address */
		eth_ptr = (struct ether_hdr *)&li_data->pkts[0];

		memset(eth_ptr, 0, sizeof(struct ether_hdr));
		eth_ptr->ether_type = htons(ETH_TYPE_IPv4);

		fill_ether_info(intfc, dir, &src_ether, &dst_ether);

		if (-1 != src_ether) {
			ether_addr_copy(&ports_eth_addr[src_ether],
				&eth_ptr->s_addr);
		}

		if (-1 != dst_ether) {
			ether_addr_copy(&ports_eth_addr[dst_ether],
				&eth_ptr->d_addr);
		}

		/* free temporary allocated buffer */
		rte_free(tmp_buf);
		tmp_buf = NULL;

		break;
	}

	return;
}

/**
 * @Brief  : Function to enqueue pkts for LI if required
 * @param  : n, no of packets
 * @param  : pkts, mbuf packets
 * @param  : PDR, pointer to pdr session info
 * @param  : intfc, interface name
 * @param  : pkts_mask, SGI interface pkt mask
 * @return : Returns nothing
 */
static void
enqueue_li_pkts(uint32_t n, struct rte_mbuf **pkts, pdr_info_t **pdr,
	uint8_t intfc, uint8_t direction, uint64_t *pkts_mask, uint8_t mask_type)
{
	uint32_t i = 0;
	uint8_t docopy = NOT_PRESENT;

	for(i = 0; i < n; i++) {
		if(pkts[i] != NULL && pdr[i] != NULL &&
				pdr[i]->far->li_config_cnt > 0) {

			far_info_t *far = pdr[i]->far;

			for (uint8_t cnt = 0; cnt < far->li_config_cnt; cnt++) {

				li_data_t *li_data = NULL;

				docopy = NOT_PRESENT;
				li_data = rte_malloc(NULL, sizeof(li_data_t), 0);
				li_data->imsi = far->session->pdrs->session->imsi;
				li_data->id = far->li_config[cnt].id;
				li_data->forward = far->li_config[cnt].forward;

				switch (intfc) {

				case WEST_INTFC:

					if ((COPY_UP_DOWN_PKTS == far->li_config[cnt].west_direction) ||
						((COPY_DOWN_PKTS == far->li_config[cnt].west_direction) &&
						(DOWNLINK_DIRECTION == direction)) ||
						((COPY_UP_PKTS == far->li_config[cnt].west_direction) &&
						(UPLINK_DIRECTION == direction))) {

						docopy = PRESENT;
						/* TODO: Filter gateway allow packets */
						/* Currently no need to handle below condition for mask_type*/
						if (ISSET_BIT(*pkts_mask, i)) {
							update_li_pkts(pkts[i], li_data, intfc, direction,
								far->li_config[cnt].west_content);
						}
					}

					break;

				case EAST_INTFC:

					if ((COPY_UP_DOWN_PKTS == far->li_config[cnt].east_direction) ||
						((COPY_DOWN_PKTS == far->li_config[cnt].east_direction) &&
						(DOWNLINK_DIRECTION == direction)) ||
						((COPY_UP_PKTS == far->li_config[cnt].east_direction) &&
						(UPLINK_DIRECTION == direction))) {

						docopy = PRESENT;

						if (ISSET_BIT(*pkts_mask, i) && ((ENCAP_MASK == mask_type) ||
								(DECAP_MASK == mask_type))) {
							update_li_sgi_pkts(pkts[i], li_data,
								far->li_config[cnt].east_content);
						}

						if (ISSET_BIT(*pkts_mask, i) && (FWD_MASK == mask_type)) {
							update_li_pkts(pkts[i], li_data, intfc, direction,
								far->li_config[cnt].east_content);
						}
					}

					break;

				default:
					docopy = NOT_PRESENT;
					break;
				}

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"id(%lu)"
					" intfc(%u) direction(%u) copy(%u) west direction(%u)"
					" west content(%u) east direction(%u) east content(%u)"
					" forward(%u)\n", LOG_VALUE,
					far->li_config[cnt].id, intfc, direction, docopy,
					far->li_config[cnt].west_direction,
					far->li_config[cnt].west_content,
					far->li_config[cnt].east_direction,
					far->li_config[cnt].east_content,
					far->li_config[cnt].forward);

				if (PRESENT == docopy) {
					if (DOWNLINK_DIRECTION == direction) {
						if (rte_ring_enqueue(li_dl_ring,
								(void *)li_data) == -ENOBUFS) {
							clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"%::Can't queue DL LI pkt- ring"
								" full...", LOG_VALUE);
						}
					} else if (UPLINK_DIRECTION == direction) {
						if (rte_ring_enqueue(li_ul_ring,
								(void *)li_data) == -ENOBUFS) {
							clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"::Can't queue UL LI pkt- ring"
								" full...", LOG_VALUE);
						}
					}
				}
			}
		}
	}
}

/**
 * @brief  : Fill pdr details
 * @param  : n, no of pdrs
 * @param  : sess_data, session information
 * @param  : pdr, structure to ne filled
 * @param  : pkts_queue_mask, packet queue mask
 * @return : Returns nothing
 */
static void
fill_pdr_info(uint32_t n, pfcp_session_datat_t **sess_data,
				pdr_info_t **pdr, uint64_t *pkts_queue_mask)
{
	uint32_t itr = 0;

	for (itr = 0; itr < n; itr++) {
		if (ISSET_BIT(*pkts_queue_mask, itr)) {
			/* Fill the PDR info form the session data */
			pdr[itr] = sess_data[itr]->pdrs;
		}
	}

	return;
}

/**
 * @brief  : Get pdr details
 * @param  : sess_data, session information
 * @param  : pdr, structure to ne filled
 * @param  : precedence, variable to precedence value
 * @param  : n, no of pdrs
 * @param  : pkts_mask, packet mask
 * @param  : fd_pkts_mask, packet mask
 * @param  : pkts_queue_mask, packet queue mask
 * @return : Returns nothing
 */
static void
get_pdr_info(pfcp_session_datat_t **sess_data, pdr_info_t **pdr,
		uint32_t **precedence, uint32_t n, uint64_t *pkts_mask,
		uint64_t *fd_pkts_mask, uint64_t *pkts_queue_mask)
{
	uint32_t j = 0;

	for (j = 0; j < n; j++) {
		if (((ISSET_BIT(*pkts_mask, j) && (ISSET_BIT(*fd_pkts_mask, j)))
					&& precedence[j] != NULL)) {
			pdr[j] = get_pdr_node(sess_data[j]->pdrs, *precedence[j]);

			/* Need to check this condition */
			if (pdr[j] == NULL) {
				RESET_BIT(*pkts_mask, j);
				//RESET_BIT(*pkts_queue_mask, j);
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT": PDR LKUP Linked List FAIL for Precedence "
					":%u\n", LOG_VALUE, *precedence[j]);
			} else {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"PDR LKUP: PDR ID: %u, FAR_ID: %u\n", LOG_VALUE,
					pdr[j]->rule_id, (pdr[j]->far)->far_id_value);
			}
		} else if (ISSET_BIT(*fd_pkts_mask, j)) {
			RESET_BIT(*pkts_mask, j);
		}
	}

	return;
}

/**
 * @brief  : Acl table lookup for sdf rule
 * @param  : pkts, mbuf packets
 * @param  : n, no of packets
 * @param  : pkts_mask, packet mask
 * @param  : fd_pkts_mask, packet mask
 * @param  : sess_data, session information
 * @param  : prcdnc, precedence value
 * @return : Returns nothing
 */
static void
acl_sdf_lookup(struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask,
			uint64_t *fd_pkts_mask, pfcp_session_datat_t **sess_data,
			uint32_t **prcdnc)
{
	uint32_t j = 0;
	uint32_t tmp_prcdnc = 0;


	for (j = 0; j < n; j++) {
		if ((ISSET_BIT(*pkts_mask, j)) && (ISSET_BIT(*fd_pkts_mask, j))) {
			if (!sess_data[j]->acl_table_indx) {
				RESET_BIT(*pkts_mask, j);
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Not Found any ACL_Table or SDF Rule for the UL\n", LOG_VALUE);
				continue;
			}
			tmp_prcdnc = 0;
			int index = 0;
			for(uint16_t itr = 0; itr < sess_data[j]->acl_table_count; itr++){
				if(sess_data[j]->acl_table_indx[itr] != 0){
					 prcdnc[j] = sdf_lookup(pkts, j,
											sess_data[j]->acl_table_indx[itr]);
				}
				if(tmp_prcdnc == 0 || (*prcdnc[j] != 0 && *prcdnc[j] < tmp_prcdnc)){
					tmp_prcdnc = *prcdnc[j];
					index = itr;
				}else{
					*prcdnc[j] = tmp_prcdnc;
				}
			}
			if(prcdnc[j] != NULL)
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"ACL SDF LKUP TABLE Index:%u, prcdnc:%u\n",
						LOG_VALUE, sess_data[j]->acl_table_indx[index], *prcdnc[j]);
		}
	}
	return;
}

void
filter_ul_traffic(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index, uint64_t *pkts_mask, uint64_t *decap_pkts_mask, pdr_info_t **pdr,
		pfcp_session_datat_t **sess_data)
{
	uint64_t pkts_queue_mask = 0;
	uint32_t *precedence[MAX_BURST_SZ] = {NULL};

	/* ACL Lookup, Filter the Uplink Traffic based on 5 tuple rule */
	acl_sdf_lookup(pkts, n, pkts_mask, decap_pkts_mask, &sess_data[0], &precedence[0]);

	/* Selection of the PDR from Session Data object based on precedence */
	get_pdr_info(&sess_data[0], &pdr[0], &precedence[0], n, pkts_mask, decap_pkts_mask,
			&pkts_queue_mask);

	/* Filter UL and DL traffic based on QER Gating */
	qer_gating(&pdr[0], n, pkts_mask, decap_pkts_mask, &pkts_queue_mask, UPLINK);

	return;
}

int
wb_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index)
{
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"In WB_Pkt_Handler\n", LOG_VALUE);
	uint64_t fwd_pkts_mask = 0;
	uint64_t pkts_queue_mask = 0;
	uint64_t decap_pkts_mask = 0;
	pdr_info_t *pdr[MAX_BURST_SZ] = {NULL};
	pdr_info_t *pdr_li[MAX_BURST_SZ] = {NULL};
	pfcp_session_datat_t *sess_data[MAX_BURST_SZ] = {NULL};

	uint64_t pkts_mask;
	pkts_mask = (~0LLU) >> (64 - n);

	/* Get the Session Data Information */
	ul_sess_info_get(pkts, n, &pkts_mask, &sess_data[0]);

	/* Burst pkt handling */
	/* Filter the Forward pkts and decasulation pkts */
	if (sess_data[0] != NULL) {
		for (uint32_t inx = 0; inx < n; inx++) {
			if (ISSET_BIT(pkts_mask, inx)) {
				if (sess_data[inx] != NULL) {
					/* SGWU: Outer Header Removal based on the configured in PDR */
					if (sess_data[inx]->hdr_rvl == NOT_SET_OUT_HDR_RVL_CRT) {
						/* Set the Foward Pkt Mask */
						SET_BIT(fwd_pkts_mask, inx);
					} else if (sess_data[inx]->hdr_rvl == GTPU_UDP_IPv4) {
						/* Set the Decasulation Pkt Mask */
						SET_BIT(decap_pkts_mask, inx);
					}
				}
			}
		}

		if (fwd_pkts_mask) {
			/* get pdr from sess data */
			get_pdr_from_sess_data(n, &sess_data[0], &pdr_li[0], &fwd_pkts_mask,
					&pkts_queue_mask);

			/* Send Session Usage Report */
			update_usage(pkts, n, &fwd_pkts_mask, pdr_li, UPLINK);

			/* enqueue west interface uplink pkts for user level packet copying */
			enqueue_li_pkts(n, pkts, pdr_li, WEST_INTFC, UPLINK_DIRECTION, &fwd_pkts_mask, FWD_MASK);

			/* Update nexthop L3 header*/
			update_nexts5s8_info(pkts, n, &pkts_mask, &fwd_pkts_mask,
					&sess_data[0], &pdr[0]);
		}

		if (decap_pkts_mask) {
			/* PGWU/SAEGWU */
			/* Get the PDR entry for LI pkts */
			get_pdr_from_sess_data(n, &sess_data[0], &pdr_li[0], &decap_pkts_mask, NULL);

			/* Send Session Usage Report */
			update_usage(pkts, n, &decap_pkts_mask, pdr_li, UPLINK);

			/* enqueue west interface uplink pkts for user level packet copying */
			enqueue_li_pkts(n, pkts, pdr_li, WEST_INTFC, UPLINK_DIRECTION, &decap_pkts_mask, DECAP_MASK);

			/* Decap GTPU and update meta data*/
			gtpu_decap(pkts, n, &pkts_mask, &decap_pkts_mask);

			/*Apply sdf filters on uplink traffic*/
			filter_ul_traffic(p, pkts, n, wk_index, &pkts_mask, &decap_pkts_mask,
					&pdr[0], &sess_data[0]);

		}
	}

	/* If Outer Header Removal Not Set in the PDR, that means forward packets */
	/* Set next hop IP to S5/S8/ DL port*/
	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, app.eb_port, &pdr[0]);

	/* up pcap dumper */
	up_pcap_dumper(pcap_dumper_west, pkts, n);

	if (decap_pkts_mask) {
		/* enqueue west interface uplink pkts for user level packet copying */
		enqueue_li_pkts(n, pkts, pdr, EAST_INTFC, UPLINK_DIRECTION, &decap_pkts_mask, DECAP_MASK);
	}

	if (fwd_pkts_mask) {
		/* enqueue west interface uplink pkts for user level packet copying */
		enqueue_li_pkts(n, pkts, pdr, EAST_INTFC, UPLINK_DIRECTION, &fwd_pkts_mask, FWD_MASK);
	}

	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Out WB_Pkt_Handler\n", LOG_VALUE);

	return 0;
}

/**
 * @brief  : Filter downlink traffic
 * @param  : p, rte pipeline data
 * @param  : pkts, mbuf packets
 * @param  : n, no of packets
 * @param  : wk_index
 * @param  : sess_data, session information
 * @param  : pdr, structure to store pdr info
 * @return : Returns packet mask value
 */
static void
filter_dl_traffic(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index, uint64_t *pkts_mask, uint64_t *fd_pkts_mask,
		pfcp_session_datat_t **sess_data, pdr_info_t **pdr)
{
	uint32_t *precedence[MAX_BURST_SZ] = {NULL};
	uint64_t pkts_queue_mask = 0;

	/* ACL Lookup, Filter the Downlink Traffic based on 5 tuple rule */
	acl_sdf_lookup(pkts, n, pkts_mask, fd_pkts_mask, &sess_data[0], &precedence[0]);

	/* Selection of the PDR from Session Data object based on precedence */
	get_pdr_info(&sess_data[0], &pdr[0], &precedence[0], n, pkts_mask, fd_pkts_mask,
			&pkts_queue_mask);

	/* Filter DL traffic based on QER Gating */
	qer_gating(&pdr[0], n, pkts_mask, fd_pkts_mask, &pkts_queue_mask, DOWNLINK);

#ifdef HYPERSCAN_DPI
	/* Send cloned dns pkts to dns handler*/
	clone_dns_pkts(pkts, n, pkts_mask);
#endif /* HYPERSCAN_DPI */

	return;
}

/**
 * Process Downlink traffic: sdf and adc filter, metering, charging and encap gtpu.
 * Update adc hash if dns reply is found with ip addresses.
 */
int
eb_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index)
{
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"In EB_Pkt_Handler\n", LOG_VALUE);
	uint64_t pkts_mask = 0;
	uint64_t pkts_queue_mask = 0;
	uint64_t fwd_pkts_mask = 0;
	uint64_t encap_pkts_mask = 0;
	pdr_info_t *pdr[MAX_BURST_SZ] = {NULL};
	pfcp_session_datat_t *sess_data[MAX_BURST_SZ] = {NULL};

	pkts_mask = (~0LLU) >> (64 - n);

	/* Get the Session Data Information */
	dl_sess_info_get(pkts, n, &pkts_mask, &sess_data[0], &pkts_queue_mask);

	/* Burst pkt handling */
	/* Filter the Forward pkts and decasulation pkts */
	if (sess_data[0] != NULL) {
		for (uint32_t inx = 0; inx < n; inx++) {
			if ((ISSET_BIT(pkts_mask, inx)) || (ISSET_BIT(pkts_queue_mask, inx))) {
				if (sess_data[inx] != NULL) {
					/* SGWU: Outer Header Creation based on the configured in PDR */
					if ((sess_data[inx]->hdr_rvl == NOT_SET_OUT_HDR_RVL_CRT)
							&& (!sess_data[inx]->ue_ip_addr)){
						/* Set the Foward Pkt Mask */
						SET_BIT(fwd_pkts_mask, inx);
					} else if (((sess_data[inx]->hdr_crt == GTPU_UDP_IPv4) ||
								(sess_data[inx]->hdr_crt == NOT_SET_OUT_HDR_RVL_CRT))
							&& (sess_data[inx]->hdr_rvl == NOT_SET_OUT_HDR_RVL_CRT)
							&& (sess_data[inx]->ue_ip_addr)) {
						/* Set the Decasulation Pkt Mask */
						SET_BIT(encap_pkts_mask, inx);
					}
				}
			}
		}

		if (fwd_pkts_mask) {
			/* SGWU */
			/* get pdr from sess data */
			get_pdr_from_sess_data(n, &sess_data[0], &pdr[0], &fwd_pkts_mask,
					&pkts_queue_mask);

			/* enqueue east interface downlink pkts for user level packet copying */
			enqueue_li_pkts(n, pkts, pdr, EAST_INTFC, DOWNLINK_DIRECTION, &fwd_pkts_mask, FWD_MASK);

			/* Update nexthop L3 header*/
			update_enb_info(pkts, n, &pkts_mask, &fwd_pkts_mask, &sess_data[0], &pdr[0]);
		}

		if (encap_pkts_mask) {
			/* PGWU/SAEGWU: Filter Downlink traffic. Apply sdf*/
			filter_dl_traffic(p, pkts, n, wk_index, &pkts_mask, &encap_pkts_mask,
					&sess_data[0], &pdr[0]);

			/* enqueue east interface downlink pkts for user level packet copying */
			enqueue_li_pkts(n, pkts, pdr, EAST_INTFC, DOWNLINK_DIRECTION, &encap_pkts_mask, ENCAP_MASK);

			/* Encap GTPU header*/
			gtpu_encap(&pdr[0], &sess_data[0], pkts, n, &pkts_mask, &encap_pkts_mask,
					&pkts_queue_mask);
		}

		/* En-queue DL pkts */
		if (pkts_queue_mask) {
			rte_pipeline_ah_packet_hijack(p, pkts_queue_mask);
			enqueue_dl_pkts(&pdr[0], &sess_data[0], pkts, pkts_queue_mask);
		}

	}

	/* Next port is UL for SPGW*/
	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, app.wb_port, &pdr[0]);

	/* Send Session Usage Report */
	update_usage(pkts, n, &pkts_mask, pdr, DOWNLINK);

	/* up pcap dumper */
	up_pcap_dumper(pcap_dumper_east, pkts, n);

	if (fwd_pkts_mask) {
		/* enqueue west interface downlink pkts for user level packet copying */
		enqueue_li_pkts(n, pkts, pdr, WEST_INTFC, DOWNLINK_DIRECTION, &fwd_pkts_mask, FWD_MASK);
	}

	if (encap_pkts_mask) {
		/* enqueue west interface downlink pkts for user level packet copying */
		enqueue_li_pkts(n, pkts, pdr, WEST_INTFC, DOWNLINK_DIRECTION, &encap_pkts_mask, ENCAP_MASK);
	}

	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Out EB_Pkt_Handler\n", LOG_VALUE);
	return 0;
}
