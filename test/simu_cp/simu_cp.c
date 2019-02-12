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
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>
#include <math.h>

#include "interface.h"
#include "main.h"
#include "packet_filters.h"
#include "util.h"
#include "cp_stats.h"

#ifdef SIMU_CP
#define SIMU_CP_FILE "../config/simu_cp.cfg"
#define NG4T_SIMU

extern char *dpn_id;
extern uint32_t num_adc_rules;
extern uint32_t adc_rule_id[MAX_ADC_RULES];
uint32_t base_s1u_spgw_gtpu_teid = 0xf0000000;
static uint32_t s1u_spgw_gtpu_teid_offset;

/* Control-Plane Simulator configure parameters. */
struct simu_params {
	uint32_t enb_ip;
	uint32_t s1u_sgw_ip;
	uint32_t ue_ip_s;
	uint32_t ue_ip_s_range;
	uint32_t as_ip_s;
	uint32_t max_ue_sess;
	uint32_t default_bearer;
	uint32_t tps;
	uint32_t duration;
#ifdef NG4T_SIMU
	uint32_t max_ue_ran;
	uint32_t max_enb_ran;
#endif


} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/* Show Total statistics of Control-plane */
static void
print_stats(struct simu_params *cfg)
{
	printf("\n**************************\n");
	printf("STATS :: \n");
	printf("**************************\n");
	printf("MAX_NUM_CS    : %u\n", cfg->max_ue_sess);
	printf("MAX_NUM_MB    : %u\n", cfg->max_ue_sess);
	printf("NUM_CS_SEND   : %"PRIu64"\n", cp_stats.create_session);
	printf("NUM_MB_SEND   : %"PRIu64"\n", cp_stats.modify_bearer);
	printf("NUM_CS_FAILED : %"PRIu64"\n", (cfg->max_ue_sess - cp_stats.create_session));
	printf("NUM_MB_FAILED : %"PRIu64"\n", (cfg->max_ue_sess - cp_stats.modify_bearer));
	printf("**************************\n\n");

	if ((cfg->max_ue_sess != cp_stats.create_session) || (cfg->max_ue_sess != cp_stats.modify_bearer)) {
		printf("\n**ERROR : DP not configure properly for %u CS/MB requests.**\n",
				cfg->max_ue_sess);
		exit(1);
	}
	printf("\n************ DP Configured successfully ************\n");

}

#ifdef DEL_SESS_REQ
/* Show Total statistics of Control-plane */
static void
print_del_stats(struct simu_params *cfg)
{
	printf("\n**************************\n");
	printf("STATS :: \n");
	printf("**************************\n");
	printf("MAX_NUM_DEL   : %u\n", cfg->max_ue_sess);
	printf("NUM_DEL_SEND  : %"PRIu64"\n", cp_stats.delete_session);
	printf("NUM_DEL_FAILED: %"PRIu64"\n", (cfg->max_ue_sess - cp_stats.delete_session));
	printf("**************************\n\n");

}
#endif

#ifdef NG4T_SIMU
/* Generate unique eNB teid. */
static uint32_t
simu_cp_enbv4_teid(int ue_idx, int max_ue_ran, int max_enb_ran,
		uint32_t *teid, uint32_t *enb_idx)
{
	int ran;
	int enb;
	int enb_of_ran;
	int ue_of_ran;
	uint32_t ue_teid;
	uint32_t session_idx = 0;

	if (max_ue_ran == 0 || max_enb_ran == 0)
		return -1; /* need to have at least one of each */

	ue_of_ran = ue_idx % max_ue_ran;
	ran = ue_idx / max_ue_ran;
	enb_of_ran = ue_of_ran % max_enb_ran;
	enb = ran * max_enb_ran + enb_of_ran;

	ue_teid = ue_of_ran + max_ue_ran * session_idx + 1;

	//*teid = teid_swap(ue_teid);
	*teid = ue_teid;
	*enb_idx = enb;
	//static int found=0;
	//if (ran <= 1 && found<500 && !(ue_idx%1))
	//{
	//  found += 1;
	//  printf("ue_idx: %d; enb_idx: %d; teid: %d\n", ue_idx, *enb_idx, *teid);
	//}

	return 0;
}
#endif

/* Generate unique teid for each create session. */
	static void
generate_teid(uint32_t *teid)
{
	*teid = base_s1u_spgw_gtpu_teid + s1u_spgw_gtpu_teid_offset;
	++s1u_spgw_gtpu_teid_offset;
}

#ifdef DEL_SESS_REQ
/* Form and delete request to DP*/
static int
process_delete_req(struct simu_params *param)
{

	printf("\n\n %50s", "Start sending delete session request ....!!! \n");

	/* Create Session Information*/
	uint32_t s1u_teid = 0;
	uint32_t enb_teid = 0;
	uint32_t enb_ip_idx = 0;

	time_t tstart, tend;
	unsigned int count = 0;
	int second_expired = 1;

	while(1) {
		if(second_expired)
			time(&tstart);
		second_expired = 0;

		while(cp_stats.delete_session < param->max_ue_sess) {

			time(&tend);
			if(fabs(difftime(tend, tstart)) >= fabs(1.0)) {
				count = 0;
				second_expired = 1;
				break;
			}

			if (count < param->tps) {
				struct session_info sess;

				memset(&sess, 0, sizeof(struct session_info));

				/*generate teid for each create session */
				generate_teid(&s1u_teid);

#ifdef NG4T_SIMU
				simu_cp_enbv4_teid(cp_stats.delete_session, param->max_ue_ran, param->max_enb_ran,
						&enb_teid, &enb_ip_idx);

#endif

				sess.ue_addr.iptype = IPTYPE_IPV4;
				sess.ue_addr.u.ipv4_addr = (param->ue_ip_s) + cp_stats.delete_session;

				sess.sess_id = SESS_ID(sess.ue_addr.u.ipv4_addr, param->default_bearer);

				struct dp_id dp_id = { .id = DPN_ID };

				if (session_delete(dp_id, sess) < 0)
					rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");

				cp_stats.delete_session++;
				++count;
			}

			if(second_expired)
				break;
		}
		if (cp_stats.delete_session >= param->max_ue_sess)
				break;
	}
	return 0;
}
#endif /* DEL_SESS_REQ */

/* Form and send CS and MB request to DP*/
static int
process_cs_mb_req(struct simu_params *param)
{
	printf("\n\n %50s", " CS and MB Requests Generator is started ....!!! \n");
	printf("\n\n %50s", " Please wait for DP configured message ....!!! \n");

	/* Create Session Information*/
	uint32_t s1u_teid = 0;
	uint32_t enb_teid = 0;
	uint32_t enb_ip_idx = 0;

	time_t tstart, tend;
	unsigned int count = 0;
	int second_expired = 1;

	while(1) {
		if(second_expired)
			time(&tstart);
		second_expired = 0;

		while(cp_stats.create_session < param->max_ue_sess){

			time(&tend);
			if(fabs(difftime(tend, tstart)) >= fabs(1.0)) {
				count = 0;
				second_expired = 1;
				break;
			}

			if (count < param->tps) {
				struct session_info sess;

				memset(&sess, 0, sizeof(struct session_info));

				/*generate teid for each create session */
				generate_teid(&s1u_teid);

#ifdef NG4T_SIMU
				simu_cp_enbv4_teid(cp_stats.create_session, param->max_ue_ran, param->max_enb_ran,
						&enb_teid, &enb_ip_idx);

#endif

				sess.ue_addr.iptype = IPTYPE_IPV4;
				sess.ue_addr.u.ipv4_addr = (param->ue_ip_s) + cp_stats.create_session;

				sess.ul_s1_info.sgw_teid = s1u_teid;
				sess.ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
				sess.ul_s1_info.sgw_addr.u.ipv4_addr = param->s1u_sgw_ip;

				sess.dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
				sess.dl_s1_info.sgw_addr.u.ipv4_addr = param->s1u_sgw_ip;

				sess.ul_apn_mtr_idx = ulambr_idx;
				sess.dl_apn_mtr_idx = dlambr_idx;
				sess.ipcan_dp_bearer_cdr.charging_id = 10;
				sess.ipcan_dp_bearer_cdr.pdn_conn_charging_id = 10;


				sess.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
				sess.ul_s1_info.enb_addr.u.ipv4_addr = param->enb_ip + enb_ip_idx;
				sess.num_ul_pcc_rules = 1;
				sess.num_dl_pcc_rules = 1;
				sess.ul_pcc_rule_id[0] = FIRST_FILTER_ID;
				sess.dl_pcc_rule_id[0] = FIRST_FILTER_ID;

				sess.sess_id = SESS_ID(sess.ue_addr.u.ipv4_addr, param->default_bearer);

				struct dp_id dp_id = { .id = DPN_ID };

				if (session_create(dp_id, sess) < 0)
					rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");

				cp_stats.create_session++;

				/* Modify the session */
				sess.dl_s1_info.enb_teid = ntohl(enb_teid);
				sess.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
				sess.dl_s1_info.enb_addr.u.ipv4_addr = param->enb_ip + enb_ip_idx;

				sess.num_adc_rules = num_adc_rules;

				for (uint32_t i = 0; i < num_adc_rules; i++)
					sess.adc_rule_id[i] = adc_rule_id[i];

				if (session_modify(dp_id, sess) < 0)
					rte_exit(EXIT_FAILURE,"Bearer Session modify fail !!!");

				++count;
				cp_stats.modify_bearer++;
			}

			if(second_expired)
				break;
		}
		if(cp_stats.create_session >= param->max_ue_sess)
			break;
	}
	return 0;
}

	static int
parse_agrs(struct simu_params *cfg)
{
	struct in_addr addr;
	const char *file_entry = NULL;
	char *end = NULL;

	struct rte_cfgfile *file = rte_cfgfile_load(SIMU_CP_FILE, 0);
	if (file == NULL)
		rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n",
				SIMU_CP_FILE);


	file_entry = rte_cfgfile_get_entry(file, "0", "S1U_SGW_IP");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		cfg->s1u_sgw_ip = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "ENODEB_IP_START");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		cfg->enb_ip = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "UE_IP_START");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		cfg->ue_ip_s = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "UE_IP_START_RANGE");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		cfg->ue_ip_s_range = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "AS_IP_START");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		cfg->as_ip_s = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "MAX_UE_SESS");
	if (file_entry)
		cfg->max_ue_sess =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "DEFAULT_BEARER");
	if (file_entry)
		cfg->default_bearer =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "TPS");
	if (file_entry)
		cfg->tps =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "BREAK_DURATION");
	if (file_entry)
		cfg->duration =  (uint32_t) strtoll(file_entry, &end, 10);

#ifdef NG4T_SIMU
	file_entry = rte_cfgfile_get_entry(file, "0", "ng4t_max_ue_ran");
	if (file_entry)
		cfg->max_ue_ran =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "ng4t_max_enb_ran");
	if (file_entry)
		cfg->max_enb_ran =  (uint32_t) strtoll(file_entry, &end, 10);
#endif
	return 0;
}

#ifdef CP_BUILD
int simu_cp(__rte_unused void *ptr)
#else
int simu_cp(void)
#endif /* CP_BUILD */
{

		struct simu_params cfg;

		/* Parsing simu config parameters. */
		int ret = parse_agrs(&cfg);
		if (ret < 0)
			exit(1);

#ifndef CP_BUILD
		/* Parse the rules into DP */
		/* Configure  PCC, Meter and SDF rules on DP. */
		init_packet_filters();

		/* Configure ADC rules on DP.*/
		parse_adc_rules();
#endif /* CP_BUILD */

		/* Wait to create stream channel with FPC*/
		sleep(5);

		/* Form and send CS and MB request to DP. */
		ret = process_cs_mb_req(&cfg);
		if (ret < 0)
			exit(1);

		/* Show CS and MB requests STATS. */
		sleep(5);
		print_stats(&cfg);

#ifdef DEL_SESS_REQ
		sleep(cfg.duration);

		/* Form and send delete request to DP. */
		ret = process_delete_req(&cfg);
		if (ret < 0)
			exit(1);

		/* Show delete session requests STATS. */
		sleep(5);
		print_del_stats(&cfg);
#endif /* DEL_SESS_REQ */


		return 0;
}
#endif /* SIMU_CP */


