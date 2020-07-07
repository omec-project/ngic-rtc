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

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_cfgfile.h>

#include "cp_config.h"
#include "cp_stats.h"


void
config_cp_ip_port(pfcp_config_t *pfcp_config)
{
	int32_t i = 0;
	int32_t num_ops_entries = 0;
	int32_t num_app_entries = 0;
	int32_t num_apn_entries = 0;
	int32_t num_cache_entries = 0;
	int32_t num_ip_pool_entries = 0;
	int32_t num_global_entries = 0;
	int32_t num_urr_entries = 0;

	struct rte_cfgfile_entry *global_entries = NULL;
	struct rte_cfgfile_entry *apn_entries = NULL;
	struct rte_cfgfile_entry *ip_pool_entries = NULL;
	struct rte_cfgfile_entry *cache_entries = NULL;
	struct rte_cfgfile_entry *app_entries = NULL;
	struct rte_cfgfile_entry *ops_entries = NULL;
	struct rte_cfgfile_entry *urr_entries = NULL;


	struct rte_cfgfile *file = rte_cfgfile_load(STATIC_CP_FILE, 0);
	if (file == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot load configuration file %s\n",
				STATIC_CP_FILE);
	}

	fprintf(stderr, "CP: PFCP Config Parsing %s\n", STATIC_CP_FILE);

	/* Read GLOBAL seaction values and configure respective params. */
	num_global_entries = rte_cfgfile_section_num_entries(file, GLOBAL_ENTRIES);

	if (num_global_entries > 0) {
		global_entries = rte_malloc_socket(NULL,
				sizeof(struct rte_cfgfile_entry) *
				num_global_entries,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	}

	if (global_entries == NULL) {
		rte_panic("Error configuring global entry of %s\n",
				STATIC_CP_FILE);
	}

	rte_cfgfile_section_entries(file, GLOBAL_ENTRIES, global_entries,
			num_global_entries);

	for (i = 0; i < num_global_entries; ++i) {

		/* Parse SGWC, PGWC and SAEGWC values from cp.cfg */
		if(strncmp(CP_TYPE, global_entries[i].name, ENTRY_NAME_SIZE) == 0) {
			pfcp_config->cp_type = (uint8_t)atoi(global_entries[i].value);

			fprintf(stderr, "CP: CP_TYPE     : %s\n",
					pfcp_config->cp_type == SGWC ? "SGW-C" :
					pfcp_config->cp_type == PGWC ? "PGW-C" :
					pfcp_config->cp_type == SAEGWC ? "SAEGW-C" : "UNKNOWN");

		}else if (strncmp(S11_IPS, global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			inet_aton(global_entries[i].value,
					&(pfcp_config->s11_ip));

			fprintf(stderr, "CP: S11_IP      : %s\n",
					inet_ntoa(pfcp_config->s11_ip));

		}else if (strncmp(S11_PORTS, global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			pfcp_config->s11_port =
					(uint16_t)atoi(global_entries[i].value);

			fprintf(stderr, "CP: S11_PORT    : %d\n",
					pfcp_config->s11_port);

		} else if (strncmp(S5S8_IPS, global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			inet_aton(global_entries[i].value,
					&(pfcp_config->s5s8_ip));

			fprintf(stderr, "CP: S5S8_IP     : %s\n",
					inet_ntoa(pfcp_config->s5s8_ip));

		} else if (strncmp(S5S8_PORTS, global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			pfcp_config->s5s8_port =
				(uint16_t)atoi(global_entries[i].value);

			fprintf(stderr, "CP: S5S8_PORT   : %d\n",
					pfcp_config->s5s8_port);

		} else if (strncmp(PFCP_IPS , global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			inet_aton(global_entries[i].value,
					&(pfcp_config->pfcp_ip));

			fprintf(stderr, "CP: PFCP_IP     : %s\n",
					inet_ntoa(pfcp_config->pfcp_ip));

		} else if (strncmp(PFCP_PORTS, global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			pfcp_config->pfcp_port =
				(uint16_t)atoi(global_entries[i].value);

			fprintf(stderr, "CP: PFCP_PORT   : %d\n",
					pfcp_config->pfcp_port);

		} else if (strncmp(DDF2_IP , global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			inet_aton(global_entries[i].value,
					&(pfcp_config->ddf2_ip));

			fprintf(stderr, "CP: DDF2_IP     : %s\n",
					inet_ntoa(pfcp_config->ddf2_ip));

		} else if (strncmp(DDF2_PORT , global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			pfcp_config->ddf2_port =
				(uint16_t)atoi(global_entries[i].value);

			fprintf(stderr, "CP: DDF2_PORT     : %d\n",
					pfcp_config->ddf2_port);

		} else if (strncmp(DDF2_INTFC , global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			strncpy(pfcp_config->ddf2_intfc, global_entries[i].value, DDF_INTFC_LEN);

			fprintf(stderr, "CP: DDF2_INTFC     : %s\n",
					pfcp_config->ddf2_intfc);

		} else if (strncmp(DADMF_IPS , global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			inet_aton(global_entries[i].value,
					&(pfcp_config->dadmf_ip));

			fprintf(stderr, "CP: DADMF_IP     : %s\n",
					inet_ntoa(pfcp_config->dadmf_ip));

		} else if (strncmp(DADMF_PORTS, global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			pfcp_config->dadmf_port =
				(uint16_t)atoi(global_entries[i].value);

			fprintf(stderr, "CP: DADMF_PORT   : %d\n",
					pfcp_config->dadmf_port);

		} else if (strncmp(MME_S11_IPS, global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			inet_aton(global_entries[i].value,
					&(pfcp_config->s11_mme_ip));

			fprintf(stderr, "CP: MME_S11_IP  : %s\n",
					inet_ntoa(pfcp_config->s11_mme_ip));

		} else if (strncmp(MME_S11_PORTS, global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {
			pfcp_config->s11_mme_port =
				(uint16_t)atoi(global_entries[i].value);

			fprintf(stderr, "CP: MME_S11_PORT: %d\n", pfcp_config->s11_mme_port);

		} else if (strncmp(UPF_PFCP_IPS , global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			inet_aton(global_entries[i].value,
					&(pfcp_config->upf_pfcp_ip));

			fprintf(stderr, "CP: UPF_PFCP_IP : %s\n",
					inet_ntoa(pfcp_config->upf_pfcp_ip));

		} else if (strncmp(UPF_PFCP_PORTS, global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			pfcp_config->upf_pfcp_port =
				(uint16_t)atoi(global_entries[i].value);

			fprintf(stderr, "CP: UPF_PFCP_PORT: %d\n",
					pfcp_config->upf_pfcp_port);
		} else if (strncmp("UPF_S5S8_IP", global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			struct in_addr tmp = {0};
			inet_aton(global_entries[i].value,
					&(tmp));
			pfcp_config->upf_s5s8_ip = ntohl(tmp.s_addr);

			fprintf(stderr, "CP: UPF_S5S8_IP : %s\n",
					inet_ntoa(tmp));

		} else if (strncmp("UPF_S5S8_MASK", global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			struct in_addr tmp = {0};
			inet_aton(global_entries[i].value, &(tmp));

			pfcp_config->upf_s5s8_mask = ntohl(tmp.s_addr);

			fprintf(stderr, "CP: UPF_S5S8_MASK : %s\n",
					inet_ntoa(tmp));

		 } else if (strncmp(REDIS_IPS , global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			inet_aton(global_entries[i].value,
					&(pfcp_config->redis_ip));

			fprintf(stderr, "CP: REDIS_IP : %s\n",
					inet_ntoa(pfcp_config->redis_ip));

		 } else if (strncmp(CP_REDIS_IP , global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			inet_aton(global_entries[i].value,
					&(pfcp_config->cp_redis_ip));

			fprintf(stderr, "CP: CP_REDIS_IP : %s\n",
					inet_ntoa(pfcp_config->cp_redis_ip));

		 } else if (strncmp(REDIS_CERT_PATH , global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			strncpy(pfcp_config->redis_cert_path, global_entries[i].value,
													REDIS_CERT_PATH_LEN);

			fprintf(stderr, "CP: REDIS_CERT_PATH : %s\n",
									pfcp_config->redis_cert_path);

		} else if (strncmp(REDIS_PORTS, global_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {

			pfcp_config->redis_port =
				(uint16_t)atoi(global_entries[i].value);

			fprintf(stderr, "CP: REDIS_PORT: %d\n",
					pfcp_config->redis_port);
		} else if (strncmp(CP_LOGGER, global_entries[i].name, ENTRY_NAME_SIZE) == 0) {
			 pfcp_config->cp_logger = (uint8_t)atoi(global_entries[i].value);
		 }

		/* Parse timer and counter values from cp.cfg */
		if(strncmp(TRANSMIT_TIMER, global_entries[i].name, ENTRY_NAME_SIZE) == 0)
			pfcp_config->transmit_timer = (int)atoi(global_entries[i].value);

		if(strncmp(PERIODIC_TIMER, global_entries[i].name, ENTRY_NAME_SIZE) == 0)
			pfcp_config->periodic_timer = (int)atoi(global_entries[i].value);

		if(strncmp(TRANSMIT_COUNT, global_entries[i].name, ENTRY_NAME_SIZE) == 0)
			pfcp_config->transmit_cnt = (uint8_t)atoi(global_entries[i].value);

		/* Parse CP Timer Request Time Out and Retries Values from cp.cfg */
		if(strncmp(REQUEST_TIMEOUT, global_entries[i].name, ENTRY_NAME_SIZE) == 0){
			if(check_cp_req_timeout_config(global_entries[i].value) == 0) {
				pfcp_config->request_timeout = (int)atoi(global_entries[i].value);
				fprintf(stderr, "CP: REQUEST_TIMEOUT: %d\n",
					pfcp_config->request_timeout);
			} else {
				rte_panic("Error configuring "
					"CP TIMER "REQUEST_TIMEOUT" invalid entry of %s\n", STATIC_CP_FILE);
			}
		}else {
			/* if CP Request Timer Parameter is not present is cp.cfg */
			/* Defualt Request Timerout value */
			/* 3 seconds = 3000 milisecond  */
			if(pfcp_config->request_timeout == 0) {
				pfcp_config->request_timeout = REQUEST_TIMEOUT_DEFAULT_VALUE;
			}
		}

		if(strncmp(REQUEST_TRIES, global_entries[i].name, ENTRY_NAME_SIZE) == 0) {
			if(check_cp_req_tries_config(global_entries[i].value) == 0) {
				pfcp_config->request_tries = (uint8_t)atoi(global_entries[i].value);
				fprintf(stderr, "CP: REQUEST_TRIES: %d\n",
					pfcp_config->request_tries);
			} else {
				rte_panic("Error configuring "
					"CP TIMER "REQUEST_TRIES" invalid entry of %s\n", STATIC_CP_FILE);
			}

		} else {
			/* if CP Request Timer Parameter is not present is cp.cfg */
			/* Defualt Request Retries value */
			if(pfcp_config->request_tries == 0) {
				pfcp_config->request_tries = REQUEST_TRIES_DEFAULT_VALUE;
			}
		}
		/* DNS Parameter for Config CP with or without DNSquery */
		if(strncmp(USE_DNS, global_entries[i].name, ENTRY_NAME_SIZE) == 0) {
			pfcp_config->use_dns = (uint8_t)atoi(global_entries[i].value);
			fprintf(stderr, "CP: %s :   %s \n", (pfcp_config->cp_type == SGWC ? "SGW-C" :
						pfcp_config->cp_type == PGWC ? "PGW-C" :
						pfcp_config->cp_type == SAEGWC ? "SAEGW-C" : "UNKNOWN"),
					((pfcp_config->use_dns)? "WITH DNS": "WITHOUT DNS"));
		}

		/* To ON/OFF CDR on PGW/SAEGW */
		if(strncmp(GENERATE_CDR, global_entries[i].name, ENTRY_NAME_SIZE) == 0) {
			pfcp_config->generate_cdr = (uint8_t)atoi(global_entries[i].value);
			fprintf(stderr, "CP: [PGW/SAEGW] CDR GENERATION : %s\n",
					(pfcp_config->generate_cdr)? "ENABLED" : "DISABLED");
			if(pfcp_config->generate_cdr > CDR_ON){
				rte_panic("Error : Invalide value aasign to paramtere GENERATE_CDR \n");

			}
		}

		/* To ON/OFF/CC_CHECK for CDR generation on SGW */
		if(strncmp(GENERATE_SGW_CDR, global_entries[i].name, ENTRY_NAME_SIZE) == 0) {
			pfcp_config->generate_sgw_cdr = (uint8_t)atoi(global_entries[i].value);
			fprintf(stderr, "CP: [SGW] CDR GENERATION : %d\n",
									(pfcp_config->generate_sgw_cdr));
			if(pfcp_config->generate_sgw_cdr > SGW_CC_CHECK){
				rte_panic("Error : Invalide value aasign to paramtere GENERATE_SGW_CDR \n");

			}
		}

		/* Charging Characteristic for the case of SGW */
		if((pfcp_config->generate_sgw_cdr == SGW_CC_CHECK) &&
				strncmp(SGW_CC, global_entries[i].name, ENTRY_NAME_SIZE) == 0) {
			pfcp_config->sgw_cc = (uint8_t)atoi(global_entries[i].value);
			fprintf(stderr, "CP: Charging Characteristic for SGW : %s\n",
													get_cc_string(pfcp_config->sgw_cc));
		}

		if(pfcp_config->cp_type != SGWC) {
			if(strncmp(USE_GX, global_entries[i].name, ENTRY_NAME_SIZE) == 0) {
				pfcp_config->use_gx = (uint8_t)atoi(global_entries[i].value);
				if(pfcp_config->use_gx <= 1) {
					fprintf(stderr, "CP: USE GX : %s\n",
							(pfcp_config->use_gx)? "ENABLED" : "DISABLED");
				}
				else {
					rte_panic("Use 0 or 1 for gx interface DISABLE/ENABLE : %s\n", STATIC_CP_FILE);
				}
			}
		}

		if(strncmp(ADD_DEFAULT_RULE, global_entries[i].name, ENTRY_NAME_SIZE) == 0) {
			pfcp_config->add_default_rule = (uint8_t)atoi(global_entries[i].value);
			fprintf(stderr, "CP: ADD_DEFAULT_RULE : %s\n",
					(pfcp_config->add_default_rule)? ((pfcp_config->add_default_rule == 1) ?
					"ALLOW ANY TO ANY" : "DENY ANY TO ANY") : "DISABLED");
		}
	}

	rte_free(global_entries);

	if ((pfcp_config->upf_s5s8_ip)
			&& (pfcp_config->upf_s5s8_mask)) {

		pfcp_config->upf_s5s8_net = pfcp_config->upf_s5s8_ip & pfcp_config->upf_s5s8_mask;
		pfcp_config->upf_s5s8_bcast_addr = pfcp_config->upf_s5s8_ip | ~(pfcp_config->upf_s5s8_mask);
		fprintf(stderr, "CP: Config:%s:Configure UPF S5S8 Intf Subnet::"
				"\n\tUP: S5S8 Intf IP:\t\t"IPV4_ADDR";\n\t",
				__func__, IPV4_ADDR_HOST_FORMAT(pfcp_config->upf_s5s8_ip));
		fprintf(stderr, "S5S8 Intf NET:\t\t\t"IPV4_ADDR";\n\t",
				IPV4_ADDR_HOST_FORMAT(pfcp_config->upf_s5s8_net));
		fprintf(stderr, "S5S8 Intf MASK:\t\t\t"IPV4_ADDR";\n\t",
				IPV4_ADDR_HOST_FORMAT(pfcp_config->upf_s5s8_mask));
		fprintf(stderr, "S5S8 Intf BCAST ADDR:\t\t"IPV4_ADDR";\n",
				IPV4_ADDR_HOST_FORMAT(pfcp_config->upf_s5s8_bcast_addr));
	}

	/* Parse APN and nameserver values. */
	uint16_t app_nameserver_ip_idx = 0;
	uint16_t ops_nameserver_ip_idx = 0;

	num_apn_entries =
		rte_cfgfile_section_num_entries(file, APN_ENTRIES);

	if (num_apn_entries > 0) {
		/* Allocate the memory. */
		apn_entries = rte_malloc_socket(NULL,
				sizeof(struct rte_cfgfile_entry) *
				num_apn_entries,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (apn_entries == NULL)
		rte_panic("Error configuring"
				"apn entry of %s\n", STATIC_CP_FILE);
	}


	/* Fill the entries in APN list. */
	int num_apn = 0;

	num_apn = rte_cfgfile_num_sections(file,
					APN_ENTRIES, APN_SEC_NAME_LEN);

	int j;
	int apn_num_entries = 0;
	int apn_idx = 0;
	total_apn_cnt = 0;
	char apn_name[APN_SEC_NAME_LEN] = {0};
	strncpy(apn_name, APN_ENTRIES,APN_SEC_NAME_LEN);

	for(i = 1 ; i <= num_apn; i++ )
	{

		apn_num_entries = rte_cfgfile_section_entries_by_index(file,
				i, apn_name, apn_entries, 10);

		if (apn_num_entries > 0 )
		{
			for(j = 0; j < apn_num_entries; ++j )
			{
				fprintf(stderr,"\nCP: [%s] = %s",
						apn_entries[j].name,
						apn_entries[j].value);


				if(strncmp(NAME, apn_entries[j].name,
							ENTRY_NAME_SIZE) == 0) {

					apn_list[apn_idx].apn_name_label = apn_entries[j].value;

				} else if (strncmp(USAGE_TYPE, apn_entries[j].name,
							ENTRY_NAME_SIZE) == 0 ) {

					apn_list[apn_idx].apn_usage_type = (int)atoi(apn_entries[j].value);

				} else if (strncmp(NETWORK_CAPABILITY, apn_entries[j].name,
							ENTRY_NAME_SIZE) == 0) {

					strncpy(apn_list[apn_idx].apn_net_cap, apn_entries[j].value, ENTRY_VALUE_SIZE);

				} else if (strncmp(TRIGGER_TYPE, apn_entries[j].name,
							ENTRY_NAME_SIZE) == 0) {

					apn_list[apn_idx].trigger_type = (int)atoi(apn_entries[j].value);

				} else if (strncmp(UPLINK_VOLTH, apn_entries[j].name,
							ENTRY_NAME_SIZE) == 0) {

					apn_list[apn_idx].uplink_volume_th = (int)atoi(apn_entries[j].value);

				} else if (strncmp(DOWNLINK_VOLTH, apn_entries[j].name,
							ENTRY_NAME_SIZE) == 0) {

					apn_list[apn_idx].downlink_volume_th = (int)atoi(apn_entries[j].value);

				} else if (strncmp(TIMETH, apn_entries[j].name,
							ENTRY_NAME_SIZE) == 0) {

					apn_list[apn_idx].time_th = (int)atoi(apn_entries[j].value);

				}

		    }
			pfcp_config->num_apn = num_apn;
			apn_list[apn_idx].apn_idx = apn_idx;

			 /*check for valid configuration*/

			 if(apn_list[apn_idx].trigger_type < 0 || apn_list[apn_idx].trigger_type > 2) {
				 fprintf(stderr, "\ncp.cfg : Wrong trigger_type"
						 " for apn : %s\n",apn_list[apn_idx].apn_name_label);
				 rte_panic("Line no : %d\n",__LINE__);
			 }

			 if(apn_list[apn_idx].uplink_volume_th <= 0 ) {
				 fprintf(stderr, "\ncp.cfg : Wrong uplink_volume_th"
						 " for apn : %s\n",apn_list[apn_idx].apn_name_label);
				 rte_panic("Line no : %d\n",__LINE__);
			 }

			 if(apn_list[apn_idx].downlink_volume_th <= 0 ) {
				 fprintf(stderr, "\ncp.cfg : Wrong downlink_volume_th"
						 " for apn : %s\n",apn_list[apn_idx].apn_name_label);
				 rte_panic("Line no : %d\n",__LINE__);
			 }

			 if(apn_list[apn_idx].time_th <= 0 ) {
				 fprintf(stderr, "\ncp.cfg : Wrong time_th"
						 " for apn : %s\n",apn_list[apn_idx].apn_name_label);
				 rte_panic("Line no : %d\n",__LINE__);
			 }
			 set_apn_name(&apn_list[apn_idx], apn_list[apn_idx].apn_name_label);
			 apn_idx++;
			 total_apn_cnt++;
		}
	}
	rte_free(apn_entries);

	/*Read Default configuration of URR*/
	num_urr_entries =
		rte_cfgfile_section_num_entries(file, URR_DEFAULT);

	if (num_urr_entries > 0) {
		urr_entries = rte_malloc_socket(NULL,
						sizeof(struct rte_cfgfile_entry)
							*num_urr_entries,
							RTE_CACHE_LINE_SIZE,
							rte_socket_id());
	}

	if (urr_entries == NULL)
		rte_panic("Error configuring"
				"URR_DEFAULT entry of %s\n", STATIC_CP_FILE);

	rte_cfgfile_section_entries(file, URR_DEFAULT,
					urr_entries,
					num_urr_entries);

	for (i = 0; i < num_urr_entries; ++i) {
		fprintf(stderr, "\nCP: [%s] = %s",
				urr_entries[i].name,
				urr_entries[i].value);
		if (strncmp(TRIGGER_TYPE, urr_entries[i].name,
						ENTRY_NAME_SIZE) == 0)
			pfcp_config->trigger_type =
					(int)atoi(urr_entries[i].value);
		if (strncmp(UPLINK_VOLTH, urr_entries[i].name,
						ENTRY_NAME_SIZE) == 0)
			pfcp_config->uplink_volume_th =
					(int)atoi(urr_entries[i].value);
		if (strncmp(DOWNLINK_VOLTH, urr_entries[i].name,
						ENTRY_NAME_SIZE) == 0)
			pfcp_config->downlink_volume_th =
					(int)atoi(urr_entries[i].value);
		if (strncmp(TIMETH, urr_entries[i].name,
						ENTRY_NAME_SIZE) == 0)
			pfcp_config->time_th =
					(int)atoi(urr_entries[i].value);
	}

	/*check for valid configuration*/

	if(pfcp_config->trigger_type < 0 || pfcp_config->trigger_type > 2) {
		fprintf(stderr, "\ncp.cfg : Wrong trigger_type"
				" for defalt configuration type [URR_DEFAULT]\n");
		rte_panic("Line no : %d\n",__LINE__);
	}

	if(pfcp_config->uplink_volume_th <= 0 ) {
		fprintf(stderr, "\ncp.cfg : Wrong uplink_volume_th"
				" for defalt configuration type [URR_DEFAULT]\n");
		rte_panic("Line no : %d\n",__LINE__);
	}

	if(pfcp_config->downlink_volume_th <= 0 ) {
		fprintf(stderr, "\ncp.cfg : Wrong downlink_volume_th"
				" for defalt configuration type [URR_DEFAULT]\n");
		rte_panic("Line no : %d\n",__LINE__);
	}

	if(pfcp_config->time_th <= 0 ) {
		fprintf(stderr, "\ncp.cfg : Wrong time_th"
				" for defalt configuration type [URR_DEFAULT]\n");
		rte_panic("Line no : %d\n",__LINE__);
	}
	rte_free(urr_entries);

	/* Read cache values from cfg seaction. */
	num_cache_entries =
		rte_cfgfile_section_num_entries(file, CACHE_ENTRIES);

	if (num_cache_entries > 0) {
		cache_entries = rte_malloc_socket(NULL,
						sizeof(struct rte_cfgfile_entry)
							*num_cache_entries,
							RTE_CACHE_LINE_SIZE,
							rte_socket_id());
	}

	if (cache_entries == NULL)
		rte_panic("Error configuring"
				"CACHE entry of %s\n", STATIC_CP_FILE);

	rte_cfgfile_section_entries(file, CACHE_ENTRIES,
					cache_entries,
					num_cache_entries);

	for (i = 0; i < num_cache_entries; ++i) {
		fprintf(stderr, "CP: [%s] = %s\n",
				cache_entries[i].name,
				cache_entries[i].value);
		if (strncmp(CONCURRENT, cache_entries[i].name,
						ENTRY_NAME_SIZE) == 0)
			pfcp_config->dns_cache.concurrent =
					(uint32_t)atoi(cache_entries[i].value);
		if (strncmp(PERCENTAGE, cache_entries[i].name,
						ENTRY_NAME_SIZE) == 0)
			pfcp_config->dns_cache.percent =
					(uint32_t)atoi(cache_entries[i].value);
		if (strncmp(INT_SEC, cache_entries[i].name,
						ENTRY_NAME_SIZE) == 0)
			pfcp_config->dns_cache.sec =
				(((uint32_t)atoi(cache_entries[i].value)) * 1000);
		if (strncmp(QUERY_TIMEOUT, cache_entries[i].name,
		                ENTRY_NAME_SIZE) == 0)
		    pfcp_config->dns_cache.timeoutms =
		            (long)atol(cache_entries[i].value);
		if (strncmp(QUERY_TRIES, cache_entries[i].name,
		                ENTRY_NAME_SIZE) == 0)
		    pfcp_config->dns_cache.tries =
		           (uint32_t)atoi(cache_entries[i].value);
	}

	rte_free(cache_entries);

	/* Read app values from cfg seaction. */
	num_app_entries =
		rte_cfgfile_section_num_entries(file, APP_ENTRIES);

	if (num_app_entries > 0) {
		app_entries = rte_malloc_socket(NULL,
						sizeof(struct rte_cfgfile_entry)
							*num_app_entries,
							RTE_CACHE_LINE_SIZE,
							rte_socket_id());
	}

	if (app_entries == NULL)
		rte_panic("Error configuring"
				"APP entry of %s\n", STATIC_CP_FILE);

	rte_cfgfile_section_entries(file, APP_ENTRIES,
					app_entries,
					num_app_entries);

	for (i = 0; i < num_app_entries; ++i) {
		fprintf(stderr, "CP: [%s] = %s\n",
				app_entries[i].name,
				app_entries[i].value);

		if (strncmp(FREQ_SEC, app_entries[i].name,
						ENTRY_NAME_SIZE) == 0)
			pfcp_config->app_dns.freq_sec =
					(uint8_t)atoi(app_entries[i].value);

		if (strncmp(FILENAME, app_entries[i].name,
						ENTRY_NAME_SIZE) == 0)
			strncpy(pfcp_config->app_dns.filename,
					app_entries[i].value,
					sizeof(pfcp_config->app_dns.filename));

		if (strncmp(NAMESERVER, app_entries[i].name,
						ENTRY_NAME_SIZE) == 0) {
			strncpy(pfcp_config->app_dns.nameserver_ip[app_nameserver_ip_idx],
					app_entries[i].value,
					sizeof(pfcp_config->app_dns.nameserver_ip[app_nameserver_ip_idx]));
			app_nameserver_ip_idx++;
		}
	}

	pfcp_config->app_dns.nameserver_cnt = app_nameserver_ip_idx;

	rte_free(app_entries);

	/* Read ops values from cfg seaction. */
	num_ops_entries =
		rte_cfgfile_section_num_entries(file, OPS_ENTRIES);

	if (num_ops_entries > 0) {
		ops_entries = rte_malloc_socket(NULL,
						sizeof(struct rte_cfgfile_entry)
							*num_ops_entries,
							RTE_CACHE_LINE_SIZE,
							rte_socket_id());
	}

	if (ops_entries == NULL)
		rte_panic("Error configuring"
				"OPS entry of %s\n", STATIC_CP_FILE);

	rte_cfgfile_section_entries(file, OPS_ENTRIES,
					ops_entries,
					num_ops_entries);

	for (i = 0; i < num_ops_entries; ++i) {
		fprintf(stderr, "CP: [%s] = %s\n",
				ops_entries[i].name,
				ops_entries[i].value);

		if (strncmp(FREQ_SEC, ops_entries[i].name,
						ENTRY_NAME_SIZE) == 0)
			pfcp_config->ops_dns.freq_sec =
					(uint8_t)atoi(ops_entries[i].value);

		if (strncmp(FILENAME, ops_entries[i].name,
						ENTRY_NAME_SIZE) == 0)
			strncpy(pfcp_config->ops_dns.filename,
					ops_entries[i].value,
					strnlen(ops_entries[i].value,CFG_VALUE_LEN));

		if (strncmp(NAMESERVER, ops_entries[i].name,
						ENTRY_NAME_SIZE) == 0) {
			strncpy(pfcp_config->ops_dns.nameserver_ip[ops_nameserver_ip_idx],
					ops_entries[i].value,
					strnlen(ops_entries[i].value,CFG_VALUE_LEN));
			ops_nameserver_ip_idx++;
		}
	}

	pfcp_config->ops_dns.nameserver_cnt = ops_nameserver_ip_idx;

	rte_free(ops_entries);

	/* Read IP_POOL_CONFIG seaction */
	num_ip_pool_entries = rte_cfgfile_section_num_entries
									(file, IP_POOL_ENTRIES);


	if (num_ip_pool_entries > 0) {
		ip_pool_entries = rte_malloc_socket(NULL,
					sizeof(struct rte_cfgfile_entry) *
					num_ip_pool_entries,
					RTE_CACHE_LINE_SIZE,
					rte_socket_id());
	if (ip_pool_entries == NULL)
		rte_panic("Error configuring ip"
				"pool entry of %s\n", STATIC_CP_FILE);
	}



	rte_cfgfile_section_entries(file, IP_POOL_ENTRIES,
					ip_pool_entries,
					num_ip_pool_entries);


	for (i = 0; i < num_ip_pool_entries; ++i) {
		fprintf(stderr, "CP: [%s] = %s\n",
				ip_pool_entries[i].name,
				ip_pool_entries[i].value);
		if (strncmp(IP_POOL_IP,
					ip_pool_entries[i].name,
					ENTRY_NAME_SIZE) == 0) {
			inet_aton(ip_pool_entries[i].value,
					&(pfcp_config->ip_pool_ip));
		} else if (strncmp
				(IP_POOL_MASK, ip_pool_entries[i].name,
				 ENTRY_NAME_SIZE) == 0) {
			inet_aton(ip_pool_entries[i].value,
					&(pfcp_config->ip_pool_mask));
		}
	}

	rte_free(ip_pool_entries);
	if (file != NULL) {
		rte_cfgfile_close(file);
		file = NULL;
	}

	return;
}

int
check_cp_req_timeout_config(char *value) {
	unsigned int idx = 0;
	if(value == NULL )
	        return -1;
	/* check string has all digit 0 to 9 */
	for(idx = 0; idx < strnlen(value,CFG_VALUE_LEN); idx++) {
	        if(isdigit(value[idx])  == 0) {
	                return -1;
	        }
	}
	/* check cp request timer timeout range */
	if((int)atoi(value) >= 1 && (int)atoi(value) <= 1800000 ) {
	        return 0;
	}

	return -1;
}

int
check_cp_req_tries_config(char *value) {
	unsigned int idx = 0;
	if(value == NULL )
	        return -1;
	/* check string has all digit 0 to 9 */
	for(idx = 0; idx < strnlen(value,CFG_VALUE_LEN); idx++) {
	        if(isdigit(value[idx])  == 0) {
	                return -1;
	        }
	}
	/* check cp request timer tries range */
	if((int)atoi(value) >= 1 && (int)atoi(value) <= 20) {
	        return 0;
	}
	return -1;
}

void
parse_apn_args(char *temp, char *ptr[3])
{

	int i;
	char *first = temp;
	char *next = NULL;

	for (i = 0; i < 3; i++) {
		ptr[i] = malloc(100);
		memset(ptr[i], 0, 100);
	}

	for (i = 0; i < 3; i++) {

		if(first!=NULL)
			next = strchr(first, ',');

		if(first == NULL && next == NULL)
		{
			ptr[i] = NULL;
			continue;
		}

		if(*(first) == '\0')  //string ends,fill remaining with NULL
		{
			ptr[i] = NULL;
			continue;
		}

		if(next!= NULL)
		{
			if(next > first) //string is present
			{
				strncpy(ptr[i], first, next - first);

			}
			else if (next == first) //first place is comma
			{
				ptr[i] = NULL;
			}
			first = next + 1;
		} else                //copy last string
		{
			if(first!=NULL)
			{
				strcpy(ptr[i],first);
				first = NULL;
			} else {
				ptr[i] = NULL; //fill remaining ptr with NULL
			}

		}
	}

}

int
get_apn_name(char *apn_name_label, char *apn_name) {

	if(apn_name_label == NULL)
		return -1;

	uint8_t length = strnlen(apn_name_label, MAX_NB_DPN);

	for (uint8_t i=0; i<length; i++) {

		uint8_t len = apn_name_label[i];

		if (i!=0)
			apn_name[i - 1] = '.';

		for (uint8_t j=i; j<(i +len); j++) {
			apn_name[j] = apn_name_label[j+1];
		}

		i = i + len;

	}
	return 0;
}
