/*
 * Copyright 2019-present Open Networking Foundation
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "monitor_config.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "cp.h"
#include "cp_config.h"
#include <rte_cfgfile.h>
#include <rte_log.h>
#include <rte_debug.h>

extern struct app_config *appl_config;

const char *primary_dns = "8.8.8.8";
const char *secondary_dns = "8.8.8.4";	

void
config_change_cbk(char *config_file, uint32_t flags)
{
	RTE_LOG_DP(INFO, CP, "Received %s. File %s flags: %x\n",
		   __FUNCTION__, config_file, flags);

	/* Move the updated config to standard path */
	static char cmd[256];
	sprintf(cmd, "cp %s %s", CP_CONFIG_ETC_PATH, CP_CONFIG_OPT_PATH);
	int ret = system(cmd);
	RTE_LOG_DP(INFO, CP, "system call return value: %d", ret);

	/* We dont expect quick updates from configmap..One update per interval. Typically 
	 * worst case 60 seconds for 1 config update. Updates are clubbed and dont come frequent 
	 * We re-register to avoid recursive callbacks 
	 */
	watch_config_change(CP_CONFIG_ETC_PATH, config_change_cbk);

	/* Lets first parse the current app_config.cfg file  */
	struct app_config *new_cfg;
	new_cfg = (struct app_config *) calloc(1, sizeof(struct app_config));
	if (new_cfg == NULL) {
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for new_cfg!\n");
	}

	init_spgwc_dynamic_config(new_cfg);
	/* Now compare whats changed and update our global application config */

	/* Data plane Selection rules config modification
	 *  Delete - Should not be removed. If removed then it will not delete the existing 
	 *           subscribers associated with that dataplane 
	 * 		    TODO : delete subscribers if DP going away 
	 *  Add - New Rules can be added for existing dataplane or new rules for new dataplane 
	 *        can be added at any time
	 *  Modify Rules : Modifying existing rules may not have any impact on existing subscribers
	 * 
	 *  Correct way to remove any DP would be to make sure all the subscribers associated with 
	 *  that DP are deleted first and then DP is removed. 
	 *  
	 * For now I am just going to switch to new config. Anyway its just selection of DPs 
	 */
	struct app_config *old_config = appl_config;
	appl_config = new_cfg; 
	struct dp_info *np; 
	np = LIST_FIRST(&old_config->dpList);
	while (np != NULL) {
		LIST_REMOVE(np, dpentries);
		free(np);
		np = LIST_FIRST(&old_config->dpList);
	}
	free(old_config);

	/* Everytime we add new config we need to add code here. How to react to config change  */
}

void 
register_config_updates(void)
{
	/* I would prefer a complete path than this relative path.
	 * Looks like it may break */
	watch_config_change(CP_CONFIG_ETC_PATH, config_change_cbk);
}

void 
init_spgwc_dynamic_config(struct app_config *cfg )
{
	// Read the config file, parse it and fill passed cfg data structure 
	const char *entry = NULL;
	unsigned int num_dp_selection_rules = 0;
	unsigned int index;
	LIST_INIT(&cfg->dpList);

	struct rte_cfgfile *file = rte_cfgfile_load(APP_CONFIG_FILE, 0);
	if (NULL == file) {
		RTE_LOG_DP(ERR, CP, "App config file is missing, ignore error...\n");
		return;
	}

	entry = rte_cfgfile_get_entry(file, "GLOBAL", "DNS_PRIMARY");
	if (entry == NULL) {
		RTE_LOG_DP(ERR, CP, "DNS_PRIMARY default config is missing. \n");
		entry = primary_dns;
	}
	inet_aton(entry, &cfg->dns_p);
	set_app_dns_primary(cfg);
	RTE_LOG_DP(INFO, CP, "Global DNS_PRIMARY address is %s \n", inet_ntoa(cfg->dns_p));

	entry = rte_cfgfile_get_entry(file, "GLOBAL", "DNS_SECONDARY");
	if (entry == NULL) {
		RTE_LOG_DP(ERR, CP, "DNS_SECONDARY default config is missing. \n");
		entry = secondary_dns;
	}
	inet_aton(entry, &cfg->dns_s);
	set_app_dns_secondary(cfg);
	RTE_LOG_DP(INFO, CP, "Global DNS_SECONDARY address is %s \n", inet_ntoa(cfg->dns_s));

	entry = rte_cfgfile_get_entry(file, "GLOBAL", "NUM_DP_SELECTION_RULES");
	if (entry == NULL) {
       		RTE_LOG_DP(ERR, CP, "NUM_DP_SELECTION_RULES missing from app_config.cfg file, abort parsing\n");
       		return;
	}
	num_dp_selection_rules = atoi(entry);

	for (index = 0; index < num_dp_selection_rules; index++) {
		static char sectionname[64] = {0};
		struct dp_info *dpInfo = NULL;
		dpInfo = (struct dp_info *)calloc(1, sizeof(struct dp_info));

		if (dpInfo == NULL) {
			RTE_LOG_DP(ERR, CP, "Could not allocate memory for dpInfo!\n");
			return;
		}
		snprintf(sectionname, sizeof(sectionname),
			 "DP_SELECTION_RULE_%u", index + 1);
		entry = rte_cfgfile_get_entry(file, sectionname, "DPID");
		if (entry) {
			dpInfo->dpId = atoi(entry);
		} else {
			RTE_LOG_DP(ERR, CP, "DPID not found in the configuration file\n");
		}

		entry = rte_cfgfile_get_entry(file, sectionname, "DPNAME");
		if (entry) {
			strncpy(dpInfo->dpName, entry, DP_SITE_NAME_MAX);
		} else {
			RTE_LOG_DP(ERR, CP, "DPNAME not found in the configuration file\n");
		}

		entry = rte_cfgfile_get_entry(file, sectionname, "MCC");
		if (entry) {
			// TODO : handle 2 digit mcc, mnc
			dpInfo->key.mcc_mnc.mcc_digit_1 = (unsigned char )entry[0];
			dpInfo->key.mcc_mnc.mcc_digit_2 = (unsigned char )entry[1];
			dpInfo->key.mcc_mnc.mcc_digit_3 = (unsigned char )entry[2];
		} else {
			RTE_LOG_DP(ERR, CP, "MCC not found in the configuration file\n");
		}

		entry = rte_cfgfile_get_entry(file, sectionname, "MNC");
		if (entry) {
			dpInfo->key.mcc_mnc.mnc_digit_1 = (unsigned char )entry[0];
			dpInfo->key.mcc_mnc.mnc_digit_2 = (unsigned char )entry[1];
			dpInfo->key.mcc_mnc.mnc_digit_3 = (unsigned char )entry[2];
		} else {
			RTE_LOG_DP(ERR, CP, "MNC not found in the configuration file\n");
		}

		entry = rte_cfgfile_get_entry(file, sectionname, "TAC");
		if (entry) {
			dpInfo->key.tac = atoi(entry);
		} else {
			RTE_LOG_DP(ERR, CP, "TAC not found in the configuration file\n");
		}
		LIST_INSERT_HEAD(&cfg->dpList, dpInfo, dpentries);
	        entry = rte_cfgfile_get_entry(file, sectionname , "DNS_PRIMARY");
	        if (entry == NULL) {
	        	RTE_LOG_DP(ERR, CP, "DNS_PRIMARY default config is missing. \n");
		        entry = primary_dns;
	        }
	        inet_aton(entry, &dpInfo->dns_p);
 		set_dp_dns_primary(dpInfo);
	        RTE_LOG_DP(INFO, CP, "DNS_PRIMARY address is %s", inet_ntoa(dpInfo->dns_p));

	        entry = rte_cfgfile_get_entry(file, sectionname , "DNS_SECONDARY");
	        if (entry == NULL) {
	        	RTE_LOG_DP(ERR, CP, "DNS_SECONDARY default config is missing. \n");
		        entry = secondary_dns;
	        }
	        inet_aton(entry, &dpInfo->dns_s);
 		set_dp_dns_secondary(dpInfo);
	        RTE_LOG_DP(INFO, CP, "DNS_SECONDARY address is %s", inet_ntoa(dpInfo->dns_s));
	}
        return;
}

/* Given key find the DP. Once DP is found then return its dpId */
uint32_t
select_dp_for_key(struct dp_key *key)
{
	RTE_LOG_DP(INFO, CP, "Key - MCC = %d%d%d MNC %d%d%d TAC = %d\n", key->mcc_mnc.mcc_digit_1,
		   key->mcc_mnc.mcc_digit_2, key->mcc_mnc.mcc_digit_3, key->mcc_mnc.mnc_digit_1,
		   key->mcc_mnc.mnc_digit_2, key->mcc_mnc.mnc_digit_3, key->tac);

	struct dp_info *np;
	LIST_FOREACH(np, &appl_config->dpList, dpentries) {
#if 0
		if(bcmp((void *)(&np->key.mcc_mnc), (void *)(&key->mcc_mnc), 3) != 0)
			continue;
#endif
		if(np->key.tac != key->tac)
			continue;
		return np->dpId;
	}
	return DPN_ID; /* 0 is invalid DP */ 
}

uint8_t
resolve_upf_context_to_dpInfo(struct upf_context *upf, char *hostname, struct in_addr s1u_sgw_ip)
{
	struct dp_info *dp;
	LIST_FOREACH(dp, &appl_config->dpList, dpentries) {
		if (!strcmp(hostname, dp->dpName)) {
			dp->upf = upf;
			dp->s1u_sgw_ip = s1u_sgw_ip;
			upf->dpId = dp->dpId;
			return 1;
		}
	}
	return 0;
}

struct in_addr
fetch_s1u_sgw_ip(uint32_t dpId)
{
	struct dp_info *dp;
	struct in_addr a = { .s_addr = 0 };
	LIST_FOREACH(dp, &appl_config->dpList, dpentries) {
		if (dpId == dp->dpId) {
			return dp->s1u_sgw_ip;
		}
	}

	rte_panic("Could not find s1u ip address for dpid: %u\n", dpId);
	rte_exit(EXIT_FAILURE, "Could not find s1u ip address for dpid: %u\n", dpId);
	/* control should never reach here */
	RTE_SET_USED(a);
	return a;
}

struct upf_context *
fetch_upf_context(uint32_t dpId)
{
	struct dp_info *dp;
	LIST_FOREACH(dp, &appl_config->dpList, dpentries) {
		if (dpId == dp->dpId) {
			return dp->upf;
		}
	}

	rte_panic("Could not find upf_context for dpid: %u\n", dpId);
	/* control should never reach here */
	return NULL;
}

struct in_addr
fetch_dns_primary_ip(uint32_t dpId, bool *present)
{
	struct dp_info *dp;
	struct in_addr dns_p = { .s_addr = 0 };
	LIST_FOREACH(dp, &appl_config->dpList, dpentries) {
		if (dpId == dp->dpId) {
			*present = true;
			return dp->dns_p;
		}
	}
	*present = get_app_primary_dns(appl_config, &dns_p);
	return dns_p;
}

struct in_addr
fetch_dns_secondary_ip(uint32_t dpId, bool *present)
{
	struct dp_info *dp;
	struct in_addr dns_s = { .s_addr = 0 };
	LIST_FOREACH(dp, &appl_config->dpList, dpentries) {
		if (dpId == dp->dpId) {
			*present = true;
			return dp->dns_s;
		}
	}
	*present = get_app_secondary_dns(appl_config, &dns_s);
	return dns_s;
}
