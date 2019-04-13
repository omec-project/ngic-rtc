
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_cfgfile.h>

#include "cp_config.h"

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

#define GLOBAL_ENTRIES                    "GLOBAL"
#define STATIC_PGWC_ENTRIES               "STATIC_PGWC"
#define STATIC_SAEGWC_SGWC_ENTRIES  "STATIC_SAEGWC_SGWC"

#define CP_TYPE          "CP_TYPE"
#define MME_S11_IPS      "MME_S11_IP"
#define MME_S11_PORTS    "MME_S11_PORT"
#define SGW_S11_IPS      "SGW_S11_IP"
#define SGW_S11_PORTS    "SGW_S11_PORT"
#define SGWC_S5S8_IPS    "SGWC_S5S8_IP"
#define SGWC_S5S8_PORTS  "SGWC_S5S8_PORT"
#define SGW_PFCP_IPS     "SGW_PFCP_IP"
#define SGW_PFCP_PORTS   "SGW_PFCP_PORT"
#define SGWU_PFCP_IPS    "SGWU_PFCP_IP"
#define SGWU_PFCP_PORTS  "SGWU_PFCP_PORT"
#define PGWC_S5S8_IPS    "PGWC_S5S8_IP"
#define PGWC_S5S8_PORTS  "PGWC_S5S8_PORT"
#define PGWU_PFCP_IPS    "PGWU_PFCP_IP"
#define PGWU_PFCP_PORTS  "PGWU_PFCP_PORT"
#define PGWC_PFCP_IPS    "PGWC_S5S8_IP"
#define PGWC_PFCP_PORTS  "PGWC_S5S8_PORT"
#define SPGWU_PFCP_IPS   "SPGWU_PFCP_IP"
#define SPGWU_PFCP_PORTS "SPGWU_PFCP_PORT"

//VS: Restoration Parameters
#define TRANSMIT_TIMER "TRANSMIT_TIMER" 
#define PERIODIC_TIMER "PERIODIC_TIMER"
#define TRANSMIT_COUNT "TRANSMIT_COUNT"

void
config_cp_ip_port(pfcp_config_t *pfcp_config)
{
	struct rte_cfgfile_entry *global_entries     = NULL;
	struct rte_cfgfile_entry *pgwu_entries       = NULL;
	struct rte_cfgfile_entry *spgwu_sgwu_entries = NULL;
	uint32_t num_global_entries;
	uint32_t num_pgwu_entries;
	uint32_t num_spgwu_sgwu_entries;
	uint32_t i = 0;

	struct rte_cfgfile *file = rte_cfgfile_load(STATIC_CP_FILE, 0);
	if (file == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot load configuration file %s\n",
				STATIC_CP_FILE);
	}

	RTE_LOG(DEBUG, CP, "PFCP Config Parsing %s\n", STATIC_CP_FILE);

	//Reading GLOBAL params
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
		RTE_LOG(DEBUG,CP,"[%s] = %s\n", global_entries[i].name,
				global_entries[i].value);
		if(strncmp(CP_TYPE, global_entries[i].name, strlen(CP_TYPE)) == 0)
			pfcp_config->cp_type = (uint8_t)atoi(global_entries[i].value);

		/* VS: Parse timer and counter values from cp.cfg */
		if(strncmp(TRANSMIT_TIMER, global_entries[i].name, strlen(TRANSMIT_TIMER)) == 0)
			pfcp_config->transmit_timer = (int)atoi(global_entries[i].value);

		if(strncmp(PERIODIC_TIMER, global_entries[i].name, strlen(PERIODIC_TIMER)) == 0)
			pfcp_config->periodic_timer = (int)atoi(global_entries[i].value);

		if(strncmp(TRANSMIT_COUNT, global_entries[i].name, strlen(TRANSMIT_COUNT)) == 0)
			pfcp_config->transmit_cnt = (uint8_t)atoi(global_entries[i].value);
	}
	rte_free(global_entries);
	RTE_LOG(DEBUG, CP, "CP_TYPE[%d]\n",pfcp_config->cp_type);

	//Reading SAEGWC_SGWC IP's
	if(pfcp_config->cp_type == SGWC || pfcp_config->cp_type == SAEGWC){

		num_spgwu_sgwu_entries = rte_cfgfile_section_num_entries(file, STATIC_SAEGWC_SGWC_ENTRIES);
		if (num_spgwu_sgwu_entries > 0) {
			spgwu_sgwu_entries = rte_malloc_socket(NULL,
					sizeof(struct rte_cfgfile_entry) *
					num_spgwu_sgwu_entries,
					RTE_CACHE_LINE_SIZE, rte_socket_id());
		}
		if (spgwu_sgwu_entries == NULL) {
			rte_panic("Error configuring saegwc_sgwc entry of %s\n",
					STATIC_CP_FILE);
		}
		rte_cfgfile_section_entries(file, STATIC_SAEGWC_SGWC_ENTRIES, spgwu_sgwu_entries,
				num_spgwu_sgwu_entries);

		uint32_t mme_s11_ip_idx    = 0, mme_s11_port_idx    = 0;
		uint32_t sgwu_pfcp_ip_idx  = 0, sgwu_pfcp_port_idx  = 0;
		uint32_t spgwu_pfcp_ip_idx = 0, spgwu_pfcp_port_idx = 0;
		uint32_t pgwc_s5s8_ip_idx  = 0, pgwc_s5s8_port_idx  = 0;
		uint32_t sgwc_s11_ip_idx   = 0, sgwc_s11_port_idx   = 0;
		uint32_t sgwc_s5s8_ip_idx  = 0, sgwc_s5s8_port_idx  = 0;
		uint32_t sgwc_pfcp_ip_idx  = 0, sgwc_pfcp_port_idx  = 0;

		for (i = 0; i < num_spgwu_sgwu_entries; i++) {
			RTE_LOG(DEBUG,CP,"[%s] = %s\n", spgwu_sgwu_entries[i].name,
					spgwu_sgwu_entries[i].value);
			if (strncmp(SGWU_PFCP_IPS , spgwu_sgwu_entries[i].name,
						strlen(SGWU_PFCP_IPS)) == 0) {
				inet_aton(spgwu_sgwu_entries[i].value, 
						&(pfcp_config->sgwu_pfcp_ip[sgwu_pfcp_ip_idx]));
				RTE_LOG(DEBUG, CP, "SGWU_PFCP_IP_[%s]\n",
						inet_ntoa(pfcp_config->sgwu_pfcp_ip[sgwu_pfcp_ip_idx]));
				sgwu_pfcp_ip_idx++;
			} else if (strncmp(SGWU_PFCP_PORTS, spgwu_sgwu_entries[i].name,
						strlen(SGWU_PFCP_PORTS)) == 0) {
				pfcp_config->sgwu_pfcp_port[sgwu_pfcp_port_idx] =
					(uint16_t)atoi(spgwu_sgwu_entries[i].value);
				RTE_LOG(DEBUG, CP, "SGWU_PFCP_PORT_[%d]\n", 
						pfcp_config->sgwu_pfcp_port[sgwu_pfcp_port_idx]);
				sgwu_pfcp_port_idx++;
			} else if (strncmp(SPGWU_PFCP_IPS, spgwu_sgwu_entries[i].name,
						strlen(SPGWU_PFCP_IPS)) == 0) {
				inet_aton(spgwu_sgwu_entries[i].value,
						&(pfcp_config->spgwu_pfcp_ip[spgwu_pfcp_ip_idx]));
				RTE_LOG(DEBUG, CP, "SPGWU_PFCP_IP_[%s]\n", 
						inet_ntoa(pfcp_config->spgwu_pfcp_ip[spgwu_pfcp_ip_idx]));
				spgwu_pfcp_ip_idx++;
			} else if (strncmp(SPGWU_PFCP_PORTS, spgwu_sgwu_entries[i].name,
						strlen(SPGWU_PFCP_PORTS)) == 0) {
				pfcp_config->spgwu_pfcp_port[spgwu_pfcp_port_idx] = 
					(uint16_t)atoi(spgwu_sgwu_entries[i].value);
				RTE_LOG(DEBUG, CP, "SPGWU_PFCP_PORT_[%d]\n", 
						pfcp_config->spgwu_pfcp_port[spgwu_pfcp_port_idx]);
				spgwu_pfcp_port_idx++;
			} else if (strncmp(MME_S11_IPS, spgwu_sgwu_entries[i].name,
						strlen(MME_S11_IPS)) == 0) {
				inet_aton(spgwu_sgwu_entries[i].value, 
						&(pfcp_config->mme_s11_ip[mme_s11_ip_idx]));
				RTE_LOG(DEBUG, CP, "MME_S11_IP_[%s]\n",
						inet_ntoa(pfcp_config->mme_s11_ip[mme_s11_ip_idx]));
				mme_s11_ip_idx++;

			} else if (strncmp(MME_S11_PORTS, spgwu_sgwu_entries[i].name,
						strlen(MME_S11_PORTS)) == 0) {
				pfcp_config->mme_s11_port[mme_s11_port_idx] = 
					(uint16_t)atoi(spgwu_sgwu_entries[i].value);
				RTE_LOG(DEBUG, CP, "MME_S11_PORT[%d]\n", pfcp_config->mme_s11_port[mme_s11_port_idx]);
				mme_s11_port_idx++;
			} else if (strncmp(PGWC_S5S8_IPS, spgwu_sgwu_entries[i].name,
						strlen(PGWC_S5S8_IPS)) == 0) {
				inet_aton(spgwu_sgwu_entries[i].value,&(pfcp_config->pgwc_s5s8_ip[pgwc_s5s8_ip_idx]));
				RTE_LOG(DEBUG, CP, "PGWC_S5S8_IP_[%s]\n",
						inet_ntoa(pfcp_config->pgwc_s5s8_ip[pgwc_s5s8_ip_idx]));
				pgwc_s5s8_ip_idx++;
			} else if (strncmp(PGWC_S5S8_PORTS, spgwu_sgwu_entries[i].name,
						strlen(PGWC_S5S8_PORTS)) == 0) {
				pfcp_config->pgwc_s5s8_port[pgwc_s5s8_port_idx] =
					(uint16_t)atoi(spgwu_sgwu_entries[i].value);
				RTE_LOG(DEBUG, CP, "PGWC_S5S8_PORT_[%d]\n",
						pfcp_config->pgwc_s5s8_port[pgwc_s5s8_port_idx]);
				pgwc_s5s8_port_idx++;
			} else if (strncmp(SGW_S11_IPS, spgwu_sgwu_entries[i].name,
						strlen(SGW_S11_IPS)) == 0) {
				inet_aton(spgwu_sgwu_entries[i].value,
						&(pfcp_config->sgwc_s11_ip[sgwc_s11_ip_idx]));
				RTE_LOG(DEBUG, CP, "SGW_S11_IP[%s]\n", 
						inet_ntoa(pfcp_config->sgwc_s11_ip[sgwc_s11_ip_idx]));
				sgwc_s11_ip_idx++;
			}else if (strncmp(SGW_S11_PORTS, spgwu_sgwu_entries[i].name,
						strlen(SGW_S11_PORTS)) == 0) {
				pfcp_config->sgwc_s11_port[sgwc_s11_port_idx] =
						(uint16_t)atoi(spgwu_sgwu_entries[i].value);
				RTE_LOG(DEBUG, CP, "SGW_S11_PORT[%d]\n",
						pfcp_config->sgwc_s11_port[sgwc_s11_port_idx]);
				sgwc_s11_port_idx++;
			} else if (strncmp(SGWC_S5S8_IPS, spgwu_sgwu_entries[i].name,
						strlen(SGWC_S5S8_IPS)) == 0) {
				inet_aton(spgwu_sgwu_entries[i].value,
						&(pfcp_config->sgwc_s5s8_ip[sgwc_s5s8_ip_idx]));
				RTE_LOG(DEBUG, CP, "SGWC_S5S8_IP[%s]\n",
						inet_ntoa(pfcp_config->sgwc_s5s8_ip[sgwc_s5s8_ip_idx]));
				sgwc_s5s8_ip_idx++;
			} else if (strncmp(SGWC_S5S8_PORTS, spgwu_sgwu_entries[i].name,
						strlen(SGWC_S5S8_PORTS)) == 0) {
				pfcp_config->sgwc_s5s8_port[sgwc_s5s8_port_idx] = 
							(uint16_t)atoi(spgwu_sgwu_entries[i].value);
				RTE_LOG(DEBUG, CP, "SGWC_S5S8_PORT[%d]\n",
							pfcp_config->sgwc_s5s8_port[sgwc_s5s8_port_idx]);
				sgwc_s5s8_port_idx++;
			} else if (strncmp(SGW_PFCP_IPS, spgwu_sgwu_entries[i].name,
						strlen(SGW_PFCP_IPS)) == 0) {
				inet_aton(spgwu_sgwu_entries[i].value,&(pfcp_config->sgwc_pfcp_ip[sgwc_pfcp_ip_idx]));
				RTE_LOG(DEBUG, CP, "SGW_PFCP_IP[%s]\n", inet_ntoa(pfcp_config->sgwc_pfcp_ip[sgwc_pfcp_ip_idx]));
				sgwc_pfcp_ip_idx++;
			} else if (strncmp(SGW_PFCP_PORTS, spgwu_sgwu_entries[i].name,
						strlen(SGW_PFCP_PORTS)) == 0) {
				pfcp_config->sgwc_pfcp_port[sgwc_pfcp_port_idx] = (uint16_t)atoi(spgwu_sgwu_entries[i].value);
				RTE_LOG(DEBUG, CP, "SGW_PFCP_PORT[%d]\n",pfcp_config->sgwc_pfcp_port[sgwc_pfcp_port_idx]);
				sgwc_pfcp_port_idx++;
			}
		}
		pfcp_config->num_mme   = mme_s11_ip_idx;
		pfcp_config->num_sgwc  = sgwc_pfcp_ip_idx;
		pfcp_config->num_pgwc  = pgwc_s5s8_ip_idx;
		pfcp_config->num_sgwu  = sgwu_pfcp_ip_idx;
		pfcp_config->num_spgwu = spgwu_pfcp_ip_idx;

		rte_free(spgwu_sgwu_entries);
	} else if (pfcp_config->cp_type == PGWC){
		num_pgwu_entries = rte_cfgfile_section_num_entries(file, STATIC_PGWC_ENTRIES);
		if (num_pgwu_entries > 0) {
			pgwu_entries = rte_malloc_socket(NULL,
					sizeof(struct rte_cfgfile_entry) *
					num_pgwu_entries,
					RTE_CACHE_LINE_SIZE, rte_socket_id());
		}

		if (pgwu_entries == NULL) {
			rte_panic("Error configuring pgwc entry of %s\n",
					STATIC_CP_FILE);
		}
		rte_cfgfile_section_entries(file, STATIC_PGWC_ENTRIES, pgwu_entries,
				num_pgwu_entries);

		uint32_t pgwu_pfcp_ip_idx = 0 , pgwu_pfcp_port_idx = 0;
		uint32_t sgwc_s5s8_ip_idx = 0 , sgwc_s5s8_port_idx = 0;
		uint32_t pgwc_pfcp_ip_idx = 0 , pgwc_pfcp_port_idx = 0;
		uint32_t pgwc_s5s8_ip_idx = 0 , pgwc_s5s8_port_idx = 0;

		for (i = 0; i < num_pgwu_entries; ++i) {
			RTE_LOG(DEBUG,CP,"[%s] = %s\n", pgwu_entries[i].name,
					pgwu_entries[i].value);

			if(strncmp(PGWU_PFCP_IPS, pgwu_entries[i].name, strlen(PGWU_PFCP_IPS)) == 0){
				inet_aton(pgwu_entries[i].value, 
						&(pfcp_config->pgwu_pfcp_ip[pgwu_pfcp_ip_idx]));
				RTE_LOG(DEBUG, CP, "PGWU_PFCP_IP_[%s]\n",
					inet_ntoa(pfcp_config->pgwu_pfcp_ip[pgwu_pfcp_ip_idx]));
				pgwu_pfcp_ip_idx++;
			} else if (strncmp(PGWU_PFCP_PORTS, pgwu_entries[i].name,
						strlen(PGWU_PFCP_PORTS)) == 0){
				pfcp_config->pgwu_pfcp_port[pgwu_pfcp_port_idx] =
					(uint16_t)atoi(pgwu_entries[i].value);
				RTE_LOG(DEBUG, CP, "PGWU_PFCP_PORT_[%d]\n",
						pfcp_config->pgwu_pfcp_port[pgwu_pfcp_port_idx]);
				pgwu_pfcp_port_idx++;
			} else if (strncmp(SGWC_S5S8_IPS, pgwu_entries[i].name,
						strlen(SGWC_S5S8_IPS)) == 0){
				inet_aton(pgwu_entries[i].value,
						&(pfcp_config->sgwc_s5s8_ip[sgwc_s5s8_ip_idx]));
				RTE_LOG(DEBUG, CP, "SGWC_S5S8_IP_[%s]\n",
						inet_ntoa(pfcp_config->sgwc_s5s8_ip[sgwc_s5s8_ip_idx]));
				sgwc_s5s8_ip_idx++;
			} else if (strncmp(SGWC_S5S8_PORTS, pgwu_entries[i].name,
						strlen(SGWC_S5S8_PORTS)) == 0){
				pfcp_config->pgwu_pfcp_port[sgwc_s5s8_port_idx] =
						(uint16_t)atoi(pgwu_entries[i].value);
				RTE_LOG(DEBUG, CP, "SGWC_S5S8_PORT_[%d]\n",
						pfcp_config->sgwc_s5s8_port[sgwc_s5s8_port_idx]);
				sgwc_s5s8_port_idx++;
			} else if (strncmp(PGWC_PFCP_IPS, pgwu_entries[i].name,
						strlen(PGWC_PFCP_IPS)) == 0){
				inet_aton(pgwu_entries[i].value,
						&(pfcp_config->pgwc_pfcp_ip[pgwc_pfcp_ip_idx]));
				RTE_LOG(DEBUG, CP, "PGWC_PFCP_IP_[%s]\n",
						inet_ntoa(pfcp_config->pgwc_pfcp_ip[pgwc_pfcp_ip_idx]));
				pgwc_pfcp_ip_idx++;
			} else if (strncmp(PGWC_PFCP_PORTS, pgwu_entries[i].name,
						strlen(PGWC_PFCP_PORTS)) == 0){
				pfcp_config->pgwc_pfcp_port[pgwc_pfcp_port_idx] =
						(uint16_t)atoi(pgwu_entries[i].value) ;
				RTE_LOG(DEBUG, CP, "PGWC_PFCP_PORT_[%d]\n", 
						pfcp_config->pgwc_pfcp_port[pgwc_pfcp_port_idx]);
				pgwc_pfcp_port_idx++;
			} else if (strncmp(PGWC_S5S8_IPS, pgwu_entries[i].name,
							strlen(PGWC_S5S8_IPS)) == 0){
				inet_aton(pgwu_entries[i].value,
							&(pfcp_config->pgwc_s5s8_ip[pgwc_s5s8_ip_idx]));
				RTE_LOG(DEBUG, CP, "PGWC_S5S8_IP_[%s]\n",
						inet_ntoa(pfcp_config->pgwc_s5s8_ip[pgwc_s5s8_ip_idx]));
				pgwc_s5s8_ip_idx++;
			} else if (strncmp(PGWC_S5S8_PORTS, pgwu_entries[i].name,
						strlen(PGWC_S5S8_PORTS)) == 0){
				pfcp_config->pgwc_s5s8_port[pgwc_s5s8_port_idx] =
								(uint16_t)atoi(pgwu_entries[i].value);
				RTE_LOG(DEBUG, CP, "PGWC_S5S8_PORT_[%d]\n",
							pfcp_config->pgwc_s5s8_port[pgwc_s5s8_port_idx]);
				pgwc_s5s8_port_idx++;
			}
		}

		pfcp_config->num_sgwc = sgwc_s5s8_ip_idx;
		pfcp_config->num_pgwc = pgwc_pfcp_ip_idx;
		pfcp_config->num_pgwu = pgwu_pfcp_ip_idx;
		rte_free(pgwu_entries);
	} else {
		rte_exit(EXIT_FAILURE, "CP Type: SGWC=01; PGWC=02; SAEGWC=03 %s\n",STATIC_CP_FILE);
	}
	return;
}
