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

#include <stdio.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>

#include "main.h"
#include "meter.h"
#include "interface.h"

#define APP_PKT_FLOW_POS                33
#define APP_PKT_COLOR_DSCP              15
#define APP_PKT_COLOR_DSTIP_LB         33
#define APP_PKT_COLOR_POS              APP_PKT_COLOR_DSCP

#if APP_PKT_FLOW_POS > 64 || APP_PKT_COLOR_POS > 64
#error Byte offset needs to be less than equal to 64
#endif
/** Traffic metering configuration */
#define APP_MODE_FWD                    0
#define APP_MODE_SRTCM_COLOR_BLIND      1
#define APP_MODE_SRTCM_COLOR_AWARE      2
#define APP_MODE_TRTCM_COLOR_BLIND      3
#define APP_MODE_TRTCM_COLOR_AWARE      4

#define APP_MODE	APP_MODE_SRTCM_COLOR_BLIND

#if APP_MODE == APP_MODE_FWD

#define FUNC_METER(a, b, c, d) (color, flow_id = flow_id,\
			pkt_len = pkt_len, time = time)
#define FUNC_CONFIG(a, b)
#define PARAMS	app_srtcm_params
#define FLOW_METER int

#elif APP_MODE == APP_MODE_SRTCM_COLOR_BLIND

#define FUNC_METER(a, b, c, d) rte_meter_srtcm_color_blind_check(a, b, c)
#define FUNC_CONFIG   rte_meter_srtcm_config
#define PARAMS        app_srtcm_params
#define PARAMS_AMBR   ambr_srtcm_params
#define FLOW_METER    struct rte_meter_srtcm

#elif (APP_MODE == APP_MODE_SRTCM_COLOR_AWARE)

#define FUNC_METER    rte_meter_srtcm_color_aware_check
#define FUNC_CONFIG   rte_meter_srtcm_config
#define PARAMS        app_srtcm_params
#define PARAMS_AMBR   ambr_srtcm_params
#define FLOW_METER    struct rte_meter_srtcm

#elif (APP_MODE == APP_MODE_TRTCM_COLOR_BLIND)

#define FUNC_METER(a, b, c, d) rte_meter_trtcm_color_blind_check(a, b, c)
#define FUNC_CONFIG  rte_meter_trtcm_config
#define PARAMS       app_trtcm_params
#define PARAMS_AMBR   ambr_trtcm_params
#define FLOW_METER   struct rte_meter_trtcm

#elif (APP_MODE == APP_MODE_TRTCM_COLOR_AWARE)

#define FUNC_METER   rte_meter_trtcm_color_aware_check
#define FUNC_CONFIG  rte_meter_trtcm_config
#define PARAMS       app_trtcm_params
#define PARAMS_AMBR   ambr_trtcm_params
#define FLOW_METER   struct rte_meter_trtcm

#else
#error Invalid value for APP_MODE
#endif

enum policer_action {
	GREEN = e_RTE_METER_GREEN,
	YELLOW = e_RTE_METER_YELLOW,
	RED = e_RTE_METER_RED,
	DROP = 3,
};
struct mtr_table {
	char name[MAX_LEN];
	struct rte_meter_srtcm_params *params;
	uint16_t num_entries;
	uint16_t max_entries;
};

static enum policer_action policer_table[e_RTE_METER_COLORS][e_RTE_METER_COLORS] = {
	{GREEN, YELLOW, RED},
	{DROP, YELLOW, RED},
	{DROP, DROP, RED}
};

/**
 * TRUE/FALSE
 */
enum boolean { FALSE, TRUE };

struct mtr_table mtr_profile_tbl;
FLOW_METER *app_flows;
FLOW_METER *ambr_flows;

/**
 * @brief  : Function to set color.
 * @param  : pkt_data, packet data
 * @param  : color
 * @return : Returns nothing
 */
static inline void
app_set_pkt_color(uint8_t *pkt_data, enum policer_action color)
{
	pkt_data[APP_PKT_COLOR_POS] = (uint8_t) color;
}

/**
 * @brief  : Process the packet to get action
 * @param  : m, srtcm context
 * @param  : pkt, mbuf pointer
 * @param  : time
 * @return : action to be performed on the packet
 */
static int
app_pkt_handle(struct rte_meter_srtcm *m, struct rte_mbuf *pkt,
				uint64_t time)
{
	uint8_t input_color, output_color;
	uint8_t *pkt_data = rte_pktmbuf_mtod(pkt, uint8_t *);
	uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt) - sizeof(struct ether_hdr);
	enum policer_action action;

	input_color = pkt_data[APP_PKT_COLOR_POS] & 0x3;
	/* color input is not used for blind modes */
	output_color =
		(uint8_t) FUNC_METER(m,
				 time,
				 pkt_len,
				 (enum rte_meter_color)input_color);

	/* Apply policing and set the output color */
	action = policer_table[input_color][output_color];

	app_set_pkt_color(pkt_data, action);

	return action;
}

/******************************************************************************/
/**
 * @brief  : Create meter param table.
 * @param  : mtr_tbl, table
 * @param  : table_name, table name
 * @param  : max_entries, max entries in table.
 * @return : Returns nothing
 */
static void
mtr_table_create(struct mtr_table *mtr_tbl,
			const char *table_name, uint32_t max_entries)
{

	mtr_tbl->num_entries = 0;
	mtr_tbl->max_entries = max_entries;
	strncpy(mtr_tbl->name, table_name, MAX_LEN);
	mtr_tbl->params = rte_zmalloc("params",
			sizeof(struct rte_meter_srtcm_params) * max_entries,
			RTE_CACHE_LINE_SIZE);
	if (mtr_tbl->params == NULL)
		rte_panic("Meter table memory alloc fail");
	clLog(clSystemLog, eCLSeverityInfo, "Meter table: %s created\n", mtr_tbl->name);
}

/**
 * @brief  : Destroy meter table.
 * @param  : mtr_tbl, table
 * @return : Returns nothing
 */
static void
mtr_table_destroy(struct mtr_table *mtr_tbl)
{
	rte_free(mtr_tbl->params);
	clLog(clSystemLog, eCLSeverityInfo, "Meter table: %s destroyed\n", mtr_tbl->name);
	memset(mtr_tbl, 0, sizeof(struct mtr_table));
}

/**
 * @brief  : Add entry in meter param table.
 * @param  : mtr_tbl, table
 * @param  : mtr_profile_index, meter profile index
 * @param  : mtr_param, meter parameters.
 * @return : Returns nothing
 */
static void
mtr_add_entry(struct mtr_table *mtr_tbl,
		uint16_t mtr_profile_index, struct mtr_params *mtr_param)
{
	struct rte_meter_srtcm_params *app_srtcm_params;

	if (mtr_tbl->num_entries == mtr_tbl->max_entries) {
		clLog(clSystemLog, eCLSeverityDebug,"MTR: Max entries reached\n");
		return;
	}
	if (mtr_profile_index >= mtr_tbl->max_entries) {
		clLog(clSystemLog, eCLSeverityDebug,"MTR: profile id greater than max entries\n");
		return;
	}

	app_srtcm_params = &mtr_tbl->params[mtr_profile_index];
	app_srtcm_params->cir = mtr_param->cir;
	app_srtcm_params->cbs = mtr_param->cbs;
	app_srtcm_params->ebs = mtr_param->ebs;
	mtr_tbl->num_entries++;
	clLog(clSystemLog, eCLSeverityInfo, "MTR_PROFILE ADD: index %d cir:%lu,"
			" cbs:%lu, ebs:%lu\n",
			mtr_profile_index, app_srtcm_params->cir,
			app_srtcm_params->cbs, app_srtcm_params->ebs);
}

/**
 * @brief  : Delete entry from meter table.
 * @param  : mtr_tbl, table
 * @param  : mtr_profile_index, meter profile index
 * @return : Returns nothing
 */
static void
mtr_del_entry(struct mtr_table *mtr_tbl, uint16_t mtr_profile_index)
{
	struct rte_meter_srtcm_params *app_srtcm_params;

	if (mtr_profile_index >= mtr_tbl->max_entries) {
		clLog(clSystemLog, eCLSeverityDebug,"MTR: profile id greater than max entries\n");
		return;
	}

	app_srtcm_params = &mtr_tbl->params[mtr_profile_index];
	app_srtcm_params->cir = 0;
	app_srtcm_params->cbs = 0;
	app_srtcm_params->ebs = 0;
	mtr_tbl->num_entries--;
}

int
mtr_cfg_entry(int msg_id, struct rte_meter_srtcm *msg_payload)
{
	struct rte_meter_srtcm *m;
	struct mtr_table *mtr_tbl = &mtr_profile_tbl;
	struct rte_meter_srtcm_params *app_srtcm_params =
					&mtr_tbl->params[msg_id];
	m = (struct rte_meter_srtcm *)msg_payload;
	/* NOTE: rte_malloc will be replaced by simple ring_alloc in future*/

	if ((msg_id == 0) || (app_srtcm_params->cir == 0)) {
		memset(m, 0, sizeof(struct rte_meter_srtcm));
		return -1;
	}

	rte_meter_srtcm_config(m, &mtr_tbl->params[msg_id]);

	clLog(clSystemLog, eCLSeverityDebug, "Configuring MTR index %d\n", msg_id);
	if ((m)->cir_period == 0)
		rte_exit(EXIT_FAILURE, "Meter config fail. cir_period is 0!!");
	return 0;
}

int
sdf_mtr_process_pkt(struct dp_sdf_per_bearer_info **sdf_info,
			void **adc_ue_info, uint64_t *adc_pkts_mask,
			struct rte_mbuf **pkt, uint32_t n, uint64_t *pkts_mask)
{
	uint64_t current_time;
	struct rte_meter_srtcm *m;
	uint32_t i;
	struct dp_sdf_per_bearer_info *psdf;
	struct dp_adc_ue_info *adc_ue;
	/* struct qos_info *qos; */ //GCC_Security flag
	enum policer_action action;

	for (i = 0; i < n; i++) {
		if (!ISSET_BIT(*pkts_mask, i))
			continue;
		psdf = (struct dp_sdf_per_bearer_info *)sdf_info[i];
		adc_ue = adc_ue_info[i];
		/* qos = &psdf->pcc_info.qos; */ //GCC_Security flag
		if (adc_ue)
			m = &adc_ue->mtr_obj;
		else
			m = &psdf->sdf_mtr_obj;

		current_time = rte_rdtsc();
		if (m->cir_period == 0) {
			clLog(clSystemLog, eCLSeverityDebug, "SDF: Either MTR not found or"
				" MTR not configured!!!\n");
			continue;
		}
		action = app_pkt_handle(m, pkt[i], current_time);
		if ((action == RED)
			|| (action == YELLOW)
			|| (action == DROP)) {
			RESET_BIT(*pkts_mask, i);
			psdf->sdf_mtr_drops += 1;
		}
	}
	return 0;
}

/**
 * @brief  : Checks if gbr profile is present in qos or not
 * @param  : qos, qos information
 * @param  : flow, data flow type
 * @return : True if gbr present, false otherwise
 */
static inline enum boolean
is_qci_gbr(struct qos_info *qos, uint32_t flow)
{
	if (flow == UL_FLOW) {
		if (qos->ul_gbr_profile_index != 0)
			return TRUE; /*skip AMBR metering.*/
	} else {
		if (qos->dl_gbr_profile_index != 0)
			return TRUE; /*skip AMBR metering.*/
	}
	return FALSE;
}

int
apn_mtr_process_pkt(struct dp_sdf_per_bearer_info **sdf_info, uint32_t flow,
			struct rte_mbuf **pkt, uint32_t n, uint64_t *pkts_mask)
{
	uint64_t current_time;
	struct rte_meter_srtcm *m;
	uint32_t i;
	struct dp_session_info *si;
	struct dp_sdf_per_bearer_info *psdf;
	struct ue_session_info *ue;
	enum policer_action action;
	uint64_t *mtr_drops;
	struct qos_info *qos;

	for (i = 0; i < n; i++) {
		if (!ISSET_BIT(*pkts_mask, i))
			continue;
		psdf = (struct dp_sdf_per_bearer_info *)sdf_info[i];
		qos = &psdf->pcc_info.qos;
		if (is_qci_gbr(qos, flow))
			continue;
		si = psdf->bear_sess_info;
		ue = si->ue_info_ptr;

		if (flow == UL_FLOW) {
			m = &ue->ul_apn_mtr_obj;
			mtr_drops = &ue->ul_apn_mtr_drops;
			clLog(clSystemLog, eCLSeverityDebug, "APN MTR UL LKUP: apn_mtr_id:%u, "
					"apn_mtr_obj:0x%"PRIx64"\n",
					ue->ul_apn_mtr_idx,
					(uint64_t)&ue->ul_apn_mtr_obj);
		} else {
			m = &ue->dl_apn_mtr_obj;
			mtr_drops = &ue->dl_apn_mtr_drops;
			clLog(clSystemLog, eCLSeverityDebug, "APN MTR DL LKUP: apn_mtr_id:%u, "
					"apn_mtr_obj:0x%"PRIx64"\n",
					ue->dl_apn_mtr_idx,
					(uint64_t)&ue->dl_apn_mtr_obj);
		}

		current_time = rte_rdtsc();
		if (m->cir_period == 0) {
			clLog(clSystemLog, eCLSeverityDebug, "APN: Either MTR not found or"
				" MTR not configured!!!\n");
			continue;
		}
		action = app_pkt_handle(m, pkt[i], current_time);
		if ((action == RED)
			|| (action == YELLOW)
			|| (action == DROP)) {
			RESET_BIT(*pkts_mask, i);
			*mtr_drops += 1;
		}
	}
	return 0;
}

int
dp_meter_profile_table_create(struct dp_id dp_id, uint32_t max_elements)
{
	if (mtr_profile_tbl.max_entries) {
		clLog(clSystemLog, eCLSeverityInfo, "Meter Profile table: \"%s\" exist\n",
					dp_id.name);
		return 0;
	}

	mtr_table_create(&mtr_profile_tbl, dp_id.name, max_elements);
	return 0;
}

int
dp_meter_profile_table_delete(struct dp_id dp_id)
{
	mtr_table_destroy(&mtr_profile_tbl);
	return 0;
}

int
dp_meter_profile_entry_add(struct dp_id dp_id, struct mtr_entry *entry)
{
	mtr_add_entry(&mtr_profile_tbl,
			entry->mtr_profile_index, &entry->mtr_param);
	return 0;
}

int
dp_meter_profile_entry_delete(struct dp_id dp_id, struct mtr_entry *entry)
{
	mtr_del_entry(&mtr_profile_tbl, entry->mtr_profile_index);
	return 0;
}


/******************** Call back functions **********************/
/**
 * @brief  : Call back to parse msg to create meter rules table
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
cb_meter_profile_table_create(struct msgbuf *msg_payload)
{
	return meter_profile_table_create(msg_payload->dp_id,
				msg_payload->msg_union.msg_table.max_elements);
}

/**
 * @brief  : Call back to parse msg to delete table
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
cb_meter_profile_table_delete(struct msgbuf *msg_payload)
{
	return meter_profile_table_delete(msg_payload->dp_id);
}

//ToDO; Remove for access this function in interface.c(PFCP)
//static
int cb_meter_profile_entry_add(struct msgbuf *msg_payload)
{
	return meter_profile_entry_add(msg_payload->dp_id,
					msg_payload->msg_union.mtr_entry);
}

/**
 * @brief  : Delete meter rules.
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
cb_meter_profile_entry_delete(struct msgbuf *msg_payload)
{
	return meter_profile_entry_delete(msg_payload->dp_id,
					msg_payload->msg_union.mtr_entry);
}

/**
 * Initialization of Meter Table Callback functions.
 */
void app_mtr_tbl_init(void)
{
	/* register msg type in DB*/
	iface_ipc_register_msg_cb(MSG_MTR_CRE, cb_meter_profile_table_create);
	iface_ipc_register_msg_cb(MSG_MTR_DES, cb_meter_profile_table_delete);
	iface_ipc_register_msg_cb(MSG_MTR_ADD, cb_meter_profile_entry_add);
	iface_ipc_register_msg_cb(MSG_MTR_DEL, cb_meter_profile_entry_delete);
}

