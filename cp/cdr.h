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

#include <stdio.h>
#include <stdlib.h>

#include "cp.h"
#include "pfcp_session.h"

#define SAEGW_CDR		86
#define SGW_CDR			84
#define PGW_CDR			85

#define CDR_BUFF_SIZE		512
#define MCC_BUFF_SIZE		5
#define MNC_BUFF_SIZE		5
#define CDR_TIME_BUFF		16
#define CDR_PDN_BUFF		8
#define CDR_TRIGG_BUFF		16
#define MAX_ULI_LENGTH 256


#define VOLUME_LIMIT        "Volume_Limit"
#define TIME_LIMIT          "Time_Limit"
#define CDR_TERMINATION		"TERMINATION"
#define IPV4				"ipv4"
#define IPV6				"ipv6"

typedef enum cp_cdr_type {
	CDR_BY_URR,
	CDR_BY_SEC_RAT
}cdr_type_t;

/**
 * @brief  : Maintains CDR related information
 */

typedef struct cdr_param_t {

	cdr_type_t cdr_type;

	uint8_t bearer_id;

	/*applicable in case of usage report*/
	uint32_t urr_id;

	uint8_t record_type;

	int change_rat_type_flag;
	uint8_t rat_type;

	uint8_t selec_mode;

	uint64_t imsi;
	uint64_t seid;

	uint64_t ul_mbr;
	uint64_t dl_mbr;
	uint64_t ul_gbr;
	uint64_t dl_gbr;

	uint32_t urseqn;

	uint32_t data_start_time;
	uint32_t data_end_time;

	uint32_t start_time;
	uint32_t end_time;

	uint32_t duration_meas;

	uint8_t mcc_digit_2;
	uint8_t mcc_digit_1;
	uint8_t mnc_digit_3;
	uint8_t mnc_digit_2;
	uint8_t mnc_digit_1;

	struct in_addr ue_ip;
	struct in_addr sgw_addr;

	uint64_t data_volume_uplink;
	uint64_t data_volume_downlink;
	uint64_t total_data_volume;

	char trigg_buff[CDR_TRIGG_BUFF];

	uint8_t pdn_type;

}cdr;

/**
 * @brief  : Fill cdr info from pfcp-sess-rep-req msg
 * @param  : seid, session id
 * @param  : *usage_report,usage report in msg
 * @return : Returns 0 on success.
 */
int
fill_cdr_info_sess_rpt_req(uint64_t seid, pfcp_usage_rpt_sess_rpt_req_ie_t *usage_report);

/**
 * @brief  : Fill cdr info from pfcp-sess-mod-resp msg
 * @param  : seid, session id
 * @param  : *usage_report,usage report in msg
 * @return : Returns 0 on success.
 */
int
fill_cdr_info_sess_mod_resp(uint64_t seid, pfcp_usage_rpt_sess_mod_rsp_ie_t *usage_report);

/**
 * @brief  : Fill cdr info from pfcp-sess-del-resp msg
 * @param  : seid, session id
 * @param  : *usage_report,usage report in msg
 * @return : Returns 0 on success.
 */
int
fill_cdr_info_sess_del_resp(uint64_t seid, pfcp_usage_rpt_sess_del_rsp_ie_t *usage_report);

/**
 * @brief  : Fill cause code to buffer in form of string
 * @param  : *usage_rpt_trig,flag containing cause code
 * @param  : (out param) buf,contain string of cause code
 * @return : Returns nothing
 */
void
urr_cause_code_to_str(pfcp_usage_rpt_trig_ie_t *usage_rpt_trig, char *buf);

/**
 * @brief  : Check pdn type & convert to string
 * @param  : pdn_type,ipv4/ipv6
 * @param  : (out param) buf,contain pdn type string
 * @return : Returns nothing
 */
void
check_pdn_type(pdn_type_ie *pdn_type, char *buf);

/**
 * @brief  : Genearet CDR into buffer & push to redis server
 * @param  : fill_cdr, structure containing cdr info
 * @return : Returns 0 on success,else -1 on failure.
 */
int
generate_cdr_info(cdr *fill_cdr);

/**
 * @brief  : Generate CDR seq no
 * @param  : nothing
 * @return : Returns unique cdr id
 */
uint32_t
generate_cdr_seq_no(void);

/**
 * @brief  : Get bearer no for pdn
 * @param  : urr_id
 * @param  : pdn
 * @return : Returns bearer index on
 *           success,else -1
 */
int
get_bearer_index_by_urr_id(uint32_t urr_id, pdn_connection *pdn);

/**
 * @brief  : Get rule name on the basis of urr id
 * @param  : urr_id
 * @param  : bearer, pointer to bearer
 * @param  : rule_name, out parameter
 * @return : Returns 0 on
 *           success,else -1
 */
int
get_rule_name_by_urr_id(uint32_t urr_id, eps_bearer *bearer,
								char *rule_name);
/**
 * @brief  : Fill different ULI parameter in buffer
 * @param  : uli, pointer to User Location Info in context
 * @param  : uli_buff, buffer as a out parameter
 * @return : Returns 0 on success
 *
 */

int
fill_user_loc_info(user_loc_info_t *uli, char *uli_buff);
