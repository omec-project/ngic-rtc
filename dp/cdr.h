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

#ifndef _CDR_H
#define _CDR_H
/**
 * @file
 * This file contains function prototypes of User data
 * PCC and ADC charging records.
 */
#include "main.h"

#define CDR_CUR_EXTENSION ".cur"
#define CDR_CSV_EXTENSION ".csv"
#define DEFAULT_CDR_PATH  "./cdr/"

#define CDR_TIME_FIELD_INDEX 1
#define NUM_CDR_FIELDS       18

#define RECORD_TIME_FORMAT "%Y%m%d%H%M%S"
#define RECORD_TIME_LENGTH 16 /* buffer size for RECORD_TIME_FORMAT-ed string */
#define BUFFER_SIZE 4096


/* cdr field type callbacks
 * all callbacks must have the same parameters
 */
//typedef uint64_t (*cb_64_type) (struct dp_session_info *session,
//		struct chrg_data_vol *vol,
//		struct dp_pcc_rules *pcc_rule,
//		struct adc_rules *adc_rule);
//typedef uint32_t (*cb_32_type) (struct dp_session_info *session,
//		struct chrg_data_vol *vol,
//		struct dp_pcc_rules *pcc_rule,
//		struct adc_rules *adc_rule);
//typedef const char *(*cb_str_type) (struct dp_session_info *session,
//		struct chrg_data_vol *vol,
//		struct dp_pcc_rules *pcc_rule,
//		struct adc_rules *adc_rule);
//typedef uint8_t (*cb_8_type) (struct dp_session_info *session,
//		struct chrg_data_vol *vol,
//		struct dp_pcc_rules *pcc_rule,
//		struct adc_rules *adc_rule);

/**
 * @brief  : Maintains cdr related information
 */
struct cdr_field_t {
	const char *header;
	enum {CDR_VALUE, CDR_CB_64, CDR_CB_32, CDR_CB_8, CDR_CB_STR} type;
	const char *format_specifier;
	union {
		uint64_t *value;
		//cb_64_type cb_64;
		//cb_32_type cb_32;
		//cb_8_type cb_8;
		//cb_str_type cb_str;
	};
};

extern struct cdr_field_t cdr_fields[NUM_CDR_FIELDS];
extern char *cdr_path;

/**
 * @brief  : Creates file system path recursively
 * @param  : path, file system path
 * @param  : No param
 * @return : Returns nothing
 */
void
create_sys_path(char *path);

/**
 * @brief  : Initialize Charging data record file.
 * @param  : No param
 * @return : Returns nothing
 */
void
cdr_init(void);

/**
 * @brief  : Closes current cdr file and redirects any remaining output to stderr
 * @param  : No param
 * @return : Returns nothing
 */
void
cdr_close(void);

/**
 * @brief  : Sets configurable CDR path based on argument. String stored is ends with '/'
 * @param  : path, cdr path
 * @return : Returns nothing
 */
void
set_cdr_path(const char *path);

/**
 * @brief  : Coverts cdr ip to string
 *           Note: This function is not thread-safe
 * @param  : addr, IP Address
 * @return : IP address represented as string in statically allocated buffer
 */
const char *
iptoa(struct ip_addr addr);

/**
 * @brief  : Export PCC record to file
 * @param  : pcc_rule, PCC rule.
 * @param  : cdr, charge data record
 * @param  : session, bearer session info.
 * @return : Returns nothing
 */
//void
//export_session_pcc_record(struct dp_pcc_rules *pcc_rule,
//					struct ipcan_dp_bearer_cdr *cdr,
//					struct dp_session_info *session);

/**
 * @brief  : Export ADC record to file
 * @param  : adc_rule, ADC rule.
 * @param  : cdr, charge data record
 * @param  : session, bearer session info.
 * @return : Returns nothing
 */
//void
//export_session_adc_record(struct adc_rules *adc_rule,
//					struct ipcan_dp_bearer_cdr *cdr,
//					struct dp_session_info *session);

/**
 * @brief  : Export CDR record to file.
 * @param  : session, dp bearer session info.
 * @param  : name, string to identify the type of CDR.
 * @param  : id, identification number based on cdr type. It can be
 *           either bearerid, adc rule id, flow id or rating group.
 * @param  : charge_record
 *           cdr structure which holds the pkt counts and bytes.
 * @return : Returns nothing
 */
//void
//export_cdr_record(struct dp_session_info *session, char *name,
//			uint32_t id, struct ipcan_dp_bearer_cdr *charge_record);

/**
 * @brief  : Export CDR record to file.
 * @param  : session, dp bearer session info.
 * @param  : name, string to identify the type of CDR.
 * @param  : id, identification number based on cdr type. It can be
 *           either bearerid, adc rule id, flow id or rating group.
 * @param  : drops. drop state
 * @param  : No param
 * @return : Returns nothing
 */
//void export_mtr(struct dp_session_info *session, char *name,
//		uint32_t id, uint64_t drops);

/**
 * @brief  : Open Extended Charging data record file.
 *           This file contains function prototypes of User data
 *           charging extended records.
 * @param  : No param
 * @return : Returns nothing
 */
void
extended_cdr_init(void);

/**
 * @brief  : Export extended CDR record to file.
 * @param  : ue_ip, ue ip address
 * @param  : app_ip, application ip address
 * @param  : pcc_info, pcc rule information
 * @return : Returns nothing
 */
void
export_extended_cdr(char *ue_ip, char *app_ip, uint8_t pkt_mask,
		struct pcc_rules *pcc_info, int direction);

#ifdef TIMER_STATS
/**
 * @brief  : Initialize Timer stats data record file.
 * @param  : No param
 * @return : Returns nothing
 */
void
timer_stats_init(void);

#endif /* TIMER_STATS */
#endif /* _CDR_H */
