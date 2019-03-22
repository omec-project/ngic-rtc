/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
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
typedef uint64_t (*cb_64_type) (struct dp_session_info *session,
		struct chrg_data_vol *vol,
		struct dp_pcc_rules *pcc_rule,
		struct adc_rules *adc_rule);
typedef uint32_t (*cb_32_type) (struct dp_session_info *session,
		struct chrg_data_vol *vol,
		struct dp_pcc_rules *pcc_rule,
		struct adc_rules *adc_rule);
typedef const char *(*cb_str_type) (struct dp_session_info *session,
		struct chrg_data_vol *vol,
		struct dp_pcc_rules *pcc_rule,
		struct adc_rules *adc_rule);
typedef uint8_t (*cb_8_type) (struct dp_session_info *session,
		struct chrg_data_vol *vol,
		struct dp_pcc_rules *pcc_rule,
		struct adc_rules *adc_rule);

struct cdr_field_t {
	const char *header;
	enum {CDR_VALUE, CDR_CB_64, CDR_CB_32, CDR_CB_8, CDR_CB_STR} type;
	const char *format_specifier;
	union {
		uint64_t *value;
		cb_64_type cb_64;
		cb_32_type cb_32;
		cb_8_type cb_8;
		cb_str_type cb_str;
	};
};

extern struct cdr_field_t cdr_fields[NUM_CDR_FIELDS];
extern char *cdr_path;

/**
* Creates file system path recursively
*/
void
create_sys_path(char *path);

/**
 * Initialize Charging data record file.
 */
void
cdr_init(void);

/**
 * Closes current cdr file and redirects any remaining output to stderr
 */
void
cdr_close(void);

/**
 * Sets configurable CDR path based on argument. String stored is ends with '/'.
 * @param path
 */
void
set_cdr_path(const char *path);

/**
 *
 * @param addr
 *	IP Address
 * @return
 *	IP address represented as string in statically allocated buffer
 *
 * This function is not thread-safe
 */
const char *
iptoa(struct ip_addr addr);


/**
 * Export PCC record to file
 * @param pcc_rule
 *	PCC rule.
 * @param cdr
 *	charge data record.
 * @param session
 *	bearer session info.
 *
 * @return
 * Void
 */
void
export_session_pcc_record(struct dp_pcc_rules *pcc_rule,
					struct ipcan_dp_bearer_cdr *cdr,
					struct dp_session_info *session);

/**
 * Export ADC record to file
 * @param adc_rule
 *	ADC rule.
 * @param cdr
 *	charge data record.
 * @param session
 *	bearer session info.
 *
 * @return
 * Void
 */
void
export_session_adc_record(struct adc_rules *adc_rule,
					struct ipcan_dp_bearer_cdr *cdr,
					struct dp_session_info *session);
/**
 * Export CDR record to file.
 * @param session
 *	dp bearer session.
 * @param name
 *	string to identify the type of CDR.
 * @param id
 *	identification number based on cdr type. It can be
 *	either bearerid, adc rule id, flow id or rating group.
 * @param charge_record
 *	cdr structure which holds the pkt counts and bytes.
 *
 * @return
 * Void
 */
void
export_cdr_record(struct dp_session_info *session, char *name,
			uint32_t id, struct ipcan_dp_bearer_cdr *charge_record);

/**
 * Export CDR record to file.
 * @param session
 *     dp bearer session.
 * @param name
 *     string to identify the type of CDR.
 * @param id
 *     identification number based on cdr type. It can be
 *     either bearerid, adc rule id, flow id or rating group.
 * @param drops
 *     drop stats.
 *
 * @return
 * Void
 */
void export_mtr(struct dp_session_info *session, char *name,
		uint32_t id, uint64_t drops);


/**
 * @file
 * This file contains function prototypes of User data
 * charging extended records.
 */

/**
 * Open Extended Charging data record file.
 */
void
extended_cdr_init(void);

/**
 * Export extended CDR record to file.
 * @param ue_ip
 *	ue ip.
 * @param app_ip
 *	application ip.
 * @param pcc_info
 *	pcc rule information
 *
 * @return
 * Void
 */
void
export_extended_cdr(char *ue_ip, char *app_ip, uint8_t pkt_mask,
		struct pcc_rules *pcc_info, int direction);

#ifdef TIMER_STATS
/**
 * Timer stats data record file.
 */
void
timer_stats_init(void);

#endif /* TIMER_STATS */
#endif /* _CDR_H */
