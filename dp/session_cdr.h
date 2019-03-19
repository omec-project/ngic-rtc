/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _SESION_CDR_H
#define _SESION_CDR_H
/**
 * @file
 * This file contains function prototypes of User data
 * charging per session records.
 */
#include "main.h"


/**
 * Open Session Charging data record file.
 */
void
sess_cdr_init(void);

/**
 * Clear the record file content.
 */
void
sess_cdr_reset(void);

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
#endif /* _SESION_CDR_H */
