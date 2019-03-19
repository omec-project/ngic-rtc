/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _METER_H_
#define _METER_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane meter config and handlers.
 */
#include <rte_mbuf.h>
#include <rte_meter.h>

/**
 * config meter entry.
 *
 * @param msg_id
 *	message id.
 * @param msg_payload
 *	pointer to msg_payload
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
mtr_cfg_entry(int msg_id, struct rte_meter_srtcm *msg_payload);

#endif				/* _METER_H_ */
