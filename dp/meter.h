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

#ifndef _METER_H_
#define _METER_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane meter config and handlers.
 */

#include "../interface/ipc/dp_ipc_api.h"
#include <rte_mbuf.h>
#include <rte_meter.h>

struct msgbuf;

/**
 * @brief  : config meter entry.
 * @param  : msg_id, message id.
 * @param  : msg_payload, pointer to msg_payload
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
mtr_cfg_entry(int msg_id, struct rte_meter_srtcm *msg_payload);

/**
 * @brief  : Call back to add adc rules entry
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
cb_adc_entry_add(struct msgbuf *msg_payload);

/**
 * @brief  : Call back to parse msg to add meter rules
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
cb_meter_profile_entry_add(struct msgbuf *msg_payload);

/**
 * @brief  : Call back to add pcc rules entry
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
cb_pcc_entry_add(struct msgbuf *msg_payload);

//int
//cb_sdf_filter_entry_add(struct msgbuf *msg_payload);

#endif				/* _METER_H_ */
