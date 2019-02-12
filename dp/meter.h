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
