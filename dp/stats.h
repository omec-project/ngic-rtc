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

#ifndef _STATS_H_
#define _STATS_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane nic and pipeline stats.
 */
#include <rte_pipeline.h>
/**
 * Function to display IN and OUT stats for all pipelines from struct.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void display_stats(void);
/**
 * Function to get IN stats of a pipeline.
 *
 * @param p
 *	rte pipeline.
 * @param port_id
 *	port id.
 * @param istats
 *	struct rte_pipeline_port_in_stats param.
 *
 * @return
 *	None
 */
void pip_istats(struct rte_pipeline *p, char *name, uint8_t port_id,
		struct rte_pipeline_port_in_stats *istats);

/**
 * Function to fill IN stats for all pipelines in struct.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void pipeline_in_stats(void);

/**
 * Function to get OUT stats of a pipeline.
 *
 * @param p
 *	rte pipeline.
 * @param name
 *	pipeline name
 * @param port_id
 *	port id.
 * @param ostats
 *	struct rte_pipeline_port_out_stats param.
 *
 * @return
 *	None
 */
void pip_ostats(struct rte_pipeline *p, char *name, uint8_t port_id,
		struct rte_pipeline_port_out_stats *ostats);

/**
 * Function to fill OUT stats for all pipelines in struct.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void pipeline_out_stats(void);

/**
 * Function to display NIC stats.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void nic_in_stats(void);
/**
 * Function to display stats header parameters.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void print_headers(void);

/**
 * Core to print the pipeline stats.
 *
 * @param
 *	Unused
 *
 * @return
 *	None
 */
#ifdef NGCORE_SHRINK
void epc_stats_core(void);
#else
void epc_stats_core(__rte_unused void *args);
#endif

#endif /*_STATS_H_ */
