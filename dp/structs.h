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

#ifndef _STRUCTS_H_
#define _STRUCTS_H_

/**
 * @brief  : Maintains pcc rule information
 */
struct pcc_id_precedence {
	uint32_t pcc_id;		/* pcc rule id */
	uint8_t precedence;		/* precedence */
	uint8_t gate_status;	/* gate status */
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : Maintains pcc rule information and entries
 */
struct filter_pcc_data {
	uint32_t entries;			/* number of elements in pcc_info */
	struct pcc_id_precedence *pcc_info;	/* pcc information */
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

//struct pdr_id_precedence {
//	uint8_t pdr_id;		/* pdr id */
//	uint8_t precedence;	/* precedence */
//	uint8_t gate_status;	/* gate status */
//} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));
//
//struct filter_sdf_data {
//	uint32_t entries;			/* number of elements in pcc_info */
//	struct pdr_id_precedence *pdr_info;	/* PDR information */
//} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

enum filter_pcc_type {
	FILTER_SDF,		/* SDF filter type */
	FILTER_ADC,		/* ADC filter type */
};

#endif /*_STRUCTS_H_ */
