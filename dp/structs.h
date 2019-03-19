/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _STRUCTS_H_
#define _STRUCTS_H_

struct pcc_id_precedence {
	uint32_t pcc_id;		/* pcc rule id */
	uint8_t precedence;		/* precedence */
	uint8_t gate_status;	/* gate status */
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

struct filter_pcc_data {
	uint32_t entries;					/* number of elements in pcc_info */
	struct pcc_id_precedence *pcc_info;	/* pcc information */
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

enum filter_pcc_type {
	FILTER_SDF,		/* SDF filter type */
	FILTER_ADC,		/* ADC filter type */
};

#endif /*_STRUCTS_H_ */
