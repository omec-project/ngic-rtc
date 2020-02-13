/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include <stdint.h>

void generate_teid(uint32_t ue, uint8_t bearer_id,
			uint32_t max_ue_sess, uint32_t *teid)
{
	*teid = max_ue_sess - ue + bearer_id;
}
