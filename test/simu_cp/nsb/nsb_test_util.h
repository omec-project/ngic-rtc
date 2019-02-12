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

#ifndef __NSB_TEST_UTIL_H
#define __NSB_TEST_UTIL_H
/**
 * Generate randum tunnel id
 *
 * @param ue
 *	ue - ue id.
 * @param bearer_id
 *	bearer_id - ue bearer id.
 * @param max_ue_sess
 *	max_ue_sess - max ue session.
 * @param teid
 *	teid - tunnel id.
 *
 * @return
 *	None
*/
void generate_teid(uint32_t ue, uint8_t bearer_id,
			uint32_t max_ue_sess, uint32_t *teid);

#endif
