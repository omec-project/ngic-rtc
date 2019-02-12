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

#include <string.h>

#include "util.h"

int
gtpv2c_buf_memcpy(gtpv2c_buffer_t *buf, void *src, uint16_t src_len)
{
	if (src_len > (GTPV2C_BUF_MAX_LEN - buf->len))
		return -1;

	memcpy(buf->val + buf->len, src, src_len);
	buf->len += src_len;

	return 0;
}

