/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _LIBGTPV2C_UTIL_H_
#define _LIBGTPV2C_UTIL_H_

#include <stdint.h>

#define GTPV2C_BUF_MAX_LEN UINT16_MAX

#pragma pack(1)

typedef struct gtpv2c_buffer_t {
	uint8_t val[GTPV2C_BUF_MAX_LEN];
	uint16_t len;
} gtpv2c_buffer_t;

#pragma pack()

/**
 * Copies values to gtpv2c buffer and updates internal
 * book-keeping counters.
 * @param buf
 *   buffer where values will be copied
 * @param src
 *   buffer to be copied.
 * @param src_len
 *   length of buffer to be copied.
 * @return
 *   0 on success, -1 on failure.
 */
int
gtpv2c_buf_memcpy(gtpv2c_buffer_t *buf, void *src, uint16_t src_len);

#endif /* _LIBGTPV2C_UTIL_H_ */
