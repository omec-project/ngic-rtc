/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef DEBUG_STR_H
#define DEBUG_STR_H

/**
 * @file
 *
 * Debug strings for Control Plane warning/error messages.
 *
 * Functions to return strings corresponding to value or error codes as
 * specified by 3gpp Technical Specifications.
 *
 */

#include <stdint.h>

#include "gtpv2c_ie.h"

/**
 * Returns cause string from code value as defined by 3gpp TS 29.274.
 *
 * @param cause
 *   The cause coded value as specified by Table 8.4-1, TS 29.274.
 * @return
 *   String describing cause code value.
 */
const char *
cause_str(enum cause_value cause);

/**
 * Returns gtp message type string from type code value as defined by 3gpp TS
 * 29.274. Messages supported by this function may be incomplete.
 *
 * @param type
 *   GTPv2 message type value as specified by table 6.1-1 in 3gpp TS 29.274.
 * @return
 *   String describing GTPv2 message type.
 */
const char *
gtp_type_str(uint8_t type);

#endif /* DEBUG_STR_H */
