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
 * @brief  : Returns cause string from code value as defined by 3gpp TS 29.274.
 * @param  : cause
 *           The cause coded value as specified by Table 8.4-1, TS 29.274.
 * @return : String describing cause code value.
 */
const char *
cause_str(enum cause_value cause);

/**
 * @brief  : Returns gtp message type string from type code value as defined by 3gpp TS
 *           29.274. Messages supported by this function may be incomplete.
 * @param  : type
 *           GTPv2 message type value as specified by table 6.1-1 in 3gpp TS 29.274.
 * @return : String describing GTPv2 message type.
 */
const char *
gtp_type_str(uint8_t type);

/**
 * @brief  : Returns Gx message type string from type code value as defined by 3gpp TS
 *           29.212. Messages supported by this function may be incomplete.
 * @param  : type
 *           Gx message type value as specified by seaction 5.6 in 3gpp TS 29.212.
 * @return : String describing Gx message type.
 */
const char *
gx_type_str(uint8_t type);
#endif /* DEBUG_STR_H */
