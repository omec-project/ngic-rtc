/*
 * Copyright (c) 2019 Sprint
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

#ifndef __ENC_DEC_BITS_H__
#define __ENC_DEC_BITS_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t decode_bits(const uint8_t source[],
                const uint16_t offset, const uint16_t bit_count, uint16_t *decoded_bit_count);

//uint16_t encode_bits(const uint64_t value, const uint16_t offset,
//        const uint16_t bit_count, uint8_t destination[],
//        uint16_t destination_length);

uint16_t encode_bits(const uint64_t value, const uint16_t bit_count,
				uint8_t destination[], const uint16_t offset);

#ifdef __cplusplus
}
#endif

#endif // __ENC_DEC_BITS_H__
