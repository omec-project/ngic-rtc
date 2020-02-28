/*Copyright (c) 2019 Sprint
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

#include "../include/sv_ies_encoder.h"
#include "../include/enc_dec_bits.h"
#include "../include/gtp_ies_encoder.h"

/**
* Encodes stn_sr to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    stn_sr
* @return
*   number of encoded bytes.
*/
int encode_gtp_stn_sr_ie(gtp_stn_sr_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;

    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->nanpi, 8,  buf + (encoded/8), encoded % CHAR_SIZE);

    encoded += encode_bits(value->filler, 4,  buf + (encoded/8), encoded % CHAR_SIZE);

    encoded += encode_bits(value->number_digit, 4,  buf + (encoded/8), encoded % CHAR_SIZE);


    return encoded/CHAR_SIZE;
}

