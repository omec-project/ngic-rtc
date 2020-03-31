/*
 * Copyright (c) 2019 Intel Corporation
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

#include "gtpv2c.h"


int
process_echo_request(gtpv2c_header_t *gtpv2c_rx, gtpv2c_header_t *gtpv2c_tx)
{
	/* Due to the union & structure alignments in the gtpv2c_header_t, the
	 * sequence number would always be present in the has_teid.seq memory
	 */
	if (gtpv2c_rx->gtpc.teid_flag)
		set_gtpv2c_echo(gtpv2c_tx,
				gtpv2c_rx->gtpc.teid_flag, GTP_ECHO_RSP,
				gtpv2c_rx->teid.has_teid.teid,
				gtpv2c_rx->teid.has_teid.seq);
	else
		set_gtpv2c_echo(gtpv2c_tx,
				gtpv2c_rx->gtpc.teid_flag, GTP_ECHO_RSP,
				0, gtpv2c_rx->teid.no_teid.seq);
	return 0;
}
