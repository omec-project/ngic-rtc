/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include "gtpv2c.h"


int
process_echo_request(gtpv2c_header *gtpv2c_rx, gtpv2c_header *gtpv2c_tx)
{
	/* Due to the union & structure alignments in the gtpv2c_header, the
	 * sequence number would always be present in the has_teid.seq memory
	 */
	if (gtpv2c_rx->gtpc.teidFlg)
		set_gtpv2c_echo(gtpv2c_tx,
				gtpv2c_rx->gtpc.teidFlg, GTP_ECHO_RSP,
				gtpv2c_rx->teid_u.has_teid.teid,
				gtpv2c_rx->teid_u.has_teid.seq);
	else
		set_gtpv2c_echo(gtpv2c_tx,
				gtpv2c_rx->gtpc.teidFlg, GTP_ECHO_RSP,
				0, gtpv2c_rx->teid_u.no_teid.seq);
	return 0;
}
