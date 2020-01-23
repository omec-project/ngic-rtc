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

#ifndef __CP_TIMER_H
#define __CP_TIMER_H

extern pfcp_config_t pfcp_config;

/**
 * @brief  : Returns peer data struct address and fill data.
 * @param  : iface, source interface type
 * @param  : peer_addr, peer node address
 * @param  : buf, holds timer data
 * @param  : buf_len, total length of data
 * @param  : itr, request_tries value in pfcp config
 * @param  : teid, teid value
 * @return : Returns pointer to filled timer entry structure
 */
peerData *
fill_timer_entry_data(enum source_interface iface, struct sockaddr_in *peer_addr,
	uint8_t *buf, uint16_t buf_len, uint8_t itr, uint32_t teid,  uint8_t ebi_index);

/**
 * @brief  : add timer entry
 * @param  : conn_data, peer node connection information
 * @param  : timeout_ms, timeout
 * @param  : cb, timer callback
 * @return : Returns true or false
 */
bool
add_timer_entry(peerData *conn_data, uint32_t timeout_ms,
				gstimercallback cb);

/**
 * @brief  : delete time entry
 * @param  : teid, teid value
 * @return : Returns nothing
 */
void
delete_timer_entry(uint32_t teid);

/**
 * @brief  : timer callback
 * @param  : ti, timer information
 * @param  : data_t, Peer node connection information
 * @return : Returns nothing
 */
void
timer_callback(gstimerinfo_t *ti, const void *data_t);

/**
 * @brief  : Fills and adds timer entry, and starts periodic timer for gtpv2c messages
 * @param  : teid, teid value
 * @param  : peer_addr, peer node address
 * @param  : buf, holds timer data
 * @param  : buf_len, total length of data
 * @return : Returns nothing
 */
void
add_gtpv2c_if_timer_entry(uint32_t teid, struct sockaddr_in *peer_addr,
	uint8_t *buf, uint16_t buf_len, uint8_t ebi_index, enum source_interface iface);

/**
 * @brief  : Fills and adds timer entry, and starts periodic timer for pfcp message
 * @param  : teid, teid value
 * @param  : peer_addr, peer node address
 * @param  : buf, holds timer data
 * @param  : buf_len, total length of data
 * @return : Returns nothing
 */
void
add_pfcp_if_timer_entry(uint32_t teid, struct sockaddr_in *peer_addr,
	uint8_t *buf, uint16_t buf_len, uint8_t ebi_index);

void
delete_pfcp_if_timer_entry(uint32_t teid, uint8_t ebi_index);

void
delete_gtpv2c_if_timer_entry(uint32_t teid);

#endif
