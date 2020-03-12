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

#ifndef PACKET_FILTERS_H
#define PACKET_FILTERS_H

/**
 * @file
 *
 * Contains functions to initialize, manage, and install packet filters internal
 * to the Control Plane as well as calls to forward the installed packet filters
 * to the Data Plane.
 */

#include "ue.h"

#define FIRST_FILTER_ID 1

#define METER_PROFILE_FILE "../config/meter_profile.cfg"
#define PCC_RULE_FILE "../config/pcc_rules.cfg"
#define SDF_RULE_FILE "../config/sdf_rules.cfg"
#define ADC_RULE_FILE "../config/adc_rules.cfg"

extern uint16_t ulambr_idx;
extern uint16_t dlambr_idx;

/**
 * @brief  : Maintains packet filter information
 */
typedef struct pkt_fltr_t {
	uint8_t direction;
	uint8_t remote_ip_mask;
	uint8_t proto;
	uint8_t proto_mask;
	uint16_t remote_port_low;
	uint16_t remote_port_high;
	struct in_addr local_ip_addr;
	uint16_t local_port_low;
	uint16_t local_port_high;
	uint8_t local_ip_mask;
	struct in_addr remote_ip_addr;
} pkt_fltr;

/**
 * @brief  : Maintains packet filter information along with uplink and
 *           downlink info
 */
typedef struct packet_filter_t {
	pkt_fltr pkt_fltr;
	uint16_t ul_mtr_idx;
	uint16_t dl_mtr_idx;
} packet_filter;

extern const pkt_fltr catch_all;

/**
 * @brief  : Adds packet filter entry
 * @param  : index, index of array where packet filter needs to be added
 * @return : Returns nothing
 */
void
push_packet_filter(uint16_t index);

/**
 * @brief  : Adds sdf rule entry
 * @param  : index, index of array where sdf rule needs to be added
 * @return : Returns nothing
 */
void
push_sdf_rules(uint16_t index);

/**
 * @brief  : Installs a packet filter in the CP & DP.
 * @param  : new_packet_filter
 *           A packet filter yet to be installed
 * @return : - >= 0 - on success - indicates index of packet filter
 *           - < 0 - on error
 */
int
install_packet_filter(const packet_filter *new_packet_filter);

/**
 * @brief  : Returns the packet filter index.
 * @param  : pf, Packet filter
 * @return : Packet filter index matching packet filter 'pf'
 */
int
get_packet_filter_id(const pkt_fltr *pf);

/**
 * @brief  : Clears the packet filter at '*pf' to accept all packets.
 * @param  : pf, The packet filter to reset
 * @return : Returns nothing
 */
void
reset_packet_filter(pkt_fltr *pf);

/**
 * @brief  : Returns direction of packet filter (uplink and/or downlink).
 * @param  : index
 *           Packet filter index
 * @return : Direction as defined as tft packet filter direction in 3gpp 24.008
 *           table 10.5.162, one of:
 *           - TFT_DIRECTION_BIDIRECTIONAL
 *           - TFT_DIRECTION_UPLINK_ONLY
 *           - TFT_DIRECTION_DOWNLINK_ONLY
 */
uint8_t
get_packet_filter_direction(uint16_t index);

/**
 * @brief  : Returns the packet filter given it's index.
 * @param  : index, Index of packet filter
 * @return : Packet filter at index
 */
packet_filter *
get_packet_filter(uint16_t index);

/**
 * @brief  : Packet filter initialization function. Reads static file and populates
 *           packet filters accordingly.
 * @param  : No Param
 * @return : Returns nothing
 */
void
init_packet_filters(void);

/**
 * @brief  : parse adc rules
 * @param  : No Param
 * @return : Returns nothing
 */
void parse_adc_rules(void);

/**
 * @brief  : Get meter profile index with matching bit rate cir
 * @param  : cir, bit rate
 * @return : Returns meter profile index of matching meter profile
 */
int meter_profile_index_get(uint64_t cir);
#endif
