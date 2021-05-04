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

#include "../cp_dp_api/vepc_cp_dp_api.h"
#include "pfcp_enum.h"

extern pfcp_config_t config;
extern struct rte_hash *timer_by_teid_hash;
extern struct rte_hash *ddn_by_seid_hash;
extern struct rte_hash *dl_timer_by_teid_hash;
extern struct rte_hash *pfcp_rep_by_seid_hash;
extern struct rte_hash *thrtl_timer_by_nodeip_hash;
extern struct rte_hash *thrtl_ddn_count_hash;
extern struct rte_hash *buffered_ddn_req_hash;

#define ZERO   0
#define ONE    1
#define TWO    2
#define THREE  3
#define FOUR   4
#define SEVEN  7

/* Values in miliseconds */
#define  TWOSEC     (2 * 1000)
#define  ONEMINUTE  (60 * 1000)
#define  TENMINUTE  (600 * 1000)
#define  ONEHOUR    (3600 * 1000)
#define  TENHOUR    (36000 * 1000)

/*@brief : ue level timer for ddn flow */
typedef struct ue_level_timer_t {
	gstimerinfo_t  pt;   /*transmit Timer*/
	uint64_t sess_id;    /*Session id*/
	_timer_t start_time;        /*start timestamp*/

}ue_level_timer;

/*@brief : struct throttling timer */
typedef struct throttling_timer_t {

	gstimerinfo_t  pt;         /*transmit Timer*/
	uint8_t throttle_factor;   /*Throttling factor*/
	node_address_t *node_ip;   /*mme ip address*/
	_timer_t start_time;       /*start timestamp*/

}throttle_timer;

/*brief : struct counters for throttling*/
typedef struct throttling_count_t{
	float  prev_ddn_eval;         /* number of previous evaluated ddn*/
	float  prev_ddn_discard;      /* number of previous discarded ddn*/
	sess_info *sess_ptr;          /* head pointer to sess_info list*/
}thrtle_count;


/**
 * @brief  : sends pfcp session modification request with drop flag for ddn.
 * @param  : pdn, pointer of pdn
 * @return : returns nothing
 */
void
send_pfcp_sess_mod_req_for_ddn(pdn_connection *pdn);
/**
 * @brief  : fill the session info structure.
 * @param  : thrtl_cnt, pointer of throttling count
 * @param  : sess_id, session id
 * @param  : pdr_count, number of pdrs
 * @param  : pdr, array of pdr ids
 * @return : Returns nothing.
 */
void fill_sess_info_id(thrtle_count *thrtl_cnt, uint64_t sess_id, uint8_t pdr_count, pfcp_pdr_id_ie_t *pdr);


/**
 * @brief  : Get the throttle count
 * @param  : nodeip, ip address of mme
 * @param  : is_mod, operation to be performed
 * @return : Returns throttle count pointer if success else null
 */
thrtle_count * get_throtle_count(node_address_t *nodeip, uint8_t is_mod);
/**
 * @brief  : insert into a new node in linked list.
 * @param  : head , head pointer in linked list
 * @param  : new_node, new node pointer to be inserted
 * @return : Returns head struture pointer if success else null.
 */
sess_info * insert_into_sess_info_list(sess_info *head, sess_info *new_node);

/**
 * @brief  : delete all nodes from  linked list.
 * @param  : head, head  pointer in linked list
 * @return : Returns nothing
 */
void delete_from_sess_info_list(sess_info *head);

/**
 * @brief  : Search into linked list with with sess_id .
 * @param  : head, head pointer of linked list
 * @param  : sess_id, session id need to be searched
 * @return : Returns sess_info pointer on success, null on failure.
 */
sess_info * search_into_sess_info_list(sess_info * head, uint64_t sess_id);

/**
 * @brief  : Removes the throttle entry for particular session.
 * @param  : context, ue_context
 * @param  : sess_id, session id need to be searched
 * @return : Returns nothing.
 */
void
delete_sess_in_thrtl_timer(ue_context *context, uint64_t sess_id);

/**
 * @brief  : fill the ue level timer  structure.
 * @param  : seid, session id
 * @return : Returns ue_level struture pointer if success else null.
 */
ue_level_timer *fill_timer_entry(uint64_t seid);

/**
 * @brief  : callback function for ue level timer.
 * @param  : ti, gstimerinfo_t
 * @param  : data, constant void pointer
 * @return : Returns nothing.
 */
void ddn_timer_callback(gstimerinfo_t *ti, const void *data_t );

/**
 * @brief  : starts ddn timer entry .
 * @param  : hash, pointer of rte_hash to store timer_entry
 * @param  : seid, session id
 * @param  : delay_value, delay_value
 * @param  : cb, callback function to be called after timer expiry
 * @return : Returns nothing.
 */
void start_ddn_timer_entry(struct rte_hash *hash, uint64_t seid, int delay_value, gstimercallback cb);

/**
 * @brief  : Removes session entry fron session hash.
 * @param  : seid, session id
 * @param  : sess_hash, pointer to rte_hash
 * @return : Returns nothing.
 */
void delete_entry_from_sess_hash(uint64_t seid, struct rte_hash *sess_hash);

/**
 * @brief  : cleanups ddn timer entry
 * @param  : hash, pointer of rte_hash to store timer_entry
 * @param  : teid, teid value
 * @param  : sess_hash, pointer of rte_hash to store session
 * @return : Returns extend timer value if exists otherwise returns 0.
 */
uint8_t delete_ddn_timer_entry(struct rte_hash *hash, uint32_t teid, struct rte_hash *sess_hash);

/**
 * @brief  : callback function for dl buffering timer.
 * @param  : ti, gstimerinfo_t
 * @param  : data, constant void pointer
 * @return : Returns nothing.
 */
void dl_buffer_timer_callback(gstimerinfo_t *ti, const void *data_t );

/**
 * @brief  : callback function for throttling timer.
 * @param  : ti, gstimerinfo_t
 * @param  : data, constant void pointer
 * @return : Returns nothing.
 */
void thrtle_timer_callback(gstimerinfo_t *ti, const void *data_t );

/**
 * @brief  : starts throttling timer entry
 * @param  : node_ip, node ip address
 * @param  : thrtlng_delay_val, delay value
 * @param  : thrtl_fact, throttling factor
 * @return : Returns nothing.
 */
void start_throttle_timer(node_address_t *node_ip, int thrtlng_delay_val, uint8_t thrtl_fact);

/**
 * @brief  : cleanups throttling timer
 * @param  : node_ip, node ip address
 * @return : Returns remaining timer value if exist otherwise return 0.
 */
uint8_t delete_thrtle_timer(node_address_t *node_ip);
/**
 * @brief  : Returns peer data struct address and fill data.
 * @param  : iface, source interface type
 * @param  : peer_addr, peer node address
 * @param  : buf, holds timer data
 * @param  : buf_len, total length of data
 * @param  : itr, request_tries value in pfcp config
 * @param  : teid, teid value
 * @param  : ebi_index
 * @return : Returns pointer to filled timer entry structure
 */
peerData *
fill_timer_entry_data(enum source_interface iface, peer_addr_t *peer_addr,
	uint8_t *buf, uint16_t buf_len, uint8_t itr, uint32_t teid,  int ebi_index );

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
 * @brief  : fills error response
 * @param  : data, Peer node connection information
 * @return : Returns nothing
 */
void association_fill_error_response(peerData *data);
/**
 * @brief  : timer callback for association request
 * @param  : ti, timer information
 * @param  : data_t, Peer node connection information
 * @return : Returns nothing
 */
void
association_timer_callback(gstimerinfo_t *ti, const void *data_t);

/**
 * @brief  : Fills and adds timer entry, and starts periodic timer for gtpv2c messages
 * @param  : teid, teid value
 * @param  : peer_addr, peer node address
 * @param  : buf, holds timer data
 * @param  : buf_len, total length of data
 * @param  : ebi_index
 * @param  : iface, source interface
 * @param  : cp_mode, cp mode type[SGWC/SAEGWC/PGWC]
 * @return : Returns nothing
 */
void
add_gtpv2c_if_timer_entry(uint32_t teid, peer_addr_t *peer_addr,
	uint8_t *buf, uint16_t buf_len, int ebi_index , enum source_interface iface,
	uint8_t cp_mode);

/**
 * @brief  : Fills and adds timer entry, and starts periodic timer for pfcp message
 * @param  : teid, teid value
 * @param  : peer_addr, peer node address
 * @param  : buf, holds timer data
 * @param  : buf_len, total length of data
 * @param  : ebi_index
 * @return : Returns nothing
 */
void
add_pfcp_if_timer_entry(uint32_t teid, peer_addr_t *peer_addr,
	uint8_t *buf, uint16_t buf_len, int ebi_index );

/**
 * @brief  : Deletes pfcp timer entry
 * @param  : teid, teid value
 * @param  : ebi_index
 * @return : Returns nothing
 */
void
delete_pfcp_if_timer_entry(uint32_t teid, int ebi_index );

/**
 * @brief  : Deletes gtp timer entry
 * @param  : teid, teid value
 * @param  : ebi_index
 * @return : Returns nothing
 */
void
delete_gtpv2c_if_timer_entry(uint32_t teid, int ebi_index);


/**
 * @brief  : Deletes association  timer entry
 * @param  : data, peerData pointer
 * @return : Returns nothing
 */
void
delete_association_timer(peerData *data);
#endif
