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

#ifndef _DP_IPC_API_H_
#define _DP_IPC_API_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of Interface message parsing.
 */
#include "interface.h"
#ifdef CP_BUILD
#include "cp.h"
#include "main.h"
#else
#include "up_main.h"
#endif  /* CP_BUILD */

/* message types */
enum dp_msg_type {
	/* Session Bearer Map Hash Table*/
	MSG_SESS_TBL_CRE,
	MSG_SESS_TBL_DES,
	MSG_SESS_CRE,
	MSG_SESS_MOD,
	MSG_SESS_DEL,
	/* ADC Rule Table*/
	MSG_ADC_TBL_CRE,
	MSG_ADC_TBL_DES,
	MSG_ADC_TBL_ADD,
	MSG_ADC_TBL_DEL,
	/* PCC Rule Table*/
	MSG_PCC_TBL_CRE,
	MSG_PCC_TBL_DES,
	MSG_PCC_TBL_ADD,
	MSG_PCC_TBL_DEL,
	/* Meter Tables*/
	MSG_MTR_CRE,
	MSG_MTR_DES,
	MSG_MTR_ADD,
	MSG_MTR_DEL,
	MSG_MTR_CFG,
	/* Filter Table for SDF & ADC*/
	MSG_SDF_CRE,
	MSG_SDF_DES,
	MSG_SDF_ADD,
	MSG_SDF_DEL,
	MSG_EXP_CDR,
	/* DDN from DP to CP*/
	MSG_DDN,
	MSG_DDN_ACK,

	MSG_END,
};

/* Table Callback msg payload */
struct cb_args_table {
	char name[MAX_LEN];	/* table name */
	uint32_t max_elements;	/* rule id */
};

/*
 * Message Structure
 */
struct msgbuf {
	long mtype;
	struct dp_id dp_id;
	union __attribute__ ((packed)) {
		struct pkt_filter pkt_filter_entry;
		struct adc_rules adc_filter_entry;
		struct pcc_rules pcc_entry;
		struct session_info sess_entry;
		struct mtr_entry mtr_entry;
		struct cb_args_table msg_table;
		struct msg_ue_cdr ue_cdr;

#ifdef CP_BUILD
		struct downlink_data_notification dl_ddn;	/** Downlink data notification info */
#else
		struct downlink_data_notification_ack_t dl_ddn; /** Downlink data notification info */
#endif  /* CP_BUILD */
	} msg_union;
};
struct msgbuf sbuf;
struct msgbuf rbuf;

uint8_t pfcp_rx[1024]; /* TODO: Decide size */

/* IPC msg node */
struct ipc_node {
	int msg_id;	/*msg type*/
	int (*msg_cb)(struct msgbuf *msg_payload);	/*callback function*/
};
struct ipc_node *basenode;

/**
 * @brief Function to recv the IPC message and process them.
 *
 * This function is not thread safe and should only be called once by DP.
 */
//int iface_process_ipc_msgs(void);


void iface_process_ipc_msgs(void);

/**
 * @brief Function to Inilialize memory for IPC msg.
 *
 * @param
 *	void
 */
void iface_init_ipc_node(void);
/**
 * @brief Functino to register call back apis with msg id..
 *
 * @param msg_id
 *	msg_id - id number on which the call back function should
 *	invoked.
 * @param msg_payload
 *	msg_payload - payload of the message
 *
 * This function is thread safe due to message queue implementation.
 */
void
iface_ipc_register_msg_cb(int msg_id,
		int (*msg_cb)(struct msgbuf *msg_payload));


//#ifdef DP_BUILD
int
udp_recv(void *msg_payload, uint32_t size,
			struct sockaddr_in *peer_addr);

/**
 * @brief Functino to Process IPC msgs.
 *
 * @param none
 * Return
 * 0 on success, -1 on failure
 */
int iface_remove_que(enum cp_dp_comm id);
void msg_handler_s11(void);
void msg_handler_s5s8(void);

#ifdef CP_BUILD
/**
 * @brief Functino to init rte hash tables.
 *
 * @param none
 * Return
 *  None
 */

int
simu_cp(__rte_unused void *ptr);

/**
 * @brief callback to handle downlink data notification messages from the
 * data plane
 * @param msg_payload
 * message payload received by control plane from the data plane
 * @return
 * 0 inicates success, error otherwise
 */
int
cb_ddn(struct msgbuf *msg_payload);

#else
	int simu_cp(void);
#endif /* CP_BUILD */
#endif /* _DP_IPC_API_H_ */

