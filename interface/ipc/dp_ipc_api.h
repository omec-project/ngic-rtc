/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _DP_IPC_API_H_
#define _DP_IPC_API_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of Interface message parsing.
 */
#include "main.h"
#include "interface.h"
#ifdef CP_BUILD
#include "cp.h"
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

#ifdef ZMQ_COMM
/*
 * Response Message Structure
 */
struct resp_msgbuf {
	long mtype;
	uint64_t op_id;
	uint64_t sess_id;
	struct dp_id dp_id;
};

struct resp_msgbuf r_buf;
#endif /* ZMQ_COMM */

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
#ifdef DP_DDN
		struct downlink_data_notification_ack_t dl_ddn; /** Downlink data notification info */
#endif  /* DP_DDN */
#endif  /* CP_BUILD */
	} msg_union;
};
struct msgbuf sbuf;
struct msgbuf rbuf;
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
int iface_process_ipc_msgs(void);

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


/**
 * @brief Functino to Process IPC msgs.
 *
 * @param none
 * Return
 * 0 on success, -1 on failure
 */
int iface_remove_que(enum cp_dp_comm id);

#ifdef CP_BUILD
/**
 * @brief Functino to init rte hash tables.
 *
 * @param none
 * Return
 *  None
 */

	int simu_cp(__rte_unused void *ptr);
#else
	int simu_cp(void);
#endif /* CP_BUILD */
#endif /* _DP_IPC_API_H_ */

