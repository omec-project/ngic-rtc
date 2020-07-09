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

#include <stdio.h>
#include <time.h>
#include <rte_hash.h>
#include <rte_errno.h>
#include <rte_debug.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_hash_crc.h>

#include "up_main.h"
#include "pfcp_up_llist.h"
#include "pfcp_up_struct.h"
#include "clogger.h"
#include "predef_rule_init.h"

#define NUM_OF_TABLES 10

#define MAX_HASH_SIZE (1 << 15)
#define MAX_PDN_HASH_SIZE (1 << 8)

#define SESS_CREATE 0
#define SESS_MODIFY 1
#define SESS_DEL 2

/* User-Plane base increment offset parameter */
static uint32_t up_qer_indx_offset;


extern struct rte_hash *sess_ctx_by_sessid_hash;
extern struct rte_hash *sess_by_teid_hash;
extern struct rte_hash *sess_by_ueip_hash;
extern struct rte_hash *pdr_by_id_hash;
extern struct rte_hash *far_by_id_hash;
extern struct rte_hash *qer_by_id_hash;
extern struct rte_hash *urr_by_id_hash;
extern struct rte_hash *timer_by_id_hash;
extern struct rte_hash *qer_rule_hash;

int8_t
add_sess_info_entry(uint64_t up_sess_id, pfcp_session_t *sess_cntxt)
{
	int ret = 0;
	pfcp_session_t *tmp = NULL;

	/* Lookup for up session context entry. */
	ret = rte_hash_lookup_data(sess_ctx_by_sessid_hash,
				&up_sess_id, (void **)&tmp);

	if ( ret < 0) {
		/* allocate memory for session info*/
		tmp = rte_zmalloc("Session_Info", sizeof(pfcp_session_t),
		        RTE_CACHE_LINE_SIZE);
		if (tmp == NULL){
		    clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to allocate memory for session info, Error: %s\n",
				LOG_VALUE, rte_strerror(rte_errno));
		    return -1;
		}

		if (sess_cntxt != NULL)
			memcpy(tmp, sess_cntxt, sizeof(pfcp_session_t));

		/* Session Entry not present. Add new session entry */
		ret = rte_hash_add_key_data(sess_ctx_by_sessid_hash,
						&up_sess_id, tmp);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add entry for UP SESSION ID: %lu"
				", Error :%s\n", LOG_VALUE, up_sess_id, rte_strerror(abs(ret)));
			/* free allocated memory */
			rte_free(tmp);
			tmp = NULL;
			return -1;
		}
	} else {
		memcpy(tmp, sess_cntxt, sizeof(pfcp_session_t));
	}

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Session entry added by UP SESSION ID: %lu\n",
		LOG_VALUE, up_sess_id);
	return 0;
}

pfcp_session_t *
get_sess_info_entry(uint64_t up_sess_id, uint8_t is_mod)
{
	int ret = 0;
	pfcp_session_t *sess_cntxt = NULL;

	ret = rte_hash_lookup_data(sess_ctx_by_sessid_hash,
				&up_sess_id, (void **)&sess_cntxt);

	if ( ret < 0) {
		/* allocate memory only if request is from session establishment */
		if (is_mod != SESS_CREATE) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Entry not found for UP SESSION ID: %lu\n", LOG_VALUE, up_sess_id);
			return NULL;
		}

		/* allocate memory for session info*/
		sess_cntxt = rte_zmalloc("Session_Info", sizeof(pfcp_session_t),
		        RTE_CACHE_LINE_SIZE);
		if (sess_cntxt == NULL){
		    clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate memory for session info, Error: %s\n",
					LOG_VALUE, rte_strerror(rte_errno));
		    return NULL;
		}

		/* Session Entry not present. Add new session entry */
		ret = rte_hash_add_key_data(sess_ctx_by_sessid_hash,
						&up_sess_id, sess_cntxt);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add entry for UP SESSION ID: %lu"
				", Error: %s\n", LOG_VALUE, up_sess_id,
				rte_strerror(abs(ret)));
			/* free allocated memory */
			rte_free(sess_cntxt);
			sess_cntxt = NULL;
			return NULL;
		}

		/* Fill the UP Session ID */
		sess_cntxt->up_seid = up_sess_id;
	}

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"UP SESSION ID: %lu\n",
		LOG_VALUE, up_sess_id);
	return sess_cntxt;

}

int8_t
del_sess_info_entry(uint64_t up_sess_id)
{
	int ret = 0;
	pfcp_session_t *sess_cntxt = NULL;

	/* Check session entry is present or Not */
	ret = rte_hash_lookup_data(sess_ctx_by_sessid_hash,
					&up_sess_id, (void **)&sess_cntxt);
	if (ret >=0 ) {
		/* Session Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(sess_ctx_by_sessid_hash, &up_sess_id);

		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found "
				"for UP SESSION ID: %lu\n", LOG_VALUE, up_sess_id);
			return -1;
		}
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"UP SESS ID: %lu\n", LOG_VALUE,
		up_sess_id);

	return 0;
}

pfcp_session_datat_t *
get_sess_by_teid_entry(uint32_t teid, pfcp_session_datat_t **head, uint8_t is_mod)
{
	int ret = 0;
	pfcp_session_datat_t *sess_cntxt = NULL;

	ret = rte_hash_lookup_data(sess_by_teid_hash,
				&teid, (void **)&sess_cntxt);

	if ( ret < 0) {
		if (is_mod != SESS_CREATE) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Entry not found for TEID: %u\n",
				LOG_VALUE, teid);
			return NULL;
		}

		/* allocate memory for session info*/
		sess_cntxt = rte_zmalloc("Sess_data_Info", sizeof(pfcp_session_datat_t),
		        RTE_CACHE_LINE_SIZE);
		if (sess_cntxt == NULL){
		    clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to allocate memory for session data info, Error: %s\n",
				LOG_VALUE, rte_strerror(abs(ret)));
		    return NULL;
		}

		/* Session Entry not present. Add new session entry */
		ret = rte_hash_add_key_data(sess_by_teid_hash,
						&teid, sess_cntxt);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add entry for TEID: %u"
					", Error: %s\n", LOG_VALUE, ntohl(teid),
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(sess_cntxt);
			sess_cntxt = NULL;
			return NULL;
		}

		/* Function to add a node in Sesions Data Linked List. */
		if (insert_sess_data_node(*head, sess_cntxt)) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add node entry in LL for TEID : %u"
				"Error :%s\n", LOG_VALUE,
				teid, rte_strerror(abs(ret)));
		}

		if (*head == NULL)
			*head = sess_cntxt;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"TEID Value: %u\n",
			LOG_VALUE, teid);
	return sess_cntxt;

}

int8_t
del_sess_by_teid_entry(uint32_t teid)
{
	int ret = 0;
	pfcp_session_datat_t *sess_cntxt = NULL;

	/* Check session entry is present or Not */
	ret = rte_hash_lookup_data(sess_by_teid_hash,
					&teid, (void **)&sess_cntxt);
	if (ret >= 0) {
		/* Session Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(sess_by_teid_hash, &teid);

		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found "
				"for TEID: %u\n", LOG_VALUE, ntohl(teid));
			return -1;
		}
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"TEID Value: %u\n",
		LOG_VALUE, ntohl(teid));

	return 0;
}

pfcp_session_datat_t *
get_sess_by_ueip_entry(uint32_t ue_ip, pfcp_session_datat_t **head, uint8_t is_mod)
{
	int ret = 0;
	pfcp_session_datat_t *sess_cntxt = NULL;

	ret = rte_hash_lookup_data(sess_by_ueip_hash,
				&ue_ip, (void **)&sess_cntxt);

	if ( ret < 0) {
		if (is_mod != SESS_CREATE) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Entry not found for UE IP: "IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ue_ip));
			return NULL;
		}

		/* allocate memory for session info*/
		sess_cntxt = rte_zmalloc("Sess_data_Info", sizeof(pfcp_session_datat_t),
		        RTE_CACHE_LINE_SIZE);
		if (sess_cntxt == NULL){
		    clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to allocate memory for session data info\n", LOG_VALUE);
		    return NULL;
		}

		/* Session Entry not present. Add new session entry */
		ret = rte_hash_add_key_data(sess_by_ueip_hash,
						&ue_ip, sess_cntxt);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add entry for UE IP: "IPV4_ADDR""
				", Error: %s\n", LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ue_ip),
				rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(sess_cntxt);
			sess_cntxt = NULL;
			return NULL;
		}

		/* Function to add a node in Sesions Data Linked List. */
		if (insert_sess_data_node(*head, sess_cntxt)) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add node entry in LInked List for UE IP: "IPV4_ADDR""
				",Error: %s\n", LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ue_ip), rte_strerror(abs(ret)));
		}

		if (*head == NULL)
			*head = sess_cntxt;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"UE IP: "IPV4_ADDR"\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ue_ip));
	return sess_cntxt;

}

int8_t
del_sess_by_ueip_entry(uint32_t ue_ip)
{
	int ret = 0;
	pfcp_session_datat_t *sess_cntxt = NULL;

	/* Check session entry is present or Not */
	ret = rte_hash_lookup_data(sess_by_ueip_hash,
					&ue_ip, (void **)&sess_cntxt);
	if (ret >= 0) {
		/* Session Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(sess_by_ueip_hash, &ue_ip);

		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found "
				"for UE IP: "IPV4_ADDR"\n",
				LOG_VALUE,IPV4_ADDR_HOST_FORMAT(ue_ip));
			return -1;
		}
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"UE IP: "IPV4_ADDR"\n",
		LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ue_ip));

	return 0;
}

pdr_info_t *
get_pdr_info_entry(uint16_t rule_id, uint32_t peer_ip,
		pdr_info_t **head, uint16_t is_add)
{
	int ret = 0;
	pdr_info_t *pdr = NULL;

	uint64_t hash_key;
	hash_key = ((uint64_t)peer_ip << 32) + rule_id;

	ret = rte_hash_lookup_data(pdr_by_id_hash,
				&hash_key, (void **)&pdr);

	if ( ret < 0) {
		if (is_add != SESS_CREATE) {
		    clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to get PDR entry\n", LOG_VALUE);
		    return NULL;
		}

		/* allocate memory for session info*/
		pdr = rte_zmalloc("Session_Info", sizeof(pdr_info_t),
		        RTE_CACHE_LINE_SIZE);
		if (pdr == NULL){
		    clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate memory for PDR info, Error: %s\n",
					LOG_VALUE, rte_strerror(abs(ret)));
		    return NULL;
		}

		/* PDR Entry not present. Add PDR Entry */
		ret = rte_hash_add_key_data(pdr_by_id_hash,
						&hash_key, pdr);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add entry for PDR ID: %u , Error: %s\n",
				LOG_VALUE, rule_id, rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(pdr);
			pdr = NULL;
			return NULL;
		}
		/* Update the rule id */
		pdr->rule_id = rule_id;

		/* Function to add a node in PDR data Linked List. */
		if (insert_pdr_node(*head, pdr)) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add node entry in Linked List"
				" for PDR ID: %u ,Error: %s\n", LOG_VALUE,
				rule_id, rte_strerror(abs(ret)));
		}

		if (*head == NULL) {
			*head = pdr;
		}
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"PDR ID: %u\n",
			LOG_VALUE, rule_id);
	return pdr;

}

int8_t
del_pdr_info_entry(uint16_t rule_id, uint32_t peer_ip)
{
	int ret = 0;
	pdr_info_t *pdr = NULL;

	uint64_t hash_key = 0;
	hash_key = ((uint64_t)peer_ip << 32) + rule_id;

	/* Check PDR entry is present or Not */
	ret = rte_hash_lookup_data(pdr_by_id_hash,
					&hash_key, (void **)&pdr);
	if (ret >= 0) {
		/* PDR Entry is present. Delete PDR Entry */
		ret = rte_hash_del_key(pdr_by_id_hash, &hash_key);

		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found "
				"for PDR ID: %u\n", LOG_VALUE, rule_id);
			return -1;
		}
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"PDR ID:%u\n",
		LOG_VALUE, rule_id);

	return 0;
}

int8_t
add_far_info_entry(uint16_t far_id, uint32_t peer_ip, far_info_t **far)
{
	int ret = 0;
	far_info_t *tmp = NULL;

	uint64_t hash_key;
	hash_key = ((uint64_t)peer_ip << 32) + far_id;

	/* Lookup for FAR entry. */
	ret = rte_hash_lookup_data(far_by_id_hash,
				&hash_key, (void **)&tmp);

	if ( ret < 0) {
		/* allocate memory for session info*/
		*far = rte_zmalloc("FAR", sizeof(far_info_t),
		        RTE_CACHE_LINE_SIZE);
		if (*far == NULL){
		    clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to allocate memory for FAR info\n", LOG_VALUE);
		    return -1;
		}

		/* FAR Entry not present. Add FAR Entry */
		ret = rte_hash_add_key_data(far_by_id_hash,
						&hash_key, *far);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add entry for FAR ID: %u"
				"Error :%s\n", LOG_VALUE, far_id, rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(*far);
			*far = NULL;
			return -1;
		}
	} else {
		if(*far != NULL)
			memcpy(tmp, *far, sizeof(far_info_t));
		else
			*far = tmp;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"FAR entry added by FAR ID: %u\n",
			LOG_VALUE, far_id);
	return 0;
}

far_info_t *
get_far_info_entry(uint16_t far_id, uint32_t peer_ip)
{
	int ret = 0;
	far_info_t *far = NULL;

	uint64_t hash_key;
	hash_key = ((uint64_t)peer_ip << 32) + far_id;

	ret = rte_hash_lookup_data(far_by_id_hash,
				&hash_key, (void **)&far);
	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Entry not found for FAR ID: %u\n", LOG_VALUE, far_id);
		return NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"FAR ID:%u, TEID Value: %u, Dst Ipv4 addr: "IPV4_ADDR", Dst Itf type:%u\n",
			LOG_VALUE, far_id, far->frwdng_parms.outer_hdr_creation.teid,
			IPV4_ADDR_HOST_FORMAT(far->frwdng_parms.outer_hdr_creation.ipv4_address),
			far->frwdng_parms.dst_intfc.interface_value);
	return far;

}

int8_t
del_far_info_entry(uint16_t far_id, uint32_t peer_ip)
{
	int ret = 0;
	far_info_t *far = NULL;

	uint64_t hash_key;
	hash_key = ((uint64_t)peer_ip << 32) + far_id;

	/* Check FAR entry is present or Not */
	ret = rte_hash_lookup_data(far_by_id_hash,
					&hash_key, (void **)&far);
	if (ret >= 0) {
		/* FAR Entry is present. Delete FAR Entry */
		ret = rte_hash_del_key(far_by_id_hash, &hash_key);

		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Entry not "
				"found for FAR ID: %u\n",LOG_VALUE, far_id);
			return -1;
		}
	}

	/* Free data from hash */
	if (far != NULL) {
		rte_free(far);
		far = NULL;
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"free the qer memory successfully with"
			" key FAR ID and PEER IP: %lu\n",
			LOG_VALUE, hash_key);
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"FAR ID:%u\n",
			LOG_VALUE, far_id);

	return 0;
}

int8_t
add_qer_info_entry(uint32_t qer_id, uint32_t peer_ip, qer_info_t **head)
{
	int ret = 0;
	qer_info_t *qer = NULL;

	uint64_t hash_key;
	hash_key = ((uint64_t)peer_ip << 32) + qer_id;

	/* Lookup for QER entry. */
	ret = rte_hash_lookup_data(qer_by_id_hash,
				&hash_key, (void **)&qer);

	if ((ret < 0) || (qer == NULL)) {
		/* allocate memory for session info*/
		qer = rte_zmalloc("QER", sizeof(qer_info_t),
		        RTE_CACHE_LINE_SIZE);
		if (qer == NULL){
		    clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to allocate memory for QER info, Error: %s\n",
				LOG_VALUE, rte_strerror(abs(ret)));
		    return -1;
		}

		/* QER Entry not present. Add QER Entry in table */
		ret = rte_hash_add_key_data(qer_by_id_hash,
						&hash_key, qer);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add QER entry for QER ID: %u"
					",Error: %s\n", LOG_VALUE, qer_id,
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(qer);
			qer = NULL;
			return -1;
		}

		/* Update the rule id */
		qer->qer_id = qer_id;

		/* Function to add a node in PDR data Linked List. */
		if (insert_qer_node(*head, qer)) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add node entry in Linked List for QER ID: %u"
					"Error: %s\n", LOG_VALUE, qer_id, rte_strerror(abs(ret)));
		}
		if (*head == NULL)
			*head = qer;

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"QER entry add for QER ID:%u\n",
				LOG_VALUE, qer_id);
		return 0;

	} else {
		if (head == NULL) {
		 	*head = qer;
		}
	}
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Found QER entry for QER ID:%u\n",
			LOG_VALUE, qer_id);
	return 0;

}

qer_info_t *
get_qer_info_entry(uint32_t qer_id, uint32_t peer_ip, qer_info_t **head)
{
	int ret = 0;
	qer_info_t *qer = NULL;

	uint64_t hash_key;
	hash_key = ((uint64_t)peer_ip << 32) + qer_id;

	/* Retireve QER entry */
	ret = rte_hash_lookup_data(qer_by_id_hash,
				&hash_key, (void **)&qer);

	if ( ret < 0) {
		/* allocate memory for session info*/
		qer = rte_zmalloc("Session_Info", sizeof(qer_info_t),
		        RTE_CACHE_LINE_SIZE);
		if (qer == NULL){
		    clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to allocate memory for QER info, Error: %s\n",
				LOG_VALUE, rte_strerror(abs(ret)));
		    return NULL;
		}

		/* QER Entry not present. Add PDR Entry */
		ret = rte_hash_add_key_data(qer_by_id_hash,
						&hash_key, qer);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add entry for QER_ID: %u"
				",Error: %s\n", LOG_VALUE, qer_id, rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(qer);
			qer = NULL;
			return NULL;
		}
		/* Update the rule id */
		qer->qer_id = qer_id;

		/* Function to add a node in PDR data Linked List. */
		if (insert_qer_node(*head, qer)) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add node entry in Linked List for QER ID: %u"
				",Error: %s\n", LOG_VALUE, qer_id, rte_strerror(abs(ret)));
		}
		if (*head == NULL)
			*head = qer;

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Add QER Entry for QER ID: %u\n",
				LOG_VALUE, qer_id);
		return qer;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Found entry for QER ID: %u\n",
			LOG_VALUE, qer_id);
	return qer;

}

int8_t
del_qer_info_entry(uint32_t qer_id, uint32_t peer_ip)
{
	int ret = 0;
	qer_info_t *qer = NULL;

	uint64_t hash_key;
	hash_key = ((uint64_t)peer_ip << 32) + qer_id;

	/* Check QER entry is present or Not */
	ret = rte_hash_lookup_data(qer_by_id_hash,
					&hash_key, (void **)&qer);
	if (ret >= 0) {
		/* QER Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(qer_by_id_hash, &hash_key);

		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found "
				"for QER_ID: %u\n", LOG_VALUE, qer_id);
			return -1;
		}
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"QER ID: %u\n",
			LOG_VALUE, qer_id);
		return 0;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Not Deleted entry for QER ID: %u\n",
		LOG_VALUE, qer_id);
	return 0;
}

int8_t
add_urr_info_entry(uint32_t urr_id, uint32_t peer_ip, urr_info_t **head)
{
	int ret = 0;
	urr_info_t *urr = NULL;

	uint64_t hash_key;
	hash_key = ((uint64_t)peer_ip << 32) + urr_id;

	/* Lookup for URR entry. */
	ret = rte_hash_lookup_data(urr_by_id_hash,
				&hash_key, (void **)&urr);

	if ( ret < 0) {
		/* allocate memory for session info*/
		urr = rte_zmalloc("URR", sizeof(urr_info_t),
		        RTE_CACHE_LINE_SIZE);
		if (urr == NULL){
		    clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate memory for URR info, Error: %s\n",
					LOG_VALUE, rte_strerror(abs(ret)));
		    return -1;
		}


		/* URR Entry not present. Add URR Entry in table */
		ret = rte_hash_add_key_data(urr_by_id_hash,
						&hash_key, urr);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add URR entry for URR ID: %u"
				",Error: %s\n", LOG_VALUE, urr_id, rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(urr);
			urr = NULL;
			return -1;
		}

		if (insert_urr_node(*head, urr)) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add node entry in Linked List for URR ID: %u"
				",Error: %s\n", LOG_VALUE, urr_id, rte_strerror(abs(ret)));
		}
		if(*head == NULL)
			*head = urr;
	}else {
		if(*head == NULL)
			*head = urr;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"URR entry add for URR ID: %u\n",
			LOG_VALUE, urr_id);
	return 0;
}

urr_info_t *
get_urr_info_entry(uint32_t urr_id, uint32_t peer_ip)
{
	int ret = 0;
	urr_info_t *urr = NULL;

	uint64_t hash_key;
	hash_key = ((uint64_t)peer_ip << 32) + urr_id;

	/* Retireve URR entry */
	ret = rte_hash_lookup_data(urr_by_id_hash,
				&hash_key, (void **)&urr);

	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found "
			"for URR ID: %u\n", LOG_VALUE, urr_id);
		return NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"URR ID: %u\n",
		LOG_VALUE, urr_id);
	return urr;

}

int8_t
del_urr_info_entry(uint32_t urr_id, uint32_t peer_ip)
{
	int ret = 0;
	urr_info_t *urr = NULL;

	uint64_t hash_key;
	hash_key = ((uint64_t)peer_ip << 32) + urr_id;

	/* Check URR entry is present or Not */
	ret = rte_hash_lookup_data(urr_by_id_hash,
					&hash_key, (void **)&urr);
	if (ret >= 0) {
		/* URR Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(urr_by_id_hash, &hash_key);

		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found "
				"for URR ID: %u\n", LOG_VALUE, urr_id);
			return -1;
		}
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"URR ID: %u\n",
			LOG_VALUE, urr_id);

	return 0;
}

qer_info_t *
add_rule_info_qer_hash(uint8_t *rule_name)
{
	int ret = 0;
	qer_info_t *qer = NULL;
	pcc_rule_name rule = {0};
	struct pcc_rules *pcc = NULL;
	struct mtr_entry *mtr = NULL;

	if (rule_name == NULL)
		return NULL;

	/* Fill/Copy the Rule Name */

	memcpy(&rule.rname, (void *)rule_name, strnlen(((char *)rule_name), MAX_RULE_LEN));

	pcc = get_predef_pcc_rule_entry(&rule, GET_RULE);
	if (pcc == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Failed to GET PCC Rule in the pcc table"
				" for Rule_Name: %s\n", LOG_VALUE, rule.rname);
		return NULL;
	}else {
		if (pcc->qos.mtr_profile_index) {
			void *mtr_rule = NULL;
			ret = get_predef_rule_entry(pcc->qos.mtr_profile_index,
						MTR_HASH, GET_RULE, (void **)&mtr_rule);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to GET MTR Rule from the internal table"
						"for Mtr_Indx: %u\n", LOG_VALUE, pcc->qos.mtr_profile_index);
				return NULL;
			} else {
				/* Fill the QER info */
				mtr = (struct mtr_entry *)mtr_rule;
				if (mtr != NULL) {
					/* allocate memory for QER info*/
					qer = rte_zmalloc("QER_prdef_Info", sizeof(pfcp_session_t),
					        RTE_CACHE_LINE_SIZE);
					if (qer == NULL){
					    clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failed to allocate memory for QER Prdef info\n",
								LOG_VALUE);
					    return NULL;
					}
					/* TODO: Handle the separate Gate Status in predef rule */
					/* Generate/Set QER ID */
					qer->qer_id = ++up_qer_indx_offset;
					/* Linked QER ID with PCC */
					pcc->qer_id = qer->qer_id;
					/* Set UL Gate Status */
					qer->gate_status.ul_gate = pcc->ul_gate_status;
					/* Set DL Gate Status */
					qer->gate_status.dl_gate = pcc->dl_gate_status;
					/* Set the Uplink Max Bitrate */
					qer->max_bitrate.ul_mbr = mtr->ul_mbr;
					/* Set the Downlink Max Bitrate */
					qer->max_bitrate.dl_mbr = mtr->dl_mbr;
					/* Set the Uplink Guaranteed Bitrate */
					qer->guaranteed_bitrate.ul_gbr = mtr->ul_gbr;
					/* Set the Downlink Guaranteed Bitrate */
					qer->guaranteed_bitrate.dl_gbr = mtr->dl_gbr;

					ret = rte_hash_add_key_data(qer_rule_hash, &qer->qer_id, qer);
					if(ret < 0){
						clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Error: Failed to add in qer_rule_hash"
							"for qer_id: %u\n", LOG_VALUE, qer->qer_id);
						return NULL;
					}
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Successfully added qer entry in qer_rule_hash for qer_id:%u\n",
							LOG_VALUE, qer->qer_id);

					return qer;
				}
			}
		}

	clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Error: Failed to get mtr index"
			"mtr_index: %u\n", LOG_VALUE, pcc->qos.mtr_profile_index);
	}
	return NULL;
}

void
init_up_hash_tables(void)
{
	struct rte_hash_parameters
		pfcp_hash_params[NUM_OF_TABLES] = {
		{	.name = "PDR_ENTRY_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint64_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "FAR_ENTRY_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint64_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "QER_ENTRY_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint64_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "URR_ENTRY_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint64_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "SESSION_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint64_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "SESSION_DATA_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "SESSION_UEIP_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "SESSION_TIMER_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{   .name = "QER_RULE_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{   .name = "SOCK_DDFIP_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		}
	};

	pdr_by_id_hash = rte_hash_create(&pfcp_hash_params[0]);
	if (!pdr_by_id_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[0].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	far_by_id_hash = rte_hash_create(&pfcp_hash_params[1]);
	if (!far_by_id_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[1].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	qer_by_id_hash = rte_hash_create(&pfcp_hash_params[2]);
	if (!qer_by_id_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[2].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	urr_by_id_hash = rte_hash_create(&pfcp_hash_params[3]);
	if (!urr_by_id_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[3].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	sess_ctx_by_sessid_hash = rte_hash_create(&pfcp_hash_params[4]);
	if (!sess_ctx_by_sessid_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[4].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	sess_by_teid_hash = rte_hash_create(&pfcp_hash_params[5]);
	if (!sess_by_teid_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[5].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	sess_by_ueip_hash = rte_hash_create(&pfcp_hash_params[6]);
	if (!sess_by_ueip_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[6].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	timer_by_id_hash = rte_hash_create(&pfcp_hash_params[7]);
	if (!timer_by_id_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[7].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	qer_rule_hash = rte_hash_create(&pfcp_hash_params[8]);
	if (!qer_rule_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[8].name,
		    rte_strerror(rte_errno), rte_errno);
	}


	printf("Session, Session Data, PDR, QER, URR, BAR and FAR "
			"hash table created successfully \n");
}

/**
 * Generate the User-Plane SESSION ID
 */
uint64_t
gen_up_sess_id(uint64_t cp_sess_id)
{
	uint64_t up_sess_id = 0;

	up_sess_id = ((((cp_sess_id >> 32) + 1) << 32)  | (cp_sess_id & 0xfffffff) );

	return up_sess_id;
}
