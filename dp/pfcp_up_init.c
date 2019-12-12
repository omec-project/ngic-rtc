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

#define NUM_OF_TABLES 7

#define MAX_HASH_SIZE (1 << 15)
#define MAX_PDN_HASH_SIZE (1 << 4)

#define SESS_CREATE 0
#define SESS_MODIFY 1
#define SESS_DEL 2

/* User-Plane base increment offset parameter */
static uint64_t up_sess_id_offset;

extern struct rte_hash *sess_ctx_by_sessid_hash;
extern struct rte_hash *sess_by_teid_hash;
extern struct rte_hash *sess_by_ueip_hash;
extern struct rte_hash *pdr_by_id_hash;
extern struct rte_hash *far_by_id_hash;
extern struct rte_hash *qer_by_id_hash;
extern struct rte_hash *urr_by_id_hash;
/**
 * Add session entry in session info hash table.
 *
 * @param up_sess_id
 * key.
 * @param pfcp_session_t sess_cntxt
 * return 0 or 1.
 *
 */
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
		    RTE_LOG_DP(ERR, DP, "%s: Failed to allocate memory for session info\n", __func__);
		    return -1;
		}

		if (sess_cntxt != NULL)
			memcpy(tmp, sess_cntxt, sizeof(pfcp_session_t));

		/* Session Entry not present. Add new session entry */
		ret = rte_hash_add_key_data(sess_ctx_by_sessid_hash,
						&up_sess_id, tmp);
		if (ret) {
			fprintf(stderr, "%s:%s:%d: Failed to add entry for UP_SESS_ID = %lu"
					"\n\tError= %s\n", __file__,
					__func__, __LINE__, up_sess_id,
					rte_strerror(abs(ret)));
			/* free allocated memory */
			rte_free(tmp);
			tmp = NULL;
			return -1;
		}
	} else {
		memcpy(tmp, sess_cntxt, sizeof(pfcp_session_t));
	}

	RTE_LOG_DP(DEBUG, DP, "%s:%s:%d: Session entry added by UP_SESS_ID:%lu\n",
			__file__, __func__, __LINE__, up_sess_id);
	return 0;
}

/**
 * Get UP Session entry from session hash table.
 *
 * @param UP SESS ID
 * key.
 * return pfcp_session_t sess_cntxt or NULL
 *
 */

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
			fprintf(stderr, "%s:%s:%d Entry not found for UP_SESS_ID: %lu...\n",
					__file__, __func__, __LINE__, up_sess_id);
			return NULL;
		}

		/* allocate memory for session info*/
		sess_cntxt = rte_zmalloc("Session_Info", sizeof(pfcp_session_t),
		        RTE_CACHE_LINE_SIZE);
		if (sess_cntxt == NULL){
		    RTE_LOG_DP(ERR, DP, "%s: Failed to allocate memory for session info\n", __func__);
		    return NULL;
		}

		/* Session Entry not present. Add new session entry */
		ret = rte_hash_add_key_data(sess_ctx_by_sessid_hash,
						&up_sess_id, sess_cntxt);
		if (ret) {
			fprintf(stderr, "%s:%s:%d: Failed to add entry for UP_SESS_ID = %lu"
					"\n\tError= %s\n", __file__,
					__func__, __LINE__, up_sess_id,
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(sess_cntxt);
			sess_cntxt = NULL;
			return NULL;
		}

		/* Fill the UP Session ID */
		sess_cntxt->up_seid = up_sess_id;
	}

	RTE_LOG_DP(DEBUG, DP, "%s:%s: UP_SESS_ID:%lu\n",
			__file__, __func__, up_sess_id);
	return sess_cntxt;

}

/**
 * Delete Session entry from Session hash table.
 *
 * @param UP SESS ID
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_sess_info_entry(uint64_t up_sess_id)
{
	int ret = 0;
	pfcp_session_t *sess_cntxt = NULL;

	/* Check session entry is present or Not */
	ret = rte_hash_lookup_data(sess_ctx_by_sessid_hash,
					&up_sess_id, (void **)&sess_cntxt);
	if (ret) {
		/* Session Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(sess_ctx_by_sessid_hash, &up_sess_id);

		if ( ret < 0) {
			fprintf(stderr, "%s:%s:%d Entry not found for UP_SESS_ID:%lu...\n",
						__file__, __func__, __LINE__, up_sess_id);
			return -1;
		}
	}

	/* Free data from hash */
	if (sess_cntxt != NULL) {
		rte_free(sess_cntxt);
		sess_cntxt = NULL;
	}

	RTE_LOG_DP(DEBUG, DP, "%s: UP_SESS_ID:%lu\n",
			__func__, up_sess_id);

	return 0;
}

/**
 * Add session data entry based on teid in session data hash table.
 *
 * @param teid
 * key.
 * @param pfcp_session_datat_t sess_cntxt
 * return 0 or 1.
 *
 */
int8_t
add_sess_by_teid_entry(uint32_t teid, pfcp_session_datat_t *sess_cntxt)
{
	int ret = 0;
	pfcp_session_datat_t *tmp = NULL;

	/* Lookup for up session data entry. */
	ret = rte_hash_lookup_data(sess_by_teid_hash,
				&teid, (void **)&tmp);

	if ( ret < 0) {
		/* allocate memory for session info*/
		tmp = rte_zmalloc("Session_Info", sizeof(pfcp_session_datat_t),
		        RTE_CACHE_LINE_SIZE);
		if (tmp == NULL){
		    RTE_LOG_DP(ERR, DP, "%s:Failed to allocate memory for session info\n", __func__);
		    return -1;
		}

		if (sess_cntxt != NULL)
			memcpy(tmp, sess_cntxt, sizeof(pfcp_session_datat_t));

		/* Session Entry not present. Add new session entry */
		ret = rte_hash_add_key_data(sess_by_teid_hash,
						&teid, tmp);
		if (ret) {
			fprintf(stderr, "%s:%s:%d: Failed to add entry for TEID = %u"
					"\n\tError= %s\n", __file__,
					__func__, __LINE__, teid,
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(tmp);
			tmp = NULL;
			return -1;
		}
	} else {
		memcpy(tmp, sess_cntxt, sizeof(pfcp_session_datat_t));
	}

	RTE_LOG_DP(DEBUG, DP, "%s:%s:%d: Session entry added by TEID:%u\n",
			__file__, __func__, __LINE__, teid);
	return 0;
}

/**
 * Get Session entry by teid from session hash table.
 *
 * @param teid
 * key.
 * return pfcp_session_datat_t sess_cntxt or NULL
 *
 */

pfcp_session_datat_t *
get_sess_by_teid_entry(uint32_t teid, pfcp_session_datat_t **head, uint8_t is_mod)
{
	int ret = 0;
	pfcp_session_datat_t *sess_cntxt = NULL;

	ret = rte_hash_lookup_data(sess_by_teid_hash,
				&teid, (void **)&sess_cntxt);

	if ( ret < 0) {
		if (is_mod != SESS_CREATE) {
			fprintf(stderr, FORMAT"Entry not found for TEID: %u...\n",
					ERR_MSG, teid);
			return NULL;
		}

		/* allocate memory for session info*/
		sess_cntxt = rte_zmalloc("Sess_data_Info", sizeof(pfcp_session_datat_t),
		        RTE_CACHE_LINE_SIZE);
		if (sess_cntxt == NULL){
		    RTE_LOG_DP(ERR, DP, "%s: Failed to allocate memory for session data info\n", __func__);
		    return NULL;
		}

		/* Session Entry not present. Add new session entry */
		ret = rte_hash_add_key_data(sess_by_teid_hash,
						&teid, sess_cntxt);
		if (ret) {
			fprintf(stderr, "%s:%s:%d: Failed to add entry for TEID = %u"
					"\n\tError= %s\n", __file__,
					__func__, __LINE__, ntohl(teid),
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(sess_cntxt);
			sess_cntxt = NULL;
			return NULL;
		}

		/* Function to add a node in Sesions Data Linked List. */
		if (insert_sess_data_node(*head, sess_cntxt)) {
			fprintf(stderr, FORMAT"Failed to add node entry in LL for TEID = %u"
					"\n\tError= %s\n", ERR_MSG,
					teid, rte_strerror(abs(ret)));
		}

		if (*head == NULL)
			*head = sess_cntxt;
	}

	RTE_LOG_DP(DEBUG, DP, "%s:%s: TEID:%u\n",
			__file__, __func__, teid);
	return sess_cntxt;

}

/**
 * Delete Session entry by teid from Session hash table.
 *
 * @param teid
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_sess_by_teid_entry(uint32_t teid)
{
	int ret = 0;
	pfcp_session_datat_t *sess_cntxt = NULL;

	/* Check session entry is present or Not */
	ret = rte_hash_lookup_data(sess_by_teid_hash,
					&teid, (void **)&sess_cntxt);
	if (ret) {
		/* Session Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(sess_by_teid_hash, &teid);

		if ( ret < 0) {
			fprintf(stderr, "%s:%s:%d Entry not found for TEID:%u...\n",
						__file__, __func__, __LINE__, ntohl(teid));
			return -1;
		}
	}

	/* Free data from hash */
	//if (sess_cntxt != NULL) {
	//	rte_free(sess_cntxt);
	//	sess_cntxt = NULL;
	//}

	RTE_LOG_DP(DEBUG, DP, "%s: TEID:%u\n",
			__func__, ntohl(teid));

	return 0;
}

/**
 * Add session data entry based on UE IP in session data hash table.
 *
 * @param UE_IP
 * key.
 * @param pfcp_session_datat_t sess_cntxt
 * return 0 or 1.
 *
 */
int8_t
add_sess_by_ueip_entry(uint32_t ue_ip, pfcp_session_datat_t **sess_cntxt)
{
	int ret = 0;
	pfcp_session_datat_t *tmp = NULL;

	/* Lookup for up session data entry. */
	ret = rte_hash_lookup_data(sess_by_ueip_hash,
				&ue_ip, (void **)&tmp);

	if ( ret < 0) {
		if (*sess_cntxt == NULL)
			return -1;

		/* Session Entry not present. Add new session entry */
		ret = rte_hash_add_key_data(sess_by_ueip_hash,
						&ue_ip, *sess_cntxt);
		if (ret) {
			fprintf(stderr, FORMAT"Failed to add entry for UE_IP = "IPV4_ADDR""
					"\n\tError= %s\n", ERR_MSG,
					IPV4_ADDR_HOST_FORMAT(ue_ip),
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(sess_cntxt);
			sess_cntxt = NULL;
			return -1;
		}
	} else {
		memcpy(tmp, *sess_cntxt, sizeof(pfcp_session_datat_t));
	}

	RTE_LOG_DP(DEBUG, DP, FORMAT"Session entry added by UE_IP:"IPV4_ADDR"\n",
			ERR_MSG, IPV4_ADDR_HOST_FORMAT(ue_ip));

	RTE_LOG_DP(DEBUG, DP, "%s: TEID:%u, Dst_Ipv4_addr:"IPV4_ADDR", Dst_Itf_type:%u\n",
			__func__,
			(sess_cntxt[0]->pdrs)->far->frwdng_parms.outer_hdr_creation.teid,
			IPV4_ADDR_HOST_FORMAT((sess_cntxt[0]->pdrs)->far->frwdng_parms.outer_hdr_creation.ipv4_address),
			(sess_cntxt[0]->pdrs)->far->frwdng_parms.dst_intfc.interface_value);
	return 0;
}

/**
 * Get Session entry by UE_IP from session hash table.
 *
 * @param UE_IP
 * key.
 * return pfcp_session_t sess_cntxt or NULL
 *
 */
pfcp_session_datat_t *
get_sess_by_ueip_entry(uint32_t ue_ip, pfcp_session_datat_t **head, uint8_t is_mod)
{
	int ret = 0;
	pfcp_session_datat_t *sess_cntxt = NULL;

	ret = rte_hash_lookup_data(sess_by_ueip_hash,
				&ue_ip, (void **)&sess_cntxt);

	if ( ret < 0) {
		if (is_mod != SESS_CREATE) {
			fprintf(stderr, FORMAT"Entry not found for UE_IP:"IPV4_ADDR"...\n",
					ERR_MSG, IPV4_ADDR_HOST_FORMAT(ue_ip));
			return NULL;
		}

		/* allocate memory for session info*/
		sess_cntxt = rte_zmalloc("Sess_data_Info", sizeof(pfcp_session_datat_t),
		        RTE_CACHE_LINE_SIZE);
		if (sess_cntxt == NULL){
		    RTE_LOG_DP(ERR, DP, "%s: Failed to allocate memory for session data info\n", __func__);
		    return NULL;
		}

		/* Session Entry not present. Add new session entry */
		ret = rte_hash_add_key_data(sess_by_ueip_hash,
						&ue_ip, sess_cntxt);
		if (ret) {
			fprintf(stderr, FORMAT"Failed to add entry for UE_IP = "IPV4_ADDR""
					"\n\tError= %s\n", ERR_MSG,
					IPV4_ADDR_HOST_FORMAT(ue_ip),
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(sess_cntxt);
			sess_cntxt = NULL;
			return NULL;
		}

		/* Function to add a node in Sesions Data Linked List. */
		if (insert_sess_data_node(*head, sess_cntxt)) {
			fprintf(stderr, FORMAT"Failed to add node entry in LL for UE_IP = "IPV4_ADDR""
					"\n\tError= %s\n", ERR_MSG,
					IPV4_ADDR_HOST_FORMAT(ue_ip),
					rte_strerror(abs(ret)));
		}

		if (*head == NULL)
			*head = sess_cntxt;
	}

	RTE_LOG_DP(DEBUG, DP, "%s: UE_IP: "IPV4_ADDR"\n",
			__func__, IPV4_ADDR_HOST_FORMAT(ue_ip));
	return sess_cntxt;

}

/**
 * Delete Session entry by UE_IP from Session hash table.
 *
 * @param UE_IP
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_sess_by_ueip_entry(uint32_t ue_ip)
{
	int ret = 0;
	pfcp_session_datat_t *sess_cntxt = NULL;

	/* Check session entry is present or Not */
	ret = rte_hash_lookup_data(sess_by_ueip_hash,
					&ue_ip, (void **)&sess_cntxt);
	if (ret) {
		/* Session Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(sess_by_ueip_hash, &ue_ip);

		if ( ret < 0) {
			fprintf(stderr, FORMAT"Entry not found for UE_IP:"IPV4_ADDR"...\n",
						__file__, __func__, __LINE__,
						IPV4_ADDR_HOST_FORMAT(ue_ip));
			return -1;
		}
	}

	RTE_LOG_DP(DEBUG, DP, "%s: UE_IP:"IPV4_ADDR"\n",
			__func__, IPV4_ADDR_HOST_FORMAT(ue_ip));

	return 0;
}

/**
 * Add PDR entry in PDR hash table.
 *
 * @param rule_id/PDR_ID
 * key.
 * @param pdr_info_t pdr
 * return 0 or 1.
 *
 */
int8_t
add_pdr_info_entry(uint16_t rule_id, pdr_info_t *pdr)
{
	int ret = 0;
	pdr_info_t *tmp = NULL;

	/* Lookup for PDR entry. */
	ret = rte_hash_lookup_data(pdr_by_id_hash,
				&rule_id, (void **)&tmp);

	if ( ret < 0) {
		/* allocate memory for session info*/
		tmp = rte_zmalloc("Session_Info", sizeof(pdr_info_t),
		        RTE_CACHE_LINE_SIZE);
		if (tmp == NULL){
		    RTE_LOG_DP(ERR, DP, "Failed to allocate memory for PDR info\n");
		    return -1;
		}

		if (pdr != NULL)
			memcpy(tmp, pdr, sizeof(pdr_info_t));

		/* PDR Entry not present. Add PDR Entry */
		ret = rte_hash_add_key_data(pdr_by_id_hash,
						&rule_id, tmp);
		if (ret) {
			fprintf(stderr, "%s:%s:%d Failed to add entry for PDR_ID = %u"
					"\n\tError= %s\n", __file__,
					__func__, __LINE__, rule_id,
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(tmp);
			tmp = NULL;
			return -1;
		}
	} else {
		memcpy(tmp, pdr, sizeof(pdr_info_t));
	}

	RTE_LOG_DP(DEBUG, DP, "%s: PDR entry add for PDR_ID:%u\n",
			__func__, rule_id);
	return 0;
}

/**
 * Get PDR entry from PDR hash table.
 *
 * @param PDR ID
 * key.
 * return pdr_info_t pdr or NULL
 *
 */
pdr_info_t *
get_pdr_info_entry(uint16_t rule_id, pdr_info_t **head)
{
	int ret = 0;
	pdr_info_t *pdr = NULL;

	ret = rte_hash_lookup_data(pdr_by_id_hash,
				&rule_id, (void **)&pdr);

	if ( ret < 0) {
		/* allocate memory for session info*/
		pdr = rte_zmalloc("Session_Info", sizeof(pdr_info_t),
		        RTE_CACHE_LINE_SIZE);
		if (pdr == NULL){
		    RTE_LOG_DP(ERR, DP, "Failed to allocate memory for PDR info\n");
		    return NULL;
		}

		/* PDR Entry not present. Add PDR Entry */
		ret = rte_hash_add_key_data(pdr_by_id_hash,
						&rule_id, pdr);
		if (ret) {
			fprintf(stderr, "%s:%s:%d Failed to add entry for PDR_ID = %u"
					"\n\tError= %s\n", __file__,
					__func__, __LINE__, rule_id,
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(pdr);
			pdr = NULL;
			return NULL;
		}
		/* Update the rule id */
		pdr->rule_id = rule_id;

		/* Function to add a node in PDR data Linked List. */
		if (insert_pdr_node(*head, pdr)) {
			fprintf(stderr, FORMAT"Failed to add node entry in LL for PDR_ID = %u"
					"\n\tError= %s\n", ERR_MSG,
					rule_id, rte_strerror(abs(ret)));
		}
		if (*head == NULL)
			*head = pdr;
	}

	RTE_LOG_DP(DEBUG, DP, "%s: PDR_ID:%u\n",
			__func__, rule_id);
	return pdr;

}

/**
 * Delete PDR entry from PDR hash table.
 *
 * @param PDR ID
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_pdr_info_entry(uint16_t rule_id)
{
	int ret = 0;
	pdr_info_t *pdr = NULL;

	/* Check PDR entry is present or Not */
	ret = rte_hash_lookup_data(pdr_by_id_hash,
					&rule_id, (void **)&pdr);
	if (ret) {
		/* PDR Entry is present. Delete PDR Entry */
		ret = rte_hash_del_key(pdr_by_id_hash, &rule_id);

		if ( ret < 0) {
			fprintf(stderr, "%s:%s:%d Entry not found for PDR_ID:%u...\n",
						__file__, __func__, __LINE__, rule_id);
			return -1;
		}
	}

	/* Free data from hash */
	//if (pdr != NULL) {
	//	rte_free(pdr);
	//	pdr = NULL;
	//}

	RTE_LOG_DP(DEBUG, DP, "%s: PDR_ID:%u\n",
			__func__, rule_id);

	return 0;
}

/**
 * Add FAR entry in FAR hash table.
 *
 * @param FAR_ID
 * key.
 * @param far_info_t far
 * return 0 or 1.
 *
 */
int8_t
add_far_info_entry(uint16_t far_id, far_info_t **far)
{
	int ret = 0;
	far_info_t *tmp = NULL;

	/* Lookup for FAR entry. */
	ret = rte_hash_lookup_data(far_by_id_hash,
				&far_id, (void **)&tmp);

	if ( ret < 0) {
		/* allocate memory for session info*/
		*far = rte_zmalloc("FAR", sizeof(far_info_t),
		        RTE_CACHE_LINE_SIZE);
		if (*far == NULL){
		    RTE_LOG_DP(ERR, DP, "Failed to allocate memory for FAR info\n");
		    return -1;
		}

		/* FAR Entry not present. Add FAR Entry */
		ret = rte_hash_add_key_data(far_by_id_hash,
						&far_id, *far);
		if (ret) {
			fprintf(stderr, "%s:%s:%d Failed to add entry for FAR_ID = %u"
					"\n\tError= %s\n", __file__,
					__func__, __LINE__, far_id,
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(*far);
			*far = NULL;
			return -1;
		}
	} else {
		memcpy(tmp, *far, sizeof(far_info_t));
	}

	RTE_LOG_DP(DEBUG, DP, "%s: FAR entry added by FAR_ID:%u\n",
			__func__, far_id);
	return 0;
}

/**
 * Get FAR entry from FAR hash table.
 *
 * @param FAR ID
 * key.
 * return far_info_t pdr or NULL
 *
 */
far_info_t *
get_far_info_entry(uint16_t far_id)
{
	int ret = 0;
	far_info_t *far = NULL;

	ret = rte_hash_lookup_data(far_by_id_hash,
				&far_id, (void **)&far);
	if ( ret < 0) {
		fprintf(stderr, "DP:"FORMAT"Entry not found for FAR_ID:%u...\n",
				ERR_MSG, far_id);
		return NULL;
	}

	RTE_LOG_DP(DEBUG, DP, "%s: FAR_ID:%u, TEID:%u, Dst_Ipv4_addr:"IPV4_ADDR", Dst_Itf_type:%u\n",
			__func__, far_id, far->frwdng_parms.outer_hdr_creation.teid,
			IPV4_ADDR_HOST_FORMAT(far->frwdng_parms.outer_hdr_creation.ipv4_address),
			far->frwdng_parms.dst_intfc.interface_value);
	return far;

}

/**
 * Delete FAR entry from FAR hash table.
 *
 * @param FAR ID
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_far_info_entry(uint16_t far_id)
{
	int ret = 0;
	far_info_t *far = NULL;

	/* Check FAR entry is present or Not */
	ret = rte_hash_lookup_data(far_by_id_hash,
					&far_id, (void **)&far);
	if (ret) {
		/* FAR Entry is present. Delete FAR Entry */
		ret = rte_hash_del_key(far_by_id_hash, &far_id);

		if ( ret < 0) {
			fprintf(stderr, "DP:"FORMAT"Entry not found for FAR_ID:%u...\n",
						ERR_MSG, far_id);
			return -1;
		}
	}

	RTE_LOG_DP(DEBUG, DP, "%s: FAR_ID:%u\n",
			__func__, far_id);

	return 0;
}

/**
 * Add QER entry in QER hash table.
 *
 * @param qer_id
 * key.
 * @param qer_info_t context
 * return 0 or 1.
 *
 */
int8_t
add_qer_info_entry(uint32_t qer_id, qer_info_t **head)
{
	int ret = 0;
	qer_info_t *qer = NULL;

	/* Lookup for QER entry. */
	ret = rte_hash_lookup_data(qer_by_id_hash,
				&qer_id, (void **)&qer);

	if ( ret < 0) {
		/* allocate memory for session info*/
		qer = rte_zmalloc("QER", sizeof(qer_info_t),
		        RTE_CACHE_LINE_SIZE);
		if (qer == NULL){
		    RTE_LOG_DP(ERR, DP, "Failed to allocate memory for QER info\n");
		    return -1;
		}

		/* QER Entry not present. Add QER Entry in table */
		ret = rte_hash_add_key_data(qer_by_id_hash,
						&qer_id, qer);
		if (ret) {
			fprintf(stderr, "%s:%s:%d Failed to add QER entry for QER_ID = %u"
					"\n\tError= %s\n", __file__,
					__func__, __LINE__, qer_id,
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
			fprintf(stderr, FORMAT"Failed to add node entry in LL for QER_ID = %u"
					"\n\tError= %s\n", ERR_MSG,
					qer_id, rte_strerror(abs(ret)));
		}
		if (*head == NULL)
			*head = qer;

	} else {
		if (head == NULL) {
		 	*head = qer;
		}
	}

	RTE_LOG_DP(DEBUG, DP, "%s: QER entry add for QER_ID:%u\n",
			__func__, qer_id);
	return 0;
}

/**
 * Get QER entry from QER hash table.
 *
 * @param QER ID
 * key.
 * return qer_info_t cntxt or NULL
 *
 */
qer_info_t *
get_qer_info_entry(uint32_t qer_id, qer_info_t **head)
{
	int ret = 0;
	qer_info_t *qer = NULL;

	/* Retireve QER entry */
	ret = rte_hash_lookup_data(qer_by_id_hash,
				&qer_id, (void **)&qer);

	if ( ret < 0) {
		/* allocate memory for session info*/
		qer = rte_zmalloc("Session_Info", sizeof(qer_info_t),
		        RTE_CACHE_LINE_SIZE);
		if (qer == NULL){
		    RTE_LOG_DP(ERR, DP, "Failed to allocate memory for QER info\n");
		    return NULL;
		}

		/* QER Entry not present. Add PDR Entry */
		ret = rte_hash_add_key_data(qer_by_id_hash,
						&qer_id, qer);
		if (ret) {
			fprintf(stderr, "%s:%s:%d Failed to add entry for QER_ID = %u"
					"\n\tError= %s\n", __file__,
					__func__, __LINE__, qer_id,
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(qer);
			qer = NULL;
			return NULL;
		}
		/* Update the rule id */
		qer->qer_id = qer_id;

		/* Function to add a node in PDR data Linked List. */
		if (insert_qer_node(*head, qer)) {
			fprintf(stderr, FORMAT"Failed to add node entry in LL for QER_ID = %u"
					"\n\tError= %s\n", ERR_MSG,
					qer_id, rte_strerror(abs(ret)));
		}
		if (*head == NULL)
			*head = qer;
	}

	RTE_LOG_DP(DEBUG, DP, "%s: QER_ID:%u\n",
			__func__, qer_id);
	return qer;

}

/**
 * Delete QER entry from QER hash table.
 *
 * @param QER ID
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_qer_info_entry(uint32_t qer_id)
{
	int ret = 0;
	qer_info_t *qer = NULL;

	/* Check QER entry is present or Not */
	ret = rte_hash_lookup_data(qer_by_id_hash,
					&qer_id, (void **)&qer);
	if (ret) {
		/* QER Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(qer_by_id_hash, &qer_id);

		if ( ret < 0) {
			fprintf(stderr, "%s:%s:%d Entry not found for QER_ID:%u...\n",
						__file__, __func__, __LINE__, qer_id);
			return -1;
		}
	}

	RTE_LOG_DP(DEBUG, DP, "%s: QER_ID:%u\n",
			__func__, qer_id);

	return 0;
}

/**
 * Add URR entry in URR hash table.
 *
 * @param urr_id
 * key.
 * @param urr_info_t context
 * return 0 or 1.
 *
 */
int8_t
add_urr_info_entry(uint32_t urr_id, urr_info_t **urr)
{
	int ret = 0;
	urr_info_t *tmp = NULL;

	/* Lookup for URR entry. */
	ret = rte_hash_lookup_data(urr_by_id_hash,
				&urr_id, (void **)&tmp);

	if ( ret < 0) {
		/* allocate memory for session info*/
		*urr = rte_zmalloc("URR", sizeof(urr_info_t),
		        RTE_CACHE_LINE_SIZE);
		if (*urr == NULL){
		    RTE_LOG_DP(ERR, DP, "Failed to allocate memory for URR info\n");
		    return -1;
		}


		/* URR Entry not present. Add URR Entry in table */
		ret = rte_hash_add_key_data(urr_by_id_hash,
						&urr_id, *urr);
		if (ret) {
			fprintf(stderr, "%s:%s:%d Failed to add URR entry for URR_ID = %u"
					"\n\tError= %s\n", __file__,
					__func__, __LINE__, urr_id,
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(*urr);
			*urr = NULL;
			return -1;
		}
	} else {
		memcpy(tmp, *urr, sizeof(urr_info_t));
	}

	RTE_LOG_DP(DEBUG, DP, "%s: URR entry add for URR_ID:%u\n",
			__func__, urr_id);
	return 0;
}

/**
 * Get URR entry from urr hash table.
 *
 * @param URR ID
 * key.
 * return urr_info_t cntxt or NULL
 *
 */
urr_info_t *
get_urr_info_entry(uint32_t urr_id)
{
	int ret = 0;
	urr_info_t *urr = NULL;

	/* Retireve URR entry */
	ret = rte_hash_lookup_data(urr_by_id_hash,
				&urr_id, (void **)&urr);

	if ( ret < 0) {
		fprintf(stderr, "%s:%s:%d Entry not found for URR_ID:%u...\n",
				__file__, __func__, __LINE__, urr_id);
		return NULL;
	}

	RTE_LOG_DP(DEBUG, DP, "%s: URR_ID:%u\n",
			__func__, urr_id);
	return urr;

}

/**
 * Delete URR entry from URR hash table.
 *
 * @param URR ID
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_urr_info_entry(uint32_t urr_id)
{
	int ret = 0;
	urr_info_t *urr = NULL;

	/* Check URR entry is present or Not */
	ret = rte_hash_lookup_data(urr_by_id_hash,
					&urr_id, (void **)&urr);
	if (ret) {
		/* URR Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(urr_by_id_hash, &urr_id);

		if ( ret < 0) {
			fprintf(stderr, "%s:%s:%d Entry not found for URR_ID:%u...\n",
						__file__, __func__, __LINE__, urr_id);
			return -1;
		}
	}

	RTE_LOG_DP(DEBUG, DP, "%s: URR_ID:%u\n",
			__func__, urr_id);

	return 0;
}

/**
 * @brief Initializes the pfcp context hash table used to account for
 * PDR, QER, BAR and FAR rules information tables and Session tables based on sessid, teid and UE_IP.
 */
void
init_up_hash_tables(void)
{
	struct rte_hash_parameters
		pfcp_hash_params[NUM_OF_TABLES] = {
		{	.name = "PDR_ENTRY_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint16_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "FAR_ENTRY_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "QER_ENTRY_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "URR_ENTRY_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "SESSION_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
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

	if ((app.spgw_cfg == PGWU) || (app.spgw_cfg == SAEGWU)) {
		sess_by_ueip_hash = rte_hash_create(&pfcp_hash_params[6]);
		if (!sess_by_ueip_hash) {
			rte_panic("%s: hash create failed: %s (%u)\n",
					pfcp_hash_params[6].name,
			    rte_strerror(rte_errno), rte_errno);
		}
	}

	fprintf(stderr, "Session, Session Data, PDR, QER, URR, BAR and FAR "
			"hash table created successfully \n");
}

/**
 * Generate the User-Plane SESSION ID
 */
uint64_t
gen_up_sess_id(uint64_t cp_sess_id)
{
	uint64_t up_sess_id = 0;

	up_sess_id = ((++up_sess_id_offset << 32) | cp_sess_id);

	return up_sess_id;
}
