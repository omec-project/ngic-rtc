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
#include <rte_hash_crc.h>

#include "csid_struct.h"
#include "clogger.h"
#include "gw_adapter.h"
#ifdef CP_BUILD
#include "gtp_ies.h"
#include "cp.h"
#include "main.h"
#else
#include "up_main.h"
#endif /* CP_BUILD */

/**
 * Add local csid entry by peer csid in peer csid hash table.
 *
 * @param csid_t peer_csid_key
 * key.
 * @param csid_t local_csid
 * @param ifce S11/Sx/S5S8
 * return 0 or 1.
 *
 */
int8_t
add_peer_csid_entry(csid_key_t *key, csid_t *csid, uint8_t iface)
{
	int ret = 0;
	csid_t *tmp = NULL;
	struct rte_hash *hash = NULL;

	if (iface == S11_SGW_PORT_ID) {
		hash = local_csids_by_mmecsid_hash;
	} else if (iface == SX_PORT_ID) {
		hash = local_csids_by_sgwcsid_hash;
	} else if (iface == S5S8_SGWC_PORT_ID) {
		hash = local_csids_by_pgwcsid_hash;
	} else if (iface == S5S8_PGWC_PORT_ID) {
		hash = local_csids_by_pgwcsid_hash;
	} else {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Selected Invalid iface "
			"type while adding peer CSID entry..\n", LOG_VALUE);
		return -1;
	}

	/* Lookup for CSID entry. */
	ret = rte_hash_lookup_data(hash,
				key, (void **)&tmp);

	if ( ret < 0) {
		tmp = rte_zmalloc_socket(NULL, sizeof(csid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to allocate the memory for csid while adding "
				"peer CSID entry\n", LOG_VALUE);
			return -1;
		}
		tmp = csid;

		/* CSID Entry add if not present */
		ret = rte_hash_add_key_data(hash,
						key, tmp);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add entry for csid: %u"
					"\n\tError= %s\n",
					LOG_VALUE, tmp->local_csid[tmp->num_csid - 1],
					rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		tmp = csid;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"CSID entry added for csid:%u\n",
			LOG_VALUE, tmp->local_csid[tmp->num_csid - 1]);
	return 0;
}

/**
 * Get local csid entry by peer csid from csid hash table.
 *
 * @param csid_t csid_key
 * key.
 * @param iface
 * return csid or -1
 *
 */
csid_t*
get_peer_csid_entry(csid_key_t *key, uint8_t iface)
{
	int ret = 0;
	csid_t *csid = NULL;
	struct rte_hash *hash = NULL;

	if (iface == S11_SGW_PORT_ID) {
		hash = local_csids_by_mmecsid_hash;
	} else if (iface == SX_PORT_ID) {
		hash = local_csids_by_sgwcsid_hash;
	} else if (iface == S5S8_SGWC_PORT_ID) {
		hash = local_csids_by_pgwcsid_hash;
	} else if (iface == S5S8_PGWC_PORT_ID) {
		hash = local_csids_by_pgwcsid_hash;
	} else {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Selected Invalid iface type..\n", LOG_VALUE);
		return NULL;
	}

	/* Check csid  entry is present or Not */
	ret = rte_hash_lookup_data(hash,
				key, (void **)&csid);

	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Entry not found in peer node hash table, CSID:%u, Node Addr:"IPV4_ADDR"\n",
				LOG_VALUE, key->local_csid, IPV4_ADDR_HOST_FORMAT(key->node_addr));

		/* Allocate the memory for local CSID */
		csid = rte_zmalloc_socket(NULL, sizeof(csid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (csid == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate the memory for CSID: %u, Node_Addr:"IPV4_ADDR"\n",
					LOG_VALUE, key->local_csid, IPV4_ADDR_HOST_FORMAT(key->node_addr));
			return NULL;
		}

		/* CSID Entry add if not present */
		ret = rte_hash_add_key_data(hash,
						key, csid);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add entry for CSID: %u, Node_Addr:"IPV4_ADDR""
					"\n\tError= %s\n",
					LOG_VALUE, key->local_csid, IPV4_ADDR_HOST_FORMAT(key->node_addr),
					rte_strerror(abs(ret)));
			return NULL;
		}
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Found Entry for Key CSID: %u, Node_Addr:"IPV4_ADDR", Num_Csids:%u, IFACE:%u\n",
			LOG_VALUE, key->local_csid, IPV4_ADDR_HOST_FORMAT(key->node_addr), csid->num_csid, iface);

	for (uint8_t itr = 0; itr < csid->num_csid; itr++) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Node_Addr:"IPV4_ADDR", Local CSID:%u, Counter:%u, Max_Counter:%u\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(csid->node_addr), csid->local_csid[itr], itr, csid->num_csid);
	}
	return csid;

}

/**
 * Delete local csid entry by peer csid from csid hash table.
 *
 * @param csid_t csid_key
 * key.
 * @param iface
 * return 0 or 1.
 *
 */
int8_t
del_peer_csid_entry(csid_key_t *key, uint8_t iface)
{
	int ret = 0;
	csid_t *csid = NULL;
	struct rte_hash *hash = NULL;

	if (iface == S11_SGW_PORT_ID) {
		hash = local_csids_by_mmecsid_hash;
	} else if (iface == SX_PORT_ID) {
		hash = local_csids_by_sgwcsid_hash;
	} else if (iface == S5S8_SGWC_PORT_ID) {
		hash = local_csids_by_pgwcsid_hash;
	} else if (iface == S5S8_PGWC_PORT_ID) {
		hash = local_csids_by_pgwcsid_hash;
	} else {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Select Invalid iface type "
			"while deleting CSID entry..\n", LOG_VALUE);
		return -1;
	}

	/* Check peer node CSID entry is present or Not */
	ret = rte_hash_lookup_data(hash,
					key, (void **)&csid);
	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"CSID entry not found..!!, CSID:%u, Node_Addr:"IPV4_ADDR"\n",
				LOG_VALUE, key->local_csid, IPV4_ADDR_HOST_FORMAT(key->node_addr));
		return -1;
	}
	/* Peer node CSID Entry is present. Delete the CSID Entry */
	ret = rte_hash_del_key(hash, key);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure in deleting "
			"peer csid entry\n", LOG_VALUE);
		return -1;
	}
	/* Free data from hash */
	if (csid != NULL){
		rte_free(csid);
		csid = NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Peer node CSID entry deleted, CSID:%u, Node_Addr:"IPV4_ADDR", IFACE:%u\n",
			LOG_VALUE, key->local_csid, IPV4_ADDR_HOST_FORMAT(key->node_addr), iface);

	return 0;
}

/**
 * Add peer node csids entry by peer node address in peer node csids hash table.
 *
 * @param node address
 * key.
 * @param fqcsid_t csids
 * return 0 or 1.
 *
 */
int8_t
add_peer_addr_csids_entry(uint32_t node_addr, fqcsid_t *csids)
{
	int ret = 0;
	fqcsid_t *tmp = NULL;
	struct rte_hash *hash = NULL;
	hash = local_csids_by_node_addr_hash;

	/* Lookup for local CSID entry. */
	ret = rte_hash_lookup_data(hash,
				&node_addr, (void **)&tmp);

	if ( ret < 0) {
		tmp = rte_zmalloc_socket(NULL, sizeof(csid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate the memory for node addr:"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr));
			return -1;
		}
		memcpy(tmp, csids, sizeof(fqcsid_t));

		/* Local CSID Entry not present. Add CSID Entry */
		ret = rte_hash_add_key_data(hash,
						&node_addr, csids);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add entry for CSIDs for Node address:"IPV4_ADDR
					"\n\tError= %s\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr),
					rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, csids, sizeof(fqcsid_t));
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"CSID entry added for node address:"IPV4_ADDR"\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr));
	return 0;
}

/**
 * Get peer node csids entry by peer node addr from peer node csids hash table.
 *
 * @param node address
 * key.
 * @param is_mod
 * return fqcsid_t or NULL
 *
 */
fqcsid_t*
get_peer_addr_csids_entry(uint32_t node_addr, uint8_t is_mod)
{
	int ret = 0;
	fqcsid_t *tmp = NULL;
	struct rte_hash *hash = NULL;
	hash = local_csids_by_node_addr_hash;

	ret = rte_hash_lookup_data(hash,
				&node_addr, (void **)&tmp);

	if ( ret < 0) {
		if (is_mod != ADD_NODE) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Entry not found for Node addrees :"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr));
			return NULL;
		}

		tmp = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate the memory for node addr:"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr));
			return NULL;
		}

		/* Local CSID Entry not present. Add CSID Entry */
		ret = rte_hash_add_key_data(hash,
						&node_addr, tmp);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add entry for CSIDs for Node address:"IPV4_ADDR
					"\n\tError= %s\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr),
					rte_strerror(abs(ret)));
			return NULL;
		}

		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Entry added for Node address: "IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr));
		return tmp;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Entry found for Node address: "IPV4_ADDR", NUM_CSIDs:%u\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr), tmp->num_csid);

	for (uint8_t itr = 0; itr < tmp->num_csid; itr++) {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Node address: "IPV4_ADDR", PEER_CSID:%u, Counter:%u, Max_Counter:%u\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(tmp->node_addr), tmp->local_csid[itr], itr, tmp->num_csid);
	}
	return tmp;

}

/**
 * Delete peer node csid entry by peer node addr from peer node csid hash table.
 *
 * @param node_address
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_peer_addr_csids_entry(uint32_t node_addr)
{
	int ret = 0;
	fqcsid_t *tmp = NULL;
	struct rte_hash *hash = NULL;
	hash = local_csids_by_node_addr_hash;

	/* Check local CSID entry is present or Not */
	ret = rte_hash_lookup_data(hash,
					&node_addr, (void **)&tmp);
	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Entry not found for Node Addr:"IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr));
		return -1;
	}
	/* Local CSID Entry is present. Delete local csid Entry */
	ret = rte_hash_del_key(hash, &node_addr);

	/* Free data from hash */
	if(tmp != NULL){
		rte_free(tmp);
		tmp = NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Entry deleted for node addr:"IPV4_ADDR"\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr));

	return 0;
}

#ifdef CP_BUILD
int
add_fqcsid_entry(gtp_fqcsid_ie_t *fqcsid, fqcsid_t *context_fqcsid)
{
	fqcsid_t *tmp = NULL;
	tmp = get_peer_addr_csids_entry(fqcsid->node_address, ADD_NODE);
	if (tmp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
			"FQ-CSID. Error : %s \n", LOG_VALUE, strerror(errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	tmp->node_addr = fqcsid->node_address;

	for(uint8_t itr = 0; itr < fqcsid->number_of_csids; itr++) {
		uint8_t match = 0;
		for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
			if (tmp->local_csid[itr1] == fqcsid->pdn_csid[itr])
				match = 1;
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Found Match FQ-CSID entry, CSID:%u, Node Address:"IPV4_ADDR"\n",
						LOG_VALUE, fqcsid->pdn_csid[itr], IPV4_ADDR_HOST_FORMAT(tmp->node_addr));
				break;
		}

		if (!match) {
			tmp->local_csid[tmp->num_csid++] = fqcsid->pdn_csid[itr];
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Add FQ-CSID entry, CSID:%u, Node Address:"IPV4_ADDR"\n",
					LOG_VALUE, fqcsid->pdn_csid[itr], IPV4_ADDR_HOST_FORMAT(tmp->node_addr));
		}
		context_fqcsid->local_csid[context_fqcsid->num_csid++] = fqcsid->pdn_csid[itr];
	}
	context_fqcsid->node_addr = fqcsid->node_address;
	return 0;
}
#endif /*CP_BUILD*/
