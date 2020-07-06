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
add_peer_csid_entry(uint16_t *key, csid_t *csid, uint8_t iface)
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
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Select Invalid iface type..\n", ERR_MSG);
		return -1;
	}

	/* Lookup for CSID entry. */
	ret = rte_hash_lookup_data(hash,
				key, (void **)&tmp);

	if ( ret < 0) {
		tmp = rte_zmalloc_socket(NULL, sizeof(csid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for csid\n",
					ERR_MSG);
			return -1;
		}
		tmp = csid;

		/* CSID Entry add if not present */
		ret = rte_hash_add_key_data(hash,
						key, tmp);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to add entry for csid : %u"
					"\n\tError= %s\n",
					ERR_MSG, tmp->local_csid,
					rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		tmp = csid;
	}

	clLog(apilogger, eCLSeverityDebug, FORMAT"CSID entry added for csid:%u\n",
			ERR_MSG, tmp->local_csid);
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
get_peer_csid_entry(uint16_t *key, uint8_t iface)
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
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Select Invalid iface type..\n", ERR_MSG);
		return NULL;
	}

	/* Check csid  entry is present or Not */
	ret = rte_hash_lookup_data(hash,
				key, (void **)&csid);

	if ( ret < 0) {
		clLog(apilogger, eCLSeverityDebug, FORMAT"Entry not found in peer node hash table..\n",
				ERR_MSG);

		/* Allocate the memory for local CSID */
		csid = rte_zmalloc_socket(NULL, sizeof(csid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (csid == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, "Failed to allocate the memory for csid\n");
			return NULL;
		}

		/* CSID Entry add if not present */
		ret = rte_hash_add_key_data(hash,
						key, csid);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to add entry for csid : %u"
					"\n\tError= %s\n",
					ERR_MSG, csid->local_csid,
					rte_strerror(abs(ret)));
			return NULL;
		}
	}

	clLog(apilogger, eCLSeverityDebug, FORMAT"CSID : %u\n",
			ERR_MSG, csid->local_csid);
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
del_peer_csid_entry(uint16_t *key, uint8_t iface)
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
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Select Invalid iface type..\n", ERR_MSG);
		return -1;
	}

	/* Check peer node CSID entry is present or Not */
	ret = rte_hash_lookup_data(hash,
					key, (void **)&csid);
	if ( ret < 0) {
		clLog(apilogger, eCLSeverityDebug, FORMAT"CSID entry not found..!!\n",
					ERR_MSG);
		return 0;
	}
	/* Peer node CSID Entry is present. Delete the CSID Entry */
	ret = rte_hash_del_key(hash, key);

	/* Free data from hash */
	rte_free(csid);

	clLog(apilogger, eCLSeverityDebug, FORMAT"Peer node CSID entry deleted\n", ERR_MSG);

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
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for node addr:"IPV4_ADDR"\n",
					ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr));
			return -1;
		}
		memcpy(tmp, csids, sizeof(fqcsid_t));

		/* Local CSID Entry not present. Add CSID Entry */
		ret = rte_hash_add_key_data(hash,
						&node_addr, csids);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to add entry for CSIDs for Node address:"IPV4_ADDR
					"\n\tError= %s\n",
					ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr),
					rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, csids, sizeof(fqcsid_t));
	}

	clLog(apilogger, eCLSeverityDebug, FORMAT"CSID entry added for node address:"IPV4_ADDR"\n",
			ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr));
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
		if (is_mod != ADD) {
			clLog(apilogger, eCLSeverityDebug, FORMAT"Entry not found for Node addrees :"IPV4_ADDR"\n",
					ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr));
			return NULL;
		}

		tmp = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for node addr:"IPV4_ADDR"\n",
					ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr));
			return NULL;
		}

		/* Local CSID Entry not present. Add CSID Entry */
		ret = rte_hash_add_key_data(hash,
						&node_addr, tmp);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to add entry for CSIDs for Node address:"IPV4_ADDR
					"\n\tError= %s\n",
					ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr),
					rte_strerror(abs(ret)));
			return NULL;
		}

		clLog(apilogger, eCLSeverityDebug, FORMAT"Entry added for Node address: "IPV4_ADDR"\n",
				ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr));
		return tmp;
	}

	clLog(apilogger, eCLSeverityDebug, FORMAT"Entry found for Node address: "IPV4_ADDR"\n",
			ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr));
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
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Entry not found for Node Addr:"IPV4_ADDR"\n",
					ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr));
		return -1;
	}
	/* Local CSID Entry is present. Delete local csid Entry */
	ret = rte_hash_del_key(hash, &node_addr);

	/* Free data from hash */
	rte_free(tmp);
	tmp = NULL;

	clLog(apilogger, eCLSeverityDebug, FORMAT"Entry deleted for node addr:"IPV4_ADDR"\n",
			ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr));

	return 0;
}

