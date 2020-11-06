/*
 * Copyright (c) 2019 Sprint
* Copyright (c) 2020 T-Mobile
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

#include "pfcp_util.h"
#include "csid_struct.h"
#include "gw_adapter.h"
#include "pfcp_enum.h"
#include "pfcp_set_ie.h"

#ifdef CP_BUILD
#include "gtp_ies.h"
#include "cp.h"
#include "main.h"
#else
#include "up_main.h"
#endif /* CP_BUILD */
extern int clSystemLog;

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
get_peer_csid_entry(csid_key_t *key, uint8_t iface, uint8_t is_mod)
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

	if (ret < 0) {
		if (is_mod != ADD_NODE) {
			(key->node_addr.ip_type == IPV6_TYPE) ?
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Entry not found for Node IPv6 addrees :"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(IPv6_CAST(key->node_addr.ipv6_addr))):
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Entry not found for Node IPv4 addrees :"IPV4_ADDR"\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(key->node_addr.ipv4_addr));
			return NULL;
		}
		(key->node_addr.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Entry not found in peer node hash table, CSID:%u, Node IPv6 Addr:"IPv6_FMT"\n",
					LOG_VALUE, key->local_csid, IPv6_PRINT(IPv6_CAST(key->node_addr.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Entry not found in peer node hash table, CSID:%u, Node IPv4 Addr:"IPV4_ADDR"\n",
					LOG_VALUE, key->local_csid, IPV4_ADDR_HOST_FORMAT(key->node_addr.ipv4_addr));

		/* Allocate the memory for local CSID */
		csid = rte_zmalloc_socket(NULL, sizeof(csid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (csid == NULL) {
			(key->node_addr.ip_type == IPV6_TYPE) ?
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to allocate the memory for CSID: %u, Node IPv6 Addr:"IPv6_FMT"\n",
						LOG_VALUE, key->local_csid, IPv6_PRINT(IPv6_CAST(key->node_addr.ipv6_addr))):
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to allocate the memory for CSID: %u, Node IPv4 Addr:"IPV4_ADDR"\n",
						LOG_VALUE, key->local_csid, IPV4_ADDR_HOST_FORMAT(key->node_addr.ipv4_addr));
			return NULL;
		}

		/* CSID Entry add if not present */
		ret = rte_hash_add_key_data(hash,
				key, csid);
		if (ret) {
			(key->node_addr.ip_type == IPV6_TYPE) ?
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to add entry for CSID: %u, Node IPv6 Addr:"IPv6_FMT""
						"\n\tError= %s\n",
						LOG_VALUE, key->local_csid, IPv6_PRINT(IPv6_CAST(key->node_addr.ipv6_addr)),
						rte_strerror(abs(ret))):
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to add entry for CSID: %u, Node IPv4 Addr:"IPV4_ADDR""
						"\n\tError= %s\n",
						LOG_VALUE, key->local_csid, IPV4_ADDR_HOST_FORMAT(key->node_addr.ipv4_addr),
						rte_strerror(abs(ret)));
			return NULL;
		}
		return csid;
	}

	(key->node_addr.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Found Entry for Key CSID: %u, Node IPv6 Addr:"IPv6_FMT", Num_Csids:%u, IFACE:%u\n",
				LOG_VALUE, key->local_csid, IPv6_PRINT(IPv6_CAST(key->node_addr.ipv6_addr)), csid->num_csid, iface):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Found Entry for Key CSID: %u, Node IPv4 Addr:"IPV4_ADDR", Num_Csids:%u, IFACE:%u\n",
				LOG_VALUE, key->local_csid, IPV4_ADDR_HOST_FORMAT(key->node_addr.ipv4_addr), csid->num_csid, iface);

	for (uint8_t itr = 0; itr < csid->num_csid; itr++) {
		(key->node_addr.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Node IPv6 Addr:"IPv6_FMT", Local CSID:%u, Counter:%u, Max_Counter:%u\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(csid->node_addr.ipv6_addr)), csid->local_csid[itr], itr, csid->num_csid):
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Node IPv4 Addr:"IPV4_ADDR", Local CSID:%u, Counter:%u, Max_Counter:%u\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(csid->node_addr.ipv4_addr), csid->local_csid[itr], itr, csid->num_csid);
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
	ret = rte_hash_lookup_data(hash, key, (void **)&csid);
	if ( ret < 0) {
		(key->node_addr.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"CSID entry not found..!!, CSID:%u, Node IPv6 Addr:"IPv6_FMT"\n",
					LOG_VALUE, key->local_csid, IPv6_PRINT(IPv6_CAST(key->node_addr.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"CSID entry not found..!!, CSID:%u, Node IPv4 Addr:"IPV4_ADDR"\n",
					LOG_VALUE, key->local_csid, IPV4_ADDR_HOST_FORMAT(key->node_addr.ipv4_addr));
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

	(key->node_addr.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer node CSID entry deleted, CSID:%u, Node IPv6 Addr:"IPv6_FMT", IFACE:%u\n",
				LOG_VALUE, key->local_csid, IPv6_PRINT(IPv6_CAST(key->node_addr.ipv6_addr)), iface):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer node CSID entry deleted, CSID:%u, Node IPv4 Addr:"IPV4_ADDR", IFACE:%u\n",
				LOG_VALUE, key->local_csid, IPV4_ADDR_HOST_FORMAT(key->node_addr.ipv4_addr), iface);

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
		tmp = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (tmp == NULL) {
			/*clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate the memory for node addr:"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr));*/
			return -1;
		}
		memcpy(tmp, csids, sizeof(fqcsid_t));

		/* Local CSID Entry not present. Add CSID Entry */
		ret = rte_hash_add_key_data(hash,
						&node_addr, csids);
		if (ret) {
			/*clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add entry for CSIDs for Node address:"IPV4_ADDR
					"\n\tError= %s\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr),
					rte_strerror(abs(ret)));*/
			return -1;
		}
	} else {
		memcpy(tmp, csids, sizeof(fqcsid_t));
	}

	/*clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"CSID entry added for node address:"IPV4_ADDR"\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr));*/
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
get_peer_addr_csids_entry(node_address_t *node_addr, uint8_t is_mod)
{
	int ret = 0;
	fqcsid_t *tmp = NULL;
	struct rte_hash *hash = NULL;
	hash = local_csids_by_node_addr_hash;

	ret = rte_hash_lookup_data(hash,
				node_addr, (void **)&tmp);

	if ( ret < 0) {
		if (is_mod != ADD_NODE) {
			(node_addr->ip_type == IPV6_TYPE) ?
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Entry not found for IPv6 Node addrees :"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(IPv6_CAST(node_addr->ipv6_addr))):
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Entry not found for IPv4 Node addrees :"IPV4_ADDR"\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr));
			return NULL;
		}

		tmp = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

		if (tmp == NULL) {
			(node_addr->ip_type == IPV6_TYPE) ?
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to allocate the memory for ipv6 node addr:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(IPv6_CAST(node_addr->ipv6_addr))):
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to allocate the memory for node addr:"IPV4_ADDR"\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr));
			return NULL;
		}

		/* Local CSID Entry not present. Add CSID Entry */
		ret = rte_hash_add_key_data(hash,
						node_addr, tmp);
		if (ret) {
			(node_addr->ip_type == IPV6_TYPE) ?
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to add entry for CSIDs for IPv6 Node address:"IPv6_FMT
						"\n\tError= %s\n",
						LOG_VALUE, IPv6_PRINT(IPv6_CAST(node_addr->ipv6_addr)),
						rte_strerror(abs(ret))):
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to add entry for CSIDs for Node address:"IPV4_ADDR
						"\n\tError= %s\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr),
						rte_strerror(abs(ret)));
			return NULL;
		}

		(node_addr->ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Entry added for IPv6 Node address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST((node_addr->ipv6_addr)))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Entry added for IPv4 Node address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr));
		return tmp;
	}

	(node_addr->ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Entry found for IPv6 Node address: "IPv6_FMT", NUM_CSIDs:%u\n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST((node_addr->ipv6_addr))), tmp->num_csid):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Entry found for Node address: "IPV4_ADDR", NUM_CSIDs:%u\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr), tmp->num_csid);

	for (uint8_t itr = 0; itr < tmp->num_csid; itr++) {
		(node_addr->ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv6 Node address: "IPv6_FMT", PEER_CSID:%u, Counter:%u, Max_Counter:%u\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(tmp->node_addr.ipv6_addr)),
					tmp->local_csid[itr], itr, tmp->num_csid):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv4 Node address: "IPV4_ADDR", PEER_CSID:%u, Counter:%u, Max_Counter:%u\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(tmp->node_addr.ipv4_addr),
					tmp->local_csid[itr], itr, tmp->num_csid);
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
del_peer_addr_csids_entry(node_address_t *node_addr)
{
	int ret = 0;
	fqcsid_t *tmp = NULL;
	struct rte_hash *hash = NULL;
	hash = local_csids_by_node_addr_hash;

	/* Check local CSID entry is present or Not */
	ret = rte_hash_lookup_data(hash,
					node_addr, (void **)&tmp);
	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Entry not found for Node Addr:"IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr));
		return -1;
	}
	/* Local CSID Entry is present. Delete local csid Entry */
	ret = rte_hash_del_key(hash, node_addr);

	/* Free data from hash */
	if ((tmp != NULL) && (tmp->num_csid)){
		rte_free(tmp);
	}
	tmp = NULL;

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Entry deleted for node addr:"IPV4_ADDR"\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr));

	return 0;
}

#ifdef CP_BUILD

int match_and_add_pfcp_sess_fqcsid(pfcp_fqcsid_ie_t *fqcsid, sess_fqcsid_t *context_fqcsid)
{
	uint8_t cnd = 0;
	uint8_t ex_csid_match = 0;
	uint8_t ex_node_addr_match = 0;
	uint8_t itr = 0;
	uint8_t num_csid = context_fqcsid->num_csid;

	for (itr = 0; itr < fqcsid->number_of_csids; itr++)
	{
		/* Reset Flags */
		ex_csid_match = 0;
		ex_node_addr_match = 0;
		for (uint8_t itr1 = 0; itr1 < context_fqcsid->num_csid; itr1++)
		{
			if (context_fqcsid->local_csid[itr1] == fqcsid->pdn_conn_set_ident[itr])
			{
				ex_csid_match = 1;

				for (uint8_t itr2 = 0; itr2 < context_fqcsid->num_csid; itr2++)
				{
					if (fqcsid->fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
						cnd = memcmp(&(context_fqcsid->node_addr[itr2].ipv4_addr),
								&(fqcsid->node_address), IPV4_SIZE);
					} else {
						cnd = memcmp(&(context_fqcsid->node_addr[itr2].ipv6_addr),
								&(fqcsid->node_address), IPV6_SIZE);
					}

					if (cnd  == 0)
					{
						ex_node_addr_match = 1;
						break;
					}
				}
				break;
			}
		}
		if ((ex_csid_match == 0) || (ex_node_addr_match == 0) ) {
			context_fqcsid->local_csid[num_csid] = fqcsid->pdn_conn_set_ident[itr];
			if (fqcsid->fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
				context_fqcsid->node_addr[num_csid].ip_type =
					PDN_TYPE_IPV4;
				memcpy(&context_fqcsid->node_addr[num_csid].ipv4_addr,
						&fqcsid->node_address, IPV4_SIZE);
			} else {
				context_fqcsid->node_addr[num_csid].ip_type =
					PDN_TYPE_IPV6;
				memcpy(&(context_fqcsid->node_addr[num_csid].ipv6_addr),
							&(fqcsid->node_address), IPV6_SIZE);
			}
			num_csid++;
		}
	}

	context_fqcsid->num_csid = num_csid;

	return 0;
}

void add_pfcp_sess_fqcsid(pfcp_fqcsid_ie_t *fqcsid, sess_fqcsid_t *context_fqcsid) {

	uint8_t num_csid = context_fqcsid->num_csid;
	for (uint8_t itr = 0; itr < fqcsid->number_of_csids; itr++)
	{
		context_fqcsid->local_csid[num_csid] = fqcsid->pdn_conn_set_ident[itr];
		if (fqcsid->fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
			context_fqcsid->node_addr[num_csid].ip_type =
				PDN_TYPE_IPV4;
			memcpy(&context_fqcsid->node_addr[num_csid].ipv4_addr,
				&fqcsid->node_address, IPV4_SIZE);
		} else {
			context_fqcsid->node_addr[num_csid].ip_type =
				PDN_TYPE_IPV6;
			memcpy(&(context_fqcsid->node_addr[num_csid].ipv6_addr),
				&(fqcsid->node_address), IPV6_SIZE);
		}
		num_csid++;
	}
	context_fqcsid->num_csid = num_csid;
}

int match_and_add_sess_fqcsid(gtp_fqcsid_ie_t *fqcsid, sess_fqcsid_t *context_fqcsid)
{
	uint8_t ex_csid_match = 0;
	uint8_t ex_node_addr_match = 0;
	uint8_t itr = 0;
	uint8_t num_csid = context_fqcsid->num_csid;
	node_address_t node_addr = {0};

	for (itr = 0; itr < fqcsid->number_of_csids; itr++)
	{
		/* Reset Flags */
		ex_csid_match = 0;
		ex_node_addr_match = 0;
		for (uint8_t itr1 = 0; itr1 < context_fqcsid->num_csid; itr1++)
		{
			if (context_fqcsid->local_csid[itr1] == fqcsid->pdn_csid[itr])
			{
				ex_csid_match = 1;

				for (uint8_t itr2 = 0; itr2 < context_fqcsid->num_csid; itr2++)
				{
					if (fqcsid->node_id_type == IPV4_GLOBAL_UNICAST) {
						node_addr.ip_type = PDN_TYPE_IPV4;
						memcpy(&node_addr.ipv4_addr, &(fqcsid->node_address), IPV4_SIZE);
					} else {
						node_addr.ip_type = PDN_TYPE_IPV6;
						memcpy(&node_addr.ipv6_addr, &(fqcsid->node_address), IPV6_SIZE);
					}

					if ((COMPARE_IP_ADDRESS(context_fqcsid->node_addr[itr2], node_addr)) == 0)
					{
						ex_node_addr_match = 1;
						break;
					}
				}
				break;
			}
		}
		if ((ex_csid_match == 0) || (ex_node_addr_match == 0) ) {
			context_fqcsid->local_csid[num_csid] = fqcsid->pdn_csid[itr];
			if (fqcsid->node_id_type == IPV4_GLOBAL_UNICAST) {
				context_fqcsid->node_addr[num_csid].ip_type =
					PDN_TYPE_IPV4;
				memcpy(&(context_fqcsid->node_addr[num_csid].ipv4_addr),
					&(fqcsid->node_address), IPV4_SIZE);
			} else {
				context_fqcsid->node_addr[num_csid].ip_type =
					PDN_TYPE_IPV6;
				memcpy(&(context_fqcsid->node_addr[num_csid].ipv6_addr),
					&(fqcsid->node_address), IPV6_SIZE);
			}
			num_csid++;
		}
	}

	context_fqcsid->num_csid = num_csid;

	return 0;
}

void add_sess_fqcsid(gtp_fqcsid_ie_t *fqcsid, sess_fqcsid_t *context_fqcsid) {

	uint8_t num_csid = context_fqcsid->num_csid;
	for (uint8_t itr = 0; itr < fqcsid->number_of_csids; itr++)
	{
		context_fqcsid->local_csid[num_csid] = fqcsid->pdn_csid[itr];
		if (fqcsid->node_id_type == IPV4_GLOBAL_UNICAST) {
			context_fqcsid->node_addr[num_csid].ip_type =
				PDN_TYPE_IPV4;
			memcpy(&(context_fqcsid->node_addr[num_csid].ipv4_addr),
				&(fqcsid->node_address), IPV4_SIZE);
		} else {
			context_fqcsid->node_addr[num_csid].ip_type =
				PDN_TYPE_IPV6;
			memcpy(&(context_fqcsid->node_addr[num_csid].ipv6_addr),
				&(fqcsid->node_address), IPV6_SIZE);
		}
		num_csid++;
	}
	context_fqcsid->num_csid = num_csid;
}

int
add_fqcsid_entry(gtp_fqcsid_ie_t *fqcsid, sess_fqcsid_t *context_fqcsid)
{
	fqcsid_t *tmp = NULL;
	node_address_t node_addr = {0};

	if (fqcsid->node_id_type == IPV4_GLOBAL_UNICAST) {
		memcpy(&(node_addr.ipv4_addr), &fqcsid->node_address, IPV4_SIZE);
		node_addr.ip_type = PDN_TYPE_IPV4;
	} else if (fqcsid->node_id_type == IPV6_GLOBAL_UNICAST) {
		memcpy(&(node_addr.ipv6_addr), &fqcsid->node_address, IPV6_SIZE);
		node_addr.ip_type = PDN_TYPE_IPV6;
	} else {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"Error : Unknown node id type: %d \n",
				LOG_VALUE, fqcsid->node_id_type);
		 return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	tmp = get_peer_addr_csids_entry(&node_addr, ADD_NODE);
	if (tmp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
			"FQ-CSID. Error : %s \n", LOG_VALUE, strerror(errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	memcpy(&tmp->node_addr, &node_addr, sizeof(node_address_t));

	for(uint8_t itr = 0; itr < fqcsid->number_of_csids; itr++) {
		uint8_t match = 0;
		for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
			if (tmp->local_csid[itr1] == fqcsid->pdn_csid[itr]) {
				match = 1;
				(tmp->node_addr.ip_type == IPV6_TYPE) ?
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Found Match FQ-CSID entry, CSID:%u, Node IPv6 Addr:"IPv6_FMT"\n",
							LOG_VALUE, fqcsid->pdn_csid[itr],
							IPv6_PRINT(IPv6_CAST(tmp->node_addr.ipv6_addr))):
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Found Match FQ-CSID entry, CSID:%u, Node IPv4 Addr:"IPV4_ADDR"\n",
							LOG_VALUE, fqcsid->pdn_csid[itr],
							IPV4_ADDR_HOST_FORMAT(tmp->node_addr.ipv4_addr));
				break;
			}
		}

		if (!match) {
			tmp->local_csid[tmp->num_csid++] = fqcsid->pdn_csid[itr];
			(tmp->node_addr.ip_type == IPV6_TYPE) ?
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Add FQ-CSID entry, CSID:%u, Node IPv6 Addr:"IPv6_FMT"\n",
						LOG_VALUE, fqcsid->pdn_csid[itr],
						IPv6_PRINT(IPv6_CAST(tmp->node_addr.ipv6_addr))):
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Add FQ-CSID entry, CSID:%u, Node IPv4 Addr:"IPV4_ADDR"\n",
						LOG_VALUE, fqcsid->pdn_csid[itr],
						IPV4_ADDR_HOST_FORMAT(tmp->node_addr.ipv4_addr));
		}
	}

	if (context_fqcsid->num_csid) {
		match_and_add_sess_fqcsid(fqcsid, context_fqcsid);
	} else {
		add_sess_fqcsid(fqcsid, context_fqcsid);
	}

	return 0;
}
#endif /*CP_BUILD*/


#if USE_CSID

fqcsid_ie_node_addr_t*
get_peer_node_addr_entry(peer_node_addr_key_t *key, uint8_t is_mod)
{
	int ret = 0;
	fqcsid_ie_node_addr_t *tmp = NULL;
	struct rte_hash *hash = NULL;
	hash = peer_node_addr_by_peer_fqcsid_node_addr_hash;

	ret = rte_hash_lookup_data(hash, key, (void **)&tmp);

	if ( ret < 0) {
		if (is_mod != ADD_NODE) {
			( (key->peer_node_addr.ip_type == PDN_TYPE_IPV4) ?
			  clLog(clSystemLog, eCLSeverityDebug,
				  LOG_FORMAT"Entry not found for Node addrees :"IPV4_ADDR"\n",
				  LOG_VALUE, IPV4_ADDR_HOST_FORMAT(key->peer_node_addr.ipv4_addr)) :
			  clLog(clSystemLog, eCLSeverityDebug,
				  LOG_FORMAT"Entry not found for Node addrees :"IPv6_FMT"\n",
				  LOG_VALUE, PRINT_IPV6_ADDR(key->peer_node_addr.ipv6_addr)));

			return NULL;
		}

		tmp = rte_zmalloc_socket(NULL, sizeof(fqcsid_ie_node_addr_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

		if (tmp == NULL) {
			( (key->peer_node_addr.ip_type == PDN_TYPE_IPV4) ?
			  clLog(clSystemLog, eCLSeverityCritical,
				  LOG_FORMAT"Failed to allocate the memory for node addr:"IPV4_ADDR"\n",
				  LOG_VALUE, IPV4_ADDR_HOST_FORMAT(key->peer_node_addr.ipv4_addr)) :
			  clLog(clSystemLog, eCLSeverityCritical,
				  LOG_FORMAT"Failed to allocate the memory for node addr:"IPv6_FMT"\n",
				  LOG_VALUE, PRINT_IPV6_ADDR(key->peer_node_addr.ipv6_addr)));
			return NULL;
		}

		/* Local CSID Entry not present. Add CSID Entry */
		ret = rte_hash_add_key_data(hash, key, tmp);
		if (ret) {
			( (key->peer_node_addr.ip_type == PDN_TYPE_IPV4) ?
			  clLog(clSystemLog, eCLSeverityCritical,
				  LOG_FORMAT"Failed to add entry for Node address:"IPV4_ADDR
				  "\n\tError= %s\n",
				  LOG_VALUE, IPV4_ADDR_HOST_FORMAT(key->peer_node_addr.ipv4_addr),
				  rte_strerror(abs(ret))) :
			  clLog(clSystemLog, eCLSeverityCritical,
				  LOG_FORMAT"Failed to add entry for Node address:"IPv6_FMT
				  "\n\tError= %s\n",
				  LOG_VALUE, PRINT_IPV6_ADDR(key->peer_node_addr.ipv6_addr),
				  rte_strerror(abs(ret))));
			return NULL;
		}
		( (key->peer_node_addr.ip_type == PDN_TYPE_IPV4) ?
		  clLog(clSystemLog, eCLSeverityDebug,
			  LOG_FORMAT"Entry added for Node address: "IPV4_ADDR"\n",
			  LOG_VALUE, IPV4_ADDR_HOST_FORMAT(key->peer_node_addr.ipv4_addr)) :
		  clLog(clSystemLog, eCLSeverityDebug,
			  LOG_FORMAT"Entry added for Node address: "IPv6_FMT"\n",
			  LOG_VALUE, PRINT_IPV6_ADDR(key->peer_node_addr.ipv6_addr)));
		return tmp;
	}
	( (tmp->fqcsid_node_addr.ip_type == PDN_TYPE_IPV4) ?
	  clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
		  "Entry found, Fqcsid IE Node address :"IPV4_ADDR" \n",
		  LOG_VALUE, IPV4_ADDR_HOST_FORMAT(tmp->fqcsid_node_addr.ipv4_addr)) :
	  clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
		  "Entry found, Fqcsid Node address :"IPv6_FMT",\n",
		  LOG_VALUE, PRINT_IPV6_ADDR(tmp->fqcsid_node_addr.ipv6_addr)));
	return tmp;

}

int8_t
del_peer_node_addr_entry(peer_node_addr_key_t *key)
{
	int ret = 0;
	fqcsid_ie_node_addr_t *tmp = NULL;
	struct rte_hash *hash = NULL;
	hash = peer_node_addr_by_peer_fqcsid_node_addr_hash;

	/* Check local CSID entry is present or Not */
	ret = rte_hash_lookup_data(hash, key, (void **)&tmp);
	if ( ret < 0) {
		(key->peer_node_addr.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Entry not found for Peer Node IPv6 Addr:"IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(key->peer_node_addr.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Entry not found for Peer Node IPv4 Addr:"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(key->peer_node_addr.ipv4_addr));
		return -1;
	}
	/* Local CSID Entry is present. Delete local csid Entry */
	ret = rte_hash_del_key(hash, key);

	/* Free data from hash */
	if(tmp != NULL){
		rte_free(tmp);
		tmp = NULL;
	}

	(key->peer_node_addr.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Entry deleted for Peer node ipv6 addr:"IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST(key->peer_node_addr.ipv6_addr))):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Entry deleted for Peer node ipv4 addr:"IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(key->peer_node_addr.ipv4_addr));

	return 0;
}

#if CP_BUILD
int8_t
add_peer_addr_entry_for_fqcsid_ie_node_addr(node_address_t *peer_node_addr,
			gtp_fqcsid_ie_t *fqcsid, uint8_t iface)
{
	uint32_t ipv4_node_addr = 0;
	fqcsid_ie_node_addr_t *tmp = NULL;
	peer_node_addr_key_t key = {0};
	node_address_t peer_node_fqcsid_ie_info = {0};

	if (fqcsid->node_id_type == IPV4_GLOBAL_UNICAST) {
		memcpy(&ipv4_node_addr, &(fqcsid->node_address), IPV4_SIZE);
		if (ipv4_node_addr == peer_node_addr->ipv4_addr) {
			return 0;
		}

		/* Fill peer fq-csid node info */
		peer_node_fqcsid_ie_info.ip_type = PDN_TYPE_IPV4;
		peer_node_fqcsid_ie_info.ipv4_addr = ipv4_node_addr;

	} else {
		if ((memcmp(&(fqcsid->node_address),
			 &peer_node_addr->ipv6_addr, IPV6_ADDRESS_LEN)) == 0) {
			return 0;
		}

		/* Fill peer fq-csid node info */
		peer_node_fqcsid_ie_info.ip_type = PDN_TYPE_IPV6;
		memcpy(&(peer_node_fqcsid_ie_info.ipv6_addr), &(fqcsid->node_address),
				IPV6_ADDRESS_LEN);
	}

	switch(peer_node_addr->ip_type) {
		case  PDN_TYPE_IPV4 :
			{
				key.peer_node_addr.ip_type = PDN_TYPE_IPV4;
				key.iface = iface;
				key.peer_node_addr.ipv4_addr = peer_node_addr->ipv4_addr;

				break;
			}
		case PDN_TYPE_IPV6 :
			{
				key.peer_node_addr.ip_type = PDN_TYPE_IPV6;
				key.iface = iface;
				memcpy(&(key.peer_node_addr.ipv6_addr),
						&(peer_node_addr->ipv6_addr), IPV6_ADDRESS_LEN);
				break;
			}
		case PDN_TYPE_IPV4_IPV6 :
			{
				key.peer_node_addr.ip_type = PDN_TYPE_IPV6;
				key.iface = iface;
				memcpy(&(key.peer_node_addr.ipv6_addr),
						&(peer_node_addr->ipv6_addr), IPV6_ADDRESS_LEN);
				break;
			}
		default :
			{
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Neither IPv4 nor "
									"IPv6 type is set ", LOG_VALUE);
				return PRESENT;
			}
	}

	tmp = get_peer_node_addr_entry(&key, ADD_NODE);
	if (tmp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
				"FQ-CSID IE address. Error : %s \n", LOG_VALUE, strerror(errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	if (fqcsid->node_id_type == IPV4_GLOBAL_UNICAST) {
		if ((ipv4_node_addr) && (ipv4_node_addr != tmp->fqcsid_node_addr.ipv4_addr)) {
			memcpy(&tmp->fqcsid_node_addr, &peer_node_fqcsid_ie_info, sizeof(node_address_t));

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Mapped:Fqcsid IE node address "
					"added : Fqcsid node address type: %d \n", LOG_VALUE,
					tmp->fqcsid_node_addr.ip_type);

		}
	} else {

		if (memcmp(tmp->fqcsid_node_addr.ipv6_addr, fqcsid->node_address,
					IPV6_ADDRESS_LEN) != 0) {
			memcpy(&tmp->fqcsid_node_addr, &peer_node_fqcsid_ie_info, sizeof(node_address_t));

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Mapped:Fqcsid IE node address "
					"added : Fqcsid node address type: %d \n", LOG_VALUE,
					tmp->fqcsid_node_addr.ip_type);
		}
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"Fqcsid IE Node address added into hash\n",
			LOG_VALUE);

	return 0;
}
#else
int8_t
add_peer_addr_entry_for_fqcsid_ie_node_addr(node_address_t *peer_node_addr,
			pfcp_fqcsid_ie_t *fqcsid, uint8_t iface)
{
	uint32_t ipv4_node_addr = 0;
	fqcsid_ie_node_addr_t *tmp = NULL;
	peer_node_addr_key_t key = {0};
	node_address_t peer_node_fqcsid_ie_info = {0};

	if (fqcsid->fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
		memcpy(&ipv4_node_addr, &(fqcsid->node_address), IPV4_SIZE);
		if (ipv4_node_addr == peer_node_addr->ipv4_addr) {
			return 0;
		}

		/* Fill peer fq-csid node info */
		peer_node_fqcsid_ie_info.ip_type = IPV4_TYPE;
		peer_node_fqcsid_ie_info.ipv4_addr = ipv4_node_addr;

	} else {
		if ((memcmp(&(fqcsid->node_address),
			 &peer_node_addr->ipv6_addr, IPV6_ADDRESS_LEN)) == 0) {
			return 0;
		}

		/* Fill peer fq-csid node info */
		peer_node_fqcsid_ie_info.ip_type = IPV6_TYPE;
		memcpy(&(peer_node_fqcsid_ie_info.ipv6_addr), &(fqcsid->node_address),
				IPV6_ADDRESS_LEN);
	}

	switch(peer_node_addr->ip_type) {
		case  PDN_TYPE_IPV4 :
			{
				key.peer_node_addr.ip_type = PDN_TYPE_IPV4;
				key.iface = iface;
				key.peer_node_addr.ipv4_addr = peer_node_addr->ipv4_addr;

				break;
			}
		case PDN_TYPE_IPV6 :
			{
				key.peer_node_addr.ip_type = PDN_TYPE_IPV6;
				key.iface = iface;
				memcpy(&(key.peer_node_addr.ipv6_addr),
						peer_node_addr->ipv6_addr, IPV6_ADDRESS_LEN);
				break;
			}
		case PDN_TYPE_IPV4_IPV6 :
			{
				key.peer_node_addr.ip_type = PDN_TYPE_IPV6;
				key.iface = iface;
				memcpy(&(key.peer_node_addr.ipv6_addr),
						&(peer_node_addr->ipv6_addr), IPV6_ADDRESS_LEN);
				break;
			}
		default :
			{
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Neither IPv4 nor "
									"IPv6 type is set ", LOG_VALUE);
				return PRESENT;
			}
	}

	tmp = get_peer_node_addr_entry(&key, ADD_NODE);
	if (tmp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
				"FQ-CSID IE address. Error : %s \n", LOG_VALUE, strerror(errno));
		return -1;
	}

	if (fqcsid->fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
		if (ipv4_node_addr && (ipv4_node_addr != tmp->fqcsid_node_addr.ipv4_addr)) {
			memcpy(&tmp->fqcsid_node_addr, &peer_node_fqcsid_ie_info, sizeof(node_address_t));

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Mapped:Fqcsid IE node address IPv4"
					"added: "IPV4_ADDR" With CP IPv4 Addr:"IPV4_ADDR"\n", LOG_VALUE,
					IPV4_ADDR_HOST_FORMAT(tmp->fqcsid_node_addr.ipv4_addr),
					IPV4_ADDR_HOST_FORMAT(key.peer_node_addr.ipv4_addr));
		}
	} else {

		if (memcmp(tmp->fqcsid_node_addr.ipv6_addr, fqcsid->node_address, IPV6_ADDRESS_LEN) != 0) {
			memcpy(&tmp->fqcsid_node_addr, &peer_node_fqcsid_ie_info, sizeof(node_address_t));

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Mapped:Fqcsid IE node address IPv6"
					"added : "IPv6_FMT" with CP IPv6 Addr: "IPv6_FMT"\n", LOG_VALUE,
					IPv6_PRINT(IPv6_CAST(tmp->fqcsid_node_addr.ipv6_addr)),
					IPv6_PRINT(IPv6_CAST(key.peer_node_addr.ipv6_addr)));
		}
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Fqcsid IE Node address added into hash\n", LOG_VALUE);

	return 0;
}
#endif /* CP_BUILD */
#endif /* USE_CSID */
