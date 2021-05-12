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
#include "up_main.h"
#include "epc_arp.h"
#include "pfcp_util.h"
#include "pfcp_enum.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"

extern struct rte_hash *arp_hash_handle[NUM_SPGW_PORTS];
extern int clSystemLog;

void
fill_pfcp_session_est_resp(pfcp_sess_estab_rsp_t *pfcp_sess_est_resp,
			uint8_t cause, int offend, node_address_t node_value,
			pfcp_sess_estab_req_t *pfcp_session_request)
{
	/*take seq no from sess establishment request when this function is called somewhere*/
	uint32_t seq  = 0;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_est_resp->header),
			PFCP_SESSION_ESTABLISHMENT_RESPONSE, HAS_SEID, seq, NO_CP_MODE_REQUIRED);

	set_node_id(&(pfcp_sess_est_resp->node_id), node_value);
	set_cause(&(pfcp_sess_est_resp->cause), cause);

	if(cause == CONDITIONALIEMISSING || cause == MANDATORYIEMISSING) {
		set_offending_ie(&(pfcp_sess_est_resp->offending_ie), offend);
	}

	if(REQUESTACCEPTED == cause) {
		uint64_t up_seid = pfcp_session_request->header.seid_seqno.has_seid.seid;;
		set_fseid(&(pfcp_sess_est_resp->up_fseid), up_seid, node_value);
	}

	if(pfcp_ctxt.cp_supported_features & CP_LOAD) {
		set_lci(&(pfcp_sess_est_resp->load_ctl_info));
	}

	if(pfcp_ctxt.cp_supported_features & CP_OVRL) {
		set_olci(&(pfcp_sess_est_resp->ovrld_ctl_info));
	}

	if(RULECREATION_MODIFICATIONFAILURE == cause) {
		set_failed_rule_id(&(pfcp_sess_est_resp->failed_rule_id));
	}
}

void
fill_pfcp_session_modify_resp(pfcp_sess_mod_rsp_t *pfcp_sess_modify_resp,
		pfcp_sess_mod_req_t *pfcp_session_mod_req, uint8_t cause, int offend)
{
	uint32_t seq  = 1;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_modify_resp->header),
			PFCP_SESSION_MODIFICATION_RESPONSE, HAS_SEID, seq, NO_CP_MODE_REQUIRED);

	set_cause(&(pfcp_sess_modify_resp->cause), cause);

	if(cause == CONDITIONALIEMISSING
			|| cause == MANDATORYIEMISSING) {
		set_offending_ie(&(pfcp_sess_modify_resp->offending_ie), offend);
	}

	//created_bar
	// Need to do
	if(cause == REQUESTACCEPTED){
		if(pfcp_session_mod_req->create_pdr_count > 0 &&
				pfcp_session_mod_req->create_pdr[0].pdi.local_fteid.ch){
			set_created_pdr_ie(&(pfcp_sess_modify_resp->created_pdr));
		}
	}

	if( pfcp_ctxt.cp_supported_features & CP_LOAD )
		set_lci(&(pfcp_sess_modify_resp->load_ctl_info));

	if( pfcp_ctxt.cp_supported_features & CP_OVRL )
		set_olci(&(pfcp_sess_modify_resp->ovrld_ctl_info));

	if(cause == RULECREATION_MODIFICATIONFAILURE){
		set_failed_rule_id(&(pfcp_sess_modify_resp->failed_rule_id));
	}

	if( pfcp_ctxt.up_supported_features & UP_PDIU )
		set_created_traffic_endpoint(&(pfcp_sess_modify_resp->createdupdated_traffic_endpt));

}

void
fill_pfcp_sess_del_resp(pfcp_sess_del_rsp_t *
		pfcp_sess_del_resp, uint8_t cause, int offend)
{

	uint32_t seq  = 1;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_del_resp->header), PFCP_SESSION_DELETION_RESPONSE,
			HAS_SEID, seq, NO_CP_MODE_REQUIRED);

	set_cause(&(pfcp_sess_del_resp->cause), cause);

	if(cause == CONDITIONALIEMISSING ||
			cause == MANDATORYIEMISSING) {

		set_offending_ie(&(pfcp_sess_del_resp->offending_ie), offend);
	}

	if( pfcp_ctxt.cp_supported_features & CP_LOAD )
		set_lci(&(pfcp_sess_del_resp->load_ctl_info));

	if( pfcp_ctxt.cp_supported_features & CP_OVRL )
		set_olci(&(pfcp_sess_del_resp->ovrld_ctl_info));
}

int sess_modify_with_endmarker(far_info_t *far)
{
	struct sess_info_endmark edmk;
	struct arp_ip_key arp_key = {0};
	struct arp_entry_data *ret_arp_data = NULL;
	int ret = 0;

	/*Retrieve the destination MAC*/
	if (far->frwdng_parms.outer_hdr_creation.ipv4_address != 0) {
		edmk.src_ip.ip_type = IPV4_TYPE;
		edmk.dst_ip.ip_type = IPV4_TYPE;
		edmk.dst_ip.ipv4_addr = far->frwdng_parms.outer_hdr_creation.ipv4_address;

		/* Set the ARP KEY */
		arp_key.ip_type.ipv4 = PRESENT;
		arp_key.ip_addr.ipv4 = edmk.dst_ip.ipv4_addr;
	} else if (far->frwdng_parms.outer_hdr_creation.ipv6_address != NULL) {
		edmk.src_ip.ip_type = IPV6_TYPE;
		edmk.dst_ip.ip_type = IPV6_TYPE;
		memcpy(edmk.dst_ip.ipv6_addr,
				 far->frwdng_parms.outer_hdr_creation.ipv6_address,
				 IPV6_ADDRESS_LEN);
		/* Set the ARP KEY */
		arp_key.ip_type.ipv6 = PRESENT;
		memcpy(arp_key.ip_addr.ipv6.s6_addr,
				edmk.dst_ip.ipv6_addr, IPV6_ADDRESS_LEN);
	}

	edmk.teid = far->frwdng_parms.outer_hdr_creation.teid;

	ret = rte_hash_lookup_data(arp_hash_handle[S1U_PORT_ID],
			&arp_key, (void **)&ret_arp_data);

	if (ret < 0) {
		(arp_key.ip_type.ipv6 == PRESENT)?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"END_MARKER:IPv6 is not resolved for sending endmarker:"IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(edmk.dst_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"END_MARKER:IPv4 is not resolved for sending endmarker:"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(edmk.dst_ip.ipv4_addr));
		return -1;
	}

	memcpy(&(edmk.destination_MAC), &(ret_arp_data->eth_addr) , sizeof(struct ether_addr));
	edmk.dst_port = ret_arp_data->port;

	/* Fill the Local SRC Address of the intf in the IPV4 header */
	if (edmk.dst_ip.ip_type == IPV4_TYPE) {
	    /* Validate the Destination IP Address subnet */
	    if (validate_Subnet(ntohl(edmk.dst_ip.ipv4_addr), app.wb_net, app.wb_bcast_addr)) {
	        /* construct iphdr with local IP Address */
	        edmk.src_ip.ipv4_addr =htonl(app.wb_ip);

	    } else if (validate_Subnet(ntohl(edmk.dst_ip.ipv4_addr), app.wb_li_net, app.wb_li_bcast_addr)) {
	        /* construct iphdr with local IP Address */
	        edmk.src_ip.ipv4_addr = app.wb_li_ip;
	    } else if (validate_Subnet(ntohl(edmk.dst_ip.ipv4_addr), app.eb_net, app.eb_bcast_addr)) {
	        /* construct iphdr with local IP Address */
	        edmk.src_ip.ipv4_addr = app.eb_ip;
	    } else if (validate_Subnet(ntohl(edmk.dst_ip.ipv4_addr), app.eb_li_net, app.eb_li_bcast_addr)) {
	        /* construct iphdr with local IP Address */
	        edmk.src_ip.ipv4_addr = htonl(app.eb_li_ip);
	    } else {
	        clLog(clSystemLog, eCLSeverityCritical,
	                LOG_FORMAT"END_MAKER:Destination IPv4 Addr "IPV4_ADDR" is NOT in local intf subnet\n",
	                LOG_VALUE, IPV4_ADDR_HOST_FORMAT(edmk.dst_ip.ipv4_addr));
	        return -1;
	    }
	} else if (edmk.dst_ip.ip_type == IPV6_TYPE) {
		/* Validate the Destination IPv6 Address Network */
		if (validate_ipv6_network(IPv6_CAST(edmk.dst_ip.ipv6_addr), app.wb_ipv6,
					app.wb_ipv6_prefix_len)) {
			/* Source interface IPv6 address */
			memcpy(&edmk.src_ip.ipv6_addr, &app.wb_ipv6, sizeof(struct in6_addr));

		} else if (validate_ipv6_network(IPv6_CAST(edmk.dst_ip.ipv6_addr), app.wb_li_ipv6,
					app.wb_li_ipv6_prefix_len)) {
			/* Source interface IPv6 address */
			memcpy(&edmk.src_ip.ipv6_addr, &app.wb_li_ipv6, sizeof(struct in6_addr));

		} else if (validate_ipv6_network(IPv6_CAST(edmk.dst_ip.ipv6_addr), app.eb_ipv6,
					app.eb_ipv6_prefix_len)) {
			/* Source interface IPv6 address */
			memcpy(&edmk.src_ip.ipv6_addr, &app.eb_ipv6, sizeof(struct in6_addr));

		} else if (validate_ipv6_network(IPv6_CAST(edmk.dst_ip.ipv6_addr), app.eb_li_ipv6,
					app.eb_li_ipv6_prefix_len)) {
			/* Source interface IPv6 address */
			memcpy(&edmk.src_ip.ipv6_addr, &app.eb_li_ipv6, sizeof(struct in6_addr));

		} else {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"END_MARKER:Destination S5S8 intf IPv6 addr "IPv6_FMT" "
					"is NOT in local intf Network\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(edmk.dst_ip.ipv6_addr)));
			return -1;
		}
	} else {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"END_MARKER: Not set appropriate IP TYpe in the destination address\n",
				LOG_VALUE);
		return -1;
	}


	/* VS: Fill the Source IP and Physical Address of the interface based on the interface value */
	if (far->frwdng_parms.dst_intfc.interface_value == ACCESS) {
		edmk.source_MAC = app.wb_ether_addr;
	}else if(far->frwdng_parms.dst_intfc.interface_value == CORE){
		edmk.source_MAC = app.eb_ether_addr;
	}

	build_endmarker_and_send(&edmk);
	return 0;
}
