/*
* Copyright (c) 2017 Sprint
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <stdint.h>
#include <string>
#include <vector>

#include "dnscache.h"
#include "epcdns.h"
#include "cdnshelper.h"

#pragma pack(1)
typedef struct nodesel_t {
	node_selector_type obj_type;
	void *node_obj;
} nodesel_t;
#pragma pack()

extern "C" void NodeSelector_callback(EPCDNS::NodeSelector &ns, void *user_data)
{
	//ns.dump();
	dns_cb_userdata_t *cb_user_data = (dns_cb_userdata_t *) user_data;
	dns_query_callback callback = cb_user_data->cb;
	void *data = cb_user_data->data;

	nodesel_t *sel = new nodesel_t();
	sel->obj_type = cb_user_data->obj_type;
	sel->node_obj = &ns;
	callback(sel, data, user_data);
}

void set_dnscache_refresh_params(unsigned int concurrent, int percent,
		long interval)
{
	DNS::Cache::setRefreshConcurrent(concurrent);
	DNS::Cache::setRefreshPercent(percent);
	DNS::Cache::setRefreshInterval(interval);
}

void set_dns_retry_params(long timeout, unsigned int retries)
{
	DNS::Cache::setQueryTimeoutMS(timeout);
	DNS::Cache::setQueryTries(retries);
}

void set_nameserver_config(const char *address, int udp_port, int tcp_port,
		nameserver_type_id ns_type)
{
	DNS::Cache::getInstance(ns_type).addNamedServer(address, udp_port, tcp_port);
}

void apply_nameserver_config(nameserver_type_id ns_type)
{
	DNS::Cache::getInstance(ns_type).applyNamedServers();
}

void init_save_dns_queries(nameserver_type_id ns_type,
		const char *qfn, int qsf)
{
	DNS::Cache::getInstance(ns_type).initSaveQueries(qfn, qsf * 1000);
}

int load_dns_queries(nameserver_type_id ns_type, const char *qfn)
{
	try
	{
	  DNS::Cache::getInstance(ns_type).loadQueries(qfn);
	}
	catch(const std::exception& e)
	{
	  return 1;
	}

	return 0;
}

void *init_pgwupf_node_selector(const char *apnoi, const char *mnc, const char *mcc)
{
	EPCDNS::PGWUPFNodeSelector *sel =
			new EPCDNS::PGWUPFNodeSelector(apnoi, mnc, mcc);

	sel->setNamedServerID(NS_OPS);

	nodesel_t *res = new nodesel_t();
	res->obj_type = PGWUPFNODESELECTOR;
	res->node_obj = sel;

	return res;
}

void *init_sgwupf_node_selector(char *lb, char *hb,
		const char *mnc, const char *mcc)
{
	EPCDNS::SGWUPFNodeSelector *sel =
				new EPCDNS::SGWUPFNodeSelector(lb, hb, mnc, mcc);

	sel->setNamedServerID(NS_OPS);

	nodesel_t *res = new nodesel_t();
	res->obj_type = SGWUPFNODESELECTOR;
	res->node_obj = sel;

	return res;
}

void *init_enbupf_node_selector(const char *enb, const char *mnc,
		const char *mcc)
{
	EPCDNS::ENodeBUPFNodeSelector *sel =
				new EPCDNS::ENodeBUPFNodeSelector(enb, mnc, mcc);

	sel->setNamedServerID(NS_APP);

	nodesel_t *res = new nodesel_t();
	res->obj_type = ENBUPFNODESELECTOR;
	res->node_obj = sel;

	return res;
}

void deinit_node_selector(void *node_obj)
{
	nodesel_t *nsel = static_cast<nodesel_t *>(node_obj);

	switch (nsel->obj_type) {
		case MMENODESELECTOR: {
			break;
		}

		case PGWNODESELECTOR: {
			break;
		}

		case PGWUPFNODESELECTOR: {
			EPCDNS::PGWUPFNodeSelector *sel = static_cast<EPCDNS::PGWUPFNodeSelector *> (nsel->node_obj);
			delete(sel);
			delete(nsel);
			break;
		}

		case SGWUPFNODESELECTOR: {
			EPCDNS::SGWUPFNodeSelector *sel = static_cast<EPCDNS::SGWUPFNodeSelector *> (nsel->node_obj);
			delete(sel);
			delete(nsel);
			break;
		}

		case ENBUPFNODESELECTOR: {
			EPCDNS::ENodeBUPFNodeSelector *sel = static_cast<EPCDNS::ENodeBUPFNodeSelector *> (nsel->node_obj);
			delete(sel);
			delete(nsel);
			break;
		}

		default:
			break;
	}
}

void set_desired_proto(void *node_obj, enum upf_app_proto_t protocol)
{
	nodesel_t *nsel = static_cast<nodesel_t *>(node_obj);

	switch (nsel->obj_type) {

		case MMENODESELECTOR: {
			break;
		}

		case PGWNODESELECTOR: {
			break;
		}

		case PGWUPFNODESELECTOR: {
			EPCDNS::PGWUPFNodeSelector *sel = static_cast<EPCDNS::PGWUPFNodeSelector *> (nsel->node_obj);
			sel->addDesiredProtocol((EPCDNS::UPFAppProtocolEnum)protocol);
			break;
		}

		case SGWUPFNODESELECTOR: {
			EPCDNS::SGWUPFNodeSelector *sel = static_cast<EPCDNS::SGWUPFNodeSelector *> (nsel->node_obj);
			sel->addDesiredProtocol((EPCDNS::UPFAppProtocolEnum)protocol);
			break;
		}

		case ENBUPFNODESELECTOR: {
			EPCDNS::ENodeBUPFNodeSelector *sel = static_cast<EPCDNS::ENodeBUPFNodeSelector *> (nsel->node_obj);
			sel->addDesiredProtocol((EPCDNS::UPFAppProtocolEnum)protocol);
			break;
		}

		default:
			break;
	}
}

void set_ueusage_type(void *node_obj, int usage_type)
{
	nodesel_t *nsel = static_cast<nodesel_t *>(node_obj);
	EPCDNS::NodeSelector *sel = static_cast<EPCDNS::NodeSelector *>(nsel->node_obj);
	sel->addDesiredUsageType(usage_type);
}

void set_nwcapability(void *node_obj, const char *nc)
{
	nodesel_t *nsel = static_cast<nodesel_t *>(node_obj);
	EPCDNS::NodeSelector *sel = static_cast<EPCDNS::NodeSelector *>(nsel->node_obj);
	sel->addDesiredNetworkCapability(nc);
}

int get_nodeselector_result(EPCDNS::NodeSelectorResult *ns_result, dns_query_result_t *result)
{
	EPCDNS::StringVector ipv4_hosts = ns_result->getIPv4Hosts();
	EPCDNS::StringVector ipv6_hosts = ns_result->getIPv6Hosts();

	if (ipv4_hosts.size() == 0 && ipv6_hosts.size() == 0)
		return 1;

	const std::string hostname = ns_result->getHostname();
	strncpy(result->hostname, hostname.c_str(), MAX_HOSTNAME_LEN);

	int j = 0;
	result->ipv4host_count = ipv4_hosts.size();
	result->ipv4_hosts = (char **)malloc(sizeof (char *) * result->ipv4host_count);
	for (EPCDNS::StringVector::const_iterator ipv4_it = ipv4_hosts.begin();
		ipv4_it != ipv4_hosts.end(); ++ipv4_it)
	{
		result->ipv4_hosts[j] = (char *)calloc(sizeof(char), 16);
		strcpy(result->ipv4_hosts[j], (*ipv4_it).c_str());
		j++;
	}

	j = 0;
	result->ipv6host_count = ipv6_hosts.size();
	result->ipv6_hosts = (char **)malloc(sizeof (char *) * result->ipv6host_count);
	for (EPCDNS::StringVector::const_iterator ipv6_it = ipv6_hosts.begin();
		ipv6_it != ipv6_hosts.end(); ++ipv6_it)
	{
		result->ipv6_hosts[j] = (char *)calloc(sizeof(char), 39);
		strcpy(result->ipv6_hosts[j], (*ipv6_it).c_str());
		j++;
	}

	return 0;
}

void process_dnsreq(void *node_obj, dns_query_result_t *result,
		uint16_t *res_count)
{
	nodesel_t *nsel = static_cast<nodesel_t *>(node_obj);

	EPCDNS::NodeSelector *sel = static_cast<EPCDNS::NodeSelector *>(nsel->node_obj);
	sel->process();
	//sel->dump();
	EPCDNS::NodeSelectorResultList& res = sel->getResults();
	*res_count = 0;
	for (EPCDNS::NodeSelectorResultList::iterator it = res.begin(); it != res.end();
			++it, ++(*res_count)) {
		if (get_nodeselector_result(*it, &result[*res_count]))
			--(*res_count);
	}
}

void process_dnsreq_async(void *node_obj, dns_cb_userdata_t *user_data)
{

	nodesel_t *nsel = static_cast<nodesel_t *>(node_obj);
	EPCDNS::NodeSelector *sel = static_cast<EPCDNS::NodeSelector *>(nsel->node_obj);
	sel->process((void *)user_data, NodeSelector_callback);

	delete(nsel);
}

void get_dns_query_res(void *node_obj, dns_query_result_t *result,
		uint16_t *res_count)
{
	nodesel_t *nsel = static_cast<nodesel_t *>(node_obj);
	EPCDNS::NodeSelector *sel = static_cast<EPCDNS::NodeSelector *>(nsel->node_obj);
	//sel->dump();
	EPCDNS::NodeSelectorResultList& res = sel->getResults();
	*res_count = 0;
	for (EPCDNS::NodeSelectorResultList::iterator it = res.begin(); it != res.end();
			++it, ++(*res_count)) {
		if (get_nodeselector_result(*it, &result[*res_count]))
			--(*res_count);
	}
}

int get_colocated_candlist(void *node_obj1, void *node_obj2,
		canonical_result_t *result)
{
	nodesel_t *nsel1 = static_cast<nodesel_t *>(node_obj1);
	nodesel_t *nsel2 = static_cast<nodesel_t *>(node_obj2);

	EPCDNS::NodeSelector *sel1  = static_cast<EPCDNS::NodeSelector *>(nsel1->node_obj);
	EPCDNS::NodeSelector *sel2  = static_cast<EPCDNS::NodeSelector *>(nsel2->node_obj);

	EPCDNS::ColocatedCandidateList ccl(sel1->getResults(), sel2->getResults());
	//ccl.dump();
	int i = 0;
	for (EPCDNS::ColocatedCandidateList::const_iterator it = ccl.begin(); it != ccl.end(); ++it, ++i)
	{
		strncpy(result[i].cano_name1, (*it)->getCanonicalNodeName1().getName().c_str(), MAX_HOSTNAME_LEN);
		strncpy(result[i].cano_name2, (*it)->getCanonicalNodeName2().getName().c_str(), MAX_HOSTNAME_LEN);
		EPCDNS::NodeSelectorResult& can1 = (*it)->getCandidate1();
		EPCDNS::NodeSelectorResult& can2 = (*it)->getCandidate2();
		get_nodeselector_result(&can1, &result[i].host1_info);
		get_nodeselector_result(&can2, &result[i].host2_info);
	}
	return i;
}

int get_colocated_candlist_fqdn(char *sgwu_fqdn, void *node_obj2,
		canonical_result_t *result)
{
	nodesel_t *nsel2 = static_cast<nodesel_t *>(node_obj2);
	EPCDNS::NodeSelector *sel2  = static_cast<EPCDNS::NodeSelector *>(nsel2->node_obj);
	std::string fqdn(sgwu_fqdn);

	EPCDNS::NodeSelectorResult *res = new EPCDNS::NodeSelectorResult();
	EPCDNS::NodeSelectorResultList *res_list = new EPCDNS::NodeSelectorResultList();

	res->setHostname(fqdn);
	res_list->push_back(res);

	EPCDNS::ColocatedCandidateList ccl(*res_list, sel2->getResults());
	//ccl.dump();
	int i = 0;
	for (EPCDNS::ColocatedCandidateList::const_iterator it = ccl.begin(); it != ccl.end(); ++it, ++i)
	{
		strncpy(result[i].cano_name1, (*it)->getCanonicalNodeName1().getName().c_str(), MAX_HOSTNAME_LEN);
		strncpy(result[i].cano_name2, (*it)->getCanonicalNodeName2().getName().c_str(), MAX_HOSTNAME_LEN);
		EPCDNS::NodeSelectorResult& can1 = (*it)->getCandidate1();
		EPCDNS::NodeSelectorResult& can2 = (*it)->getCandidate2();
		get_nodeselector_result(&can1, &result[i].host1_info);
		get_nodeselector_result(&can2, &result[i].host2_info);
	}
	return i;
}

uint8_t get_node_selector_type(void *node_obj)
{
	nodesel_t *nsel = static_cast<nodesel_t *>(node_obj);
	return nsel->obj_type;
}

void set_dns_local_ip(nameserver_type_id ns_type, const char *local_ip)
{
	DNS::Cache::getInstance(ns_type).setLocalIpAddress(local_ip);
}
