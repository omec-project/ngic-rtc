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

#ifndef __CDNSHELPER_H
#define __CDNSHELPER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "cdnsutil.h"

typedef enum node_selector_type {
	MMENODESELECTOR,
	PGWNODESELECTOR,
	PGWUPFNODESELECTOR,
	SGWNODESELECTOR,
	SGWUPFNODESELECTOR,
	ENBUPFNODESELECTOR,
} node_selector_type;

enum upf_app_proto_t
{
	UPF_X_SXA,
	UPF_X_SXB,
	UPF_X_SXC,
};

typedef enum nameserver_type_id {
	NS_OPS = 1,
	NS_APP = 2
} nameserver_type_id;

typedef int (*dns_query_callback) (void *ns, void *data, void *user_data);

typedef struct dns_cb_userdata_t {
	dns_query_callback cb;
	node_selector_type obj_type;
	void *data;
} dns_cb_userdata_t;

void set_dnscache_refresh_params(unsigned int concurrent, int percent,
		long interval);

void set_nameserver_config(const char *address, int udp_port, int tcp_port,
		nameserver_type_id ns_type);

void apply_nameserver_config(nameserver_type_id ns_type);

void init_save_dns_queries(nameserver_type_id ns_type,
		const char *qfn, int qsf);

int load_dns_queries(nameserver_type_id ns_type, const char *qfn);

void *init_pgwupf_node_selector(const char *apnoi, const char *mnc,
		const char *mcc);

void *init_sgwupf_node_selector(char *lb, char *hb,
		const char *mnc, const char *mcc);

void *init_enbupf_node_selector(const char *enb, const char *mnc,
		const char *mcc);

void deinit_node_selector(void *node_obj);

void set_desired_proto(void *node_obj, enum upf_app_proto_t protocol);

void set_ueusage_type(void *node_obj, int usage_type);

void set_nwcapability(void *node_obj, const char *nc);

void process_dnsreq(void *node_obj, dns_query_result_t *result,
		uint16_t *res_count);

void process_dnsreq_async(void *node_obj, dns_cb_userdata_t *user_data);

void get_dns_query_res(void *node_obj, dns_query_result_t *result,
		uint16_t *res_count);

int get_colocated_candlist(void *node_obj1,	void *node_obj2,
		canonical_result_t *result);

int get_colocated_candlist_fqdn(char *sgwu_fqdn, void *node_obj2,
		canonical_result_t *result);

void set_dns_retry_params(long timeout, unsigned int retries);

uint8_t get_node_selector_type(void *node_obj);

void set_dns_local_ip(nameserver_type_id ns_type, const char *local_ip);

#ifdef __cplusplus
}
#endif

#endif // #ifndef __CDNSHELPER_H
