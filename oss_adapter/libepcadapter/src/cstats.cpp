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

#include <stdlib.h>

#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <time.h>
#include <netinet/ip.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define RAPIDJSON_NAMESPACE statsrapidjson
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "etevent.h"
#include "etime.h"
#include "gw_structs.h"
#include "cstats.h"
#include "elogger.h"
#include "cstats_dev.h"
#include "gw_adapter.h"

long oss_resetsec;
uint64_t reset_time;
cp_configuration_t *cp_config_ptr;
dp_configuration_t *dp_config_ptr;

class CStats: public EThreadPrivate
{
public:

	static CStats &singleton() {
		if (!m_singleton) {
			m_singleton = new CStats();
			// app id = 1, thread id = 1, pVoid = NULL, currently not used by epctools
			m_singleton->init(1, 1, NULL);
			}
		return *m_singleton;
	}

	void setInterval(long interval) {
		 m_interval = interval;
	}

	void setpInterval(long interval) {
		p_interval = interval;
	}

	long getInterval() {
		return m_interval;
	}

	long getpInterval() {
		return p_interval;
	}

	void setStatLoggingSuppress(bool suppress) {
		statLoggingSuppress = suppress;
	}

	bool getStatLoggingSuppress() {
		return statLoggingSuppress;
	}

	CStats();
	~CStats();
	void serializeJSON(std::string &json, bool suppressed);
	Void onInit();
	Void onTimer(EThreadEventTimer *ptimer);
	void updateInterval(long interval);

private:
	static CStats *m_singleton;
	long m_interval;
	long p_interval;
   	bool statLoggingSuppress;
	EThreadEventTimer statsTimer;
};

int get_number_of_request_tries(char **response, int request_tries)
{
	std::string res = "{\"request_tries\": " + std::to_string(request_tries) + "}";
	*response = strdup(res.c_str());
	return REST_SUCESSS;
}

int get_pcap_generation_status(char **response, uint8_t pcap_gen_status)
{
	std::string res;
	if ((pcap_gen_status == PCAP_GEN_ON) || (pcap_gen_status == PCAP_GEN_RESTART))
		res = "{\"PCAP_GENERATION\": \"START\"}";
	else if (pcap_gen_status == PCAP_GEN_OFF)
                res = "{\"PCAP_GENERATION\": \"STOP\"}";

	*response = strdup(res.c_str());
	return REST_SUCESSS;
}

int get_number_of_transmit_count(char **response, int transmit_count)
{
	std::string res = "{\"transmit_count\": " + std::to_string(transmit_count) + "}";
	*response = strdup(res.c_str());
	return REST_SUCESSS;
}

int get_transmit_timer_value(char **response, int transmit_timer_value)
{
	std::string res = "{\"transmit_timer\": " + std::to_string(transmit_timer_value) + "}";
	*response = strdup(res.c_str());
	return REST_SUCESSS;
}

int get_periodic_timer_value(char **response, int periodic_timer_value)
{
	std::string res = "{\"periodic_timer\": " + std::to_string(periodic_timer_value) + "}";
	*response = strdup(res.c_str());
	return REST_SUCESSS;
}

int get_request_timeout_value(char **response, int request_timeout_value)
{
	std::string res = "{\"request_timeout\": " + std::to_string(request_timeout_value) + "}";
	*response = strdup(res.c_str());
	return REST_SUCESSS;
}

int csGetInterval(char **response)
{
	std::string res = "{\"statfreq\": " + std::to_string(CStats::singleton().getInterval()) + "}";
	*response = strdup(res.c_str());
	return REST_SUCESSS;
}

int csGetStatLogging(char **response)
{
    std::string res;
    if(CStats::singleton().getStatLoggingSuppress()) {
        res = "{\"statlog\": \"suppress\"}";
	} else {
        res = "{\"statlog\": \"all\"}";
	}

	*response = strdup(res.c_str());
	return REST_SUCESSS;
}

int csUpdateStatLogging(const char *json, char **response)
{
	statsrapidjson::Document doc;
	doc.Parse(json);
	if(doc.HasParseError())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}
	if(!doc.HasMember("statlog") || !doc["statlog"].IsString())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}

    string StatLoggingStr = doc["statlog"].GetString();

    if(StatLoggingStr == "suppress")
        CStats::singleton().setStatLoggingSuppress(true);
    else if(StatLoggingStr == "all")
        CStats::singleton().setStatLoggingSuppress(false);
    else{
            if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
            return REST_FAIL;
    }

	if (response)
		*response = strdup("{\"result\": \"OK\"}");

	return REST_SUCESSS;
}


int csUpdateInterval(const char *json, char **response)
{
	statsrapidjson::Document doc;
	doc.Parse(json);
	if(doc.HasParseError())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}
	if(!doc.HasMember("statfreq") || !doc["statfreq"].IsUint64())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}

	unsigned long statfreq = doc["statfreq"].GetUint64();
	CStats::singleton().updateInterval(statfreq);

	if (response)
		*response = strdup("{\"result\": \"OK\"}");

	return REST_SUCESSS;
}

int get_request_tries_value(const char *json, char **response)
{

	statsrapidjson::Document doc;
	doc.Parse(json);
	if(doc.HasParseError())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}
	if(!doc.HasMember("request_tries") || !doc["request_tries"].IsUint64())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}
	unsigned long request_tries = doc["request_tries"].GetUint64();
	return request_tries;
}

int get_transmit_count_value(const char *json, char **response)
{

	statsrapidjson::Document doc;
	doc.Parse(json);
	if(doc.HasParseError())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}
	if(!doc.HasMember("transmit_count") || !doc["transmit_count"].IsUint64())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}

	unsigned long transmit_count = doc["transmit_count"].GetUint64();
	return transmit_count;
}

int get_request_timeout_value_in_milliseconds(const char *json, char **response)
{

	statsrapidjson::Document doc;
	doc.Parse(json);
	if(doc.HasParseError())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}
	if(!doc.HasMember("request_timeout") || !doc["request_timeout"].IsUint64())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}

	unsigned long request_timeout_value = doc["request_timeout"].GetUint64();
	return request_timeout_value;
}

int get_periodic_timer_value_in_seconds(const char *json, char **response)
{

	statsrapidjson::Document doc;
	doc.Parse(json);
	if(doc.HasParseError())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}
	if(!doc.HasMember("periodic_timer") || !doc["periodic_timer"].IsUint64())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}

	unsigned long periodic_timer_value = doc["periodic_timer"].GetUint64();
	return periodic_timer_value;
}

int get_transmit_timer_value_in_seconds(const char *json, char **response)
{

	statsrapidjson::Document doc;
	doc.Parse(json);
	if(doc.HasParseError())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}
	if(!doc.HasMember("transmit_timer") || !doc["transmit_timer"].IsUint64())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}

	unsigned long transmit_timer_value = doc["transmit_timer"].GetUint64();
	return transmit_timer_value;
}

int get_pcap_generation_cmd_value(const char *json, char **response)
{
	statsrapidjson::Document doc;
	doc.Parse(json);
	if(doc.HasParseError())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}
	if(!doc.HasMember("generate_pcap") || !doc["generate_pcap"].IsString())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}

	std::string pcap_generation_cmd  = doc["generate_pcap"].GetString();

	if ((pcap_generation_cmd == "start") || (pcap_generation_cmd == "START"))
		return PCAP_GEN_ON;
	else if ((pcap_generation_cmd == "stop") || (pcap_generation_cmd == "STOP"))
		return PCAP_GEN_OFF;
	else if ((pcap_generation_cmd == "restart") || (pcap_generation_cmd == "RESTART"))
		return PCAP_GEN_RESTART;

	return REST_FAIL;
}

void  construct_json(const char *param,const char *value, char *buf)
{
	const char *ret;
	statsrapidjson::Document document;
	document.SetObject();
	statsrapidjson::Document::AllocatorType &allocator = document.GetAllocator();

	document.AddMember("parameter",statsrapidjson::StringRef(param),allocator);
	document.AddMember("set_value",statsrapidjson::StringRef(value),allocator);

	statsrapidjson::StringBuffer strbuf;
	statsrapidjson::Writer<statsrapidjson::StringBuffer> writer(strbuf);
	document.Accept(writer);

	ret=strbuf.GetString();
	strcpy(buf,ret);

}

int  resp_cmd_not_supported(uint8_t gw_type, char **response)
{
	char temp[JSON_RESP_SIZE];
	strncpy(temp, "{ \"ERROR\": \"NOT SUPPORTED COMMAND ON ", ENTRY_NAME_SIZE);
	strncat(temp, ossGatewayStr[gw_type], ENTRY_VALUE_SIZE);
	strncat(temp, "\"}", 3);
	*response = strdup(temp);
	return REST_FAIL;
}

int csGetLive(char **response)
{
	std::string live;
	CStats::singleton().serializeJSON(live,true);
	*response = strdup(live.c_str());
	return REST_SUCESSS;
}

int get_cp_configuration(char **response, cp_configuration_t *cp_config_ptr)
{

	if(cp_config_ptr == NULL)
	{
		if (response)
			*response = strdup("{\"result\": \"system failure\"}");
		return REST_FAIL;
	}

	std::string json;
	statsrapidjson::Document document;
	document.SetObject();
	statsrapidjson::Document::AllocatorType& allocator = document.GetAllocator();
	statsrapidjson::Value valArray(statsrapidjson::kArrayType);
	char ipv6[INET6_ADDRSTRLEN] = {0};

	document.AddMember("Gateway Type", statsrapidjson::StringRef(ossGatewayStr[cp_config_ptr->cp_type]), allocator);

	statsrapidjson::Value s11(statsrapidjson::kObjectType);
	s11.AddMember("S11 SGW IP", statsrapidjson::Value(inet_ntoa(cp_config_ptr->s11_ip), allocator).Move(), allocator);
	s11.AddMember("S11 SGW Port", cp_config_ptr->s11_port, allocator);
	s11.AddMember(statsrapidjson::StringRef("S11 SGW IPV6"),
			statsrapidjson::Value(inet_ntop(AF_INET6,
			&cp_config_ptr->s11_ip_v6, ipv6, INET6_ADDRSTRLEN), allocator).Move(), allocator);
	document.AddMember("S11 Interface", s11, allocator);

	statsrapidjson::Value s5s8(statsrapidjson::kObjectType);
	s5s8.AddMember("S5S8 IP", statsrapidjson::Value(inet_ntoa(cp_config_ptr->s5s8_ip), allocator).Move(), allocator);
	s5s8.AddMember("S5S8 Port", cp_config_ptr->s5s8_port, allocator);
	s5s8.AddMember(statsrapidjson::StringRef(" S5S8 IPV6"),
		statsrapidjson::Value(inet_ntop(AF_INET6,
		&cp_config_ptr->s5s8_ip_v6, ipv6, INET6_ADDRSTRLEN), allocator).Move(), allocator);
	document.AddMember("S5S8 Interface", s5s8, allocator);

	statsrapidjson::Value sx(statsrapidjson::kObjectType);
	sx.AddMember("PFCP IP", statsrapidjson::Value(inet_ntoa(cp_config_ptr->pfcp_ip), allocator).Move(), allocator);
	sx.AddMember("PFCP Port", cp_config_ptr->pfcp_port, allocator);
	sx.AddMember("UPF PFCP IP", statsrapidjson::Value(inet_ntoa(cp_config_ptr->upf_pfcp_ip), allocator).Move(), allocator);
	sx.AddMember("UPF PFCP Port", cp_config_ptr->upf_pfcp_port, allocator);
	sx.AddMember(statsrapidjson::StringRef("PFCP IPV6"),
		statsrapidjson::Value(inet_ntop(AF_INET6,
		&cp_config_ptr->pfcp_ip_v6, ipv6, INET6_ADDRSTRLEN), allocator).Move(), allocator);
	sx.AddMember(statsrapidjson::StringRef("UPF PFCP IPV6"),
		statsrapidjson::Value(inet_ntop(AF_INET6,
		&cp_config_ptr->upf_pfcp_ip_v6, ipv6, INET6_ADDRSTRLEN), allocator).Move(), allocator);
	document.AddMember("SX Interface", sx, allocator);

	statsrapidjson::Value li(statsrapidjson::kObjectType);
	li.AddMember(statsrapidjson::StringRef("DADMF IP"),
			statsrapidjson::StringRef(cp_config_ptr->dadmf_ip), allocator);

	li.AddMember("DADMF Port", cp_config_ptr->dadmf_port, allocator);
	li.AddMember(statsrapidjson::StringRef("DDF2 IP"),
			statsrapidjson::StringRef(cp_config_ptr->ddf2_ip), allocator);

	li.AddMember("DDF2 Port", cp_config_ptr->ddf2_port, allocator);
	li.AddMember(statsrapidjson::StringRef("DDF2 Local IP"),
			statsrapidjson::StringRef(cp_config_ptr->ddf2_local_ip), allocator);
	li.AddMember(statsrapidjson::StringRef("DADMF Local IP"),
			statsrapidjson::StringRef(cp_config_ptr->dadmf_local_addr), allocator);
	document.AddMember("LI Interface", li, allocator);

	statsrapidjson::Value urr_default(statsrapidjson::kObjectType);
	urr_default.AddMember("Trigger Type", cp_config_ptr->trigger_type, allocator);
	urr_default.AddMember("Uplink Volume Thresold", cp_config_ptr->uplink_volume_th, allocator);
	urr_default.AddMember("Downlink Volume Thresold", cp_config_ptr->downlink_volume_th, allocator);
	urr_default.AddMember("Time Thresold", cp_config_ptr->time_th, allocator);
	document.AddMember("URR DEFAULT PARAMETERS", urr_default, allocator);

	document.AddMember("Generate CDR", cp_config_ptr->generate_cdr, allocator);
	if(cp_config_ptr->is_gx_interface) {
		document.AddMember("USE GX", cp_config_ptr->use_gx, allocator);
	} else {
		document.AddMember("USE GX", statsrapidjson::StringRef("Not Applicable On SGWC"), allocator);
	}
	document.AddMember("Generate SGW CDR", cp_config_ptr->generate_sgw_cdr, allocator);
	if(cp_config_ptr->generate_sgw_cdr == SGW_CHARGING_CHARACTERISTICS) {
		document.AddMember("SGW Charging Characteristics", cp_config_ptr->sgw_cc, allocator);
	} else {
		 document.AddMember("SGW Charging Characteristics",
				 statsrapidjson::StringRef("SGW Charging Characteristics Flag Is Disable In cp.cfg"), allocator);
	}

	statsrapidjson::Value redis_server(statsrapidjson::kObjectType);
	redis_server.AddMember("Redis Server IP", statsrapidjson::Value(cp_config_ptr->redis_ip_buff,
				allocator).Move(), allocator);
	redis_server.AddMember("Redis Server Port", cp_config_ptr->redis_port, allocator);
	redis_server.AddMember("CP Redis IP", statsrapidjson::Value(cp_config_ptr->cp_redis_ip_buff,
				allocator).Move(), allocator);
	redis_server.AddMember(statsrapidjson::StringRef("Redis Cert Path"),
			statsrapidjson::StringRef(cp_config_ptr->redis_cert_path), allocator);
	document.AddMember("Redis Server Info", redis_server, allocator);

	document.AddMember("Suggested Packet Count",
		cp_config_ptr->dl_buf_suggested_pkt_cnt, allocator);
	document.AddMember("Low Level ARP Priority",
		cp_config_ptr->low_lvl_arp_priority, allocator);

	statsrapidjson::Value restoration(statsrapidjson::kObjectType);
	restoration.AddMember("Periodic Timer", cp_config_ptr->restoration_params.periodic_timer, allocator);
	restoration.AddMember("Transmit Timer", cp_config_ptr->restoration_params.transmit_timer, allocator);
	restoration.AddMember("Transmit Count", cp_config_ptr->restoration_params.transmit_cnt, allocator);
	document.AddMember("Restoration Parameters", restoration, allocator);

	document.AddMember("Request Timeout", cp_config_ptr->request_timeout, allocator);
	document.AddMember("Request Tries", cp_config_ptr->request_tries, allocator);
	document.AddMember("Add Default Rule", cp_config_ptr->add_default_rule, allocator);
	document.AddMember("IP Allocation Mode", cp_config_ptr->ip_allocation_mode, allocator);
	document.AddMember("IP Type Supported", cp_config_ptr->ip_type_supported, allocator);
	document.AddMember("IP Type Priority", cp_config_ptr->ip_type_priority, allocator);

	statsrapidjson::Value ip_pool(statsrapidjson::kObjectType);
	ip_pool.AddMember("IP Pool IP", statsrapidjson::Value(inet_ntoa(cp_config_ptr->ip_pool_ip), allocator).Move(), allocator);
	ip_pool.AddMember("IP Pool Mask", statsrapidjson::Value(inet_ntoa(cp_config_ptr->ip_pool_mask), allocator).Move(), allocator);
	ip_pool.AddMember(statsrapidjson::StringRef("IPV6 Network ID"),
		statsrapidjson::Value(inet_ntop(AF_INET6,
		&cp_config_ptr->ipv6_network_id, ipv6, INET6_ADDRSTRLEN), allocator).Move(), allocator);
	ip_pool.AddMember("IPV6 Prefix Len", cp_config_ptr->ipv6_prefix_len, allocator);
	document.AddMember("IP Pool Config", ip_pool, allocator);

	document.AddMember("Use DNS", cp_config_ptr->use_dns, allocator);
	document.AddMember("CP DNS IP", statsrapidjson::Value(cp_config_ptr->cp_dns_ip_buff,
		allocator).Move(), allocator);

	document.AddMember("CLI REST IP", statsrapidjson::Value(cp_config_ptr->cli_rest_ip_buff,
		allocator).Move(), allocator);
	document.AddMember("CLI REST PORT", cp_config_ptr->cli_rest_port, allocator);

	statsrapidjson::Value apnList(statsrapidjson::kArrayType);

	for(unsigned int itr_apn = 0; itr_apn < cp_config_ptr->num_apn; itr_apn++)
	{
		statsrapidjson::Value value(statsrapidjson::kObjectType);
		value.AddMember(statsrapidjson::StringRef("APN Name Label"),
				statsrapidjson::StringRef(cp_config_ptr->apn_list[itr_apn].apn_name_label), allocator);
		value.AddMember(statsrapidjson::StringRef("APN Usage Type"), cp_config_ptr->apn_list[itr_apn].apn_usage_type, allocator);
		value.AddMember(statsrapidjson::StringRef("APN Network Capability"),
				statsrapidjson::StringRef(cp_config_ptr->apn_list[itr_apn].apn_net_cap), allocator);
		value.AddMember(statsrapidjson::StringRef("Trigger Type"), cp_config_ptr->apn_list[itr_apn].trigger_type, allocator);
		value.AddMember(statsrapidjson::StringRef("Uplink Volume Threshold"),
				cp_config_ptr->apn_list[itr_apn].uplink_volume_th, allocator);
		value.AddMember(statsrapidjson::StringRef("Downlink Volume Threshold"),
				cp_config_ptr->apn_list[itr_apn].downlink_volume_th, allocator);
		value.AddMember(statsrapidjson::StringRef("Time Threshold"),
				cp_config_ptr->apn_list[itr_apn].time_th, allocator);
		value.AddMember("IP Pool IP", statsrapidjson::Value(inet_ntoa(cp_config_ptr->apn_list[itr_apn].ip_pool_ip), allocator).Move(), allocator);
		value.AddMember("IP Pool Mask", statsrapidjson::Value(inet_ntoa(cp_config_ptr->apn_list[itr_apn].ip_pool_mask), allocator).Move(), allocator);
		value.AddMember(statsrapidjson::StringRef("IPV6 Network ID"),
			statsrapidjson::Value(inet_ntop(AF_INET6,
			&cp_config_ptr->apn_list[itr_apn].ipv6_network_id, ipv6, INET6_ADDRSTRLEN), allocator).Move(), allocator);
		value.AddMember("IPV6 Prefix Len", cp_config_ptr->apn_list[itr_apn].ipv6_prefix_len, allocator);
			apnList.PushBack(value, allocator);

	}

	document.AddMember("APN List", apnList, allocator);

	statsrapidjson::Value dns_cache(statsrapidjson::kObjectType);
	dns_cache.AddMember(statsrapidjson::StringRef("Concurrent"), cp_config_ptr->dns_cache.concurrent, allocator);
	dns_cache.AddMember(statsrapidjson::StringRef("Interval Seconds"), cp_config_ptr->dns_cache.sec, allocator);
	dns_cache.AddMember(statsrapidjson::StringRef("Percentage"), cp_config_ptr->dns_cache.percent, allocator);
	dns_cache.AddMember(statsrapidjson::StringRef("Query Timeouts MilliSeconds"), cp_config_ptr->dns_cache.timeoutms, allocator);
	dns_cache.AddMember(statsrapidjson::StringRef("Query Tries"), cp_config_ptr->dns_cache.tries, allocator);

	statsrapidjson::Value app_dns(statsrapidjson::kObjectType);
	app_dns.AddMember(statsrapidjson::StringRef("Frequency Seconds"), cp_config_ptr->app_dns.freq_sec, allocator);
	app_dns.AddMember("Filename", statsrapidjson::StringRef(cp_config_ptr->app_dns.filename), allocator);
	app_dns.AddMember("Nameserver",
		statsrapidjson::StringRef(cp_config_ptr->app_dns.nameserver_ip[cp_config_ptr->app_dns.nameserver_cnt-1]), allocator);

	statsrapidjson::Value ops_dns(statsrapidjson::kObjectType);
	ops_dns.AddMember(statsrapidjson::StringRef("Frequency Seconds"), cp_config_ptr->ops_dns.freq_sec, allocator);
	ops_dns.AddMember("Filename", statsrapidjson::StringRef(cp_config_ptr->ops_dns.filename), allocator);
	ops_dns.AddMember("Nameserver",
		statsrapidjson::StringRef(cp_config_ptr->ops_dns.nameserver_ip[cp_config_ptr->ops_dns.nameserver_cnt-1]), allocator);

	document.AddMember("DNS CACHE", dns_cache, allocator);
	document.AddMember("DNS APP", app_dns, allocator);
	document.AddMember("DNS OPS", ops_dns, allocator);

	statsrapidjson::StringBuffer strbuf;
	statsrapidjson::Writer<statsrapidjson::StringBuffer> writer(strbuf);
	document.Accept(writer);
	json = strbuf.GetString();
	*response = strdup(json.c_str());

	return REST_SUCESSS;
}

int get_dp_configuration(char **response, dp_configuration_t *dp_config_ptr)
{
	if(dp_config_ptr == NULL)
	{
		if (response)
			*response = strdup("{\"result\": \"system failure\"}");
		return REST_FAIL;
	}

	std::string json;
	statsrapidjson::Document document;
	document.SetObject();
	statsrapidjson::Document::AllocatorType& allocator = document.GetAllocator();
	char ipv6[INET6_ADDRSTRLEN] = {0};

	document.AddMember("Gateway Type", statsrapidjson::StringRef(ossGatewayStr[dp_config_ptr->dp_type]), allocator);

	statsrapidjson::Value sx(statsrapidjson::kObjectType);
	sx.AddMember("PFCP IPV4", statsrapidjson::Value(inet_ntoa(dp_config_ptr->dp_comm_ip), allocator).Move(), allocator);
	sx.AddMember("PFCP PORT", dp_config_ptr->dp_comm_port, allocator);
	sx.AddMember(statsrapidjson::StringRef("PFCP IPV6"),
			statsrapidjson::Value(inet_ntop(AF_INET6,
			&dp_config_ptr->dp_comm_ipv6, ipv6, INET6_ADDRSTRLEN), allocator).Move(), allocator);
	sx.AddMember("PFCP IPV6 Prefix Len", dp_config_ptr->pfcp_ipv6_prefix_len, allocator);
	document.AddMember("SX Interface", sx, allocator);

	statsrapidjson::Value teid(statsrapidjson::kObjectType);
	teid.AddMember("Teidri Timeout", dp_config_ptr->teidri_timeout, allocator);
	teid.AddMember("Teidri Value", dp_config_ptr->teidri_val, allocator);
	document.AddMember("Teid Parameters", teid, allocator);

	statsrapidjson::Value restoration(statsrapidjson::kObjectType);
	restoration.AddMember("Periodic Timer", dp_config_ptr->restoration_params.periodic_timer, allocator);
	restoration.AddMember("Transmit Timer", dp_config_ptr->restoration_params.transmit_timer, allocator);
	restoration.AddMember("Transmit Count", dp_config_ptr->restoration_params.transmit_cnt, allocator);
	document.AddMember("Restoration Parameters", restoration, allocator);

	document.AddMember("Generate Pcap", dp_config_ptr->generate_pcap, allocator);
	document.AddMember("CLI REST IP", statsrapidjson::Value(dp_config_ptr->cli_rest_ip_buff,
		allocator).Move(), allocator);
	document.AddMember("CLI REST PORT", dp_config_ptr->cli_rest_port, allocator);
	document.AddMember("Numa", dp_config_ptr->numa_on, allocator);
	document.AddMember("GTPU Sequence Number In", dp_config_ptr->gtpu_seqnb_in, allocator);
	document.AddMember("GTPU Sequence Number Out", dp_config_ptr->gtpu_seqnb_out, allocator);
	document.AddMember("West Gateway IP", statsrapidjson::Value(inet_ntoa(*((struct in_addr *)&dp_config_ptr->wb_gw_ip)),
			allocator).Move(), allocator);
	document.AddMember("East Gateway IP", statsrapidjson::Value(inet_ntoa(*((struct in_addr *)&dp_config_ptr->eb_gw_ip)),
		allocator).Move(), allocator);

	statsrapidjson::Value west(statsrapidjson::kObjectType);
	west.AddMember("West Kni Interface", statsrapidjson::StringRef(dp_config_ptr->wb_iface_name), allocator);
	west.AddMember("West Bound IPV4", statsrapidjson::Value(inet_ntoa(*((struct in_addr *)&dp_config_ptr->wb_ip)),
				allocator).Move(), allocator);
	west.AddMember(statsrapidjson::StringRef("West Bound IPV6"),
			statsrapidjson::Value(inet_ntop(AF_INET6,
			&dp_config_ptr->wb_ipv6, ipv6, INET6_ADDRSTRLEN), allocator).Move(), allocator);
	west.AddMember("West Bound IPV6 Prefix Len", dp_config_ptr->wb_ipv6_prefix_len, allocator);
	west.AddMember("West Bound Mask", statsrapidjson::Value(inet_ntoa(*((struct in_addr *)&dp_config_ptr->wb_mask)),
				allocator).Move(), allocator);
	west.AddMember("West Bound Mac", statsrapidjson::StringRef(dp_config_ptr->wb_mac), allocator);
	document.AddMember("West User Plane", west, allocator);

	statsrapidjson::Value east(statsrapidjson::kObjectType);
	east.AddMember("East Kni Interface", statsrapidjson::StringRef(dp_config_ptr->eb_iface_name), allocator);
	east.AddMember("East Bound IPV4", statsrapidjson::Value(inet_ntoa(*((struct in_addr *)&dp_config_ptr->eb_ip)),
				allocator).Move(), allocator);
	east.AddMember(statsrapidjson::StringRef("East Bound IPV6"),
		statsrapidjson::Value(inet_ntop(AF_INET6,
		&dp_config_ptr->eb_ipv6, ipv6, INET6_ADDRSTRLEN), allocator).Move(), allocator);
	east.AddMember("East Bound IPV6 Prefix Len", dp_config_ptr->eb_ipv6_prefix_len, allocator);
	east.AddMember("East Bound Mask", statsrapidjson::Value(inet_ntoa(*((struct in_addr *)&dp_config_ptr->eb_mask)),
				allocator).Move(), allocator);
	east.AddMember("East Bound Mac", statsrapidjson::StringRef(dp_config_ptr->eb_mac), allocator);
	document.AddMember("East User Plane", east, allocator);

	statsrapidjson::Value li(statsrapidjson::kObjectType);
	li.AddMember("DDF2 IP",
			statsrapidjson::Value(dp_config_ptr->ddf2_ip, allocator).Move(), allocator);
	li.AddMember("DDF2 Port", dp_config_ptr->ddf2_port, allocator);
	li.AddMember("DDF2 Local IP",
			statsrapidjson::Value(dp_config_ptr->ddf2_local_ip, allocator).Move(), allocator);

	li.AddMember("DDF3 IP",
			statsrapidjson::Value(dp_config_ptr->ddf3_ip, allocator).Move(), allocator);
	li.AddMember("DDF3 Port", dp_config_ptr->ddf3_port, allocator);
	li.AddMember("DDF3 Local IP",
			statsrapidjson::Value(dp_config_ptr->ddf3_local_ip, allocator).Move(), allocator);

	document.AddMember("LI Interface", li, allocator);

	statsrapidjson::Value logical_interface(statsrapidjson::kObjectType);
	logical_interface.AddMember("West Bound LI IPV4",
		statsrapidjson::Value(inet_ntoa(*((struct in_addr *)&dp_config_ptr->wb_li_ip)), allocator).Move(), allocator);
	logical_interface.AddMember("West Bound LI Mask",
			statsrapidjson::Value(inet_ntoa(*((struct in_addr *)&dp_config_ptr->wb_li_mask)), allocator).Move(), allocator);
	logical_interface.AddMember(statsrapidjson::StringRef("West Bound LI Interface"),
			statsrapidjson::StringRef(dp_config_ptr->wb_li_iface_name), allocator);
	logical_interface.AddMember(statsrapidjson::StringRef("West Bound LI IPV6"),
		statsrapidjson::Value(inet_ntop(AF_INET6,
		&dp_config_ptr->wb_li_ipv6, ipv6, INET6_ADDRSTRLEN), allocator).Move(), allocator);
	logical_interface.AddMember("West Bound LI IPV6 Prefix Len", dp_config_ptr->wb_li_ipv6_prefix_len, allocator);
	logical_interface.AddMember("East Bound LI IPV4",
		statsrapidjson::Value(inet_ntoa(*((struct in_addr *)&dp_config_ptr->eb_li_ip)), allocator).Move(), allocator);
	logical_interface.AddMember("East Bound LI Mask",
			statsrapidjson::Value(inet_ntoa(*((struct in_addr *)&dp_config_ptr->eb_li_mask)), allocator).Move(), allocator);
	logical_interface.AddMember(statsrapidjson::StringRef("East Bound LI Interface"),
			statsrapidjson::StringRef(dp_config_ptr->eb_li_iface_name), allocator);
	logical_interface.AddMember(statsrapidjson::StringRef("East Bound LI IPV6"),
		statsrapidjson::Value(inet_ntop(AF_INET6,
		&dp_config_ptr->eb_li_ipv6, ipv6, INET6_ADDRSTRLEN), allocator).Move(), allocator);
	logical_interface.AddMember("East Bound LI IPV6 Prefix Len", dp_config_ptr->eb_li_ipv6_prefix_len, allocator);
	document.AddMember("Logical Interface", logical_interface, allocator);

	statsrapidjson::StringBuffer strbuf;
	statsrapidjson::Writer<statsrapidjson::StringBuffer> writer(strbuf);
	document.Accept(writer);
	json = strbuf.GetString();
	*response = strdup(json.c_str());
	return REST_SUCESSS;
}

int csGetLiveAll(char **response)
{
       std::string live;
       CStats::singleton().serializeJSON(live,false);
       *response = strdup(live.c_str());
       return REST_SUCESSS;
}

int csResetStats(const char *json, char **response)
{

	statsrapidjson::Document doc;
	doc.Parse(json);
	if(doc.HasParseError())
	{
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return REST_FAIL;
	}

	if (response)
		*response = strdup("{\"result\": \"OK\"}");
	 return REST_SUCESSS;
}


CStats *CStats::m_singleton = NULL;

CStats::CStats()
{
	m_interval = CLI_STATS_TIMER_INTERVAL;
	p_interval = CLI_STATS_TIMER_INTERVAL;
	statLoggingSuppress = true;

}

CStats::~CStats()
{
}

Void
CStats::onInit()
{
	statsTimer.setInterval(CStats::singleton().getInterval());
	statsTimer.setOneShot(False);
	initTimer(statsTimer);
	statsTimer.start();
}

Void
CStats::onTimer(EThreadEventTimer *ptimer)
{
	std::string statJson;
	EString jsonDump;
	CStats::singleton().serializeJSON(statJson,
		CStats::singleton().getStatLoggingSuppress());
	jsonDump = statJson;
    ELogger::log(STATS_LOGID).debug(jsonDump);
    ELogger::log(STATS_LOGID).flush();
	if(CStats::singleton().getInterval() != CStats::singleton().getpInterval()) {
		// stop the previous timer and start the new timer
		statsTimer.stop();
        statsTimer.setInterval(CStats::singleton().getInterval());
        statsTimer.setOneShot(false);
        statsTimer.start();
	}
	CStats::singleton().setpInterval(CStats::singleton().getInterval());
}

void CStats::updateInterval(long interval)
{
	CStats::singleton().setInterval(interval);
}

void statTimerInit(void) {
	CStats::singleton();
}

void CStats::serializeJSON(std::string &json,bool suppressed=true)
{
    string data;
    statsrapidjson::Document document;
    document.SetObject();
    statsrapidjson::Document::AllocatorType& allocator = document.GetAllocator();
    statsrapidjson::Value valArray(statsrapidjson::kArrayType);

    CStatGateway gateway(suppressed);
    gateway.serialize(cli_node_ptr, document, valArray, allocator);

    statsrapidjson::StringBuffer strbuf;
    statsrapidjson::Writer<statsrapidjson::StringBuffer> writer(strbuf);
    document.Accept(writer);
    json = strbuf.GetString();
}


