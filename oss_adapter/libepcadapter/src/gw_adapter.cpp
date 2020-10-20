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

#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "spdlog/sinks/basic_file_sink.h"

#include "epc/epctools.h"
#include "elogger.h"
#include "etypes.h"
#include "cstats.h"

#include "rest_apis.h"
#include "gw_adapter.h"
#include "cdadmfapi.h"

#define STANDARD_SINKSET             (1)
#define LOG_QUEUE_SIZE               (8192)
#define LOG_THREADS                  (1)
#define LOG_SYSTEM                   (1)
#define MAXSIZEMB                    (5)
#define MAXFILES                     (10)
#define PFCP_HEARTBEAT_REQUEST       (1)
#define PFCP_HEARTBEAT_RESPONSE      (2)
#define GTPU_ECHO_REQUEST            (0x01)
#define GTPU_ECHO_RESPONSE           (0x02)

cli_node_t cli_node = {0};
EManagementEndpoint *pRestHandle;
li_df_config_t li_config[MAX_LI_ENTRIES] = {0};

int8_t init_log_module(const char *filename)
{
	EGetOpt opt;
	EString optfile;
	try {
		opt.loadFile(filename);
	} catch (const std::exception &e) {
		std::cerr << e.what() << '\n';
		return -1;
	}

	EpcTools::Initialize(opt);
	ELogger::log(STANDARD_LOGID).startup("EpcTools initialization complete" );
	return 0;
}

void clLog(const int logid, enum CLoggerSeverity sev, const char *fmt, ...)
{
	char szBuff[2048] = {0};
	va_list args;
	va_start(args, fmt);
	vsnprintf(szBuff, sizeof(szBuff), fmt, args);
	va_end(args);
	switch (sev)
	{
		case eCLSeverityDebug:   { ELogger::log(logid).info(szBuff);     break;  }
		case eCLSeverityInfo:    { ELogger::log(logid).startup(szBuff);  break;  }
		case eCLSeverityStartup: { ELogger::log(logid).debug(szBuff);    break;  }
		case eCLSeverityMinor:   { ELogger::log(logid).minor(szBuff);    break;  }
		case eCLSeverityMajor:   { ELogger::log(logid).major(szBuff);    break;  }
		case eCLSeverityCritical:{ ELogger::log(logid).critical(szBuff); break;  }
	}
}

int8_t init_rest_framework(char *cli_rest_ip, uint16_t port)
{
	struct addrinfo *ip_type = NULL;
	/* Adding 2 bytes for [] format required of ipv6 */
	char ip_format[IPV6_STR_LEN + 2] = {0};

	/*Check for IP type (ipv4/ipv6)*/
	if (getaddrinfo(cli_rest_ip, NULL, NULL, &ip_type)) {
		return -1;
	}

	if(ip_type->ai_family == AF_INET6) {
		ip_format[0] = '[';
		ip_format[1] = '\0';
		strncat(ip_format, cli_rest_ip, IPV6_STR_LEN);
		ip_format[strnlen(ip_format, IPV6_STR_LEN)] = ']';
		ip_format[strnlen(ip_format, IPV6_STR_LEN) + 1] = '\0';

	} else {
		strncpy(ip_format, cli_rest_ip, IP_ADDR_V4_LEN);
	}

	Pistache::Address addr(ip_format, port);

	pRestHandle = new EManagementEndpoint(addr);

	RestStateLiveGet *pSLGet = new RestStateLiveGet(ELogger::log(STANDARD_LOGID));
	pSLGet->registerCallback(get_stat_live);
	pRestHandle->registerHandler(*pSLGet);

	RestPeriodicTimerGet *pPTGet = new RestPeriodicTimerGet(ELogger::log(STANDARD_LOGID));
	pPTGet->registerCallback(get_pt);
	pRestHandle->registerHandler(*pPTGet);

	RestTransmitTimerGet *pTTGet = new RestTransmitTimerGet(ELogger::log(STANDARD_LOGID));
	pTTGet->registerCallback(get_tt);
	pRestHandle->registerHandler(*pTTGet);

	RestTransmitCountGet *pTCGet = new RestTransmitCountGet(ELogger::log(STANDARD_LOGID));
	pTCGet->registerCallback(get_tc);
	pRestHandle->registerHandler(*pTCGet);

	RestRequestTriesGet *pRTGet = new RestRequestTriesGet(ELogger::log(STANDARD_LOGID));
	pRTGet->registerCallback(get_rt);
	pRestHandle->registerHandler(*pRTGet);

	RestRequestTimeoutGet *pRTOGet = new RestRequestTimeoutGet(ELogger::log(STANDARD_LOGID));
	pRTOGet->registerCallback(get_rto);
	pRestHandle->registerHandler(*pRTOGet);

	RestStatLoggingGet *pSLoggingGet = new RestStatLoggingGet(ELogger::log(STANDARD_LOGID));
	pSLoggingGet->registerCallback(get_stat_logging);
	pRestHandle->registerHandler(*pSLoggingGet);

	RestPcapStatusGet *pPSGet = new RestPcapStatusGet(ELogger::log(STANDARD_LOGID));
	pPSGet->registerCallback(get_generate_pcap_status);
	pRestHandle->registerHandler(*pPSGet);

	RestConfigurationGet *pCGet = new RestConfigurationGet(ELogger::log(STANDARD_LOGID));
	pCGet->registerCallback(get_configuration);
	pRestHandle->registerHandler(*pCGet);

	RestStatLiveAllGet *pSLAGet = new RestStatLiveAllGet(ELogger::log(STANDARD_LOGID));
	pSLAGet->registerCallback(get_stat_live_all);
	pRestHandle->registerHandler(*pSLAGet);

	RestStatFrequencyGet *pSFGet = new RestStatFrequencyGet(ELogger::log(STANDARD_LOGID));
	pSFGet->registerCallback(get_stat_frequency);
	pRestHandle->registerHandler(*pSFGet);

	RestPeriodicTimerPost *pPTPost = new RestPeriodicTimerPost(ELogger::log(STANDARD_LOGID));
	pPTPost->registerCallback(post_pt);
	pRestHandle->registerHandler(*pPTPost);

	RestTransmitTimerPost *pTTPost = new RestTransmitTimerPost(ELogger::log(STANDARD_LOGID));
	pTTPost->registerCallback(post_tt);
	pRestHandle->registerHandler(*pTTPost);

	RestTransmitCountPost *pTCPost = new RestTransmitCountPost(ELogger::log(STANDARD_LOGID));
	pTCPost->registerCallback(post_tc);
	pRestHandle->registerHandler(*pTCPost);

	RestRequestTimeoutPost *pRTOPost = new RestRequestTimeoutPost(ELogger::log(STANDARD_LOGID));
	pRTOPost->registerCallback(post_rto);
	pRestHandle->registerHandler(*pRTOPost);

	RestRequestTriesPost *pRTPost = new RestRequestTriesPost(ELogger::log(STANDARD_LOGID));
	pRTPost->registerCallback(post_rt);
	pRestHandle->registerHandler(*pRTPost);

	RestStatLoggingPost *pSLPOST = new RestStatLoggingPost(ELogger::log(STANDARD_LOGID));
	pSLPOST->registerCallback(post_stat_logging);
	pRestHandle->registerHandler(*pSLPOST);

	RestPcapStatusPost *pPSPost = new RestPcapStatusPost(ELogger::log(STANDARD_LOGID));
	pPSPost->registerCallback(post_generate_pcap_cmd);
	pRestHandle->registerHandler(*pPSPost);

	RestResetStatPost *pRSPost = new RestResetStatPost(ELogger::log(STANDARD_LOGID));
	pRSPost->registerCallback(reset_cli_stats);
	pRestHandle->registerHandler(*pRSPost);


	RestStatFrequencyPost *pSFPost = new RestStatFrequencyPost(ELogger::log(STANDARD_LOGID));
	pSFPost->registerCallback(post_stat_frequency);
	pRestHandle->registerHandler(*pSFPost);

	RestUEDetailsPost *pAddUEPost = new RestUEDetailsPost(ELogger::log(STANDARD_LOGID));
	pAddUEPost->registerCallback(add_ue_entry_details);
	pRestHandle->registerHandler(*pAddUEPost);

	RestUEDetailsPut *pUpdateUEPut = new RestUEDetailsPut(ELogger::log(STANDARD_LOGID));
	pUpdateUEPut->registerCallback(update_ue_entry_details);
	pRestHandle->registerHandler(*pUpdateUEPut);

	RestUEDetailsDel *pDeleteUEDel = new RestUEDetailsDel(ELogger::log(STANDARD_LOGID));
	pDeleteUEDel->registerCallback(delete_ue_entry_details);
	pRestHandle->registerHandler(*pDeleteUEDel);

	/* Starts REST service */
	pRestHandle->start();

	return 0;
}

void init_stats_timer()
{
	statTimerInit();
}

bool is_last_activity_update(uint8_t msg_type, CLIinterface it)
{
	EInterfaceType it_cli = (EInterfaceType) it;

	switch(it_cli) {
		case itS11:
			if((ossS11MessageDefs[s11MessageTypes[msg_type]].dir == dIn) ||
					(ossS11MessageDefs[s11MessageTypes[msg_type]].dir == dRespRcvd))
				return true;
			break;

		case itS5S8:
			if((ossS5s8MessageDefs[s5s8MessageTypes[msg_type]].dir == dIn) ||
					(ossS5s8MessageDefs[s5s8MessageTypes[msg_type]].dir == dRespRcvd))
				return true;
			break;

		case itSx:
			if((ossSxMessageDefs[sxMessageTypes[msg_type]].dir == dIn) ||
					(ossSxMessageDefs[sxMessageTypes[msg_type]].dir == dRespRcvd))
				return true;
			break;

		case itGx:
			if((ossGxMessageDefs[gxMessageTypes[msg_type]].dir == dIn) ||
					(ossGxMessageDefs[gxMessageTypes[msg_type]].dir == dRespRcvd))
				return true;
			break;

		case itS1U:
			/*TODO*/
			break;

		case itSGI:
			/*TODO*/
			break;
	}

	return false;
}

int update_cli_stats(peer_address_t *cli_peer_addr, uint8_t msg_type, int dir, CLIinterface it)
{
	int index = -1;

	static char stat_timestamp[LAST_TIMER_SIZE];
	add_cli_peer(cli_peer_addr, it);

	get_current_time_oss(stat_timestamp);

	clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Updating CLI Stats: "
		"Msg Type: %d, Direction: %d\n", LOG_VALUE, msg_type, dir);

	index = get_peer_index(cli_peer_addr);

	if(index == -1) {
		clLog(STANDARD_LOGID, eCLSeverityDebug,
			LOG_FORMAT"CLI: Peer not found\n", LOG_VALUE);
		return index;
	}

	if(msg_type == PFCP_HEARTBEAT_REQUEST || msg_type == GTP_ECHO_REQ
			|| msg_type == GTPU_ECHO_REQUEST) {
		__sync_add_and_fetch(&cli_node.peer[index]->hcrequest[dir], 1);
		if (dir == RCVD)
			update_last_activity(cli_peer_addr, stat_timestamp);

	} else if(msg_type == PFCP_HEARTBEAT_RESPONSE || msg_type == GTP_ECHO_RSP
			|| msg_type == GTPU_ECHO_RESPONSE) {
		__sync_add_and_fetch(&cli_node.peer[index]->hcresponse[dir], 1);
		if (dir == RCVD)
			update_last_activity(cli_peer_addr, stat_timestamp);
	} else {

		if(is_last_activity_update(msg_type,it))
			update_last_activity(cli_peer_addr, stat_timestamp);

		switch(cli_node.peer[index]->intfctype) {
			case itS11:
				__sync_add_and_fetch(&cli_node.peer[index]->stats.s11[s11MessageTypes[msg_type]].cnt[dir], 1);
				strncpy(cli_node.peer[index]->stats.s11[s11MessageTypes[msg_type]].ts, stat_timestamp, LAST_TIMER_SIZE);
				break;
			case itS5S8:
				__sync_add_and_fetch(&cli_node.peer[index]->stats.s5s8[s5s8MessageTypes[msg_type]].cnt[dir], 1);
				strncpy(cli_node.peer[index]->stats.s5s8[s5s8MessageTypes[msg_type]].ts, stat_timestamp, LAST_TIMER_SIZE);
				break;
			case itSx:
				__sync_add_and_fetch(&cli_node.peer[index]->stats.sx[sxMessageTypes[msg_type]].cnt[dir], 1);
				strncpy(cli_node.peer[index]->stats.sx[sxMessageTypes[msg_type]].ts, stat_timestamp, LAST_TIMER_SIZE);
				break;
			case itGx:
				__sync_add_and_fetch(&cli_node.peer[index]->stats.gx[gxMessageTypes[msg_type]].cnt[dir], 1);
				strncpy(cli_node.peer[index]->stats.gx[gxMessageTypes[msg_type]].ts, stat_timestamp, LAST_TIMER_SIZE);
				break;
			default:
				clLog(STANDARD_LOGID, eCLSeverityCritical,
					LOG_FORMAT"CLI: Not supported interface", LOG_VALUE);
				break;
		}
	}
	return 0;
}

void add_cli_peer(peer_address_t *cli_peer_addr, CLIinterface it)
{
	int index = -1;
	SPeer temp_peer = {0};
	char ipv6[INET6_ADDRSTRLEN] = {0};
	EInterfaceType it_cli = (EInterfaceType) it;

	index = get_peer_index(cli_peer_addr);

	if (index == -1)
	{
		index = get_first_index();
		cli_node.peer[index] = (SPeer *)calloc(1,sizeof(temp_peer));

		if(cli_peer_addr->type == IPV4_TYPE) {
			cli_node.peer[index]->cli_peer_addr.type |= cli_peer_addr->type;
			cli_node.peer[index]->cli_peer_addr.ipv4.sin_addr.s_addr =
				cli_peer_addr->ipv4.sin_addr.s_addr;
			clLog(STANDARD_LOGID, eCLSeverityDebug,
				LOG_FORMAT"CLI: Request rcvd for IP Address: %s\n", LOG_VALUE,
				inet_ntoa(cli_peer_addr->ipv4.sin_addr));

		} else if(cli_peer_addr->type == IPV6_TYPE) {
			cli_node.peer[index]->cli_peer_addr.type |= cli_peer_addr->type;
			cli_node.peer[index]->cli_peer_addr.ipv6.sin6_addr =
				cli_peer_addr->ipv6.sin6_addr;
			clLog(STANDARD_LOGID, eCLSeverityDebug,
				LOG_FORMAT"CLI: Request rcvd for IP Address: %s\n", LOG_VALUE,
				inet_ntop(AF_INET6, &cli_peer_addr->ipv6.sin6_addr,
				ipv6, INET6_ADDRSTRLEN));
		} else {
			clLog(STANDARD_LOGID, eCLSeverityDebug,
				LOG_FORMAT"Not supported IP type %d", LOG_VALUE, cli_peer_addr->type);
		}
		cli_node.peer[index]->intfctype = it_cli;
		cli_node.peer[index]->status = FALSE;
		cli_node.cli_config.number_of_transmit_count =
			(*cli_node.cli_config.gw_adapter_callback_list.get_transmit_count)();
		cli_node.cli_config.transmit_timer_value =
			(*cli_node.cli_config.gw_adapter_callback_list.get_transmit_timer)();
		cli_node.peer[index]->response_timeout = &cli_node.cli_config.transmit_timer_value;
		cli_node.peer[index]->maxtimeout = &cli_node.cli_config.number_of_transmit_count;
		cli_node.peer[index]->timeouts = 0;
		clLog(STANDARD_LOGID, eCLSeverityDebug,
			LOG_FORMAT"Interface type is: %d\n", LOG_VALUE, it);
		cli_node.cli_config.nbr_of_peer++;

		if (index == cli_node.cli_config.cnt_peer)
			cli_node.cli_config.cnt_peer++;
	}
	else {
		clLog(STANDARD_LOGID, eCLSeverityDebug,
			LOG_FORMAT"CLI: Peer already exist\n", LOG_VALUE);
	}
}

int get_peer_index(peer_address_t *cli_peer_addr)
{
	int i = 0;
	char ipv6[INET6_ADDRSTRLEN] = {0};

	for(i = 0; i < cli_node.cli_config.cnt_peer; i++)
	{
		if(cli_node.peer[i] != NULL)
		{
			if(cli_peer_addr->type == IPV4_TYPE) {
				if(cli_node.peer[i]->cli_peer_addr.ipv4.sin_addr.s_addr ==
					cli_peer_addr->ipv4.sin_addr.s_addr) {
				clLog(STANDARD_LOGID, eCLSeverityDebug,
					LOG_FORMAT"CLI: Request rcvd for IP Address: %s\n", LOG_VALUE,
					inet_ntoa(cli_peer_addr->ipv4.sin_addr));
				return i;
				}

			} else if(cli_peer_addr->type == IPV6_TYPE) {
				if(memcmp(&cli_node.peer[i]->cli_peer_addr.ipv6.sin6_addr,
					&cli_peer_addr->ipv6.sin6_addr, IP_ADDR_V6_LEN) == 0) {
				clLog(STANDARD_LOGID, eCLSeverityDebug,
					LOG_FORMAT"CLI: Request rcvd for IP Address: %s\n", LOG_VALUE,
					inet_ntop(AF_INET6, &cli_peer_addr->ipv6.sin6_addr,
					ipv6, INET6_ADDRSTRLEN));
					return i;
				}
			} else {
				clLog(STANDARD_LOGID, eCLSeverityDebug,
					LOG_FORMAT"Not supported IP type %d", LOG_VALUE, cli_peer_addr->type);
			}
		}
	}

	if(cli_peer_addr->type == IPV4_TYPE) {
		clLog(STANDARD_LOGID, eCLSeverityDebug,
			LOG_FORMAT"CLI: Peer not exist for IP: %s\n", LOG_VALUE,
			inet_ntoa(cli_peer_addr->ipv4.sin_addr));

	} else if(cli_peer_addr->type == IPV6_TYPE) {
		clLog(STANDARD_LOGID, eCLSeverityDebug,
			LOG_FORMAT"CLI: Peer not exist for IP: %s\n", LOG_VALUE,
			inet_ntop(AF_INET6, &cli_peer_addr->ipv6.sin6_addr,
			ipv6, INET6_ADDRSTRLEN));
	} else {
		clLog(STANDARD_LOGID, eCLSeverityDebug,
			LOG_FORMAT"Not supported IP type %d", LOG_VALUE, cli_peer_addr->type);
	}
	return -1;
}

int get_first_index(void)
{
	int i;

	for(i = 0; i < cli_node.cli_config.cnt_peer ; i++)
	{
		if(cli_node.peer[i] == NULL)
		{
				return i;
		}
	}
	return i;
}

int update_peer_timeouts(peer_address_t *cli_peer_addr, uint8_t val)
{

	int index = -1;

	index = get_peer_index(cli_peer_addr);
	if (index == -1)
	{
		return index;
	}

	cli_node.peer[index]->timeouts = val;

	return 0;
}

int update_peer_status(peer_address_t *cli_peer_addr, bool val)
{

	int index = -1;

	index = get_peer_index(cli_peer_addr);

	if (index == -1)
	{
		return index;
	}

	cli_node.peer[index]->status = val;

	return 0;
}

int delete_cli_peer(peer_address_t *cli_peer_addr)
{
	int index = -1;

	index = get_peer_index(cli_peer_addr);

	if (index == -1)
	{
		return index;
	}

	free(cli_node.peer[index]);
	cli_node.peer[index] = NULL;

	cli_node.cli_config.nbr_of_peer--;

	return 0;
}

int update_last_activity(peer_address_t *cli_peer_addr, char *time_stamp)
{
	int index = -1;

	index = get_peer_index(cli_peer_addr);

	if(index == -1)
	{
		return index;
	}

	strncpy(cli_node.peer[index]->lastactivity, time_stamp, LAST_TIMER_SIZE);

	return 0;
}

int update_sys_stat(int index, int operation)
{
	if(operation)
		__sync_add_and_fetch(&cli_node.stats[index],1);
	else
		__sync_add_and_fetch(&cli_node.stats[index],-1);

	return 0;
}

int change_config_file(const char *path, const char *param, const char *value)
{
	char buffer[LINE_SIZE], temp[ENTRY_VALUE_SIZE+ENTRY_NAME_SIZE+2];
	char *ptr;
	const char *temp_filename = "temp.cfg";

	strncpy(temp, param, ENTRY_NAME_SIZE);
	strncat(temp, "=", 1);
	strncat(temp, value, ENTRY_VALUE_SIZE);
	strncat(temp, "\n", 1);

	FILE *file=fopen(path,"r+");

	if(file==NULL){
		clLog(STANDARD_LOGID, eCLSeverityCritical,
			LOG_FORMAT"Error while opening %s file\n", LOG_VALUE, path);
		return -1;
	}

	FILE *file_1=fopen("temp.cfg","w");
	if(file==NULL){
		clLog(STANDARD_LOGID, eCLSeverityCritical,
			LOG_FORMAT"Error while creating file\n", LOG_VALUE);
		return -1;
	}

	while(fgets(buffer,sizeof(buffer),file)!=NULL)
	{
		if((ptr=strstr(buffer,param))!=NULL && buffer[0]!='#' && buffer[0]!=';')
		{
			fputs(temp,file_1);
			continue;
		}
		fputs(buffer,file_1);
	}
	fclose(file);
	fclose(file_1);

	if((remove(path))!=0)
		clLog(STANDARD_LOGID, eCLSeverityCritical,
			LOG_FORMAT"Delete file ERROR\n", LOG_VALUE);

	rename(temp_filename, path);

	return 0;
}

void set_gw_type(uint8_t gateway_type)
{
	cli_node.gw_type = gateway_type;
}

uint8_t get_gw_type(void) {
	return cli_node.gw_type;
}

bool is_cmd_supported(int cmd_number) {

	if(!supported_commands[get_gw_type()][cmd_number])
		return false;

	return true;
}

void get_current_time_oss(char *last_time_stamp)
{
	struct tm * last_timer;
	time_t rawtime;
	time(&rawtime);
	last_timer = gmtime(&rawtime);
	strftime(last_time_stamp, LAST_TIMER_SIZE, "%FT%T", last_timer);
}

static int reset_stats(void)
{
	reset_time = *(cli_node.upsecs);

	int peer_itr = 0, msgs_itr = 0;

	for(peer_itr = 0; peer_itr < cli_node.cli_config.nbr_of_peer; peer_itr++) {

		if (cli_node.peer[peer_itr] != NULL)
		{
			switch(cli_node.peer[peer_itr]->intfctype)
			{
				case itS11:

					for (msgs_itr = 0; msgs_itr < S11_STATS_SIZE; msgs_itr++) {
						cli_node.peer[peer_itr]->stats.s11[msgs_itr].cnt[0] = 0;
						cli_node.peer[peer_itr]->stats.s11[msgs_itr].cnt[1] = 0;
						memset(cli_node.peer[peer_itr]->stats.s11[msgs_itr].ts,
							'\0', LAST_TIMER_SIZE);
					}
					break;
				case itS5S8:
					for (msgs_itr = 0; msgs_itr < S5S8_STATS_SIZE; msgs_itr++) {
						cli_node.peer[peer_itr]->stats.s5s8[msgs_itr].cnt[0] = 0;
						cli_node.peer[peer_itr]->stats.s5s8[msgs_itr].cnt[1] = 0;
						memset(cli_node.peer[peer_itr]->stats.s5s8[msgs_itr].ts,
							'\0', LAST_TIMER_SIZE);
					}
					break;
				case itSx:

					for (msgs_itr = 0; msgs_itr < SX_STATS_SIZE; msgs_itr++)
					{
						cli_node.peer[peer_itr]->stats.sx[msgs_itr].cnt[0] = 0;
						cli_node.peer[peer_itr]->stats.sx[msgs_itr].cnt[1] = 0;
						memset(cli_node.peer[peer_itr]->stats.sx[msgs_itr].ts,
							'\0', LAST_TIMER_SIZE);
					}
					break;
				case itGx:

					for (msgs_itr = 0; msgs_itr < GX_STATS_SIZE; msgs_itr++)
					{
						cli_node.peer[peer_itr]->stats.gx[msgs_itr].cnt[0] = 0;
						cli_node.peer[peer_itr]->stats.gx[msgs_itr].cnt[1] = 0;
						memset(cli_node.peer[peer_itr]->stats.gx[msgs_itr].ts,
							'\0', LAST_TIMER_SIZE);
					}
					break;
				default:
					clLog(STANDARD_LOGID, eCLSeverityCritical,
						LOG_FORMAT"CLI: Not supported interface", LOG_VALUE);
					break;
			}

		cli_node.peer[peer_itr]->hcrequest[0] = 0;
		cli_node.peer[peer_itr]->hcrequest[1] = 0;
		cli_node.peer[peer_itr]->hcresponse[0] = 0;
		cli_node.peer[peer_itr]->hcresponse[1] = 0;
		memset(cli_node.peer[peer_itr]->lastactivity,
			'\0', LAST_TIMER_SIZE);

		}

	}

	return 0;
}

void set_mac_value(char *mac_addr_char_ptr, uint8_t *mac_addr_int_ptr)
{
	uint8_t itr = 0;
	for(itr = 0; itr < MAC_ADDR_BYTES_IN_INT_ARRAY; itr++) {
		if(itr != MAC_ADDR_BYTES_IN_INT_ARRAY - 1)
			/* we need to add two bytes in char array */
			if(mac_addr_int_ptr[itr] > FOUR_BIT_MAX_VALUE)
				snprintf((mac_addr_char_ptr+(itr*3)), 4, "%x:", mac_addr_int_ptr[itr]);
			else snprintf((mac_addr_char_ptr+(itr*3)), 4, "0%x:", mac_addr_int_ptr[itr]);
		else
			if(mac_addr_int_ptr[itr] > FOUR_BIT_MAX_VALUE)
				snprintf((mac_addr_char_ptr+(itr*3)), 3, "%x", mac_addr_int_ptr[itr]);
			else
				snprintf((mac_addr_char_ptr+(itr*3)), 3, "0%x", mac_addr_int_ptr[itr]);
	}
}

int post_stat_frequency(const char *request_body, char **response_body)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"post_stat_frequency() body=[%s]", LOG_VALUE, request_body);

	return csUpdateInterval(request_body, response_body);
}

int get_stat_frequency(const char *request_body, char **response_body)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"get_stat_frequency() body=[%s]", LOG_VALUE, request_body);

	return csGetInterval(response_body);
}

int post_rt(const char *request_body, char **response_body)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"post_request_tries() body=[%s]", LOG_VALUE, request_body);

	const char *param = "REQUEST_TRIES";
	char path[PATH_LEN] = {0};
	char value[ENTRY_VALUE_SIZE] = {0};
	char temp[JSON_RESP_SIZE] = {0};
	if (get_gw_type() == OSS_CONTROL_PLANE)
		strncpy(path, CP_PATH, PATH_LEN);
	else if (get_gw_type() == OSS_USER_PLANE)
		strncpy(path, DP_PATH, PATH_LEN);

	if(!is_cmd_supported(REQUEST_TRIES_INDEX)) {
		return resp_cmd_not_supported(get_gw_type(), response_body);
	}

	cli_node.cli_config.number_of_request_tries = get_request_tries_value(request_body, response_body);
	snprintf(value, ENTRY_VALUE_SIZE, "%d", cli_node.cli_config.number_of_request_tries);

	if (get_gw_type() == OSS_CONTROL_PLANE) {
		(*cli_node.cli_config.gw_adapter_callback_list.update_request_tries)(cli_node.cli_config.number_of_request_tries);
	}

	change_config_file(path, param, value);
	construct_json(param,value,temp);
	*response_body=strdup((const char *)temp);

	return REST_SUCESSS;
}

int get_rt(const char *request_body, char **response_body)
{

	clLog(STANDARD_LOGID, eCLSeverityDebug,
		LOG_FORMAT"get_request_tries() body=[%s]", LOG_VALUE, request_body);

	if(!is_cmd_supported(REQUEST_TRIES_INDEX)) {
		return resp_cmd_not_supported(get_gw_type(), response_body);
	}

	if (get_gw_type() == OSS_CONTROL_PLANE) {
		cli_node.cli_config.number_of_request_tries = (*cli_node.cli_config.gw_adapter_callback_list.get_request_tries)();
	}

	return get_number_of_request_tries(response_body, cli_node.cli_config.number_of_request_tries);
}

int post_tc(const char *request_body, char **response_body)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"post_transmit_count() body=[%s]", LOG_VALUE, request_body);

	const char *param = "TRANSMIT_COUNT";
	char path[PATH_LEN] = {0};
	char value[ENTRY_VALUE_SIZE] = {0};
	char temp[JSON_RESP_SIZE] = {0};
	if (get_gw_type() == OSS_CONTROL_PLANE)
		strncpy(path, CP_PATH, PATH_LEN);
	else if (get_gw_type() == OSS_USER_PLANE)
		strncpy(path, DP_PATH, PATH_LEN);

	cli_node.cli_config.number_of_transmit_count = get_transmit_count_value(request_body, response_body);
	snprintf(value, ENTRY_VALUE_SIZE, "%d", cli_node.cli_config.number_of_transmit_count);

	(*cli_node.cli_config.gw_adapter_callback_list.update_transmit_count)(cli_node.cli_config.number_of_transmit_count);

	change_config_file(path, param, value);
	construct_json(param,value,temp);
	*response_body=strdup((const char *)temp);

	return REST_SUCESSS;
}

int get_tc(const char *request_body, char **response_body)
{

	clLog(STANDARD_LOGID, eCLSeverityDebug,
		LOG_FORMAT"get_transmit_count() body=[%s]", LOG_VALUE, request_body);

	cli_node.cli_config.number_of_transmit_count = (*cli_node.cli_config.gw_adapter_callback_list.get_transmit_count)();

	return get_number_of_transmit_count(response_body, cli_node.cli_config.number_of_transmit_count);
}

int post_tt(const char *request_body, char **response_body)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"post_transmit_timer() body=[%s]", LOG_VALUE, request_body);

	const char *param = "TRANSMIT_TIMER";
	char path[PATH_LEN] = {0};
	char value[ENTRY_VALUE_SIZE] = {0};
	char temp[JSON_RESP_SIZE] = {0};
	if (get_gw_type() == OSS_CONTROL_PLANE)
		strncpy(path, CP_PATH, PATH_LEN);
	else if (get_gw_type() == OSS_USER_PLANE)
		strncpy(path, DP_PATH, PATH_LEN);

	cli_node.cli_config.transmit_timer_value = get_transmit_timer_value_in_seconds(request_body, response_body);
	(*cli_node.cli_config.gw_adapter_callback_list.update_transmit_timer)(cli_node.cli_config.transmit_timer_value);
	snprintf(value, ENTRY_VALUE_SIZE, "%d", cli_node.cli_config.transmit_timer_value);

	change_config_file(path, param, value);
	construct_json(param,value,temp);
	*response_body=strdup((const char *)temp);

	return REST_SUCESSS;

}

int get_tt(const char *request_body, char **response_body)
{

	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"get_transmit_timer() body=[%s]", LOG_VALUE, request_body);

	cli_node.cli_config.transmit_timer_value = (*cli_node.cli_config.gw_adapter_callback_list.get_transmit_timer)();

	return get_transmit_timer_value(response_body, cli_node.cli_config.transmit_timer_value);
}

int post_rto(const char *request_body, char **response_body)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"post_request_timeout() body=[%s]", LOG_VALUE, request_body);

	const char *param = "REQUEST_TIMEOUT";
	char path[PATH_LEN] = {0};
	char value[ENTRY_VALUE_SIZE] = {0};
	char temp[JSON_RESP_SIZE] = {0};
	if (get_gw_type() == OSS_CONTROL_PLANE)
		strncpy(path, CP_PATH, PATH_LEN);
	else if (get_gw_type() == OSS_USER_PLANE)
		strncpy(path, DP_PATH, PATH_LEN);

	if(!is_cmd_supported(REQUEST_TIMEOUT_INDEX)) {
		return resp_cmd_not_supported(get_gw_type(), response_body);
	}

	cli_node.cli_config.request_timeout_value = get_request_timeout_value_in_milliseconds(request_body,
		response_body);


	if (get_gw_type() == OSS_CONTROL_PLANE) {
		(*cli_node.cli_config.gw_adapter_callback_list.update_request_timeout)(cli_node.cli_config.request_timeout_value);
	}

	snprintf(value, ENTRY_VALUE_SIZE, "%d", cli_node.cli_config.request_timeout_value);
	change_config_file(path, param, value);
	construct_json(param,value,temp);
	*response_body=strdup((const char *)temp);

	return REST_SUCESSS;
}

int get_rto(const char *request_body, char **response_body)
{

	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"get_request_timeout() body=[%s]", LOG_VALUE, request_body);

	if(!is_cmd_supported(REQUEST_TIMEOUT_INDEX)) {
		return resp_cmd_not_supported(get_gw_type(), response_body);
	}

	if (get_gw_type() == OSS_CONTROL_PLANE) {
		cli_node.cli_config.request_timeout_value = (*cli_node.cli_config.gw_adapter_callback_list.get_request_timeout)();
	}

	return get_request_timeout_value(response_body, cli_node.cli_config.request_timeout_value);
}

int post_pt(const char *request_body, char **response_body)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"post_periodic_timer() body=[%s]", LOG_VALUE, request_body);

	const char *param = "PERIODIC_TIMER";
	char path[PATH_LEN] = {0};
	char value[ENTRY_VALUE_SIZE] = {0};
	char temp[JSON_RESP_SIZE] = {0};
	if (get_gw_type() == OSS_CONTROL_PLANE)
		strncpy(path, CP_PATH, PATH_LEN);
	else if (get_gw_type() == OSS_USER_PLANE)
		strncpy(path, DP_PATH, PATH_LEN);

	cli_node.cli_config.periodic_timer_value = get_periodic_timer_value_in_seconds(request_body,
		response_body);
	(*cli_node.cli_config.gw_adapter_callback_list.update_periodic_timer)(cli_node.cli_config.periodic_timer_value);
	snprintf(value, ENTRY_VALUE_SIZE, "%d", cli_node.cli_config.periodic_timer_value);

	change_config_file(path, param, value);
	construct_json(param,value,temp);
	*response_body=strdup((const char *)temp);

	return REST_SUCESSS;

}

int get_pt(const char *request_body, char **response_body)
{

	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"get_periodic_timer() body=[%s]", LOG_VALUE, request_body);

	cli_node.cli_config.periodic_timer_value = (*cli_node.cli_config.gw_adapter_callback_list.get_periodic_timer)();

	return get_periodic_timer_value(response_body, cli_node.cli_config.periodic_timer_value);
}

int post_stat_logging(const char *request_body, char **response_body)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"post_stat_logging() body=[%s]", LOG_VALUE, request_body);

	return csUpdateStatLogging(request_body, response_body);
}

int get_stat_logging(const char *request_body, char **response_body)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"get_stat_logging() body=[%s]", LOG_VALUE, request_body);

	return csGetStatLogging(response_body);
}

int post_generate_pcap_cmd(const char *request_body, char **response_body)
{

	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"post_generate_pcap_cmd() body=[%s]", LOG_VALUE, request_body);

	if(!is_cmd_supported(PCAP_GENERATION_INDEX)) {
		return resp_cmd_not_supported(get_gw_type(), response_body);
	}

	uint8_t pcap_status = 0;
	const char *param = "PCAP_GENERATION";
	char path[PATH_LEN] = {0};
	char value[ENTRY_VALUE_SIZE] = {0};
	char temp[JSON_RESP_SIZE] = {0};
	if (get_gw_type() == OSS_CONTROL_PLANE)
		strncpy(path, CP_PATH, PATH_LEN);
	else if (get_gw_type() == OSS_USER_PLANE)
		strncpy(path, DP_PATH, PATH_LEN);

	pcap_status = get_pcap_generation_cmd_value(request_body, response_body);

	if (pcap_status == REST_FAIL) {
		snprintf(value, ENTRY_VALUE_SIZE, "%s", "REST_FAIL");
		construct_json(param,value,temp);
		*response_body=strdup((const char *)temp);
		return REST_FAIL;
	}

	if (get_gw_type() == OSS_USER_PLANE) {
		(*cli_node.cli_config.gw_adapter_callback_list.update_pcap_status)(pcap_status);
	}

	snprintf(value, ENTRY_VALUE_SIZE, "%s", ((pcap_status) ? ((pcap_status == PCAP_GEN_ON) ?
				"START" : ((pcap_status == PCAP_GEN_RESTART) ? "RESTART" :
				"INVALID CMD" )) : "STOP"));

	construct_json(param,value,temp);
	*response_body=strdup((const char *)temp);

	return REST_SUCESSS;
}

int get_generate_pcap_status(const char *request_body, char **response_body)
{

	clLog(STANDARD_LOGID, eCLSeverityDebug,
		LOG_FORMAT"get_generate_pcap_status() body=[%s]", LOG_VALUE, request_body);

	if(!is_cmd_supported(PCAP_GENERATION_INDEX)) {
		return resp_cmd_not_supported(get_gw_type(), response_body);
	}

	if (get_gw_type() == OSS_USER_PLANE) {
		cli_node.cli_config.generate_pcap_status = (*cli_node.cli_config.gw_adapter_callback_list.get_generate_pcap)();
	}

	return get_pcap_generation_status(response_body, cli_node.cli_config.generate_pcap_status);
}

int get_stat_live(const char *request_body, char **response_body)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"get_stat_live() body=[%s]", LOG_VALUE, request_body);

	return csGetLive(response_body);
}

int get_configuration(const char *request_body, char **response_body)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo, "get_configuration() body=[%s]",
			request_body);

	if (get_gw_type() == OSS_CONTROL_PLANE) {
		(*cli_node.cli_config.gw_adapter_callback_list.get_cp_config)(&cli_node.cli_config.cp_configuration);
		return get_cp_configuration(response_body, &cli_node.cli_config.cp_configuration);
	} else if (get_gw_type() == OSS_USER_PLANE) {
		(*cli_node.cli_config.gw_adapter_callback_list.get_dp_config)(&cli_node.cli_config.dp_configuration);
		return get_dp_configuration(response_body, &cli_node.cli_config.dp_configuration);
	}

	return REST_SUCESSS;
}

int reset_cli_stats(const char *request_body, char **response_body)
{
	int value;
	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"reset_stats() body=[%s]", LOG_VALUE, request_body);

	value =  csResetStats(request_body, response_body);
	if(value == REST_SUCESSS)
	{
		reset_stats();
		return value;
	}
	return value;
}

int get_stat_live_all(const char *request_body, char **response_body)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"get_stat_live_all() body=[%s]", LOG_VALUE, request_body);

	return csGetLiveAll(response_body);
}


int add_ue_entry_details(const char *request_body, char **response_body)
{
	int iRet = 0;

	uint16_t uiCntr = 0;

	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"add_ue_entry_details() body=[%s]", LOG_VALUE, request_body);

	iRet = parseJsonReqFillStruct(request_body, response_body, li_config, &uiCntr);

	if(iRet == REST_SUCESSS && get_gw_type() == OSS_CONTROL_PLANE)
		(*cli_node.cli_config.gw_adapter_callback_list.add_ue_entry)(li_config, uiCntr);

	return iRet;
}

int update_ue_entry_details(const char *request_body, char **response_body)
{
	int iRet = 0;
	uint16_t uiCntr = 0;

	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"update_ue_entry_details() body=[%s]", LOG_VALUE, request_body);

	iRet = parseJsonReqFillStruct(request_body, response_body, li_config, &uiCntr);

	if(iRet == REST_SUCESSS && get_gw_type() == OSS_CONTROL_PLANE)
		(*cli_node.cli_config.gw_adapter_callback_list.update_ue_entry)(li_config, uiCntr);

	return iRet;
}

int delete_ue_entry_details(const char *request_body, char **response_body)
{
	int iRet = 0;
	uint16_t uiCntr = 0;
	uint64_t uiIds[MAX_LI_ENTRIES] = {0};

	clLog(STANDARD_LOGID, eCLSeverityInfo,
		LOG_FORMAT"delete_ue_entry_details() body=[%s]", LOG_VALUE, request_body);

	iRet = parseJsonReqForId(request_body, response_body, uiIds, &uiCntr);

	if(iRet == REST_SUCESSS && get_gw_type() == OSS_CONTROL_PLANE)
		(*cli_node.cli_config.gw_adapter_callback_list.delete_ue_entry)(uiIds, uiCntr);

	return iRet;
}
