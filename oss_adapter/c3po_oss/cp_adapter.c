#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_cfgfile.h>
#include <rte_memory.h>
#include <time.h>
#include <math.h>
#include "../../cp/cp_stats.h"
#include "../../cp/cp.h"

#include "cp_adapter.h"
#include "crest.h"
#include "clogger.h"
#include "cstats.h"

#include <sys/stat.h>


#include "../../interface/interface.h"
#include "../../cp/gtpv2c.h"
#include "../../cp/ue.h"

#include "../../pfcp_messages/pfcp_set_ie.h"

//////////////////////////////////////////////////////////////////////////////////

extern pfcp_config_t pfcp_config;

int s11MessageTypes [] = {
    -1,-1,-1,0,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,1,2,5,6,3,4,9,10,
    7,8,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,13,14,15,16,17,18,19,20,21,22,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,23,24,25,26,27,
    28,29,30,31,32,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    35,36,33,34,11,12,37,38,39,40,41,42,-1,-1,-1,-1,43,44,-1,45,
    46,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,47,48
};

int s5s8MessageTypes [] = {
    -1,-1,-1,0,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,1,2,5,6,3,4,9,10,
    7,8,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,13,14,15,16,17,18,-1,19,20,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,21,22,23,24,25,
    26,27,28,29,30,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,31,32,11,12,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    33,34
};

int sxaMessageTypes [] = {
    -1,0,1,-1,-1,2,3,4,5,6,7,8,9,10,11,12,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,13,14,15,16,17,18,19,20
};

int sxbMessageTypes [] = {
    -1,0,1,-1,-1,2,3,4,5,6,7,8,9,10,11,12,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,13,14,15,16,17,18,19,20
};

int sxasxbMessageTypes [] = {
    -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,15,16,17,18,19,20,21,22
};

int update_cli_stats(uint32_t ip_addr, uint8_t msg_type,int dir,char *time_stamp)
{
	int ret = 0;
	int index = -1;

	clLog(clSystemLog, eCLSeverityDebug, "Inside update_cli_stats\n");
	clLog(clSystemLog, eCLSeverityDebug, "msg_type:%d\n",msg_type);
	clLog(clSystemLog, eCLSeverityDebug, "dir:%d\n",dir);
	clLog(clSystemLog, eCLSeverityDebug, "ip_addr is :%s\n",
						inet_ntoa(*((struct in_addr *)&ip_addr)));

	index = get_peer_index(ip_addr);

	if(index == -1)
	{
		clLog(clSystemLog, eCLSeverityDebug,"peer not found\n");
		return -1;
	}

	if (msg_type == GTP_ECHO_REQ || msg_type == PFCP_HEARTBEAT_REQUEST)
	{
		__sync_add_and_fetch(&cli_node.peer[index]->hcrequest[dir], 1);
	}
	else if (msg_type == GTP_ECHO_RSP || msg_type == PFCP_HEARTBEAT_RESPONSE)
	{
		__sync_add_and_fetch(&cli_node.peer[index]->hcresponse[dir], 1);
	}
	else {

	switch(cli_node.peer[index]->intfctype)
	{
		case itS11:
					__sync_add_and_fetch(&cli_node.peer[index]->stats.s11[s11MessageTypes[msg_type]].cnt[dir], 1);
					strcpy(cli_node.peer[index]->stats.s11[s11MessageTypes[msg_type]].ts, time_stamp);
					break;
		case itS5S8:
					__sync_add_and_fetch(&cli_node.peer[index]->stats.s5s8[s5s8MessageTypes[msg_type]].cnt[dir], 1);
					strcpy(cli_node.peer[index]->stats.s5s8[s5s8MessageTypes[msg_type]].ts, time_stamp);
					break;
		case itSxa:
					__sync_add_and_fetch(&cli_node.peer[index]->stats.sxa[sxaMessageTypes[msg_type]].cnt[dir], 1);
					strcpy(cli_node.peer[index]->stats.sxa[sxaMessageTypes[msg_type]].ts, time_stamp);
					break;
		case itSxb:
					__sync_add_and_fetch(&cli_node.peer[index]->stats.sxb[sxbMessageTypes[msg_type]].cnt[dir], 1);
					strcpy(cli_node.peer[index]->stats.sxb[sxbMessageTypes[msg_type]].ts, time_stamp);
					break;
		case itSxaSxb:
					__sync_add_and_fetch(&cli_node.peer[index]->stats.sxasxb[sxasxbMessageTypes[msg_type]].cnt[dir], 1);
					strcpy(cli_node.peer[index]->stats.sxasxb[sxasxbMessageTypes[msg_type]].ts, time_stamp);
					break;
		/*case itGx:
					cli_node.peer[index]->stats.gx[gxMessageTypes[msg_type]].cnt[dir]++;
					cli_node.peer[index]->stats.gx[gxMessageTypes[msg_type]].ts = time_stamp;
					break;*/
		default :
					 clLog(clSystemLog, eCLSeverityCritical,"CLI:No such a interface");
					 break;
	}
	}

	return ret;

}

int get_peer_index(uint32_t ip_addr)
{
	int i;

	for(i = 0; i < cnt_peer ; i++)
	{
		if(cli_node.peer[i]!=NULL)
		{
			if(cli_node.peer[i]->ipaddr.s_addr == ip_addr )
				return i;
		}
	}

	return -1;
}

int get_first_index(void)
{
	int i;

	for(i = 0; i < cnt_peer ; i++)
	{
		if(cli_node.peer[i] == NULL)
		{
				return i;
		}
	}
	return i;
}




void add_cli_peer(uint32_t ip_addr,EInterfaceType it)
{
	int index = -1;
	SPeer temp_peer;

	clLog(clSystemLog, eCLSeverityDebug,
			"CLI:Request rcvd for ip addr:%s\n",
			inet_ntoa(*((struct in_addr *)&ip_addr)));

	/*Check peer is allready added or not*/
	index = get_peer_index(ip_addr);

	if (index == -1)  /*peer is not added yet*/
	{
		index = get_first_index(); /*find the postn*/
		cli_node.peer[index] = calloc(1,sizeof(temp_peer));

		//Initialization
		cli_node.peer[index]->ipaddr = (*(struct in_addr *)&ip_addr);
		cli_node.peer[index]->intfctype = it;
		cli_node.peer[index]->status = FALSE;
		cli_node.peer[index]->response_timeout = pfcp_config.transmit_timer;
		cli_node.peer[index]->maxtimeout = pfcp_config.transmit_cnt + 1;
		cli_node.peer[index]->timeouts = 0;

		clLog(clSystemLog, eCLSeverityDebug,
						"Interface type is : %d\n",it);
		clLog(clSystemLog, eCLSeverityDebug,
						"Added peer with ip addr : %s\n\n",
						inet_ntoa(cli_node.peer[index]->ipaddr));

		nbr_of_peer++; /*peer count incremented*/

		if (index == cnt_peer)
			cnt_peer++;

	}
	else {
		clLog(clSystemLog, eCLSeverityDebug,"CLI:peer allready exist\n");
	}

}

int update_peer_timeouts(uint32_t ip_addr,uint8_t val)
{

	int ret = -1;
	int index = -1;

	index = get_peer_index(ip_addr);

	if (index == -1)
	{
		clLog(clSystemLog, eCLSeverityDebug,
				"peer :%s doesn't exist\n ",
				inet_ntoa(*((struct in_addr *)&ip_addr)));
		return ret;
	}

	cli_node.peer[index]->timeouts = val;

	return 0;

}

int update_peer_status(uint32_t ip_addr,bool val)
{

	int ret = -1;
	int index = -1;

	index = get_peer_index(ip_addr);

	if (index == -1)
	{
		clLog(clSystemLog, eCLSeverityDebug,
				"peer :%s doesn't exist\n ",
				inet_ntoa(*((struct in_addr *)&ip_addr)));
		return ret;
	}

	cli_node.peer[index]->status = val;

	return 0;

}


int delete_cli_peer(uint32_t ip_addr)
{
	int ret = -1;
	int index = -1;

	index = get_peer_index(ip_addr);

	if (index == -1)
	{
		clLog(clSystemLog, eCLSeverityDebug,
				"peer :%s doesn't exist\n ",
				inet_ntoa(*((struct in_addr *)&ip_addr)));
		return ret;
	}

	free(cli_node.peer[index]);
	cli_node.peer[index] = NULL;

	nbr_of_peer--; /*decrement peer count*/

	return 0;

}


int update_last_activity(uint32_t ip_addr, char *time_stamp)
{
	int index = -1;

	index = get_peer_index(ip_addr);

	if(index == -1)
	{
		clLog(clSystemLog, eCLSeverityDebug,"peer not found\n");
		return -1;
	}

	strcpy(cli_node.peer[index]->lastactivity, time_stamp);

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


///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

	static int
get_logger(const char *request_body, char **response_body)
{
	char *loggers = NULL;

	clLog(clSystemLog, eCLSeverityInfo, "get_logger() body=[%s]",
			request_body);

	loggers = clGetLoggers();
	*response_body = strdup(loggers);

	if (*response_body) {
		free(loggers);
		return REST_SUCESSS;
	}

	return REST_FAIL;
}

	static int
post_logger(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo, "post_logger() body=[%s]",
			request_body);

	return clUpdateLogger(request_body, response_body);
}


	static int
get_cp_logger(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,"get_cp_logger() body=[%s]",request_body);

	return clRecentLogger(request_body, response_body);
}


	static int
post_max_size(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo, "post_max_size() body=[%s]",
			request_body);

	return clRecentSetMaxsize(request_body, response_body);
}

	static int
get_max_size(const char *request_body, char **response_body)
{

	clLog(clSystemLog, eCLSeverityMajor, "get_max_size() body=[%s]",request_body);

	return clRecentLogMaxsize(request_body, response_body);

}

//////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////

	static int
get_stat_frequency(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo, "get_stat_frequency() body=[%s]",
			request_body);

	return csGetInterval(response_body);
}


	static int
post_stat_frequency(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo, "post_stat_frequency() body=[%s]",
			request_body);

	return csUpdateInterval(request_body, response_body);
}
	static int
get_stat_logging(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo, "get_stat_logging() body=[%s]",
			request_body);

	return csGetStatLogging(response_body);
}

static int
post_stat_logging(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo, "post_stat_logging() body=[%s]",
			request_body);

	return csUpdateStatLogging(request_body, response_body);
}
	static int
get_stat_live(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo, "get_stat_live() body=[%s]",
			request_body);

	return csGetLive(response_body);
}

	static int
get_stat_live_all(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo, "get_stat_live_all() body=[%s]",
			request_body);

	return csGetLiveAll(response_body);
}

/////////////////////////////////////////////////////////////////////////////////

void
init_rest_methods(int port_no, size_t thread_count)
{
	crInit(clGetAuditLogger(), port_no, thread_count);

	/*Commands related with logging*/

	crRegisterStaticHandler(eCRCommandGet, "/logger", get_logger);
	crRegisterStaticHandler(eCRCommandPost, "/logger", post_logger);
	crRegisterStaticHandler(eCRCommandGet, "/cp_logger", get_cp_logger);
	crRegisterStaticHandler(eCRCommandGet, "/max_size", get_max_size);
	crRegisterStaticHandler(eCRCommandPost, "/max_size", post_max_size);

	/*Commands related with statistics*/

	crRegisterStaticHandler(eCRCommandGet, "/statfreq", get_stat_frequency);
	crRegisterStaticHandler(eCRCommandPost, "/statfreq", post_stat_frequency);

	crRegisterStaticHandler(eCRCommandGet, "/statlogging", get_stat_logging);
	crRegisterStaticHandler(eCRCommandPost, "/statlogging", post_stat_logging);

	crRegisterStaticHandler(eCRCommandGet, "/statlive", get_stat_live);
	crRegisterStaticHandler(eCRCommandGet, "/statliveall", get_stat_live_all);

	crStart();

}
