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

//struct cp_stats_t cp_stats;

//extern struct in_addr dp_comm_ip;
//extern struct in_addr cp_comm_ip;

//extern uint16_t dp_comm_port;
//extern uint16_t cp_comm_port;

int64_t
get_stat_spgwc(int category_id, int value_id, int peer_id)
{
	int64_t value = 0;
	clock_t t;
	//size_t len ;
	switch(category_id) {

		case common_stat:
			switch(value_id) {
				case active_session:
					value = cp_stats.create_session - cp_stats.delete_session;
					break;
				case upsecs:
					t = clock() - cp_stats.execution_time;
					double time_taken = ((double)t)/CLOCKS_PER_SEC;
					value = ceil(time_taken);
					value = (int)time_taken;
					//printf("upsec is %lu\n",value);
					break;
					/*case resetsecs:
					  len = 965;
					  get_current_file_size(len);
					  t = cp_stats.reset_time;
					  time_taken = ((double)t)/CLOCKS_PER_SEC;
					  value = ceil(time_taken);
					  value = (int)time_taken;
					//printf("reset time is %lu\n",value);


					break;*/
				default:
					break;
			}
			break;
		case s11_interface:
			switch(value_id) {

				case set_timeouts:
					value = 13;
					break;
				case set_req_sent:
					value = cp_stats.number_of_sgwc_health_req++;
					break;
				case set_req_received:
					value = cp_stats.number_of_mme_resp_to_sgwc_health_req++;
					break;
				case set_resp_sent:
					value = cp_stats.number_of_mme_health_req;
					break;
				case set_resp_received:
					value = cp_stats.number_of_sgwc_resp_to_mme_health_req;
					break;
				case create_session:
					value = cp_stats.create_session;
					break;
				case modify_bearer:
					value = cp_stats.modify_bearer;
					break;
				case delete_session:
					value = cp_stats.delete_session;
					break;
				case number_of_ues:
					//value = cp_stats.number_of_ues;
					value = cp_stats.create_session-cp_stats.delete_session;
					break;
				/*case number_of_connected_ues:
					//value = cp_stats.number_of_connected_ues;
					value = cp_stats.create_session-cp_stats.delete_session;
					break;*/
				/*case number_of_suspended_ues:
					//value = cp_stats.rel_access_bearer;
					value = cp_stats.create_session-cp_stats.delete_session;
					break;*/
				case sgw_nbr_of_pdn_connections:
					//value = cp_stats.number_of_ues;
					value = cp_stats.create_session-cp_stats.delete_session;
					break;
				case sgw_nbr_of_bearers:
					value = cp_stats.create_session - cp_stats.delete_session;
					break;
				/*case sgw_nbr_of_active_bearers:
					//value = cp_stats.create_session - cp_stats.rel_access_bearer - cp_stats.delete_session;
					value = cp_stats.create_session-cp_stats.delete_session;
					break;
				case sgw_nbr_of_idle_bearers:
					//value = cp_stats.rel_access_bearer;
					value = cp_stats.create_session-cp_stats.delete_session;
					break;*/
				default:
					break;
				}
				break;
		case sx_interface:
			switch(peer_id) {
				case peer1:
					switch(value_id) {
						case set_resp_timeout:
							value = 18;
							break;
						case set_max_timeouts:
							value = 19;
							break;
						case set_timeouts:
							value = 20;
							break;
						case set_req_sent:
							value = 21;
							break;
						case set_req_received:
							value = 22;
							break;
						case set_resp_sent:
							value = 23;
							break;
						case set_resp_received:
							value = 24;
							break;
						case session_establishment_req_sent:
							value = cp_stats.session_establishment_req_sent;
							break;
						case session_establishment_resp_acc_rcvd:
							value = cp_stats.session_establishment_resp_acc_rcvd;
							break;
						case session_establishment_resp_rej_rcvd:
							value = cp_stats.session_establishment_resp_rej_rcvd;
						        break;
						case session_deletion_req_sent:
							value = cp_stats.session_deletion_req_sent;
							break;
						case session_deletion_resp_acc_rcvd:
							value = cp_stats.session_deletion_resp_acc_rcvd;
							break;
						case session_deletion_resp_rej_rcvd:
							value = cp_stats.session_deletion_resp_rej_rcvd;
							break;
						case association_setup_req_sent:
							value = cp_stats.association_setup_req_sent;
							break;
						case association_setup_resp_acc_rcvd:
							value = cp_stats.association_setup_resp_acc_rcvd;
							break;
						case association_setup_resp_rej_rcvd:
							value = cp_stats.association_setup_resp_rej_rcvd;
							break;
						case session_modification_req_sent:
							value = cp_stats.session_modification_req_sent;
							break;
						case session_modification_resp_acc_rcvd:
							value = cp_stats.session_modification_resp_acc_rcvd;
							break;
						case session_modification_resp_rej_rcvd:
							value = cp_stats.session_modification_resp_rej_rcvd;
							break;
						default:
							break;
						}
						break;
				default:
					break;
				}
			break;
		case s5s8_interface:
			switch(value_id) {
				case set_resp_timeout:
					value = 18;
					break;
				case set_max_timeouts:
					value = 19;
					break;
				case set_timeouts:
					value = 20;
					break;
				case set_req_sent:
					value = 21;
					break;
				case set_req_received:
					value = 22;
					break;
				case set_resp_sent:
					value = 23;
					break;
				case set_resp_received:
					value = 24;
					break;
				case sm_create_session_req_sent:
					value = cp_stats.sm_create_session_req_sent;
					break;
				case sm_create_session_resp_acc_rcvd:
					value = cp_stats.create_session_resp_acc_rcvd;
					break;
				case sm_create_session_resp_rej_rcvd:
					value = cp_stats.create_session_resp_rej_rcvd;
					break;
				case sm_delete_session_req_sent:
					value = cp_stats.sm_delete_session_req_sent;
					break;
				case sm_delete_session_resp_acc_rcvd:
					value = cp_stats.sm_delete_session_resp_acc_rcvd;
					break;
				case sm_delete_session_resp_rej_rcvd:
					value = cp_stats.sm_delete_session_resp_rej_rcvd;
					break;
				/*case sm_create_session_req_rcvd: 
					value = cp_stats.sm_create_session_req_rcvd;
					value = 31;
					break;
				case sm_delete_session_req_rcvd:
					value = cp_stats.sm_delete_session_req_rcvd;
					value = 32;
					break;
				case sm_s5s8_nbr_of_ues:
					value = cp_stats.create_session-cp_stats.delete_session;
					value = 33;
					break;*/	

				default:
					break;
				}
			break;
		default:
			break;
	}
	return value;
}


///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

int64_t
get_stat_pgwc(int category_id, int value_id, int peer_id)
{
	int64_t value = 0;
	clock_t t;
	//size_t len ;
	switch(category_id) {

		case common_stat_pgwc:
			switch(value_id) {
				case active_session_pgwc:
					value = cp_stats.create_session - cp_stats.delete_session;
					break;
				case upsecs_pgwc:
					t = clock() - cp_stats.execution_time;
					double time_taken = ((double)t)/CLOCKS_PER_SEC;
					value = ceil(time_taken);
					value = (int)time_taken;
					//printf("upsec is %lu\n",value);
					break;
					/*case resetsecs:
					  len = 965;
					  get_current_file_size(len);
					  t = cp_stats.reset_time;
					  time_taken = ((double)t)/CLOCKS_PER_SEC;
					  value = ceil(time_taken);
					  value = (int)time_taken;
					//printf("reset time is %lu\n",value);


					break;*/
				default:
					break;
			}
			break;
		case sx_interface_pgwc:
			switch(peer_id) {
				case peer1_pgwc:
					switch(value_id) {
						case set_resp_timeout_pgwc:
							value = 18;
							break;
						case set_max_timeouts_pgwc:
							value = 19;
							break;
						case set_timeouts_pgwc:
							value = 20;
							break;
						case set_req_sent_pgwc:
							value = 21;
							break;
						case set_req_received_pgwc:
							value = 22;
							break;
						case set_resp_sent_pgwc:
							value = 23;
							break;
						case set_resp_received_pgwc:
							value = 24;
							break;
						case session_establishment_req_sent_pgwc:
							value = cp_stats.session_establishment_req_sent;
							break;
						case session_establishment_resp_acc_rcvd_pgwc:
							value = cp_stats.session_establishment_resp_acc_rcvd;
							break;
						case session_establishment_resp_rej_rcvd_pgwc:
							value = cp_stats.session_establishment_resp_rej_rcvd;
						        break;
						/*case session_modification_req_sent_pgwc:
							value = cp_stats.session_modification_req_sent;
							value = 224;
							break;
						case session_modification_resp_acc_rcvd_pgwc:
							value = cp_stats.session_modification_resp_acc_rcvd;
							value = 225;
							break;
						case session_modification_resp_rej_rcvd_pgwc:
							value = cp_stats.session_modification_resp_rej_rcvd;
							value = 226;
							break;*/
						case session_deletion_req_sent_pgwc:
							value = cp_stats.session_deletion_req_sent;
							break;
						case session_deletion_resp_acc_rcvd_pgwc:
							value = cp_stats.session_deletion_resp_acc_rcvd;
							break;
						case session_deletion_resp_rej_rcvd_pgwc:
							value = cp_stats.session_deletion_resp_rej_rcvd;
							break;
						case association_setup_req_sent_pgwc:
							value = cp_stats.association_setup_req_sent;
							break;
						case association_setup_resp_acc_rcvd_pgwc:
							value = cp_stats.association_setup_resp_acc_rcvd;
							break;
						case association_setup_resp_rej_rcvd_pgwc:
							value = cp_stats.association_setup_resp_rej_rcvd;
							break;
						default:
							break;
							}
					break;
				default:
					break;
				}
				break;
		case s5s8_interface_pgwc:
			switch(value_id) {
				case sm_create_session_req_rcvd_pgwc: 
					value = cp_stats.sm_create_session_req_rcvd;
					break;
				case sm_delete_session_req_rcvd_pgwc:
					value = cp_stats.sm_delete_session_req_rcvd;
					break;
				case sm_s5s8_nbr_of_ues_pgwc:
					value = cp_stats.sm_create_session_req_rcvd-cp_stats.sm_delete_session_req_rcvd;
					break;	

				default:
					break;
			}
			break;
		default:
			break;
	}
	return value;
}
/*const char *
  get_time_stat(int category_id, int value_id, int peer_id)
  {

//category_id = interface_id
//peer_id = peer_id
//value_id = message_id

const char *value=NULL;


switch (category_id)
{
case 0:

switch (peer_id)
{
case 0:
switch(value_id)
{
case create_session:
value = cp_stats.create_session_time;
break;
case delete_session:
value = cp_stats.delete_session_time;
break;
default:
break;
}
default :
break;
}
break;
default:
break;

}

return value;

}*/















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
get_stat_live(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo, "get_stat_live() body=[%s]",
			request_body);

	return csGetLive(response_body);
}


/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

	static int
post_s11_mme_ip(const char *request_body,char **response_body)
{

	int ret;
	char s11_mme_ip[1024];
	char temp[512]={0};

	const char *path = "../config/cp_config.cfg";
	const char *param = "S11_MME_IP";
	const char *effect="after restart";


	clLog(clSystemLog, eCLSeverityInfo, "post_s11_mme_ip() body=[%s]",
			request_body);

	ret = parse_config_param(param,request_body,response_body,s11_mme_ip);

	if(ret!=0)
		return 400;

	ret=change_config_file(path, param, s11_mme_ip);

	if(ret!=0)
		return 400;

	construct_json(param,s11_mme_ip,effect,temp);
	*response_body=strdup((const char *)temp);

	return 200;
}


	static int
post_s11_sgw_ip(const char *request_body,char **response_body)
{
	int ret;
	char s11_sgw_ip[1024];
	char temp[512]={0};

	const char *path = "../config/cp_config.cfg";
	const char *param = "S11_SGW_IP";
	const char *effect="after restart";


	clLog(clSystemLog, eCLSeverityInfo, "post_s11_sgw_ip() body=[%s]",
			request_body);

	ret = parse_config_param(param,request_body,response_body,s11_sgw_ip);

	if(ret!=0)
		return 400;

	ret=change_config_file(path, param, s11_sgw_ip);

	if(ret!=0)
		return 400;

	construct_json(param,s11_sgw_ip,effect,temp);
	*response_body=strdup((const char *)temp);

	return 200;

}

	static int
post_s1u_sgw_ip(const char *request_body,char **response_body)
{
	int ret;
	char s1u_sgw_ip[1024];
	char temp[512]={0};

	const char *path = "../config/cp_config.cfg";
	const char *param = "S1U_SGW_IP";
	const char *effect="after restart";


	clLog(clSystemLog, eCLSeverityInfo, "post_s1u_sgw_ip() body=[%s]",
			request_body);

	ret = parse_config_param(param,request_body,response_body,s1u_sgw_ip);

	if(ret!=0)
		return 400;

	ret=change_config_file(path, param, s1u_sgw_ip);

	if(ret!=0)
		return 400;

	construct_json(param,s1u_sgw_ip,effect,temp);
	*response_body=strdup((const char *)temp);

	return 200;
}


	static int
post_s5s8_sgwu_ip(const char *request_body,char **response_body)
{
	int ret;
	char s5s8_sgwu_ip[1024];
	char temp[512]={0};

	const char *path = "../config/cp_config.cfg";
	const char *param = "S5S8_SGWU_IP";
	const char *effect="after restart";


	clLog(clSystemLog, eCLSeverityInfo, "post_s5s8_sgwu_ip() body=[%s]",
			request_body);

	ret = parse_config_param(param,request_body,response_body,s5s8_sgwu_ip);

	if(ret!=0)
		return 400;

	ret=change_config_file(path, param, s5s8_sgwu_ip);

	if(ret!=0)
		return 400;

	construct_json(param,s5s8_sgwu_ip,effect,temp);
	*response_body=strdup((const char *)temp);

	return 200;

}


	static int
post_s5s8_sgwc_ip(const char *request_body,char **response_body)
{
	int ret;
	char s5s8_sgwc_ip[1024];
	char temp[512]={0};

	const char *path = "../config/cp_config.cfg";
	const char *param = "S5S8_SGWC_IP";
	const char *effect="after restart";


	clLog(clSystemLog, eCLSeverityInfo, "post_s5s8_sgwc_ip() body=[%s]",
			request_body);

	ret = parse_config_param(param,request_body,response_body,s5s8_sgwc_ip);

	if(ret!=0)
		return 400;

	ret=change_config_file(path, param, s5s8_sgwc_ip);

	if(ret!=0)
		return 400;

	construct_json(param,s5s8_sgwc_ip,effect,temp);
	*response_body=strdup((const char *)temp);

	return 200;

}

	static int
post_s5s8_pgwc_ip(const char *request_body,char **response_body)
{
	int ret;
	char s5s8_pgwc_ip[1024];
	char temp[512]={0};

	const char *path = "../config/cp_config.cfg";
	const char *param = "S5S8_PGWC_IP";
	const char *effect="after restart";


	clLog(clSystemLog, eCLSeverityInfo, "post_s5s8_pgwc_ip() body=[%s]",
			request_body);

	ret = parse_config_param(param,request_body,response_body,s5s8_pgwc_ip);

	if(ret!=0)
		return 400;

	ret=change_config_file(path, param, s5s8_pgwc_ip);

	if(ret!=0)
		return 400;

	construct_json(param,s5s8_pgwc_ip,effect,temp);
	*response_body=strdup((const char *)temp);

	return 200;

}


	static int
post_s5s8_pgwu_ip(const char *request_body,char **response_body)
{
	int ret;
	char s5s8_pgwu_ip[1024];
	char temp[512]={0};

	const char *path = "../config/cp_config.cfg";
	const char *param = "S5S8_PGWU_IP";
	const char *effect="after restart";


	clLog(clSystemLog, eCLSeverityInfo, "post_s5s8_pgwu_ip() body=[%s]",
			request_body);

	ret = parse_config_param(param,request_body,response_body,s5s8_pgwu_ip);

	if(ret!=0)
		return 400;

	ret=change_config_file(path, param, s5s8_pgwu_ip);

	if(ret!=0)
		return 400;

	construct_json(param,s5s8_pgwu_ip,effect,temp);
	*response_body=strdup((const char *)temp);

	return 200;

}

	static int
post_dp_comm_ip(const char *request_body,char **response_body)
{
	int ret;
	char dp_comm_ip[1024];
	char temp[512]={0};

	const char *path = "../config/interface.cfg";
	const char *param = "dp_comm_ip";
	const char *effect="after restart";


	clLog(clSystemLog, eCLSeverityInfo, "post_dp_comm_ip() body=[%s]",
			request_body);

	ret = parse_config_param(param,request_body,response_body,dp_comm_ip);

	if(ret!=0)
		return 400;

	ret=change_config_file(path, param, dp_comm_ip);

	if(ret!=0)
		return 400;

	construct_json(param,dp_comm_ip,effect,temp);
	*response_body=strdup((const char *)temp);

	return 200;

}


	static int
post_dp_comm_port(const char *request_body,char **response_body)
{
	int ret;
	char dp_comm_port[1024];
	char temp[512]={0};

	const char *path = "../config/interface.cfg";
	const char *param = "dp_comm_port";
	const char *effect="after restart";


	clLog(clSystemLog, eCLSeverityInfo, "post_dp_comm_port() body=[%s]",
			request_body);

	ret = parse_config_param(param,request_body,response_body,dp_comm_port);

	if(ret!=0)
		return 400;

	ret=change_config_file(path, param, dp_comm_port);

	if(ret!=0)
		return 400;

	construct_json(param,dp_comm_port,effect,temp);
	*response_body=strdup((const char *)temp);

	return 200;

}

	static int
post_cp_comm_ip(const char *request_body,char **response_body)
{
	int ret;
	char cp_comm_ip[1024];
	char temp[512]={0};

	const char *path = "../config/interface.cfg";
	const char *param = "cp_comm_ip";
	const char *effect="after restart";


	clLog(clSystemLog, eCLSeverityInfo, "post_cp_comm_ip() body=[%s]",
			request_body);

	ret = parse_config_param(param,request_body,response_body,cp_comm_ip);

	if(ret!=0)
		return 400;

	ret=change_config_file(path, param, cp_comm_ip);

	if(ret!=0)
		return 400;

	construct_json(param,cp_comm_ip,effect,temp);
	*response_body=strdup((const char *)temp);

	return 200;

}

	static int
post_cp_comm_port(const char *request_body,char **response_body)
{
	int ret;
	char cp_comm_port[1024];
	char temp[512]={0};

	const char *path = "../config/interface.cfg";
	const char *param = "cp_comm_port";
	const char *effect="after restart";


	clLog(clSystemLog, eCLSeverityInfo, "post_cp_comm_port() body=[%s]",
			request_body);

	ret = parse_config_param(param,request_body,response_body,cp_comm_port);

	if(ret!=0)
		return 400;

	ret=change_config_file(path, param, cp_comm_port);

	if(ret!=0)
		return 400;

	construct_json(param,cp_comm_port,effect,temp);
	*response_body=strdup((const char *)temp);

	return 200;

}


	static int
post_cp_apn(const char *request_body,char **response_body)
{

	int ret;
	char cp_apn[1024]={0};
	char value[1024]={0};

	const char *path = "../config/cp_config.cfg";
	const char *param = "APN";
	const char *effect="after restart";


	clLog(clSystemLog, eCLSeverityInfo, "post_cp_apn() body=[%s]",
			request_body);

	ret=parse_config_param(param,request_body,response_body,cp_apn);

	if(ret!=0)
		return 400;

	ret=read_config_file(path,param,value);

	if(ret!=0)
		return 400;


	strcat(value,",");
	strcat(value,cp_apn);

	ret=change_config_file(path, param, value);


	if(ret!=0)
		return 400;

	set_apn_name(&apn_list[apnidx++],cp_apn);

	display_apn_list();

	memset(value,0,1024);

	construct_json(param,cp_apn,effect,value);
	*response_body=strdup((const char *)value);

	return 200;
}


	static int
get_cp_apn(const char *request_body, char **response_body)
{

	int ret;
	char value[1024]={0};
	const char *param="APN";
	const char *path="../config/cp_config.cfg";

	ret=read_config_file(path,param,value);

	if(ret!=0)
		return 400;


	char buf2[256] = "{\"APN\": \"";

	clLog(clSystemLog, eCLSeverityInfo, "GET apn() body=[%s]",
			request_body);

	strcat(buf2, value);
	strcat(buf2, "\"}\n");
	*response_body = strdup((const char *)buf2);

	return REST_SUCESSS;

}

	static int
delete_cp_apn(const char *request_body, char **response_body)   //delete from running code.
{

	int ret;
	char cp_apn[1024];
	char temp[512]={0};

	const char *param="APN";
	const char *path="../config/cp_config.cfg";
	const char *effect="now";


	clLog(clSystemLog, eCLSeverityInfo, "delete_cp_apn() body=[%s]",
			request_body);

	ret = parse_config_param(param,request_body,response_body, cp_apn);

	if(ret!=0)
		return 400;

	printf("before deleting list\n");
	display_apn_list();


	ret=delete_apn(cp_apn);   //delete from running code.
	apnidx--;

	if(ret!=0)
		return 400;

	printf("after deleting list\n");
	display_apn_list();

	delete_cfg_cp_apn(path,param,cp_apn);    //delete from cfg file.

	construct_json(param,cp_apn,effect,temp);
	*response_body=strdup((const char *)temp);

	return 200;

}



	static int
get_dp_comm_ip(const char *request_body, char **response_body)
{

	const char *value;
	const char *param="dp_comm_ip";
	const char *path="../config/interface.cfg";

	value=dpdk_cfg_read_config_file(path,param);

	char buf2[256] = "{\"dp_comm__ip\": \"";

	clLog(clSystemLog, eCLSeverityInfo, "GET dp_comm_ip() body=[%s]",
			request_body);

	strcat(buf2, value);
	strcat(buf2, "\"}\n");
	*response_body = strdup((const char *)buf2);

	return REST_SUCESSS;

}

	static int
get_dp_comm_port(const char *request_body, char **response_body)
{

	const char *value;
	const char *param="dp_comm_port";
	const char *path="../config/interface.cfg";

	value=dpdk_cfg_read_config_file(path,param);

	char buf2[256] = "{\"dp_comm_port\": \"";

	clLog(clSystemLog, eCLSeverityInfo, "GET dp_comm_port() body=[%s]",
			request_body);

	strcat(buf2, value);
	strcat(buf2, "\"}\n");
	*response_body = strdup((const char *)buf2);

	return REST_SUCESSS;

}

	static int
get_cp_comm_port(const char *request_body, char **response_body)
{

	const char *value;
	const char *param="cp_comm_port";
	const char *path="../config/interface.cfg";

	value=dpdk_cfg_read_config_file(path,param);

	char buf2[256] = "{\"cp_comm_port\": \"";

	clLog(clSystemLog, eCLSeverityInfo, "GET cp_comm_port() body=[%s]",
			request_body);

	strcat(buf2, value);
	strcat(buf2, "\"}\n");
	*response_body = strdup((const char *)buf2);

	return REST_SUCESSS;

}

	static int
get_cp_comm_ip(const char *request_body, char **response_body)
{

	const char *value;
	const char *param="cp_comm_ip";
	const char *path="../config/interface.cfg";

	value=dpdk_cfg_read_config_file(path,param);

	char buf2[256] = "{\"cp_comm__ip\": \"";

	clLog(clSystemLog, eCLSeverityInfo, "GET cp_comm_ip() body=[%s]",
			request_body);

	strcat(buf2, value);
	strcat(buf2, "\"}\n");
	*response_body = strdup((const char *)buf2);

	return REST_SUCESSS;

}

	static int
get_s11_mme_ip(const char *request_body, char **response_body)
{
	int ret;
	char value[1024]={0};
	const char *param="S11_MME_IP";
	const char *path="../config/cp_config.cfg";

	ret=read_config_file(path,param,value);

	if(ret!=0)
		return 400;


	char buf2[256] = "{\"S11_MME_IP\": \"";

	clLog(clSystemLog, eCLSeverityInfo, "GET s11_mme_ip() body=[%s]",
			request_body);

	strcat(buf2, value);
	strcat(buf2, "\"}\n");
	*response_body = strdup((const char *)buf2);

	return REST_SUCESSS;

}

	static int
get_s11_sgw_ip(const char *request_body, char **response_body)
{
	int ret;
	char value[1024]={0};
	const char *param="S11_SGW_IP";
	const char *path="../config/cp_config.cfg";

	ret=read_config_file(path,param,value);

	if(ret!=0)
		return 400;


	char buf2[256] = "{\"S11_SGW_IP\": \"";

	clLog(clSystemLog, eCLSeverityInfo, "GET s11_sgw_ip() body=[%s]",
			request_body);

	strcat(buf2, value);
	strcat(buf2, "\"}\n");
	*response_body = strdup((const char *)buf2);

	return REST_SUCESSS;
}

	static int
get_s1u_sgw_ip(const char *request_body, char **response_body)
{
	int ret;
	char value[1024]={0};
	const char *param="S1U_SGW_IP";
	const char *path="../config/cp_config.cfg";

	ret=read_config_file(path,param,value);

	if(ret!=0)
		return 400;


	char buf2[256] = "{\"S1U_SGW_IP\": \"";

	clLog(clSystemLog, eCLSeverityInfo, "GET s1u_sgw_ip() body=[%s]",
			request_body);

	strcat(buf2, value);
	strcat(buf2, "\"}\n");
	*response_body = strdup((const char *)buf2);

	return REST_SUCESSS;


}

	static int
get_s5s8_sgwu_ip(const char *request_body, char **response_body)
{
	int ret;
	char value[1024]={0};
	const char *param="S5S8_SGWU_IP";
	const char *path="../config/cp_config.cfg";

	ret=read_config_file(path,param,value);

	if(ret!=0)
		return 400;


	char buf2[256] = "{\"S5S8_SGWU_IP\": \"";

	clLog(clSystemLog, eCLSeverityInfo, "GET s5s8_sgwu_ip() body=[%s]",
			request_body);

	strcat(buf2, value);
	strcat(buf2, "\"}\n");
	*response_body = strdup((const char *)buf2);

	return REST_SUCESSS;

}

	static int
get_s5s8_sgwc_ip(const char *request_body, char **response_body)
{
	int ret;
	char value[1024]={0};
	const char *param="S5S8_SGWC_IP";
	const char *path="../config/cp_config.cfg";

	ret=read_config_file(path,param,value);

	if(ret!=0)
		return 400;


	char buf2[256] = "{\"S5S8_SGWC_IP\": \"";

	clLog(clSystemLog, eCLSeverityInfo, "GET s5s8_sgwc_ip() body=[%s]",
			request_body);

	strcat(buf2, value);
	strcat(buf2, "\"}\n");
	*response_body = strdup((const char *)buf2);

	return REST_SUCESSS;

}

	static int
get_s5s8_pgwc_ip(const char *request_body, char **response_body)
{
	int ret;
	char value[1024]={0};
	const char *param="S5S8_PGWC_IP";
	const char *path="../config/cp_config.cfg";

	ret=read_config_file(path,param,value);

	if(ret!=0)
		return 400;


	char buf2[256] = "{\"S5S8_PGWC_IP\": \"";

	clLog(clSystemLog, eCLSeverityInfo, "GET s5s8_pgwc_ip() body=[%s]",
			request_body);

	strcat(buf2, value);
	strcat(buf2, "\"}\n");
	*response_body = strdup((const char *)buf2);

	return REST_SUCESSS;


}

	static int
get_s5s8_pgwu_ip(const char *request_body, char **response_body)
{
	int ret;
	char value[1024]={0};
	const char *param="S5S8_PGWU_IP";
	const char *path="../config/cp_config.cfg";

	ret=read_config_file(path,param,value);

	if(ret!=0)
		return 400;


	char buf2[256] = "{\"S5S8_PGWU_IP\": \"";

	clLog(clSystemLog, eCLSeverityInfo, "GET s5s8_pgwu_ip() body=[%s]",
			request_body);

	strcat(buf2, value);
	strcat(buf2, "\"}\n");
	*response_body = strdup((const char *)buf2);

	return REST_SUCESSS;

}
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////


void display_apn_list(void)
{
	int i;
	//for(i=0; i<apnidx; i++)
	for(i=0; i<MAX_NB_DPN; i++)
	{
		//if(apn_list[i].apn_name_label==NULL)
		//continue;
		//printf("apn : %s\n",apn_list[i].apn_name_label);
		printf("apn : %s\n",(apn_list+i)->apn_name_label);
	}
}



int delete_apn(char *apn_label)
{
	int index,i;
	apn temp;
	apn *temp1;
	set_apn_name(&temp,apn_label);

	temp1=get_apn(temp.apn_name_label,temp.apn_name_length);

	if(temp1==NULL)    //apn does not exist.
		return -1;

	index=temp1->apn_idx;
	//printf("index :%d\n",index);

	rte_free(temp.apn_name_label);            //free temporary memory.

	for(i=index; i < apnidx-1; i++)           //shift all below apn.
	{
		apn_list[i].apn_name_label=apn_list[i+1].apn_name_label;
		apn_list[i].apn_name_length=apn_list[i+1].apn_name_length;
		apn_list[i].apn_idx=apn_list[i+1].apn_idx;
	}

	while(i<MAX_NB_DPN)                             //as this apn value is copied above
	{                                               //make this apn NULL.
		apn_list[i].apn_name_label=NULL;
		apn_list[i].apn_name_length=0;
		apn_list[i].apn_idx=0;
		i++;
	}

	return 0;

}


int delete_cfg_cp_apn(const char *path, const char *param, const char *value)
{

	char buffer[256];
	char *ptr;
	const char *new = "temp.cfg";

	FILE *file=fopen(path,"r+");

	if(file==NULL){
		printf("error while opening %s file\n",path);
		return 1;
	}

	FILE *file_1=fopen("temp.cfg","w");
	if(file==NULL){
		printf("error while creating\n");
		return 1;
	}

	while(fgets(buffer,sizeof(buffer),file)!=NULL)
	{
		if((ptr=strstr(buffer,param))!=NULL && buffer[0]!='#')
		{
			int ret;
			char *s_ptr=NULL;
			char buffer2[100]={0};
			char *ptr1=buffer+4;
			char r_buff[100]="APN=";

			strncpy(buffer2,ptr1,(strlen(ptr1)-1));
			char *parse_ptr=strtok(buffer2,",");

			while(parse_ptr!=NULL)
			{
				ret=strcmp(parse_ptr,value);    //skip this apn.
				if(ret==0)
				{
					parse_ptr = strtok(NULL,",");
					continue;
				}
				strcat(r_buff,parse_ptr);
				strcat(r_buff,",");
				parse_ptr = strtok(NULL,",");

			}
			s_ptr=r_buff+(strlen(r_buff)-1);
			*s_ptr='\0';
			strcat(r_buff,"\n");
			if(buffer[0]!=';')                    //skip comment character.
			{
				fputs(r_buff,file_1);
				continue;
			}
		}
		fputs(buffer,file_1);
	}
	fclose(file);
	fclose(file_1);

	if((remove(path))!=0)
		printf("delete ERROR\n");

	rename(new,path);

	return 0;
}


const char *dpdk_cfg_read_config_file(const char *path,const char *param)
{
	const char *value;

	struct rte_cfgfile *file = rte_cfgfile_load(path,0);

	if (file == NULL)
		rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n",path);

	value=rte_cfgfile_get_entry(file,"0",param);
	if(value==NULL)
	{
		printf("NOT FOUND");
		return NULL;
	}

	rte_cfgfile_close(file);
	return value;

}

int read_config_file(const char *path,const char *param, char *buff)
{

	struct rte_cfgfile_parameters comment;
	comment.comment_character='#';
	const char *value;

	struct rte_cfgfile *file = rte_cfgfile_load_with_params(path,1,&comment);

	if (file == NULL)
		rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n",path);

	value=rte_cfgfile_get_entry(file,"GLOBAL",param);
	if(value==NULL)
	{
		printf("NOT FOUND");
		return -1;
	}

	rte_cfgfile_close(file);
	strcpy(buff,value);
	return 0;

}

int change_config_file(const char *path, const char *param, const char *value)
{

	char buffer[256], temp[256];
	char *ptr;
	const char *new = "temp.cfg";

	strcpy(temp, param);
	strcat(temp, "=");
	strcat(temp, value);
	strcat(temp, "\n");

	FILE *file=fopen(path,"r+");

	if(file==NULL){
		printf("error while opening %s file\n",path);
		return 1;
	}

	FILE *file_1=fopen("temp.cfg","w");
	if(file==NULL){
		printf("error while creating\n");
		return 1;
	}

	while(fgets(buffer,sizeof(buffer),file)!=NULL)
	{
		if((ptr=strstr(buffer,param))!=NULL && buffer[0]!='#' && buffer[0]!=';')
		{
			//if(buffer[0]!=';')                    //skip comment character.
			//{
			fputs(temp,file_1);
			continue;
			//}
		}
		fputs(buffer,file_1);
	}
	fclose(file);
	fclose(file_1);

	if((remove(path))!=0)
		printf("delete ERROR\n");

	rename(new,path);

	return 0;
}


/*void get_current_file_size(size_t len)
  {

  struct stat st;
  stat("logs/cp_stat.log",&st);
  size_t size = st.st_size;
  size_t max_size = (1*5000);
//printf("current json size is %lu \n",len);
//printf("current file size is : %lu \n",size);
static int flag=0;
static clock_t reset_time;
//reset_time = clock()-cp_stats.execution_time;
if (flag==0)
reset_time = cp_stats.execution_time ;

if( len > max_size-size )         //reset log will be take place
{
//reset_time+ = cp_stats.reset_time;
reset_time = clock();
flag=1;
}


//current_time = clock();
//reset_time = current_time-cp_stats.execution_time;
cp_stats.reset_time = clock()-reset_time;

//cp_stats.reset_time = ((clock()-reset_time)/CLOCKS_PER_SEC);
//printf("reset time is %lu",cp_stats.reset_time);

}*/

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
	crRegisterStaticHandler(eCRCommandGet, "/statlive", get_stat_live);

	/*Commands related with configuration */

	crRegisterStaticHandler(eCRCommandGet, "/dp_comm_ip", get_dp_comm_ip);
	crRegisterStaticHandler(eCRCommandPost, "/dp_comm_ip", post_dp_comm_ip);
	crRegisterStaticHandler(eCRCommandGet, "/dp_comm_port", get_dp_comm_port);
	crRegisterStaticHandler(eCRCommandPost, "/dp_comm_port", post_dp_comm_port);

	crRegisterStaticHandler(eCRCommandGet, "/cp_comm_ip", get_cp_comm_ip);
	crRegisterStaticHandler(eCRCommandPost, "/cp_comm_ip", post_cp_comm_ip);
	crRegisterStaticHandler(eCRCommandGet, "/cp_comm_port", get_cp_comm_port);
	crRegisterStaticHandler(eCRCommandPost, "/cp_comm_port", post_cp_comm_port);
	crRegisterStaticHandler(eCRCommandGet, "/cp_apn", get_cp_apn);
	crRegisterStaticHandler(eCRCommandPost, "/cp_apn", post_cp_apn);
	crRegisterStaticHandler(eCRCommandDelete, "/cp_apn", delete_cp_apn);

	crRegisterStaticHandler(eCRCommandGet, "/s11_mme_ip", get_s11_mme_ip);
	crRegisterStaticHandler(eCRCommandGet, "/s11_sgw_ip", get_s11_sgw_ip);
	crRegisterStaticHandler(eCRCommandGet, "/s1u_sgw_ip", get_s1u_sgw_ip);
	crRegisterStaticHandler(eCRCommandGet, "/s5s8_sgwu_ip", get_s5s8_sgwu_ip);
	crRegisterStaticHandler(eCRCommandGet, "/s5s8_sgwc_ip", get_s5s8_sgwc_ip);
	crRegisterStaticHandler(eCRCommandGet, "/s5s8_pgwc_ip", get_s5s8_pgwc_ip);
	crRegisterStaticHandler(eCRCommandGet, "/s5s8_pgwu_ip", get_s5s8_pgwu_ip);

	crRegisterStaticHandler(eCRCommandPost, "/s11_mme_ip", post_s11_mme_ip);
	crRegisterStaticHandler(eCRCommandPost, "/s11_sgw_ip", post_s11_sgw_ip);
	crRegisterStaticHandler(eCRCommandPost, "/s1u_sgw_ip", post_s1u_sgw_ip);
	crRegisterStaticHandler(eCRCommandPost, "/s5s8_sgwu_ip", post_s5s8_sgwu_ip);
	crRegisterStaticHandler(eCRCommandPost, "/s5s8_sgwc_ip", post_s5s8_sgwc_ip);
	crRegisterStaticHandler(eCRCommandPost, "/s5s8_pgwc_ip", post_s5s8_pgwc_ip);
	crRegisterStaticHandler(eCRCommandPost, "/s5s8_pgwu_ip", post_s5s8_pgwu_ip);

	crStart();

}
