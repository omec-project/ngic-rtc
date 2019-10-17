#ifndef CP_ADAPTER_H
#define CP_ADAPTER_H

#define REST_SUCESSS  200
#define REST_FAIL     400


/*
 * Define type of Control Plane response common Statatics Cases(CP)
 */
enum cli_response_common_stat {
	active_session = 0,
	upsecs = 1,
	resetsecs = 2,
};

/*
 * Define type of Control Plane health Switch Cases(CP)
 */
enum cp_health_stat {
	set_status = 0,
	set_timeouts = 1,
	set_req_sent = 2,
	set_req_received = 3,
	set_resp_sent = 4,
	set_resp_received = 5,
};

/*
 * Define type of Control Plane s11 Statatics Cases(CP)
 */
enum cp_stat_s11 {
	create_session = 0,
	modify_bearer = 1,
	delete_session = 2,
	number_of_ues = 3,
	release_access_bearer = 4,
	downlink_data_notification_ack = 5,
	sgw_nbr_of_pdn_connections = 6,
	sgw_nbr_of_bearers = 7,
	downlink_data_notification_req_send = 8,

};

/*
 * Define type of Control Plane s5s8 Statatics Cases(CP)
 */

enum cp_stat_sx {

	session_establishment_req_sent = 0,
	session_establishment_resp_acc_rcvd = 1,
	session_deletion_req_sent = 2,
	session_deletion_resp_acc_rcvd = 3,
	association_setup_req_sent = 4,
	association_setup_resp_acc_rcvd = 5,
	session_modification_req_sent = 6,
	session_modification_resp_acc_rcvd = 7,
	downlink_data_notification = 8,

};

enum cp_stat_s5s8 {
	sm_create_session_req_sent = 0,
	sm_create_session_resp_acc_rcvd = 1,
	sm_delete_session_req_sent = 2,
	sm_delete_session_resp_acc_rcvd = 3,
};

/////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

enum cp_stat_sx_pgwc {

	session_establishment_req_sent_pgwc = 0,
	session_establishment_resp_acc_rcvd_pgwc = 1,
	session_deletion_req_sent_pgwc = 2,
	session_deletion_resp_acc_rcvd_pgwc = 3,
	association_setup_req_sent_pgwc = 4,
	association_setup_resp_acc_rcvd_pgwc = 5,


};

enum cp_stat_s5s8_pgwc {
	sm_create_session_req_rcvd_pgwc = 0,
	sm_delete_session_req_rcvd_pgwc = 1,
	sm_s5s8_nbr_of_ues_pgwc = 2,
};
/*
 * Define type of Control Plane catagories Cases(CP)
 */
enum cli_response_catagory_case_spgwc {
	s11_interface = 0,
	sx_interface = 1,
	s5s8_interface = 2,
};

enum cli_response_catagory_case_pgwc {
	sx_interface_pgwc = 0,
	s5s8_interface_pgwc = 1,
};



///////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/*
 * Define type of Control Plane sx interface peer list(CP)
 */
enum sx_peer_list {
	peer1 = 0,
	peer2 = 1,
	peer3 = 2,
};

enum sx_peer_list_pgwc {
	peer1_pgwc = 0,
	peer2_pgwc = 1,
	peer3_pgwc = 2,
};

enum lastactivity_of_peer {
	peer_lastactivity = 0,
};

/**
 * @brief retrive the statstics of element
 * identifier
 * @param category_id - table identifier
 * @param value_id - element identifier in table
 * @param peer_id - peer identifier in table
 * @return
 * @value of the element.
 */

int64_t get_stat_spgwc(int category_id, int value_id, int peer_id);
int64_t get_stat_pgwc(int category_id, int value_id, int peer_id);
int64_t get_stat_common(int value_id);
int64_t get_stat_health(int category_id, int value_id, int peer_id);
int64_t get_stat_health_pgwc(int category_id, int value_id, int peer_id);
const char * get_time_stat(int category_id, int value_id, int peer_id);
const char * get_time_stat_pgwc(int category_id, int value_id, int peer_id);

const char * get_lastactivity_time_sgwc(int category_id, int value_id, int peer_id);
const char * get_lastactivity_time_pgwc(int category_id, int value_id, int peer_id);

/**
 * @brief initiates the rest service
 * @param port_no  - Rest service port number
 * @param thread_count - number of threads
 * @return void
 */
void init_rest_methods(int port_no, size_t thread_count);

int change_config_file(const char *path,const char *param,const char *value);


void display_apn_list(void);
int delete_apn(char *apn_label);
int delete_cfg_cp_apn(const char *path, const char *param, const char *value);
int read_config_file(const char *path,const char *param,char *buff);

const char *dpdk_cfg_read_config_file(const char *path,const char *param);

#endif


typedef long long int _timer_t;

#define TIMER_GET_CURRENT_TP(now)                                             \
({                                                                            \
 struct timespec ts;                                                          \
 now = clock_gettime(CLOCK_REALTIME,&ts) ?                                    \
 	-1 : (((_timer_t)ts.tv_sec) * 1000000000) + ((_timer_t)ts.tv_nsec);   \
 now;                                                                         \
 })

#define TIMER_GET_ELAPSED_NS(start)                                           \
({                                                                            \
 _timer_t ns;                                                                 \
 TIMER_GET_CURRENT_TP(ns);                                                    \
 if (ns != -1){                                                               \
 	ns -= start;                                                          \
 }									      \
 ns;                                                                          \
 })

extern _timer_t st_time;
