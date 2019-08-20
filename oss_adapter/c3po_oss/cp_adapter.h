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
	/*set_resp_timeout = 0,
	set_max_timeouts = 1,*/
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
	//number_of_connected_ues = 3,
	//number_of_suspended_ues = 4,
	release_access_bearer = 4,
	downlink_data_notification_ack = 5,
	sgw_nbr_of_pdn_connections = 6,
	sgw_nbr_of_bearers = 7,
	downlink_data_notification_req_send = 8,
	//sgw_nbr_of_active_bearers = 7,
	//sgw_nbr_of_idle_bearers = 8,
};
/*
 * Define type of Control Plane s5s8 Statatics Cases(CP)
 */

enum cp_stat_sx {

	session_establishment_req_sent = 0,
	session_establishment_resp_acc_rcvd = 1,
	session_establishment_resp_rej_rcvd = 2,
	session_deletion_req_sent = 3,
	session_deletion_resp_acc_rcvd = 4,
	session_deletion_resp_rej_rcvd = 5,
	association_setup_req_sent = 6,
	association_setup_resp_acc_rcvd = 7,
	association_setup_resp_rej_rcvd = 8,
	session_modification_req_sent = 9,
	session_modification_resp_acc_rcvd = 10,
	session_modification_resp_rej_rcvd = 11,
	downlink_data_notification = 12,

};

enum cp_stat_s5s8 {
	sm_create_session_req_sent = 0,
	sm_create_session_resp_acc_rcvd = 1,
	sm_create_session_resp_rej_rcvd = 2,
	sm_delete_session_req_sent = 3,
	sm_delete_session_resp_acc_rcvd = 4,
	sm_delete_session_resp_rej_rcvd = 5,
	/*sm_create_session_req_rcvd = 6,
	sm_delete_session_req_rcvd = 7,
	sm_s5s8_nbr_of_ues = 8,*/
};

/////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

/*
enum cli_response_common_stat_pgwc {
	active_session_pgwc = 0,
	upsecs_pgwc = 1,
	resetsecs_pgwc = 2,
};
*/
enum cp_stat_sx_pgwc {

	session_establishment_req_sent_pgwc = 0,
	session_establishment_resp_acc_rcvd_pgwc = 1,
	session_establishment_resp_rej_rcvd_pgwc = 2,
	session_deletion_req_sent_pgwc = 3,
	session_deletion_resp_acc_rcvd_pgwc = 4,
	session_deletion_resp_rej_rcvd_pgwc = 5,
	association_setup_req_sent_pgwc = 6,
	association_setup_resp_acc_rcvd_pgwc = 7,
	association_setup_resp_rej_rcvd_pgwc = 8,
	/*session_modification_req_sent_pgwc = 9,
	session_modification_resp_acc_rcvd_pgwc = 10,
	session_modification_resp_rej_rcvd_pgwc = 11,*/

};
/*enum cp_stat_s5s8_sgwc {
	sm_create_session_req_sent_sgwc = 0,
	create_session_resp_acc_rcvd_sgwc = 1,
	create_session_resp_rej_rcvd_sgwc = 2,
	sm_delete_session_req_sent_sgwc = 3,
	sm_delete_session_resp_acc_rcvd_sgwc = 4,
	sm_delete_session_resp_rej_rcvd_sgwc = 5,
	sm_create_session_req_rcvd_sgwc = 6,
	sm_delete_session_req_rcvd_sgwc = 7,
	s5s8_nbr_of_ues_sgwc = 8,
};*/

enum cp_stat_s5s8_pgwc {
	sm_create_session_req_rcvd_pgwc = 0,
	sm_delete_session_req_rcvd_pgwc = 1,
	sm_s5s8_nbr_of_ues_pgwc = 2,
};
/*
 * Define type of Control Plane catagories Cases(CP)
 */
enum cli_response_catagory_case_spgwc {
	//common_stat = -1,
	s11_interface = 0,
	sx_interface = 1,
	s5s8_interface = 2,
};

enum cli_response_catagory_case_pgwc {
	//common_stat_pgwc = -1,
	//s11_interface_pgwc = 0,
	sx_interface_pgwc = 0,
	s5s8_interface_pgwc = 1,
};
/*
enum cp_health_stat_pgwc {
	set_resp_timeout_pgwc = -1,
	set_max_timeouts_pgwc = -2,
	set_timeouts_pgwc = -3,
	set_req_sent_pgwc = -4,
	set_req_received_pgwc = -5,
	set_resp_sent_pgwc = -6,
	set_resp_received_pgwc = -7,
};
*/

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
/*extern enum cp_stat_s11 s11_cp_stat;
extern enum cp_stat_s5s8 s5s8_cp_stat;
extern enum cli_response_common_stat cli_common_stat;
extern enum cli_response_catagory_case cli_catagory;
extern enum cp_health_stat health_stat;
extern enum sx_peer_list peer_list_sx;*/
/**
 * @file
 *
 * Control Plane SGW statistic declarations
 */

/**
 * @brief counters used to log SGW UEs statistics
 */

/*
struct sgw_ues_stats {
	uint64_t number_of_ues;
	uint64_t number_of_connected_ues;
	uint64_t number_of_suspended_ues;

};
*/
/**
 * @brief retrive the statstics of element
 * identifier
 * @param category_id - table identifier
 * @param value_id - element identifier in table
 * @param peer_id - peer identifier in table
 * @return
 * @value of the element.
 */
//int64_t get_stat(int category_id, int value_id, int peer_id);
int64_t get_stat_spgwc(int category_id, int value_id, int peer_id);
int64_t get_stat_pgwc(int category_id, int value_id, int peer_id);
int64_t get_stat_common(int value_id);
int64_t get_stat_health(int category_id, int value_id, int peer_id);
int64_t get_stat_health_pgwc(int category_id, int value_id, int peer_id);
//const char * get_time_stat(int category_id, int value_id, int peer_id);
//void get_current_file_size(size_t len);
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
//const char* dpdk_read_config_file(const char *path,const char *param,const char *value);
int read_config_file(const char *path,const char *param,char *buff);

const char *dpdk_cfg_read_config_file(const char *path,const char *param);

#endif
