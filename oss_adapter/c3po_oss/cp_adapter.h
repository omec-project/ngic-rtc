#ifndef CP_ADAPTER_H
#define CP_ADAPTER_H

#define REST_SUCESSS  200
#define REST_FAIL     400

/**
 * @brief initiates the rest service
 * @param port_no  - Rest service port number
 * @param thread_count - number of threads
 * @return void
 */
void init_rest_methods(int port_no, size_t thread_count);

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


/////////////////////////////////////////////////////////////////////////////////////////

#define MAX_PEER 10
#define S11_MSG_TYPE_LEN 49
#define S5S8_MSG_TYPE_LEN 35
#define SXA_MSG_TYPE_LEN 21
#define SXB_MSG_TYPE_LEN 21
#define SXASXB_MSG_TYPE_LEN 23
#define GX_MSG_TYPE_LEN 6
#define SYSTEM_MSG_TYPE_LEN 4

#define GTP_CREATE_SESSION_REQ                               (32)
#define GTP_CREATE_SESSION_RSP                               (33)
#define GTP_MODIFY_BEARER_REQ                                (34)
#define GTP_MODIFY_BEARER_RSP                                (35)
#define GTP_DELETE_SESSION_REQ                               (36)
#define GTP_DELETE_SESSION_RSP                               (37)
#define GTP_CREATE_BEARER_REQ                                (95)
#define GTP_CREATE_BEARER_RSP                                (96)


typedef enum {
	REQ = 0,
	ACC = 0,
	REJ = 1,
	SENT = 0,
	RCVD = 1,
} Dir;



typedef enum {
	itS11,
	itS5S8,
	itSxa,
	itSxb,
	itSxaSxb,
	itGx
} EInterfaceType;

typedef enum {
	dIn,
	dOut,
	dRespSend,
	dRespRcvd,
	dBoth,
	dNone
} EDirection;

typedef enum {
	DECREMENT,
	INCREMENT,
} Operation;

typedef enum {
	number_of_active_session,
	number_of_users,
	number_of_bearers,
	number_of_pdn_connections,
} SystemStats;

typedef struct {
	int msgtype;
	const char *msgname;
	EDirection dir;
} MessageType;

typedef struct {
	int cnt[2];
	//time_t ts;
	char ts[80];
} Statistic;

#define SENT 0
#define RCVD 1
#define FALSE 0
#define TRUE 1

typedef struct {
	struct in_addr ipaddr;
	EInterfaceType intfctype;

	bool status;
	int response_timeout;  //TRANSMIT TIMER
	uint8_t maxtimeout;    //TRANSMIT COUNT in cp.cfg
	uint8_t timeouts;

	char lastactivity[80];

	int hcrequest[2];
	int hcresponse[2];
	union {
		Statistic s11[51];
		Statistic s5s8[37];
		Statistic sxa[21];
		Statistic sxb[21];
		Statistic sxasxb[23];
		Statistic gx[23];
	} stats;
} SPeer;

/*
 * 0 --> active sessions
 * 1 --> Nbr-of-ues
 * 2 --> Nbr-of-pdn-conn
 * & so on.
 */


typedef struct {
	uint8_t cp_type;
	uint64_t *upsecs;
	uint64_t *resetsecs;
	//uint64_t upsecs;
	uint64_t stats[5];
	SPeer *peer[MAX_PEER];

}cli_node_t;

extern cli_node_t cli_node;



//extern SPeer *peer[MAX_PEER];
extern int cnt_peer;  /*last index of array*/
extern int nbr_of_peer; /*total nbr of peer count*/


int update_cli_stats(uint32_t ip_addr, uint8_t mgs_type,int dir,char *time_stamp);
int get_peer_index(uint32_t ip_addr);
void add_cli_peer(uint32_t ip_addr,EInterfaceType it);
int update_peer_status(uint32_t ip_addr,bool val);
int update_peer_timeouts(uint32_t ip_addr,uint8_t val);
int delete_cli_peer(uint32_t ip_addr);
int get_first_index(void);
int update_last_activity(uint32_t ip_addr, char *time_stamp);
int update_sys_stat(int index, int operation);

/*NK:*/
extern MessageType s11MessageDefs[2];
extern int s11MessageTypes[220];

#endif
