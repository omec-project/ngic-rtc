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
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdbool.h>


#ifdef CP_BUILD

#include "../../cp/cp_stats.h"
#include "../../cp/cp.h"

#include "../../interface/interface.h"
#include "../../cp/gtpv2c.h"
#include "../../cp/ue.h"
#include "../../li_config.h"

#else

#include "up_main.h"
#include "gtpu.h"

#endif /* CP_BUILD */

#include "gw_adapter.h"
#include "crest.h"
#include "clogger.h"
#include "cstats.h"
#include "cdadmfapi.h"

#include "../../pfcp_messages/pfcp_set_ie.h"

//////////////////////////////////////////////////////////////////////////////////


/*CLI :new logic definations*/
cli_node_t cli_node = {0};
SPeer *peer[MAX_PEER] = {NULL};
int cnt_peer = 0;
int nbr_of_peer = 0;
uint64_t oss_reset_time;
uint64_t reset_time = 0;

int number_of_transmit_count;
int number_of_request_tries;
int transmit_timer_value;
int periodic_timer_value;
int request_timeout_value;
cp_configuration_t cp_configuration = {0};
dp_configuration_t dp_configuration = {0};

MessageType ossS5s8MessageDefs[] = {
	{       3       , "Version Not Supported Indication",dNone      },
	{       32      , "Create Session Request",  dIn                },//if SGWC then send, if PGWC then recv
	{       33      , "Create Session Response",dRespRcvd           },//if SGWC then recv, if PGWC then send
	{       36      , "Delete Session Request",  dIn                },//if SGWC then send, if PGWC then recv
	{       37      , "Delete Session Response",dRespRcvd           },//if SGWC then recv, if PGWC then send
	{       34      , "Modify Bearer Request",dIn                   },  //if SGWC then send, if PGWC then recv
	{       35      , "Modify Bearer Response",dRespRcvd            },//if SGWC then recv, if PGWC then send
	{       40      , "Remote UE Report Notification",dNone         },
	{       41      , "Remote UE Report Acknowledge",dNone          },
	{       38      , "Change Notification Request",dNone           },
	{       39      , "Change Notification Response",dNone          },
	{       164     , "Resume Notification",dNone                   },
	{       165     , "Resume Acknowledge",dNone                    },
	{       64      , "Modify Bearer Command",dNone                 },
	{       65      , "Modify Bearer Failure Indication",dNone      },
	{       66      , "Delete Bearer Command",dIn                   },
	{       67      , "Delete Bearer Failure Indication",dNone      },
	{       68      , "Bearer Resource Command",dNone               },
	{       69      , "Bearer Resource Failure Indication",dNone    },
	{       71      , "Trace Session Activation",dNone              },
	{       72      , "Trace Session Deactivation",dNone            },
	{       95      , "Create Bearer Request",dIn                   },//if SGWC then recv, if PGWC then send
	{       96      , "Create Bearer Response",dOut                 },//if SGWC then send, if PGWC then recv
	{       97      , "Update Bearer Request",dIn                   },
	{       98      , "Update Bearer Response",dRespSend            },
	{       99      , "Delete Bearer Request",dIn                   },
	{       100     , "Delete Bearer Response",dRespSend            },
	{       101     , "Delete PDN Connection Set Request",dBoth     },
	{       102     , "Delete PDN Connection Set Response",dBoth    },
	{       103     , "PGW Downlink Triggering Notification",dNone  },
	{       104     , "PGW Downlink Triggering Acknowledge",dNone   },
	{       162     , "Suspend Notification",dNone                  },
	{       163     , "Suspend Acknowledge",dNone                   },
	{       200     , "Update PDN Connection Set Request",dIn     },
	{       201     , "Update PDN Connection Set Response",dRespRcvd    },
	{       -1      , NULL,dNone                                    }
};

MessageType ossS11MessageDefs[] = {
	{       3       ,"Version Not Supported Indication", dNone                },
	{       32      ,"Create Session Request", dIn                            },
	{       33      ,"Create Session Response", dRespSend                     },
	{       36      ,"Delete Session Request", dIn                            },
	{       37      ,"Delete Session Response", dRespSend                     },
	{       34      ,"Modify Bearer Request", dIn                             },
	{       35      ,"Modify Bearer Response", dRespSend                      },
	{       40      ,"Remote UE Report Notification", dNone                   },
	{       41      ,"Remote UE Report Acknowledge", dNone                    },
	{       38      ,"Change Notification Request", dIn                       },
	{       39      ,"Change Notification Response", dRespSend                },
	{       164     ,"Resume Notification", dNone                             },
	{       165     ,"Resume Acknowledge", dNone                              },
	{       64      ,"Modify Bearer Command", dIn                             },
	{       65      ,"Modify Bearer Failure Indication", dRespSend            },
	{       66      ,"Delete Bearer Command", dIn                             },
	{       67      ,"Delete Bearer Failure Indication", dRespSend            },
	{       68      ,"Bearer Resource Command", dIn                           },
	{       69      ,"Bearer Resource Failure Indication", dRespSend          },
	{       70      ,"Downlink Data Notification Failure Indication", dNone   },
	{       71      ,"Trace Session Activation", dNone                        },
	{       72      ,"Trace Session Deactivation", dNone                      },
	{       73      ,"Stop Paging Indication", dNone                          },
	{       95      ,"Create Bearer Request", dOut                            },
	{       96      ,"Create Bearer Response", dRespRcvd                      },
	{       97      ,"Update Bearer Request", dOut                            },
	{       98      ,"Update Bearer Response", dRespRcvd                      },
	{       99      ,"Delete Bearer Request", dOut                            },
	{       100     ,"Delete Bearer Response", dRespRcvd                      },
	{       101     ,"Delete PDN Connection Set Request", dBoth               },
	{       102     ,"Delete PDN Connection Set Response", dBoth              },
	{       103     ,"PGW Downlink Triggering Notification", dNone            },
	{       104     ,"PGW Downlink Triggering Acknowledge", dNone             },
	{       162     ,"Suspend Notification", dNone                            },
	{       163     ,"Suspend Acknowledge", dNone                             },
	{       160     ,"Create Forwarding Tunnel Request", dNone                },
	{       161     ,"Create Forwarding Tunnel Response", dNone               },
	{       166     ,"Create Indirect Data Forwarding Tunnel Request", dNone  },
	{       167     ,"Create Indirect Data Forwarding Tunnel Response", dNone },
	{       168     ,"Delete Indirect Data Forwarding Tunnel Request", dNone  },
	{       169     ,"Delete Indirect Data Forwarding Tunnel Response", dNone },
	{       170     ,"Release Access Bearers Request", dIn                    },
	{       171     ,"Release Access Bearers Response", dRespSend             },
	{       176     ,"Downlink Data Notification", dOut                       },
	{       177     ,"Downlink Data Notification Acknowledge", dRespRcvd      },
	{       179     ,"PGW Restart Notification", dOut                         },
	{       180     ,"PGW Restart Notification Acknowledge", dRespRcvd        },
	{       211     ,"Modify Access Bearers Request", dIn                     },
	{       212     ,"Modify Access Bearers Response", dRespSend              },
	{       -1      , NULL,dNone                                              }
};

#ifdef CP_BUILD


MessageType ossSxMessageDefs[] = {
	{  1 ,"PFCP Heartbeat Request",dNone                   },
	{  2 ,"PFCP Heartbeat Response",dNone                  },
	{  3 ,"PFCP PFD Management Request",dOut               },
	{  4 ,"PFCP PFD Management Response",dRespRcvd         },
	{  5 ,"PFCP Association Setup Request",dOut            },
	{  6 ,"PFCP Association Setup Response",dRespRcvd      },
	{  7 ,"PFCP Association Update Request",dNone          },
	{  8 ,"PFCP Association Update Response",dNone         },
	{  9 ,"PFCP Association Release Request",dNone         },
	{  10 ,"PFCP Association Release Response",dNone       },
	{  11 ,"PFCP Version Not Supported Response",dNone     },
	{  12 ,"PFCP Node Report Request",dNone                },
	{  13 ,"PFCP Node Report Response",dNone               },
	{  14 ,"PFCP Session Set Deletion Request",dBoth       },
	{  15 ,"PFCP Session Set Deletion Response",dBoth      },
	{  50 ,"PFCP Session Establishment Request",dOut       },
	{  51 ,"PFCP Session Establishment Response",dRespRcvd },
	{  52 ,"PFCP Session Modification Request",dOut        },
	{  53 ,"PFCP Session Modification Response",dRespRcvd  },
	{  54 ,"PFCP Session Deletion Request",dOut            },
	{  55 ,"PFCP Session Deletion Response",dRespRcvd      },
	{  56 ,"PFCP Session Report Request",dIn               },
	{  57 ,"PFCP Session Report Response",dRespSend        },
	{         -1     , NULL,dNone                          }
};

#else /* DP_BUILD */

MessageType ossSxMessageDefs[] = {
	{         1      ,"PFCP Heartbeat Request",dNone                  },
	{         2      ,"PFCP Heartbeat Response",dNone                 },
	{         3      ,"PFCP PFD Management Request",dIn               },
	{         4      ,"PFCP PFD Management Response",dRespSend        },
	{         5      ,"PFCP Association Setup Request",dIn            },
	{         6      ,"PFCP Association Setup Response",dRespSend     },
	{         7      ,"PFCP Association Update Request",dNone         },
	{         8      ,"PFCP Association Update Response",dNone        },
	{         9      ,"PFCP Association Release Request",dNone        },
	{         10     ,"PFCP Association Release Response",dNone       },
	{         11     ,"PFCP Version Not Supported Response",dNone     },
	{         12     ,"PFCP Node Report Request",dNone                },
	{         13     ,"PFCP Node Report Response",dNone               },
	{         14     ,"PFCP Session Set Deletion Request",dBoth       },
	{         15     ,"PFCP Session Set Deletion Response",dBoth      },
	{         50     ,"PFCP Session Establishment Request",dIn        },
	{         51     ,"PFCP Session Establishment Response",dRespSend },
	{         52     ,"PFCP Session Modification Request",dIn         },
	{         53     ,"PFCP Session Modification Response",dRespSend  },
	{         54     ,"PFCP Session Deletion Request",dIn             },
	{         55     ,"PFCP Session Deletion Response",dRespSend      },
	{         56     ,"PFCP Session Report Request",dOut              },
	{         57     ,"PFCP Session Report Response",dRespRcvd        },
	{         -1     , NULL,dNone                                     }
};
#endif /* CP_BUILD */

MessageType ossGxMessageDefs[] = {
	{     120    ,"Credit Control Request Initial",dOut   },
	{     121    ,"Credit Control Answer Initial",dIn     },
	{     122    ,"Credit Control Request Update",dOut    },
	{     123    ,"Credit Control Answer Update",dIn      },
	{     124    ,"Credit Control Request Terminate",dOut },
	{     125    ,"Credit Control Answer Terminate",dIn   },
	{     126    ,"Re-Auth-Request",dIn                   },
	{     127    ,"Re-Auth Answer",dOut                   },
	{     -1     , NULL,dNone                             }
};


MessageType ossSystemMessageDefs[] = {
	{  0    ,"Number of active session",dNone  },
	{  1    ,"Number of ues",dNone             },
	{  2    ,"Number of bearers",dNone         },
	{  3    ,"Number of pdn connections",dNone },
	{  -1   , NULL,dNone                       }
};

char ossInterfaceStr[][10] = {
	"s11" ,
#ifdef CP_BUILD
	"s5s8",
#else
	"gtpv1",
#endif
	"sx",
	"gx",
	"gtpv1",
	"sgi",
	"none"
};

char ossInterfaceProtocolStr[][10] = {
	"gtpv2" ,
#ifdef CP_BUILD
	"gtpv2",
#else
	"gtpv1",
#endif
	"pfcp",
	"diameter",
	"gtpv1",
	"none"
};

char ossGatewayStr[][16] = {
	"none",
	"Control Plane",
	"User Plane"
};




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

int sxMessageTypes [] = {
	-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,15,16,17,18,19,20,21,22
};

int gxMessageTypes [] = {
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,0,
	1,2,3,4,5,6,7
};

int supported_commands[][CMD_LIST_SIZE] = {
	{0,0,0,0,0,0,0,0,0,0},
	{1,1,1,1,1,0,0,0,0,0},
	{1,1,1,0,0,0,0,0,0,0}
};

bool is_last_activity_update(uint8_t msg_type, CLIinterface it)
{
	EInterfaceType it_cli;

	it_cli = it;

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




int update_cli_stats(uint32_t ip_addr, uint8_t msg_type, int dir, CLIinterface it)
{
	int ret = 0;
	int index = -1;

	static char stat_timestamp[LAST_TIMER_SIZE];
	add_cli_peer(ip_addr,it);

	get_current_time_oss(stat_timestamp);

	clLog(clSystemLog, eCLSeverityTrace, LOG_FORMAT"Updating CLI Stats: "
		"Msg Type: %d,"
		" Direction: %d,"
		" IP Address: %s\n",
		LOG_VALUE, msg_type, dir,
		inet_ntoa(*((struct in_addr*)&ip_addr)));

	index = get_peer_index(ip_addr);

	if(index == -1) {
		clLog(clSystemLog, eCLSeverityTrace,
			LOG_FORMAT"CLI: Peer not found\n", LOG_VALUE);
		return -1;
	}
#ifdef CP_BUILD
	if(msg_type == PFCP_HEARTBEAT_REQUEST || msg_type == GTP_ECHO_REQ) {
		__sync_add_and_fetch(&cli_node.peer[index]->hcrequest[dir], 1);
		if (dir == RCVD)
			update_last_activity(ip_addr, stat_timestamp);

	} else if(msg_type == PFCP_HEARTBEAT_RESPONSE || msg_type == GTP_ECHO_RSP) {
		__sync_add_and_fetch(&cli_node.peer[index]->hcresponse[dir], 1);
		if (dir == RCVD)
			update_last_activity(ip_addr, stat_timestamp);
#else
	if(msg_type == PFCP_HEARTBEAT_REQUEST || msg_type == GTPU_ECHO_REQUEST ) {
		__sync_add_and_fetch(&cli_node.peer[index]->hcrequest[dir], 1);
		if (dir == RCVD)
			update_last_activity(ip_addr, stat_timestamp);
	} else if(msg_type == PFCP_HEARTBEAT_RESPONSE || msg_type == GTPU_ECHO_RESPONSE ) {
		__sync_add_and_fetch(&cli_node.peer[index]->hcresponse[dir], 1);
		if (dir == RCVD)
			update_last_activity(ip_addr, stat_timestamp);
#endif
	} else {

		if(is_last_activity_update(msg_type,it))
			update_last_activity(ip_addr, stat_timestamp);

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
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"CLI: Not supported interface", LOG_VALUE);
				break;

		}
	}
	return ret;
}

void add_cli_peer(uint32_t ip_addr,CLIinterface it)
{
	int index = -1;
	SPeer temp_peer;

	EInterfaceType it_cli;

	it_cli = it;

	clLog(clSystemLog, eCLSeverityTrace,
			LOG_FORMAT"CLI: Request rcvd for IP Address: %s\n",
			LOG_VALUE, inet_ntoa(*((struct in_addr *)&ip_addr)));

	/*Check peer is allready added or not*/
	index = get_peer_index(ip_addr);

	if (index == -1)  /*peer is not added yet*/
	{
		index = get_first_index(); /*find the postn*/
		cli_node.peer[index] = calloc(1,sizeof(temp_peer));

		//Initialization
		cli_node.peer[index]->ipaddr = (*(struct in_addr *)&ip_addr);
		cli_node.peer[index]->intfctype = it_cli;
		cli_node.peer[index]->status = FALSE;

		/*TODO Need to revisit after DP timer counter get*/
#ifdef DP_BUILD
				cli_node.peer[index]->response_timeout = &transmit_timer_value;
				cli_node.peer[index]->maxtimeout = &number_of_transmit_count;
#else
				cli_node.peer[index]->response_timeout = &transmit_timer_value;
				cli_node.peer[index]->maxtimeout = &number_of_transmit_count;
#endif

				cli_node.peer[index]->timeouts = 0;

				clLog(clSystemLog, eCLSeverityTrace,
					LOG_FORMAT"Interface type is: %d\n", LOG_VALUE, it);
				clLog(clSystemLog, eCLSeverityTrace,
					LOG_FORMAT"Added peer with IP Address: %s\n", LOG_VALUE,
					inet_ntoa(cli_node.peer[index]->ipaddr));

				nbr_of_peer++; /*peer count incremented*/

				if (index == cnt_peer)
					cnt_peer++;
	}
	else {
		clLog(clSystemLog, eCLSeverityTrace,
			LOG_FORMAT"CLI: Peer already exist\n", LOG_VALUE);
	}
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
	clLog(clSystemLog, eCLSeverityTrace,
			LOG_FORMAT"Peer: %s doesn't exist\n", LOG_VALUE,
			inet_ntoa(*((struct in_addr *)&ip_addr)));
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

int update_peer_timeouts(uint32_t ip_addr,uint8_t val)
{

	int ret = -1;
	int index = -1;

	index = get_peer_index(ip_addr);

	if (index == -1)
	{
		clLog(clSystemLog, eCLSeverityTrace,
				LOG_FORMAT"Peer: %s doesn't exist\n", LOG_VALUE,
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
		clLog(clSystemLog, eCLSeverityTrace,
			LOG_FORMAT"Peer: %s doesn't exist\n", LOG_VALUE,
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
		clLog(clSystemLog, eCLSeverityTrace,
			LOG_FORMAT"Peer: %s doesn't exist\n", LOG_VALUE,
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
		clLog(clSystemLog, eCLSeverityTrace,
			LOG_FORMAT"Peer not found\n", LOG_VALUE);
		return -1;
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

void reset_sys_stat(void)
{
	uint8_t itr_sys_stats = 0;

	for (itr_sys_stats = 0;  itr_sys_stats < MAX_SYS_STATS; itr_sys_stats++ ) {
		cli_node.stats[itr_sys_stats] = 0;
	}
}

#ifdef CP_BUILD
void fill_cp_configuration(void)
{
	cp_configuration.cp_type = OSS_CONTROL_PLANE;
	cp_configuration.s11_mme_ip.s_addr = pfcp_config.s11_mme_ip.s_addr;
	cp_configuration.s11_mme_port = pfcp_config.s11_mme_port;
	cp_configuration.s11_port = pfcp_config.s11_port;
	cp_configuration.s5s8_port = pfcp_config.s5s8_port;
	cp_configuration.pfcp_port = pfcp_config.pfcp_port;
	cp_configuration.dadmf_port = pfcp_config.dadmf_port;
	cp_configuration.dadmf_ip.s_addr = pfcp_config.dadmf_ip.s_addr;
	cp_configuration.upf_pfcp_port = pfcp_config.upf_pfcp_port;
	cp_configuration.upf_pfcp_ip.s_addr = pfcp_config.upf_pfcp_ip.s_addr;
	cp_configuration.redis_port = pfcp_config.redis_port;
	cp_configuration.redis_ip.s_addr = pfcp_config.redis_ip.s_addr;
	cp_configuration.request_tries = pfcp_config.request_tries;
	cp_configuration.request_timeout = pfcp_config.request_timeout;
	cp_configuration.cp_logger = pfcp_config.cp_logger;
	cp_configuration.use_dns = pfcp_config.use_dns;
	cp_configuration.trigger_type = pfcp_config.trigger_type;
	cp_configuration.uplink_volume_th = pfcp_config.uplink_volume_th;
	cp_configuration.downlink_volume_th = pfcp_config.downlink_volume_th;
	cp_configuration.time_th = pfcp_config.time_th;
	cp_configuration.ip_pool_ip.s_addr = pfcp_config.ip_pool_ip.s_addr;
	cp_configuration.generate_cdr = pfcp_config.generate_cdr;
	cp_configuration.generate_sgw_cdr = pfcp_config.generate_sgw_cdr;
	cp_configuration.sgw_cc = pfcp_config.sgw_cc;
	cp_configuration.ip_pool_mask.s_addr = pfcp_config.ip_pool_mask.s_addr;
	cp_configuration.num_apn = pfcp_config.num_apn;
	cp_configuration.restoration_params.transmit_cnt = pfcp_config.transmit_cnt;
	cp_configuration.restoration_params.transmit_timer = pfcp_config.transmit_timer;
	cp_configuration.restoration_params.periodic_timer = pfcp_config.periodic_timer;
	cp_configuration.cp_redis_ip.s_addr = pfcp_config.cp_redis_ip.s_addr;
	cp_configuration.ddf2_ip.s_addr = pfcp_config.ddf2_ip.s_addr;
	cp_configuration.add_default_rule = pfcp_config.add_default_rule;
	cp_configuration.ddf2_port = pfcp_config.ddf2_port;
	strncpy(cp_configuration.redis_cert_path, pfcp_config.redis_cert_path, REDIS_CERT_PATH_LEN);
	strncpy(cp_configuration.ddf2_intfc, pfcp_config.ddf2_intfc, DDF_INTFC_LEN);
	cp_configuration.use_gx = pfcp_config.use_gx;
	cp_configuration.generate_sgw_cdr = pfcp_config.generate_sgw_cdr;
	cp_configuration.sgw_cc = pfcp_config.sgw_cc;
	cp_configuration.upf_s5s8_ip = htonl(pfcp_config.upf_s5s8_ip);
	cp_configuration.upf_s5s8_mask = htonl(pfcp_config.upf_s5s8_mask);
	if(pfcp_config.cp_type != SGWC)
	{
		cp_configuration.is_gx_interface = PRESENT;
	}

	if(cp_configuration.ip_byte_order_changed == PRESENT)
	{
		cp_configuration.s11_ip.s_addr = htonl(pfcp_config.s11_ip.s_addr);
		cp_configuration.s5s8_ip.s_addr = htonl(pfcp_config.s5s8_ip.s_addr);
		cp_configuration.pfcp_ip.s_addr = htonl(pfcp_config.pfcp_ip.s_addr);
	}
	else
	{
		cp_configuration.s11_ip.s_addr = pfcp_config.s11_ip.s_addr;
		cp_configuration.s5s8_ip.s_addr = pfcp_config.s5s8_ip.s_addr;
		cp_configuration.pfcp_ip.s_addr = pfcp_config.pfcp_ip.s_addr;
	}

	for(uint8_t itr_apn = 0; itr_apn < cp_configuration.num_apn; itr_apn++)
	{
		cp_configuration.apn_list[itr_apn].apn_usage_type = apn_list[itr_apn].apn_usage_type;
		cp_configuration.apn_list[itr_apn].trigger_type = apn_list[itr_apn].trigger_type;
		cp_configuration.apn_list[itr_apn].uplink_volume_th = apn_list[itr_apn].uplink_volume_th;
		cp_configuration.apn_list[itr_apn].downlink_volume_th = apn_list[itr_apn].downlink_volume_th;
		cp_configuration.apn_list[itr_apn].time_th = apn_list[itr_apn].time_th;
		strncpy(cp_configuration.apn_list[itr_apn].apn_name_label,
				apn_list[itr_apn].apn_name_label+1, APN_NAME_LEN);
		strncpy(cp_configuration.apn_list[itr_apn].apn_net_cap, apn_list[itr_apn].apn_net_cap, MAX_NETCAP_LEN);
	}

	cp_configuration.dns_cache.concurrent = pfcp_config.dns_cache.concurrent;
	cp_configuration.dns_cache.sec = pfcp_config.dns_cache.sec;
	cp_configuration.dns_cache.percent = pfcp_config.dns_cache.percent;
	cp_configuration.dns_cache.timeoutms = pfcp_config.dns_cache.timeoutms;
	cp_configuration.dns_cache.tries = pfcp_config.dns_cache.tries;

	cp_configuration.app_dns.freq_sec = pfcp_config.app_dns.freq_sec;
	cp_configuration.app_dns.nameserver_cnt = pfcp_config.app_dns.nameserver_cnt;
	strncpy(cp_configuration.app_dns.filename, pfcp_config.app_dns.filename, PATH_LEN);
	strncpy(cp_configuration.app_dns.nameserver_ip[pfcp_config.app_dns.nameserver_cnt-DNS_IP_INDEX],
			pfcp_config.app_dns.nameserver_ip[pfcp_config.app_dns.nameserver_cnt-DNS_IP_INDEX], INET_ADDRSTRLEN);

	cp_configuration.ops_dns.freq_sec = pfcp_config.ops_dns.freq_sec;
	cp_configuration.ops_dns.nameserver_cnt = pfcp_config.ops_dns.nameserver_cnt;
	strncpy(cp_configuration.ops_dns.filename, pfcp_config.ops_dns.filename, PATH_LEN);
	strncpy(cp_configuration.ops_dns.nameserver_ip[pfcp_config.ops_dns.nameserver_cnt-DNS_IP_INDEX],
			pfcp_config.ops_dns.nameserver_ip[pfcp_config.ops_dns.nameserver_cnt-DNS_IP_INDEX], INET_ADDRSTRLEN);
}
#else
void fill_dp_configuration(void)
{
	dp_configuration.dp_type = OSS_USER_PLANE;
	dp_configuration.restoration_params.transmit_cnt = app.transmit_cnt;
	dp_configuration.restoration_params.transmit_timer = app.transmit_timer;
	dp_configuration.restoration_params.periodic_timer = app.periodic_timer;

	dp_configuration.ddf2_ip = app.ddf2_ip;
	dp_configuration.ddf3_ip = app.ddf3_ip;
	dp_configuration.ddf2_port = app.ddf2_port;
	dp_configuration.ddf3_port = app.ddf3_port;
	strncpy(dp_configuration.ddf2_intfc, app.ddf2_intfc, DDF_INTFC_LEN);
	strncpy(dp_configuration.ddf3_intfc, app.ddf3_intfc, DDF_INTFC_LEN);

	strncpy(dp_configuration.wb_iface_name, app.wb_iface_name, MAX_LEN);
	strncpy(dp_configuration.eb_iface_name, app.eb_iface_name, MAX_LEN);
	dp_configuration.wb_li_mask = htonl(app.wb_li_mask);
	dp_configuration.wb_li_ip = htonl(app.wb_li_ip);
	strncpy(dp_configuration.wb_li_iface_name, app.wb_li_iface_name, MAX_LEN);
	dp_configuration.gtpu_seqnb_out = app.gtpu_seqnb_out;
	dp_configuration.gtpu_seqnb_in = app.gtpu_seqnb_in;

	dp_configuration.numa_on = app.numa_on;
	dp_configuration.teidri_val = app.teidri_val;
	dp_configuration.teidri_timeout = app.teidri_timeout;
	dp_configuration.dp_logger = app.dp_logger;
	dp_configuration.generate_pcap = app.generate_pcap;
	dp_configuration.cp_comm_ip.s_addr = htonl(cp_comm_ip.s_addr);
	dp_configuration.dp_comm_ip.s_addr = htonl(dp_comm_ip.s_addr);
	dp_configuration.cp_comm_port = cp_comm_port;
	dp_configuration.dp_comm_port = dp_comm_port;

	dp_configuration.wb_ip = htonl(app.wb_ip);
	dp_configuration.wb_mask = htonl(app.wb_mask);
	set_mac_value(dp_configuration.wb_mac, app.wb_ether_addr.addr_bytes);

	dp_configuration.eb_ip = htonl(app.eb_ip);
	dp_configuration.eb_mask = htonl(app.eb_mask);
	set_mac_value(dp_configuration.eb_mac, app.eb_ether_addr.addr_bytes);

}
#endif

int update_periodic_timer_value(int periodic_timer_value) {

	peerData *conn_data = NULL;

#ifdef CP_BUILD
	pfcp_config.periodic_timer = periodic_timer_value;
#else
	app.periodic_timer = periodic_timer_value;
#endif

	const void *key;
	uint32_t iter = 0;

	if(conn_hash_handle != NULL) {
		while (rte_hash_iterate(conn_hash_handle, &key, (void **)&conn_data, &iter) >= 0) {

			conn_data->pt.ti_ms = (periodic_timer_value * 1000);
		}
	}

	return 0;
}

int update_transmit_timer_value(int transmit_timer_value)
{

	peerData *conn_data = NULL;

#ifdef CP_BUILD
	pfcp_config.transmit_timer = transmit_timer_value;
#else
	app.transmit_timer = transmit_timer_value;
#endif

	const void *key;
	uint32_t iter = 0;

	if(conn_hash_handle != NULL) {
		while (rte_hash_iterate(conn_hash_handle, &key, (void **)&conn_data, &iter) >= 0) {

			conn_data->tt.ti_ms = (transmit_timer_value * 1000);
		}
	}

	return 0;
}

int change_config_file(const char *path, const char *param, const char *value)
{

	char buffer[LINE_SIZE], temp[ENTRY_VALUE_SIZE+ENTRY_NAME_SIZE+2];
	char *ptr;
	const char *new = "temp.cfg";

	strncpy(temp, param, ENTRY_NAME_SIZE);
	strncat(temp, "=", 1);
	strncat(temp, value, ENTRY_VALUE_SIZE);
	strncat(temp, "\n", 1);

	FILE *file=fopen(path,"r+");

	if(file==NULL){
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Error while opening %s file\n", LOG_VALUE, path);
		return 1;
	}

	FILE *file_1=fopen("temp.cfg","w");
	if(file==NULL){
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Error while creating file\n", LOG_VALUE);
		return 1;
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
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Delete file ERROR\n", LOG_VALUE);

	rename(new,path);

	return 0;
}

uint8_t get_gw_type(void) {

	uint8_t gw_type = 0;

#ifdef CP_BUILD
	gw_type = OSS_CONTROL_PLANE;
#else
	gw_type = OSS_USER_PLANE;
#endif

return gw_type;

}

bool is_cmd_supported(int cmd_number) {

	if(!supported_commands[get_gw_type()][cmd_number])
		return false;

	return true;
}

///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

static int
get_logger(const char *request_body, char **response_body)
{
	char *loggers = NULL;

	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_logger() body=[%s]", LOG_VALUE, request_body);

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
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"post_logger() body=[%s]", LOG_VALUE, request_body);

	return clUpdateLogger(request_body, response_body);
}


	static int
get_cp_logger(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_cp_logger() body=[%s]", LOG_VALUE, request_body);

	return clRecentLogger(request_body, response_body);
}


	static int
post_max_size(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"post_max_size() body=[%s]", LOG_VALUE, request_body);

	return clRecentSetMaxsize(request_body, response_body);
}

	static int
get_max_size(const char *request_body, char **response_body)
{

	clLog(clSystemLog, eCLSeverityMajor,
		LOG_FORMAT"get_max_size() body=[%s]", LOG_VALUE, request_body);

	return clRecentLogMaxsize(request_body, response_body);

}

//////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////

	static int
get_stat_frequency(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_stat_frequency() body=[%s]", LOG_VALUE, request_body);

	return csGetInterval(response_body);
}


	static int
post_stat_frequency(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"post_stat_frequency() body=[%s]", LOG_VALUE, request_body);

	return csUpdateInterval(request_body, response_body);
}

static int
post_request_tries(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"post_request_tries() body=[%s]", LOG_VALUE, request_body);

	const char *param="REQUEST_TRIES";
	const char *path="../config/cp.cfg";
	char value[ENTRY_VALUE_SIZE]={0};
	char temp[JSON_RESP_SIZE]={0};

	if(!is_cmd_supported(REQUEST_TRIES_INDEX)) {
		return resp_cmd_not_supported(get_gw_type(), response_body);
	}

	number_of_request_tries = get_request_tries_value(request_body, response_body);
	snprintf(value, ENTRY_VALUE_SIZE, "%d", number_of_request_tries);

#ifdef CP_BUILD
	pfcp_config.request_tries = number_of_request_tries;
#endif

	change_config_file(path, param, value);
	construct_json(param,value,temp);
	*response_body=strdup((const char *)temp);

	return REST_SUCESSS;
}

static int
get_request_tries(const char *request_body, char **response_body)
{

	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_request_tries() body=[%s]", LOG_VALUE, request_body);

	if(!is_cmd_supported(REQUEST_TRIES_INDEX)) {
		return resp_cmd_not_supported(get_gw_type(), response_body);
	}

	return get_number_of_request_tries(response_body, number_of_request_tries);
}

#ifdef DP_BUILD
static int
get_generate_pcap_status(const char *request_body, char **response_body)
{

	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_generate_pcap_status() body=[%s]", LOG_VALUE, request_body);

	return get_pcap_generation_status(response_body, app.generate_pcap);
}
#endif

static int
get_transmit_count(const char *request_body, char **response_body)
{

	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_transmit_count() body=[%s]", LOG_VALUE, request_body);

	return get_number_of_transmit_count(response_body, number_of_transmit_count);
}

static int
post_transmit_count(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"post_transmit_count() body=[%s]", LOG_VALUE, request_body);

	const char *param="TRANSMIT_COUNT";
#ifdef CP_BUILD
	const char *path="../config/cp.cfg";
#else
	const char *path="../config/dp.cfg";
#endif

	char value[ENTRY_VALUE_SIZE]={0};
	char temp[JSON_RESP_SIZE]={0};

	number_of_transmit_count = get_transmit_count_value(request_body, response_body);
	snprintf(value, ENTRY_VALUE_SIZE, "%d", number_of_transmit_count);

#ifdef CP_BUILD
	pfcp_config.transmit_cnt = number_of_transmit_count;
#else
	app.transmit_cnt = number_of_transmit_count;
#endif

	change_config_file(path, param, value);
	construct_json(param,value,temp);
	*response_body=strdup((const char *)temp);

	return REST_SUCESSS;
}

static int
get_transmit_timer(const char *request_body, char **response_body)
{

	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_transmit_timer() body=[%s]", LOG_VALUE, request_body);

	return get_transmit_timer_value(response_body, transmit_timer_value);
}

static int
post_transmit_timer(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"post_transmit_timer() body=[%s]", LOG_VALUE, request_body);

	const char *param="TRANSMIT_TIMER";
#ifdef CP_BUILD
	const char *path="../config/cp.cfg";
#else
	const char *path="../config/dp.cfg";
#endif

	char value[ENTRY_VALUE_SIZE]={0};
	char temp[JSON_RESP_SIZE]={0};

	transmit_timer_value = get_transmit_timer_value_in_seconds(request_body, response_body);
	update_transmit_timer_value(transmit_timer_value);
	snprintf(value, ENTRY_VALUE_SIZE, "%d", transmit_timer_value);

	change_config_file(path, param, value);
	construct_json(param,value,temp);
	*response_body=strdup((const char *)temp);

	return REST_SUCESSS;

}

static int
get_request_timeout(const char *request_body, char **response_body)
{

	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_request_timeout() body=[%s]", LOG_VALUE, request_body);

	if(!is_cmd_supported(REQUEST_TIMEOUT_INDEX)) {
		return resp_cmd_not_supported(get_gw_type(), response_body);
	}

	return get_request_timeout_value(response_body, request_timeout_value);
}

static int
post_request_timeout(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"post_request_timeout() body=[%s]", LOG_VALUE, request_body);

	if(!is_cmd_supported(REQUEST_TIMEOUT_INDEX)) {
		return resp_cmd_not_supported(get_gw_type(), response_body);
	}

	request_timeout_value = get_request_timeout_value_in_milliseconds(request_body, response_body);
#ifdef CP_BUILD
	const char *param="REQUEST_TIMEOUT";
	const char *path="../config/cp.cfg";
	char value[ENTRY_VALUE_SIZE]={0};
	char temp[JSON_RESP_SIZE]={0};
	pfcp_config.request_timeout = request_timeout_value;
	snprintf(value, ENTRY_VALUE_SIZE, "%d", request_timeout_value);

	change_config_file(path, param, value);
	construct_json(param,value,temp);
	*response_body=strdup((const char *)temp);

#endif /* CP_BUILD */
	return REST_SUCESSS;
}

static int
get_periodic_timer(const char *request_body, char **response_body)
{

	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_periodic_timer() body=[%s]", LOG_VALUE, request_body);

	return get_periodic_timer_value(response_body, periodic_timer_value);
}

static int
post_periodic_timer(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"post_periodic_timer() body=[%s]", LOG_VALUE, request_body);

	const char *param="PERIODIC_TIMER";
#ifdef CP_BUILD
	const char *path="../config/cp.cfg";
#else
	const char *path="../config/dp.cfg";
#endif

	char value[ENTRY_VALUE_SIZE]={0};
	char temp[JSON_RESP_SIZE]={0};

	periodic_timer_value = get_periodic_timer_value_in_seconds(request_body, response_body);
	update_periodic_timer_value(periodic_timer_value);
	snprintf(value, ENTRY_VALUE_SIZE, "%d", periodic_timer_value);

	change_config_file(path, param, value);
	construct_json(param,value,temp);
	*response_body=strdup((const char *)temp);

	return REST_SUCESSS;

}

	static int
get_stat_logging(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_stat_logging() body=[%s]", LOG_VALUE, request_body);

	return csGetStatLogging(response_body);
}

static int
post_stat_logging(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"post_stat_logging() body=[%s]", LOG_VALUE, request_body);

	return csUpdateStatLogging(request_body, response_body);
}

#ifdef DP_BUILD
static int
post_generate_pcap_cmd(const char *request_body, char **response_body)
{

	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"post_generate_pcap_cmd() body=[%s]", LOG_VALUE, request_body);

	uint8_t res = 0;
	const char *param= "PCAP_GENERATION";
	char value[ENTRY_VALUE_SIZE]= {0};
	char temp[JSON_RESP_SIZE]= {0};

	res = get_pcap_generation_cmd_value(request_body, response_body);
	if (res == REST_FAIL) {
		snprintf(value, ENTRY_VALUE_SIZE, "%s", "REST_FAIL");
		construct_json(param,value,temp);
		*response_body=strdup((const char *)temp);
		return REST_FAIL;
	}
	/* update pcap generation command */
	app.generate_pcap = res;

	snprintf(value, ENTRY_VALUE_SIZE, "%s", ((res) ? ((res == START_PCAP_GEN) ?
				"START" : ((res == RESTART_PCAP_GEN) ? "RESTART" :
				"INVALID CMD" )) : "STOP"));

	construct_json(param,value,temp);
	*response_body=strdup((const char *)temp);

	return REST_SUCESSS;
}
#endif

	static int
get_stat_live(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_stat_live() body=[%s]", LOG_VALUE, request_body);

	return csGetLive(response_body);
}


static int
get_configuration(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo, "get_configuration() body=[%s]",
			request_body);
#ifdef CP_BUILD
	fill_cp_configuration();
	return get_cp_configuration(response_body, &cp_configuration);
#else
	fill_dp_configuration();
	return get_dp_configuration(response_body, &dp_configuration);
#endif

}

static int
reset_cli_stats(const char *request_body, char **response_body)
{
	int value;
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"reset_stats() body=[%s]", LOG_VALUE, request_body);

	value =  csResetStats(request_body, response_body);
	if(value == REST_SUCESSS)
	{
		reset_stats();
		return value;
	}
	return value;
}

	static int
get_stat_live_all(const char *request_body, char **response_body)
{
	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_stat_live_all() body=[%s]", LOG_VALUE, request_body);

	return csGetLiveAll(response_body);
}

#ifdef CP_BUILD
static int
get_add_ue_entry_details(const char *request_body, char **response_body)
{
	int iRet;
	uint16_t uiCntr = 0;
	struct li_df_config_t li_config[MAX_LI_ENTRIES] = {0};

	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_add_ue_entry_details() body=[%s]", LOG_VALUE, request_body);

	iRet = parseJsonReqFillStruct(request_body, response_body, li_config, &uiCntr);

	fillup_li_df_hash(li_config, uiCntr);

	return iRet;
}

static int
get_update_ue_entry_details(const char *request_body, char **response_body)
{
	int iRet;
	uint16_t uiCntr = 0;
	struct li_df_config_t li_config[MAX_LI_ENTRIES] = {0};

	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_update_ue_entry_details() body=[%s]", LOG_VALUE, request_body);

	iRet = parseJsonReqFillStruct(request_body, response_body, li_config, &uiCntr);

	fillup_li_df_hash(li_config, uiCntr);

	return iRet;
}

static int
get_delete_ue_entry_details(const char *request_body, char **response_body)
{
	int iRet;
	uint16_t uiCntr = 0;
	uint64_t uiIds[MAX_LI_ENTRIES] = {0};

	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"get_delete_ue_entry_details() body=[%s]", LOG_VALUE, request_body);

	iRet = parseJsonReqForId(request_body, response_body, uiIds, &uiCntr);

	del_li_entry(uiIds, uiCntr);

	return iRet;
}
#endif

void
get_current_time_oss(char *last_time_stamp)
{
	struct tm * last_timer;
	time_t rawtime;
	time (&rawtime);
	last_timer = gmtime(&rawtime);
	strftime (last_time_stamp,LAST_TIMER_SIZE,"%FT%T",last_timer);
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

	crRegisterStaticHandler(eCRCommandPost, "/request_tries", post_request_tries);
	crRegisterStaticHandler(eCRCommandPost, "/transmit_count", post_transmit_count);
	crRegisterStaticHandler(eCRCommandGet, "/request_tries", get_request_tries);
	crRegisterStaticHandler(eCRCommandGet, "/transmit_count", get_transmit_count);
	crRegisterStaticHandler(eCRCommandPost, "/request_timeout", post_request_timeout);
	crRegisterStaticHandler(eCRCommandPost, "/periodic_timer", post_periodic_timer);
	crRegisterStaticHandler(eCRCommandPost, "/transmit_timer", post_transmit_timer);
	crRegisterStaticHandler(eCRCommandGet, "/request_timeout", get_request_timeout);
	crRegisterStaticHandler(eCRCommandGet, "/periodic_timer", get_periodic_timer);
	crRegisterStaticHandler(eCRCommandGet, "/transmit_timer", get_transmit_timer);
	crRegisterStaticHandler(eCRCommandGet, "/configlive", get_configuration);

#ifdef DP_BUILD
	crRegisterStaticHandler(eCRCommandGet, "/generate_pcap", get_generate_pcap_status);
	crRegisterStaticHandler(eCRCommandPost, "/generate_pcap", post_generate_pcap_cmd);
#endif

	crRegisterStaticHandler(eCRCommandGet, "/statlive", get_stat_live);
	crRegisterStaticHandler(eCRCommandGet, "/statliveall", get_stat_live_all);


	crRegisterStaticHandler(eCRCommandPost, "/reset_stats", reset_cli_stats);
#ifdef CP_BUILD
	crRegisterStaticHandler(eCRCommandPost, "/addueentry", get_add_ue_entry_details);
	crRegisterStaticHandler(eCRCommandPost, "/updateueentry", get_update_ue_entry_details);
	crRegisterStaticHandler(eCRCommandPost, "/deleteueentry", get_delete_ue_entry_details);
#endif

	crStart();

}

void init_cli_module(uint8_t gw_logger)
{

#ifdef DP_BUILD

	cli_node.gw_type = OSS_USER_PLANE;

	clSetOption(eCLOptLogFileName, "logs/dp.log");
	clSetOption(eCLOptStatFileName, "logs/dp_stat.log");
	clSetOption(eCLOptAuditFileName, "logs/dp_sys.log");

	clInit("User Plane", gw_logger);

	clAddRecentLogger("User Plane","dp",5);
#else

	clSetOption(eCLOptLogFileName, "logs/cp.log");
	clSetOption(eCLOptStatFileName, "logs/cp_stat.log");
	clSetOption(eCLOptAuditFileName, "logs/cp_sys.log");


	cli_node.gw_type = OSS_CONTROL_PLANE;

	clInit("Control Plane", gw_logger);

	clAddRecentLogger("Control Plane","cp",5);
#endif
	csInit(clGetStatsLogger(), 5000);
	csStart();
	cli_node.upsecs = &oss_reset_time;
	cli_init(&cli_node,&cnt_peer);
	init_rest_methods(12997, 1);
}

int reset_stats(void) {

	reset_time = *(cli_node.upsecs);

	int peer_itr = 0, msgs_itr = 0;

	for(peer_itr=0; peer_itr<nbr_of_peer; peer_itr++) {

		if (cli_node.peer[peer_itr] != NULL)
		{
			switch(cli_node.peer[peer_itr]->intfctype)
			{
				case itS11:

					for (msgs_itr=0; msgs_itr<S11_STATS_SIZE; msgs_itr++) {
						cli_node.peer[peer_itr]->stats.s11[msgs_itr].cnt[0] = 0;
						cli_node.peer[peer_itr]->stats.s11[msgs_itr].cnt[1] = 0;
						memset(cli_node.peer[peer_itr]->stats.s11[msgs_itr].ts, '\0', LAST_TIMER_SIZE);
					}
					break;
				case itS5S8:
					for (msgs_itr=0; msgs_itr<S5S8_STATS_SIZE; msgs_itr++) {
						cli_node.peer[peer_itr]->stats.s5s8[msgs_itr].cnt[0] = 0;
						cli_node.peer[peer_itr]->stats.s5s8[msgs_itr].cnt[1] = 0;
						memset(cli_node.peer[peer_itr]->stats.s5s8[msgs_itr].ts, '\0', LAST_TIMER_SIZE);
					}
					break;
				case itSx:

					for (msgs_itr=0; msgs_itr<SX_STATS_SIZE; msgs_itr++)
					{
						cli_node.peer[peer_itr]->stats.sx[msgs_itr].cnt[0] = 0;
						cli_node.peer[peer_itr]->stats.sx[msgs_itr].cnt[1] = 0;
						memset(cli_node.peer[peer_itr]->stats.sx[msgs_itr].ts, '\0', LAST_TIMER_SIZE);
					}
					break;
				case itGx:

					for (msgs_itr=0; msgs_itr<GX_STATS_SIZE; msgs_itr++)
					{
						cli_node.peer[peer_itr]->stats.gx[msgs_itr].cnt[0] = 0;
						cli_node.peer[peer_itr]->stats.gx[msgs_itr].cnt[1] = 0;
						memset(cli_node.peer[peer_itr]->stats.gx[msgs_itr].ts, '\0', LAST_TIMER_SIZE);
					}
					break;
				default:
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"CLI: Not supported interface", LOG_VALUE);
					break;
			}

		cli_node.peer[peer_itr]->hcrequest[0] = 0;
		cli_node.peer[peer_itr]->hcrequest[1] = 0;
		cli_node.peer[peer_itr]->hcresponse[0] = 0;
		cli_node.peer[peer_itr]->hcresponse[1] = 0;
		memset(cli_node.peer[peer_itr]->lastactivity, '\0', LAST_TIMER_SIZE);

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
