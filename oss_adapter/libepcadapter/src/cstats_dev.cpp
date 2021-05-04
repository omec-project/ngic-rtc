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

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "gw_adapter.h"
#include "gw_structs.h"
#include "etime.h"

#define RAPIDJSON_NAMESPACE statsrapidjson
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "cstats.h"
#include "cstats_dev.h"
#include "elogger.h"

using namespace std;

cli_node_t *cli_node_ptr;
int *oss_cnt_peer;

extern  long oss_resetsec;

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
	{1,1,1,0,0,1,0,0,0,0}
};

MessageType ossS5s8MessageDefs[] = {
	{       3       , "Version Not Supported Indication", dNone, dNone            },
	{       32      , "Create Session Request",  dOut, dIn                        },
	{       33      , "Create Session Response", dRespRcvd, dRespSend             },
	{       36      , "Delete Session Request",  dOut, dIn                        },
	{       37      , "Delete Session Response", dRespRcvd, dRespSend             },
	{       34      , "Modify Bearer Request", dOut, dIn                          },
	{       35      , "Modify Bearer Response", dRespRcvd, dRespSend              },
	{       40      , "Remote UE Report Notification", dNone , dNone              },
	{       41      , "Remote UE Report Acknowledge", dNone, dNone                },
	{       38      , "Change Notification Request", dOut, dIn                    },
	{       39      , "Change Notification Response",dRespRcvd, dRespSend         },
	{       164     , "Resume Notification", dNone, dNone                         },
	{       165     , "Resume Acknowledge", dNone, dNone                          },
	{       64      , "Modify Bearer Command", dOut, dIn                          },
	{       65      , "Modify Bearer Failure Indication", dRespRcvd, dRespSend    },
	{       66      , "Delete Bearer Command", dOut, dIn                          },
	{       67      , "Delete Bearer Failure Indication", dRespRcvd, dRespSend    },
	{       68      , "Bearer Resource Command", dOut, dIn                        },
	{       69      , "Bearer Resource Failure Indication", dRespRcvd, dRespSend  },
	{       71      , "Trace Session Activation", dNone, dNone                    },
	{       72      , "Trace Session Deactivation", dNone, dNone                  },
	{       95      , "Create Bearer Request", dIn, dOut                          },
	{       96      , "Create Bearer Response", dRespSend, dRespRcvd              },
	{       97      , "Update Bearer Request", dIn, dOut                          },
	{       98      , "Update Bearer Response", dRespSend, dRespRcvd              },
	{       99      , "Delete Bearer Request", dIn, dOut                          },
	{       100     , "Delete Bearer Response", dRespSend, dRespRcvd              },
	{       101     , "Delete PDN Connection Set Request", dBoth, dBoth           },
	{       102     , "Delete PDN Connection Set Response", dBoth, dBoth          },
	{       103     , "PGW Downlink Triggering Notification", dNone, dNone        },
	{       104     , "PGW Downlink Triggering Acknowledge", dNone, dNone         },
	{       162     , "Suspend Notification", dNone, dNone                        },
	{       163     , "Suspend Acknowledge", dNone, dNone                         },
	{       200     , "Update PDN Connection Set Request", dOut, dIn              },
	{       201     , "Update PDN Connection Set Response", dRespRcvd, dRespSend  },
	{       -1      , NULL, dNone, dNone                                          }
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

MessageType ossSxMessageDefs_cp[] = {
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

MessageType ossSxMessageDefs_dp[] = {
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

char ossInterfaceStr_cp[][MAX_INTERFACE_NAME_LEN] = {
	"s11" ,
	"s5s8",
	"sx",
	"gx",
	"gtpv1",
	"sgi",
	"none"
};

char ossInterfaceStr_dp[][MAX_INTERFACE_NAME_LEN] = {
	"s11" ,
	"gtpv1",
	"sx",
	"gx",
	"gtpv1",
	"sgi",
	"none"
};

char ossInterfaceProtocolStr_cp[][MAX_INTERFACE_NAME_LEN] = {
	"gtpv2" ,
	"gtpv2",
	"pfcp",
	"diameter",
	"gtpv1",
	"none"
};

char ossInterfaceProtocolStr_dp[][MAX_INTERFACE_NAME_LEN] = {
	"gtpv2" ,
	"gtpv1",
	"pfcp",
	"diameter",
	"gtpv1",
	"none"
};


char ossGatewayStr[MAX_GATEWAY_NAME_LEN][MAX_GATEWAY_NAME_LEN] = {
	"none",
	"Control Plane",
	"User Plane"
};

MessageType ossSxMessageDefs[MAX_NUM_GW_MESSAGES];
char ossInterfaceProtocolStr[MAX_INTERFACE_NAME_LEN][MAX_INTERFACE_NAME_LEN];
char ossInterfaceStr[MAX_INTERFACE_NAME_LEN][MAX_INTERFACE_NAME_LEN];

void cli_init(cli_node_t *cli_node,int *cnt_peer)
{
	clLog(STANDARD_LOGID, eCLSeverityDebug,
			".................................. cli init................" );
	cli_node_ptr = cli_node;
	oss_cnt_peer = cnt_peer;
	if (cli_node->gw_type == OSS_CONTROL_PLANE) {
		memcpy(ossSxMessageDefs, ossSxMessageDefs_cp, sizeof(ossSxMessageDefs_cp));
		memcpy(ossInterfaceStr, ossInterfaceStr_cp, sizeof(ossInterfaceStr_cp));
		memcpy(ossInterfaceProtocolStr, ossInterfaceProtocolStr_cp, sizeof(ossInterfaceProtocolStr_cp));
	} else {
		memcpy(ossSxMessageDefs, ossSxMessageDefs_dp, sizeof(ossSxMessageDefs_cp));
		memcpy(ossInterfaceStr, ossInterfaceStr_dp, sizeof(ossInterfaceStr_dp));
		memcpy(ossInterfaceProtocolStr, ossInterfaceProtocolStr_dp, sizeof(ossInterfaceProtocolStr_dp));
	}
}


void CStatMessages::serializeS11(const SPeer* peer,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator)
{
    for(int i = 0; i < S11_MSG_TYPE_LEN; i++) {
        if((peer->stats.s11[i].cnt[SENT] == 0 && peer->stats.s11[i].cnt[RCVD] == 0) && suppress) {
            continue;
        }

        statsrapidjson::Value value(statsrapidjson::kObjectType);
        value.AddMember(
            statsrapidjson::StringRef("type"), statsrapidjson::StringRef(ossS11MessageDefs[i].msgname), allocator);

        switch(ossS11MessageDefs[i].dir) {
        case dIn:
            value.AddMember(statsrapidjson::StringRef("rcvd"), peer->stats.s11[i].cnt[RCVD], allocator);
            break;

        case dOut:
            value.AddMember(statsrapidjson::StringRef("sent"), peer->stats.s11[i].cnt[SENT], allocator);
            break;

        case dRespSend:
            value.AddMember(statsrapidjson::StringRef("sent_acc"), peer->stats.s11[i].cnt[ACC], allocator);
            value.AddMember(statsrapidjson::StringRef("sent_rej"), peer->stats.s11[i].cnt[REJ], allocator);
            break;

        case dRespRcvd:
            value.AddMember(statsrapidjson::StringRef("rcvd_acc"), peer->stats.s11[i].cnt[ACC], allocator);
            value.AddMember(statsrapidjson::StringRef("rcvd_rej"), peer->stats.s11[i].cnt[REJ], allocator);
            break;

        case dBoth:
            value.AddMember(statsrapidjson::StringRef("sent"), peer->stats.s11[i].cnt[SENT], allocator);
            value.AddMember(statsrapidjson::StringRef("rcvd"), peer->stats.s11[i].cnt[RCVD], allocator);
            break;

        case dNone:
            value.AddMember(statsrapidjson::StringRef("count"), peer->stats.s11[i].cnt[BOTH], allocator);
            break;
        }

	if((peer->stats.s11[i].ts != NULL) && (strlen(peer->stats.s11[i].ts) != 0))
		value.AddMember(statsrapidjson::StringRef("last"), statsrapidjson::StringRef(peer->stats.s11[i].ts), allocator);
        arrayObjects.PushBack(value, allocator);
    }
}

void CStatMessages::serializeS5S8(const SPeer* peer,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator)
{
    for(int i = 0; i < S5S8_MSG_TYPE_LEN; i++) {
        if((peer->stats.s5s8[i].cnt[SENT] == 0 && peer->stats.s5s8[i].cnt[RCVD] == 0) && suppress) {
            continue;
        }
        statsrapidjson::Value value(statsrapidjson::kObjectType);
        value.AddMember(
            statsrapidjson::StringRef("type"), statsrapidjson::StringRef(ossS5s8MessageDefs[i].msgname), allocator);

        switch(ossS5s8MessageDefs[i].dir) {
        case dIn:
            value.AddMember(statsrapidjson::StringRef("rcvd"), peer->stats.s5s8[i].cnt[RCVD], allocator);
            break;

        case dOut:
            value.AddMember(statsrapidjson::StringRef("sent"), peer->stats.s5s8[i].cnt[SENT], allocator);
            break;

        case dRespSend:
            value.AddMember(statsrapidjson::StringRef("sent_acc"), peer->stats.s5s8[i].cnt[ACC], allocator);
            value.AddMember(statsrapidjson::StringRef("sent_rej"), peer->stats.s5s8[i].cnt[REJ], allocator);
            break;

        case dRespRcvd:
            value.AddMember(statsrapidjson::StringRef("rcvd_acc"), peer->stats.s5s8[i].cnt[ACC], allocator);
            value.AddMember(statsrapidjson::StringRef("rcvd_rej"), peer->stats.s5s8[i].cnt[REJ], allocator);
            break;

        case dBoth:
            value.AddMember(statsrapidjson::StringRef("sent"), peer->stats.s5s8[i].cnt[SENT], allocator);
            value.AddMember(statsrapidjson::StringRef("rcvd"), peer->stats.s5s8[i].cnt[RCVD], allocator);
            break;

        case dNone:
            value.AddMember(statsrapidjson::StringRef("count"), peer->stats.s5s8[i].cnt[BOTH], allocator);
            break;
        }

	if((peer->stats.s5s8[i].ts != NULL) && (strlen(peer->stats.s5s8[i].ts) != 0))
        	value.AddMember(statsrapidjson::StringRef("last"), statsrapidjson::StringRef(peer->stats.s5s8[i].ts), allocator);
        arrayObjects.PushBack(value, allocator);
    }
}

void CStatMessages::serializeSx(const SPeer* peer,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator)
{
    for(int i = 0; i < SX_MSG_TYPE_LEN; i++) {
        if((peer->stats.sx[i].cnt[SENT] == 0 && peer->stats.sx[i].cnt[RCVD] == 0) && suppress) {
            continue;
        }
        statsrapidjson::Value value(statsrapidjson::kObjectType);
        value.AddMember(
            statsrapidjson::StringRef("type"), statsrapidjson::StringRef(ossSxMessageDefs[i].msgname), allocator);

        switch(ossSxMessageDefs[i].dir) {
        case dIn:
            value.AddMember(statsrapidjson::StringRef("rcvd"), peer->stats.sx[i].cnt[RCVD], allocator);
            break;

        case dOut:
            value.AddMember(statsrapidjson::StringRef("sent"), peer->stats.sx[i].cnt[SENT], allocator);
            break;

        case dRespSend:
            value.AddMember(statsrapidjson::StringRef("sent_acc"), peer->stats.sx[i].cnt[ACC], allocator);
            value.AddMember(statsrapidjson::StringRef("sent_rej"), peer->stats.sx[i].cnt[REJ], allocator);
            break;

        case dRespRcvd:
            value.AddMember(statsrapidjson::StringRef("rcvd_acc"), peer->stats.sx[i].cnt[ACC], allocator);
            value.AddMember(statsrapidjson::StringRef("rcvd_rej"), peer->stats.sx[i].cnt[REJ], allocator);
            break;

        case dBoth:
            value.AddMember(statsrapidjson::StringRef("sent"), peer->stats.sx[i].cnt[SENT], allocator);
            value.AddMember(statsrapidjson::StringRef("rcvd"), peer->stats.sx[i].cnt[RCVD], allocator);
            break;

        case dNone:
            value.AddMember(statsrapidjson::StringRef("count"), peer->stats.sx[i].cnt[BOTH], allocator);
            break;
        }

    if((peer->stats.sx[i].ts != NULL) && (strlen(peer->stats.sx[i].ts) != 0))
        	value.AddMember(statsrapidjson::StringRef("last"), statsrapidjson::StringRef(peer->stats.sx[i].ts), allocator);
        arrayObjects.PushBack(value, allocator);
    }
}

void CStatMessages::serializeGx(const SPeer* peer,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator)
{
    for(int i = 0; i < GX_MSG_TYPE_LEN; i++) {
        if((peer->stats.gx[i].cnt[SENT] == 0 && peer->stats.gx[i].cnt[RCVD] == 0) && suppress) {
            continue;
        }
        statsrapidjson::Value value(statsrapidjson::kObjectType);
        value.AddMember(
            statsrapidjson::StringRef("type"), statsrapidjson::StringRef(ossGxMessageDefs[i].msgname), allocator);

        switch(ossGxMessageDefs[i].dir) {
        case dIn:
            value.AddMember(statsrapidjson::StringRef("rcvd"), peer->stats.gx[i].cnt[RCVD], allocator);
            break;

        case dOut:
            value.AddMember(statsrapidjson::StringRef("sent"), peer->stats.gx[i].cnt[SENT], allocator);
            break;

        case dRespSend:
            value.AddMember(statsrapidjson::StringRef("sent_acc"), peer->stats.gx[i].cnt[ACC], allocator);
            value.AddMember(statsrapidjson::StringRef("sent_rej"), peer->stats.gx[i].cnt[REJ], allocator);
            break;

        case dRespRcvd:
            value.AddMember(statsrapidjson::StringRef("rcvd_acc"), peer->stats.gx[i].cnt[ACC], allocator);
            value.AddMember(statsrapidjson::StringRef("rcvd_rej"), peer->stats.gx[i].cnt[REJ], allocator);
            break;

        case dBoth:
            value.AddMember(statsrapidjson::StringRef("sent"), peer->stats.gx[i].cnt[SENT], allocator);
            value.AddMember(statsrapidjson::StringRef("rcvd"), peer->stats.gx[i].cnt[RCVD], allocator);
            break;

        case dNone:
            value.AddMember(statsrapidjson::StringRef("count"), peer->stats.gx[i].cnt[BOTH], allocator);
            break;
        }

    if((peer->stats.gx[i].ts != NULL) && (strlen(peer->stats.gx[i].ts) != 0))
               value.AddMember(statsrapidjson::StringRef("last"), statsrapidjson::StringRef(peer->stats.gx[i].ts), allocator);
        arrayObjects.PushBack(value, allocator);
    }
}


void CStatMessages::serializeSystem(const cli_node_t *cli_node,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator)
{
    // 0 == Number of active session so skip it.
    for(int i = 1; i < SYSTEM_MSG_TYPE_LEN; i++) {
        if((cli_node->stats[i] == 0) && suppress)
            continue;
        statsrapidjson::Value value(statsrapidjson::kObjectType);
        value.AddMember(
            statsrapidjson::StringRef("type"), statsrapidjson::StringRef(ossSystemMessageDefs[i].msgname), allocator);

        switch(ossSystemMessageDefs[i].dir) {
        case dNone:
            value.AddMember(statsrapidjson::StringRef("count"), cli_node->stats[i], allocator);
            break;
		default:
			break;
        }
        arrayObjects.PushBack(value, allocator);
    }
}

void CStatMessages::serialize(const SPeer* peer,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator)
{

    switch(peer->intfctype) {
    case itS11:
        serializeS11(peer, row, arrayObjects, allocator);
        break;
    case itS5S8:
		if (cli_node_ptr->gw_type == OSS_CONTROL_PLANE)
        serializeS5S8(peer, row, arrayObjects, allocator);
        break;
    case itSx:
    	serializeSx(peer, row, arrayObjects, allocator);
        break;
    case itGx:
		serializeGx(peer, row, arrayObjects, allocator);
        break;
	default:
			break;
    }
}


void CStatHealth::serialize(const SPeer* peer,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator)
{
    statsrapidjson::Value reqValue(statsrapidjson::kObjectType);
    statsrapidjson::Value respValue(statsrapidjson::kObjectType);
    statsrapidjson::Value reqValues(statsrapidjson::kArrayType);
    statsrapidjson::Value respValues(statsrapidjson::kArrayType);

    row.AddMember(statsrapidjson::StringRef("responsetimeout"), (*(peer->response_timeout)), allocator);
    row.AddMember(statsrapidjson::StringRef("maxtimeouts"), (*(peer->maxtimeout))+1, allocator);
    row.AddMember(statsrapidjson::StringRef("timeouts"), peer->timeouts, allocator);

    reqValue.AddMember(statsrapidjson::StringRef("sent"), peer->hcrequest[SENT], allocator);
    reqValue.AddMember(statsrapidjson::StringRef("received"), peer->hcrequest[RCVD], allocator);
    row.AddMember(statsrapidjson::StringRef("requests"), reqValue, allocator);

    respValue.AddMember(statsrapidjson::StringRef("sent"), peer->hcresponse[SENT], allocator);
    respValue.AddMember(statsrapidjson::StringRef("received"), peer->hcresponse[RCVD], allocator);
    row.AddMember(statsrapidjson::StringRef("responses"), respValue, allocator);
}

void CStatPeers::serialize(const SPeer* peer,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator)
{
    statsrapidjson::Value ipValue(statsrapidjson::kObjectType);
	char ipv6[INET6_ADDRSTRLEN];

	if(peer->cli_peer_addr.type == IPV4_TYPE)
    	ipValue.AddMember(statsrapidjson::StringRef("ip"),
			statsrapidjson::Value(inet_ntoa(peer->cli_peer_addr.ipv4.sin_addr), allocator).Move(), allocator);
    	else if(peer->cli_peer_addr.type == IPV6_TYPE)
		ipValue.AddMember(statsrapidjson::StringRef("ip"),
			statsrapidjson::Value(inet_ntop(AF_INET6,
			&peer->cli_peer_addr.ipv6.sin6_addr, ipv6, INET6_ADDRSTRLEN), allocator).Move(), allocator);
	else
		clLog(STANDARD_LOGID, eCLSeverityDebug,
			LOG_FORMAT"Not supported IP type %d", LOG_VALUE, peer->cli_peer_addr.type);

	row.AddMember(statsrapidjson::StringRef("address"), ipValue, allocator);

    	if(peer->status)
       		row.AddMember(statsrapidjson::StringRef("active"), statsrapidjson::StringRef("true"), allocator);
    	else
		row.AddMember(statsrapidjson::StringRef("active"), statsrapidjson::StringRef("false"), allocator);
	if(peer->lastactivity != NULL)
		row.AddMember(
        statsrapidjson::StringRef("lastactivity"), statsrapidjson::StringRef(peer->lastactivity), allocator);

    	statsrapidjson::Value rowHealth(statsrapidjson::kObjectType);
    	CStatHealth health(suppress);
    	health.serialize(peer, rowHealth, arrayObjects, allocator);
    	row.AddMember(statsrapidjson::Value(health.getNodeName().c_str(), allocator).Move(), rowHealth, allocator);

    statsrapidjson::Value msgValues(statsrapidjson::kArrayType);
    CStatMessages msg(suppress);
    msg.serialize(peer, row, msgValues, allocator);
    row.AddMember(statsrapidjson::Value(msg.getNodeName().c_str(), allocator).Move(), msgValues, allocator);
}

void CStatInterfaces::serializeInterface(cli_node_t *cli_node,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator,EInterfaceType it)
{
    statsrapidjson::Value value(statsrapidjson::kObjectType);
    value.AddMember(statsrapidjson::StringRef("name"), statsrapidjson::StringRef(ossInterfaceStr[it]), allocator);
    value.AddMember(statsrapidjson::StringRef("protocol"), statsrapidjson::StringRef(ossInterfaceProtocolStr[it]), allocator);
    statsrapidjson::Value peerValues(statsrapidjson::kArrayType);

    SPeer **oss_peer_ar = cli_node->peer;
    for(int i = 0; i < *(oss_cnt_peer); i++) {

        SPeer* peerPtrLoop = *(oss_peer_ar + i) ;
        if(peerPtrLoop == NULL)
        {
            continue;
        }

        if(peerPtrLoop->intfctype == it)
        {
			statsrapidjson::Value value1(statsrapidjson::kObjectType);
            peer.serialize(peerPtrLoop, value1, arrayObjects, allocator);
			peerValues.PushBack(value1, allocator);
        }
    }

    value.AddMember(statsrapidjson::Value(peer.getNodeName().c_str(), allocator).Move(), peerValues, allocator);
    arrayObjects.PushBack(value, allocator);
}


void CStatInterfaces::serialize(cli_node_t *cli_node,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator)
{
    switch(cli_node->gw_type) {

    case OSS_CONTROL_PLANE:
        serializeInterface(cli_node,row,arrayObjects,allocator,itS11);
        serializeInterface(cli_node,row,arrayObjects,allocator,itS5S8);
        serializeInterface(cli_node,row,arrayObjects,allocator,itSx);
		serializeInterface(cli_node,row,arrayObjects,allocator,itGx);
        break;

    case OSS_USER_PLANE:
		serializeInterface(cli_node,row,arrayObjects,allocator,itSx);
		serializeInterface(cli_node,row,arrayObjects,allocator,itS1U);
		serializeInterface(cli_node,row,arrayObjects,allocator,itS5S8);
		serializeInterface(cli_node,row,arrayObjects,allocator,itSGI);
		break;
	default:
		break;
    }
}

void CStatGateway::serialize(cli_node_t *cli_node,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator)
{
    ETime now = ETime::Now();
	initInterfaceDirection( static_cast<cp_config>(cli_node->gw_type));
    statsrapidjson::Value valArray(statsrapidjson::kArrayType);

    row.AddMember("nodename", statsrapidjson::StringRef(ossGatewayStr[cli_node->gw_type]), allocator);
    now.Format(reportTimeStr, "%Y-%m-%dT%H:%M:%S.%0", false);
    row.AddMember("reporttime", statsrapidjson::StringRef( reportTimeStr.c_str()  ), allocator);
    row.AddMember("upsecs", *(cli_node->upsecs), allocator);
    row.AddMember("resetsecs", *(cli_node->upsecs) - reset_time , allocator);
    interfaces.serialize(cli_node, row, valArray, allocator);
    row.AddMember(statsrapidjson::Value(interfaces.getNodeName().c_str(), allocator).Move(), valArray, allocator);

    statsrapidjson::Value sessionValue(statsrapidjson::kObjectType);
    CStatSession session(suppress);
    session.serialize(cli_node, sessionValue, arrayObjects, allocator);
    row.AddMember(statsrapidjson::Value(session.getNodeName().c_str(), allocator).Move(), sessionValue, allocator);

  	statsrapidjson::Value systemValue(statsrapidjson::kObjectType);
   	CStatSystem system(suppress);
   	system.serialize(cli_node, systemValue, arrayObjects, allocator);
   	row.AddMember(statsrapidjson::Value(system.getNodeName().c_str(), allocator).Move(), systemValue, allocator);
}

void CStatGateway::initInterfaceDirection(cp_config gatway)
{
	switch(gatway) {

		case OSS_CONTROL_PLANE:
			if(cli_node_ptr->s5s8_selection == OSS_S5S8_SENDER) {
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_CREATE_SESSION_REQ]].dir = dOut;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_CREATE_SESSION_RSP]].dir = dRespRcvd;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_SESSION_REQ]].dir = dOut;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_SESSION_RSP]].dir = dRespRcvd;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_MODIFY_BEARER_REQ]].dir = dOut;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_MODIFY_BEARER_RSP]].dir = dRespRcvd;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_CREATE_BEARER_REQ]].dir = dIn;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_CREATE_BEARER_RSP]].dir = dRespSend;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_UPDATE_BEARER_REQ]].dir = dIn;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_UPDATE_BEARER_RSP]].dir = dRespSend;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_BEARER_REQ]].dir = dIn;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_BEARER_RSP]].dir = dRespSend;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_CHANGE_NOTIFICATION_REQ]].dir = dOut;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_CHANGE_NOTIFICATION_RSP]].dir = dRespRcvd;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_PDN_CONNECTION_SET_REQ]].dir = dBoth;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_UPDATE_PDN_CONNECTION_SET_REQ]].dir = dOut;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_UPDATE_PDN_CONNECTION_SET_RSP]].dir = dRespRcvd;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_BEARER_CMD]].dir = dOut;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_BEARER_FAILURE_IND]].dir = dRespRcvd;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_MODIFY_BEARER_CMD]].dir = dOut;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_MODIFY_BEARER_FAILURE_IND]].dir = dRespRcvd;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_BEARER_RESOURCE_CMD]].dir = dOut;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_BEARER_RESOURCE_FAILURE_IND]].dir = dRespRcvd;
			}
			if(cli_node_ptr->s5s8_selection == OSS_S5S8_RECEIVER) {
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_CREATE_SESSION_REQ]].dir = dIn;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_CREATE_SESSION_RSP]].dir = dRespSend;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_SESSION_REQ]].dir = dIn;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_SESSION_RSP]].dir = dRespSend;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_MODIFY_BEARER_REQ]].dir = dIn;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_MODIFY_BEARER_RSP]].dir = dRespSend;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_CREATE_BEARER_REQ]].dir = dOut;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_CREATE_BEARER_RSP]].dir = dRespRcvd;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_UPDATE_BEARER_REQ]].dir = dOut;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_UPDATE_BEARER_RSP]].dir = dRespRcvd;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_BEARER_REQ]].dir = dOut;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_BEARER_RSP]].dir = dRespRcvd;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_CHANGE_NOTIFICATION_REQ]].dir = dIn;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_CHANGE_NOTIFICATION_RSP]].dir = dRespSend;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_PDN_CONNECTION_SET_REQ]].dir = dBoth;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_UPDATE_PDN_CONNECTION_SET_REQ]].dir = dIn;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_UPDATE_PDN_CONNECTION_SET_RSP]].dir = dRespSend;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_BEARER_CMD]].dir = dIn;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_DELETE_BEARER_FAILURE_IND]].dir = dRespSend;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_MODIFY_BEARER_CMD]].dir = dIn;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_MODIFY_BEARER_FAILURE_IND]].dir = dRespSend;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_BEARER_RESOURCE_CMD]].dir = dIn;
				ossS5s8MessageDefs[s5s8MessageTypes[GTP_BEARER_RESOURCE_FAILURE_IND]].dir = dRespSend;
			}
			break;
		default:
			break;
	}
}

void CStatSystem::serialize(cli_node_t *cli_node,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator)
{
    statsrapidjson::Value msgValueArr(statsrapidjson::kArrayType);
    CStatMessages msg(suppress);
    msg.serializeSystem(cli_node, row, msgValueArr, allocator);
	row.AddMember(statsrapidjson::Value(msg.getNodeName().c_str(), allocator).Move(), msgValueArr, allocator);
}

void CStatSession::serialize(cli_node_t *cli_node,
    statsrapidjson::Value& row,
    statsrapidjson::Value& arrayObjects,
    statsrapidjson::Document::AllocatorType& allocator)
{
    row.AddMember(statsrapidjson::StringRef("active"),
		cli_node->stats[number_of_active_session], allocator);
}
