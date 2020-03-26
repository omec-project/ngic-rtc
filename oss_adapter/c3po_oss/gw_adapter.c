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

#else

#include "up_main.h"
#include "gtpu.h"

#endif /* CP_BUILD */

#include "gw_adapter.h"
#include "crest.h"
#include "clogger.h"
#include "cstats.h"

#include "../../pfcp_messages/pfcp_set_ie.h"

//////////////////////////////////////////////////////////////////////////////////


/*CLI :new logic definations*/
cli_node_t cli_node = {0};
SPeer *peer[MAX_PEER] = {NULL};
int cnt_peer = 0;
int nbr_of_peer = 0;
uint64_t oss_reset_time;

int s11logger;
int s5s8logger;
int sxlogger;
int gxlogger;
int apilogger;
int epclogger;
int s_one_u_logger;
int sgilogger;
int knilogger;


MessageType ossS5s8MessageDefs[] = {
        {       3       , "Version Not Supported Indication",dNone      },
        {       32      , "Create Session Request",  dIn        	},//if SGWC then send, if PGWC then recv
        {       33      , "Create Session Response",dRespRcvd   	},//if SGWC then recv, if PGWC then send
        {       36      , "Delete Session Request",  dIn        	},//if SGWC then send, if PGWC then recv
        {       37      , "Delete Session Response",dRespRcvd   	},//if SGWC then recv, if PGWC then send
        {       34      , "Modify Bearer Request",dIn 			},	  //if SGWC then send, if PGWC then recv
        {       35      , "Modify Bearer Response",dRespRcvd    	},//if SGWC then recv, if PGWC then send
        {       40      , "Remote UE Report Notification",dNone 	},
        {       41      , "Remote UE Report Acknowledge",dNone  	},
        {       38      , "Change Notification Request",dNone   	},
        {       39      , "Change Notification Response",dNone  	},
        {       164     , "Resume Notification",dNone   		},
        {       165     , "Resume Acknowledge",dNone    		},
        {       64      , "Modify Bearer Command",dNone 		},
        {       65      , "Modify Bearer Failure Indication",dNone      },
        {       66      , "Delete Bearer Command",dNone 		},
        {       67      , "Delete Bearer Failure Indication",dNone      },
        {       68      , "Bearer Resource Command",dNone       	},
        {       69      , "Bearer Resource Failure Indication",dNone    },
        {       71      , "Trace Session Activation",dNone      	},
        {       72      , "Trace Session Deactivation",dNone    	},
        {       95      , "Create Bearer Request",dIn 		},//if SGWC then recv, if PGWC then send
        {       96      , "Create Bearer Response",dOut        	},//if SGWC then send, if PGWC then recv
        {       97      , "Update Bearer Request",dNone 		},
        {       98      , "Update Bearer Response",dNone        	},
        {       99      , "Delete Bearer Request",dNone 		},
        {       100     , "Delete Bearer Response",dNone        	},
        {       101     , "Delete PDN Connection Set Request",dNone     },
        {       102     , "Delete PDN Connection Set Response",dNone    },
        {       103     , "PGW Downlink Triggering Notification",dNone  },
        {       104     , "PGW Downlink Triggering Acknowledge",dNone   },
        {       162     , "Suspend Notification",dNone  		},
        {       163     , "Suspend Acknowledge",dNone   		},
        {       200     , "Update PDN Connection Set Request",dNone     },
        {       201     , "Update PDN Connection Set Response",dNone    },
        {       -1      , NULL,dNone  					}
};

MessageType ossS11MessageDefs[] = {
        {       3       ,"Version Not Supported Indication", dNone 	},
        {       32      ,"Create Session Request", dIn 			},
        {       33      ,"Create Session Response", dRespSend 		},
        {       36      ,"Delete Session Request", dIn 			},
        {       37      ,"Delete Session Response", dRespSend 		},
        {       34      ,"Modify Bearer Request", dIn 			},
        {       35      ,"Modify Bearer Response", dRespSend 		},
        {       40      ,"Remote UE Report Notification", dNone 	},
        {       41      ,"Remote UE Report Acknowledge", dNone 		},
        {       38      ,"Change Notification Request", dNone 		},
        {       39      ,"Change Notification Response", dNone 		},
        {       164     ,"Resume Notification", dNone 			},
        {       165     ,"Resume Acknowledge", dNone 			},
        {       64      ,"Modify Bearer Command", dNone 		},
        {       65      ,"Modify Bearer Failure Indication", dNone 	},
        {       66      ,"Delete Bearer Command", dNone 		},
        {       67      ,"Delete Bearer Failure Indication", dNone 	},
        {       68      ,"Bearer Resource Command", dNone 		},
        {       69      ,"Bearer Resource Failure Indication", dNone 	},
        {       70      ,"Downlink Data Notification Failure Indication", dNone },
        {       71      ,"Trace Session Activation", dNone 		},
        {       72      ,"Trace Session Deactivation", dNone 		},
        {       73      ,"Stop Paging Indication", dNone 		},
        {       95      ,"Create Bearer Request", dOut	 		},
        {       96      ,"Create Bearer Response", dRespRcvd	 	},
        {       97      ,"Update Bearer Request", dNone 		},
        {       98      ,"Update Bearer Response", dNone 		},
        {       99      ,"Delete Bearer Request", dNone 		},
        {       100     ,"Delete Bearer Response", dNone 		},
        {       101     ,"Delete PDN Connection Set Request", dNone 	},
        {       102     ,"Delete PDN Connection Set Response", dNone 	},
        {       103     ,"PGW Downlink Triggering Notification", dNone 	},
        {       104     ,"PGW Downlink Triggering Acknowledge", dNone 	},
        {       162     ,"Suspend Notification", dNone 			},
        {       163     ,"Suspend Acknowledge", dNone 			},
        {       160     ,"Create Forwarding Tunnel Request", dNone 	},
        {       161     ,"Create Forwarding Tunnel Response", dNone 	},
        {       166     ,"Create Indirect Data Forwarding Tunnel Request", dNone },
        {       167     ,"Create Indirect Data Forwarding Tunnel Response", dNone },
        {       168     ,"Delete Indirect Data Forwarding Tunnel Request", dNone },
        {       169     ,"Delete Indirect Data Forwarding Tunnel Response", dNone },
        {       170     ,"Release Access Bearers Request", dIn 		},
        {       171     ,"Release Access Bearers Response", dRespSend 	},
        {       176     ,"Downlink Data Notification", dOut 		},
        {       177     ,"Downlink Data Notification Acknowledge", dRespRcvd },
        {       179     ,"PGW Restart Notification", dNone 		},
        {       180     ,"PGW Restart Notification Acknowledge", dNone 	},
        {       211     ,"Modify Access Bearers Request", dNone 	},
        {       212     ,"Modify Access Bearers Response", dNone 	},
        {       -1      , NULL,dNone  					}
};

#ifdef CP_BUILD

MessageType ossSxaMessageDefs[] = {
        {	   1	  ,"PFCP Heartbeat Request",dNone		},
        {	   2	  ,"PFCP Heartbeat Response",dNone		},
        {	   5	  ,"PFCP Association Setup Request",dOut	},
        {	   6	  ,"PFCP Association Setup Response",dRespRcvd	},
        {	   7	  ,"PFCP Association Update Request",dNone	},
        {	   8	  ,"PFCP Association Update Response",dNone	},
        {	   9	  ,"PFCP Association Release Request",dNone	},
        {	   10	  ,"PFCP Association Release Response",dNone	},
        {	   11	  ,"PFCP Version Not Supported Response",dNone	},
        {	   12	  ,"PFCP Node Report Request",dNone		},
        {	   13	  ,"PFCP Node Report Response",dNone		},
        {	   14	  ,"PFCP Session Set Deletion Request",dNone	},
        {	   15	  ,"PFCP Session Set Deletion Response",dNone	},
        {	   50	  ,"PFCP Session Establishment Request",dOut	},
        {	   51	  ,"PFCP Session Establishment Response",dRespRcvd},
        {	   52	  ,"PFCP Session Modification Request",dOut	},
        {	   53	  ,"PFCP Session Modification Response",dRespRcvd},
        {	   54	  ,"PFCP Session Deletion Request",dOut		},
        {	   55	  ,"PFCP Session Deletion Response",dRespRcvd	},
        {	   56	  ,"PFCP Session Report Request",dIn		},
        {	   57	  ,"PFCP Session Report Response",dRespSend	},
        {          -1     , NULL,dNone					}
};

MessageType ossSxbMessageDefs[] = {
        {	  1	  ,"PFCP Heartbeat Request",dNone		},
        {	  2	  ,"PFCP Heartbeat Response",dNone		},
	{  	  3       ,"PFCP PFD Management Request",dOut           },
	{         4       ,"PFCP PFD Management Response",dRespRcvd     },
        {	  5	  ,"PFCP Association Setup Request",dOut	},
        {	  6	  ,"PFCP Association Setup Response",dRespRcvd	},
        {	  7	  ,"PFCP Association Update Request",dNone	},
        {	  8	  ,"PFCP Association Update Response",dNone	},
        {	  9	  ,"PFCP Association Release Request",dNone	},
        {	  10	  ,"PFCP Association Release Response",dNone	},
        {	  11	  ,"PFCP Version Not Supported Response",dNone	},
        {	  12	  ,"PFCP Node Report Request",dNone		},
        {	  13	  ,"PFCP Node Report Response",dNone		},
        {	  14	  ,"PFCP Session Set Deletion Request",dNone	},
        {	  15	  ,"PFCP Session Set Deletion Response",dNone	},
        {	  50	  ,"PFCP Session Establishment Request",dOut	},
        {	  51	  ,"PFCP Session Establishment Response",dRespRcvd},
        {	  52	  ,"PFCP Session Modification Request",dOut	},
        {	  53	  ,"PFCP Session Modification Response",dRespRcvd},
        {	  54	  ,"PFCP Session Deletion Request",dOut		},
        {	  55	  ,"PFCP Session Deletion Response",dRespRcvd	},
        {	  56	  ,"PFCP Session Report Request",dIn		},
        {	  57	  ,"PFCP Session Report Response",dRespSend	},
        {         -1      , NULL,dNone  				}
};

MessageType ossSxaSxbMessageDefs[] = {
        {	  1	 ,"PFCP Heartbeat Request",dNone		},
        {	  2	 ,"PFCP Heartbeat Response",dNone		},
        {	  3	 ,"PFCP PFD Management Request",dOut		},
        {	  4	 ,"PFCP PFD Management Response",dRespRcvd	},
        {	  5	 ,"PFCP Association Setup Request",dOut		},
        {	  6	 ,"PFCP Association Setup Response",dRespRcvd	},
        {	  7	 ,"PFCP Association Update Request",dNone	},
        {	  8	 ,"PFCP Association Update Response",dNone	},
        {	  9	 ,"PFCP Association Release Request",dNone	},
        {	  10	 ,"PFCP Association Release Response",dNone	},
        {	  11	 ,"PFCP Version Not Supported Response",dNone	},
        {	  12	 ,"PFCP Node Report Request",dNone		},
        {	  13	 ,"PFCP Node Report Response",dNone		},
        {	  14	 ,"PFCP Session Set Deletion Request",dNone	},
        {	  15	 ,"PFCP Session Set Deletion Response",dNone	},
        {	  50	 ,"PFCP Session Establishment Request",dOut	},
        {	  51	 ,"PFCP Session Establishment Response",dRespRcvd},
        {	  52	 ,"PFCP Session Modification Request",dOut	},
        {	  53	 ,"PFCP Session Modification Response",dRespRcvd},
        {	  54	 ,"PFCP Session Deletion Request",dOut		},
        {	  55	 ,"PFCP Session Deletion Response",dRespRcvd	},
        {	  56	 ,"PFCP Session Report Request",dIn		},
        {	  57	 ,"PFCP Session Report Response",dRespSend	},
        {         -1     , NULL,dNone  					}
};

#else /* DP_BUILD */

MessageType ossSxaMessageDefs[] = {
        {          1      ,"PFCP Heartbeat Request",dNone               },
        {          2      ,"PFCP Heartbeat Response",dNone              },
        {          5      ,"PFCP Association Setup Request",dIn        },
        {          6      ,"PFCP Association Setup Response",dRespSend  },
        {          7      ,"PFCP Association Update Request",dNone      },
        {          8      ,"PFCP Association Update Response",dNone     },
        {          9      ,"PFCP Association Release Request",dNone     },
        {          10     ,"PFCP Association Release Response",dNone    },
        {          11     ,"PFCP Version Not Supported Response",dNone  },
        {          12     ,"PFCP Node Report Request",dNone             },
        {          13     ,"PFCP Node Report Response",dNone            },
        {          14     ,"PFCP Session Set Deletion Request",dNone    },
        {          15     ,"PFCP Session Set Deletion Response",dNone   },
        {          50     ,"PFCP Session Establishment Request",dIn    },
        {          51     ,"PFCP Session Establishment Response",dRespSend},
        {          52     ,"PFCP Session Modification Request",dIn     },
        {          53     ,"PFCP Session Modification Response",dRespSend},
        {          54     ,"PFCP Session Deletion Request",dIn         },
        {          55     ,"PFCP Session Deletion Response",dRespSend   },
        {          56     ,"PFCP Session Report Request",dOut           },
        {          57     ,"PFCP Session Report Response",dRespRcvd     },
        {          -1     , NULL,dNone			  		}
};
MessageType ossSxbMessageDefs[] = {
        {         1       ,"PFCP Heartbeat Request",dNone               },
        {         2       ,"PFCP Heartbeat Response",dNone              },
	{         3       ,"PFCP PFD Management Request",dIn           },
	{         4       ,"PFCP PFD Management Response",dRespSend    },
        {         5       ,"PFCP Association Setup Request",dIn        },
        {         6       ,"PFCP Association Setup Response",dRespSend  },
        {         7       ,"PFCP Association Update Request",dNone      },
        {         8       ,"PFCP Association Update Response",dNone     },
        {         9       ,"PFCP Association Release Request",dNone     },
        {         10      ,"PFCP Association Release Response",dNone    },
        {         11      ,"PFCP Version Not Supported Response",dNone  },
        {         12      ,"PFCP Node Report Request",dNone             },
        {         13      ,"PFCP Node Report Response",dNone            },
        {         14      ,"PFCP Session Set Deletion Request",dNone    },
        {         15      ,"PFCP Session Set Deletion Response",dNone   },
        {         50      ,"PFCP Session Establishment Request",dIn    },
        {         51      ,"PFCP Session Establishment Response",dRespSend},
        {         52      ,"PFCP Session Modification Request",dIn     },
        {         53      ,"PFCP Session Modification Response",dRespSend},
        {         54      ,"PFCP Session Deletion Request",dIn         },
        {         55      ,"PFCP Session Deletion Response",dRespSend   },
        {         56      ,"PFCP Session Report Request",dOut           },
        {         57      ,"PFCP Session Report Response",dRespRcvd     },
        {         -1      , NULL,dNone  				}
};
MessageType ossSxaSxbMessageDefs[] = {
        {         1      ,"PFCP Heartbeat Request",dNone                },
        {         2      ,"PFCP Heartbeat Response",dNone               },
        {         3      ,"PFCP PFD Management Request",dIn             },
        {         4      ,"PFCP PFD Management Response",dRespSend      },
        {         5      ,"PFCP Association Setup Request",dIn         },
        {         6      ,"PFCP Association Setup Response",dRespSend   },
        {         7      ,"PFCP Association Update Request",dNone       },
        {         8      ,"PFCP Association Update Response",dNone      },
        {         9      ,"PFCP Association Release Request",dNone      },
        {         10     ,"PFCP Association Release Response",dNone     },
        {         11     ,"PFCP Version Not Supported Response",dNone   },
        {         12     ,"PFCP Node Report Request",dNone              },
        {         13     ,"PFCP Node Report Response",dNone             },
        {         14     ,"PFCP Session Set Deletion Request",dNone     },
        {         15     ,"PFCP Session Set Deletion Response",dNone    },
        {         50     ,"PFCP Session Establishment Request",dIn     },
        {         51     ,"PFCP Session Establishment Response",dRespSend},
        {         52     ,"PFCP Session Modification Request",dIn      },
        {         53     ,"PFCP Session Modification Response",dRespSend},
        {         54     ,"PFCP Session Deletion Request",dIn          },
        {         55     ,"PFCP Session Deletion Response",dRespSend    },
        {         56     ,"PFCP Session Report Request",dOut            },
        {         57     ,"PFCP Session Report Response",dRespRcvd      },
        {         -1     , NULL,dNone                                   }
};
#endif /* CP_BUILD */

MessageType ossGxMessageDefs[] = {
    {     120    ,"Credit Control Request Initial",dOut             },
    {     121    ,"Credit Control Answer Initial",dIn               },
    {     122    ,"Credit Control Request Update",dOut              },
    {     123    ,"Credit Control Answer Update",dIn                },
    {     124    ,"Credit Control Request Terminate",dOut         },
    {     125    ,"Credit Control Answer Terminate",dIn           },
    {     126    ,"Re-Auth-Request",dIn                            },
    {     127    ,"Re-Auth Answer",dOut                             },
    {     -1     , NULL,dNone                                       }
};


MessageType ossSystemMessageDefs[] = {
    {  0    ,"Number of active session",dNone	},
    {  1    ,"Number of ues",dNone  		},
    {  2    ,"Number of bearers",dNone          },
    {  3    ,"Number of pdn connections",dNone  },
    {  -1   , NULL,dNone  			}
};

char ossInterfaceStr[][10] = {
    "s11" ,
    "s5s8",
    "sxa",
    "sxb",
    "sxasxb",
    "gx",
	"s1u",
	"sgi",
    "none"
};

char ossInterfaceProtocolStr[][10] = {
    "gtpv2" ,
#ifdef CP_BUILD
    "gtpv2",
#else
	"gtp",
#endif
    "pfcp",
    "pfcp",
    "pfcp",
    "diameter",
	"gtp",
    "none"
};

char ossGatewayStr[][10] = {
    "none",
    "SGWC",
    "PGWC",
    "SAEGWC",
    "SGWU",
    "PGWU",
    "SAEGWU"
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

int sxaMessageTypes [] = {
    -1,0,1,-1,-1,2,3,4,5,6,7,8,9,10,11,12,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,13,14,15,16,17,18,19,20
};

int sxbMessageTypes [] = {
    -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,15,16,17,18,19,20,21,22
};

int sxasxbMessageTypes [] = {
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


bool is_last_activity_update(uint8_t msg_type, CLIinterface it)
{
    EInterfaceType it_cli;
    if(it == SX) {
#ifdef DP_BUILD
        if(app.spgw_cfg == SGWU)
            it_cli = itSxa;
        else if(app.spgw_cfg == PGWU)
            it_cli = itSxb;
        else
            it_cli = itSxaSxb;
#else
        if(pfcp_config.cp_type == SGWC)
            it_cli = itSxa;
        else if(pfcp_config.cp_type == PGWC)
            it_cli = itSxb;
        else
            it_cli = itSxaSxb;
#endif
    } else if(it == GX)
        it_cli = itGx;
    else if(it == S1U)
        it_cli = itS1U;
    else if(it == SGI)
        it_cli = itSGI;
    else if(it == S5S8)
        it_cli = itS5S8;
    else
        it_cli = itS11;

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

    case itSxa:
        if((ossSxaMessageDefs[sxaMessageTypes[msg_type]].dir == dIn) ||
            (ossSxaMessageDefs[sxaMessageTypes[msg_type]].dir == dRespRcvd))
            return true;
        break;

    case itSxb:
        if((ossSxbMessageDefs[sxbMessageTypes[msg_type]].dir == dIn) ||
            (ossSxbMessageDefs[sxbMessageTypes[msg_type]].dir == dRespRcvd))
            return true;
        break;

    case itSxaSxb:
        if((ossSxaSxbMessageDefs[sxasxbMessageTypes[msg_type]].dir == dIn) ||
            (ossSxaSxbMessageDefs[sxasxbMessageTypes[msg_type]].dir == dRespRcvd))
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

	if(is_last_activity_update(msg_type,it))
			update_last_activity(ip_addr, stat_timestamp);

	clLog(clSystemLog, eCLSeverityTrace, "Updating update_cli_stats\n"
										"msg_type:%d,"
										"dir:%d,"
										"ip_addr is :%s\n",
											msg_type,dir,
											inet_ntoa(*((struct in_addr*)&ip_addr)));

	index = get_peer_index(ip_addr);

	if(index == -1) {
		clLog(clSystemLog, eCLSeverityTrace, "peer not found\n");
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

		switch(cli_node.peer[index]->intfctype) {
			case itS11:
				__sync_add_and_fetch(&cli_node.peer[index]->stats.s11[s11MessageTypes[msg_type]].cnt[dir], 1);
				strcpy(cli_node.peer[index]->stats.s11[s11MessageTypes[msg_type]].ts, stat_timestamp);
				break;
			case itS5S8:
				__sync_add_and_fetch(&cli_node.peer[index]->stats.s5s8[s5s8MessageTypes[msg_type]].cnt[dir], 1);
				strcpy(cli_node.peer[index]->stats.s5s8[s5s8MessageTypes[msg_type]].ts, stat_timestamp);
				break;
			case itSxa:
				__sync_add_and_fetch(&cli_node.peer[index]->stats.sxa[sxaMessageTypes[msg_type]].cnt[dir], 1);
				strcpy(cli_node.peer[index]->stats.sxa[sxaMessageTypes[msg_type]].ts, stat_timestamp);
				break;
			case itSxb:
				__sync_add_and_fetch(&cli_node.peer[index]->stats.sxb[sxbMessageTypes[msg_type]].cnt[dir], 1);
				strcpy(cli_node.peer[index]->stats.sxb[sxbMessageTypes[msg_type]].ts, stat_timestamp);
				break;
			case itSxaSxb:
				__sync_add_and_fetch(&cli_node.peer[index]->stats.sxasxb[sxasxbMessageTypes[msg_type]].cnt[dir], 1);
				strcpy(cli_node.peer[index]->stats.sxasxb[sxasxbMessageTypes[msg_type]].ts, stat_timestamp);
				break;
               		case itGx:
                                __sync_add_and_fetch(&cli_node.peer[index]->stats.gx[gxMessageTypes[msg_type]].cnt[dir], 1);
                                strcpy(cli_node.peer[index]->stats.gx[gxMessageTypes[msg_type]].ts, stat_timestamp);
                                break;
			default:
				clLog(clSystemLog, eCLSeverityCritical, "CLI:No such a interface");
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

	/*NK:need to optimize*/
	if (it == SX)
	{
#ifdef DP_BUILD
		if (app.spgw_cfg == SGWU){
			it_cli = itSxa;
		} else if (app.spgw_cfg == PGWU){
			it_cli = itSxb;
		} else{
			it_cli = itSxaSxb;
		}
#else
		if (pfcp_config.cp_type == SGWC){
			it_cli = itSxa;
		} else if (pfcp_config.cp_type == PGWC){
			it_cli = itSxb;
		} else{
			it_cli = itSxaSxb;
		}
#endif

	} else if (it == GX)
	{
		it_cli = itGx;
	} else if (it == S1U)
	{
		it_cli = itS1U;
	} else if (it == SGI)
	{
		it_cli = itSGI;
	}else if (it == S5S8)
	{
		it_cli = itS5S8;
	}else
	{
		it_cli = itS11;
	}

        clLog(clSystemLog, eCLSeverityTrace,
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
                cli_node.peer[index]->intfctype = it_cli;
                cli_node.peer[index]->status = FALSE;

		/*TODO Need to revisit after DP timer counter get*/
#ifdef DP_BUILD
				cli_node.peer[index]->response_timeout = app.transmit_timer;
				cli_node.peer[index]->maxtimeout = app.transmit_cnt + 1;
#else
				cli_node.peer[index]->response_timeout = pfcp_config.transmit_timer;
				cli_node.peer[index]->maxtimeout = pfcp_config.transmit_cnt + 1;
#endif

                cli_node.peer[index]->timeouts = 0;

                clLog(clSystemLog, eCLSeverityTrace,
                                                "Interface type is : %d\n",it);
                clLog(clSystemLog, eCLSeverityTrace,
                                                "Added peer with ip addr : %s\n\n",
                                                inet_ntoa(cli_node.peer[index]->ipaddr));

                nbr_of_peer++; /*peer count incremented*/

                if (index == cnt_peer)
                        cnt_peer++;
        }
        else {
                clLog(clSystemLog, eCLSeverityTrace,"CLI:peer already exist\n");
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
		clLog(clSystemLog, eCLSeverityTrace,
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
		clLog(clSystemLog, eCLSeverityTrace,
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
		clLog(clSystemLog, eCLSeverityTrace,"peer not found\n");
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

void
get_current_time_oss(char *last_time_stamp)
{
        struct tm * last_timer;
        time_t rawtime;
        time (&rawtime);
        last_timer = localtime (&rawtime);
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

	crRegisterStaticHandler(eCRCommandGet, "/statlive", get_stat_live);
	crRegisterStaticHandler(eCRCommandGet, "/statliveall", get_stat_live_all);

	crStart();

}

void init_cli_module(uint8_t gw_logger)
{

#ifdef DP_BUILD

	if (app.spgw_cfg == SGWU){
            cli_node.gw_type = OSS_SGWU;
        } else if (app.spgw_cfg == PGWU){
	    cli_node.gw_type = OSS_PGWU;
        } else{
            cli_node.gw_type = OSS_SAEGWU;
        }

	clSetOption(eCLOptLogFileName, "logs/dp.log");
	clSetOption(eCLOptStatFileName, "logs/dp_stat.log");
	clSetOption(eCLOptAuditFileName, "logs/dp_sys.log");

        if (app.spgw_cfg == SGWU){
		clInit("sgwu", gw_logger);
		s_one_u_logger = clAddLogger("s1u", gw_logger);
		s5s8logger = clAddLogger("s5s8", gw_logger);
	} else if (app.spgw_cfg == PGWU){
		clInit("pgwu", gw_logger);
		sgilogger = clAddLogger("sgi", gw_logger);
		s5s8logger = clAddLogger("s5s8", gw_logger);
	} else{
		clInit("saegwu", gw_logger);
		sgilogger = clAddLogger("sgi", gw_logger);
		s_one_u_logger = clAddLogger("s1u", gw_logger);
	}

	knilogger = clAddLogger("kni", gw_logger);
	sxlogger = clAddLogger("sx", gw_logger);
	apilogger = clAddLogger("api", gw_logger);
	epclogger = clAddLogger("epc", gw_logger);
	clAddRecentLogger("sgwu-001","dp",5);
#else

	clSetOption(eCLOptLogFileName, "logs/cp.log");
	clSetOption(eCLOptStatFileName, "logs/cp_stat.log");
	clSetOption(eCLOptAuditFileName, "logs/cp_sys.log");

	    switch(pfcp_config.cp_type) {
        case SGWC:
            cli_node.gw_type = OSS_SGWC;
			clInit("sgwc", gw_logger);
            break;
        case PGWC:
            cli_node.gw_type = OSS_PGWC;
			clInit("pgwc", gw_logger);
            break;
        case SAEGWC:
            cli_node.gw_type = OSS_SAEGWC;
			clInit("saegw", gw_logger);
            break;
    }

	if (spgw_cfg == SGWC || spgw_cfg == SAEGWC) {
		s11logger = clAddLogger("s11", gw_logger);
	}
	if (spgw_cfg == SGWC || spgw_cfg == PGWC)
		s5s8logger = clAddLogger("s5s8", gw_logger);
	if (spgw_cfg == SAEGWC || spgw_cfg == PGWC)
		gxlogger = clAddLogger("Gx", gw_logger);

	sxlogger = clAddLogger("sx", gw_logger);
	apilogger = clAddLogger("api", gw_logger);
	epclogger = clAddLogger("epc", gw_logger);
	clAddRecentLogger("sgwc-001","cp",5);
#endif
	clStart();
	csInit(clGetStatsLogger(), 5000);
	csStart();
	cli_node.upsecs = &oss_reset_time;
	cli_init(&cli_node,&cnt_peer);
	init_rest_methods(12997, 1);
}

