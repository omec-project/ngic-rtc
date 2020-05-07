# Copyright (c) 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

MAKEFLAGS += -j

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk
include $(NG_CORE)/config/ng-core_cfg.mk

OSS_UTIL_ROOT = $(NG_CORE)/oss_adapter/c3po_oss/oss-util
LIBGTPV2C_ROOT = $(SRCDIR)/../libgtpv2c
LIBPFCP_ROOT = $(SRCDIR)/../libpfcp

# binary name
APP = ngic_controlplane

# all source are stored in SRCS-y

SRCS-y := main.c
SRCS-y += ue.c
SRCS-y += cp.c
SRCS-y += gtpv2c.c
SRCS-y += cp_init.c
SRCS-y += cp_stats.c
SRCS-y += cp_config.c
SRCS-y += debug_str.c
SRCS-y += gtpv2c_set_ie.c
SRCS-y += cp_timer.c
SRCS-y += packet_filters.c
SRCS-y += gtpc_session.c
SRCS-y += gtpv2c_error_rsp.c

SRCS-y += state_machine/sm_init.o
SRCS-y += state_machine/sm_hand.o
SRCS-y += state_machine/sm_gtpc_pcnd.o
SRCS-y += state_machine/sm_s5s8_pcnd.o
SRCS-y += state_machine/sm_pfcp_pcnd.o

SRCS-y += gtpv2c_messages/bearer_resource_cmd.o
SRCS-y += gtpv2c_messages/create_bearer.o
SRCS-y += gtpv2c_messages/create_session.o
SRCS-y += gtpv2c_messages/create_s5s8_session.o
SRCS-y += gtpv2c_messages/delete_bearer.o
SRCS-y += gtpv2c_messages/delete_session.o
SRCS-y += gtpv2c_messages/delete_s5s8_session.o
SRCS-y += gtpv2c_messages/gtpv2c_echo.o
SRCS-y += gtpv2c_messages/modify_bearer.o
SRCS-y += gtpv2c_messages/downlink_data_notification.o
SRCS-y += gtpv2c_messages/release_access_bearer.o
SRCS-y += $(SRCDIR)/../pfcp_messages/pfcp_association.o
SRCS-y += $(SRCDIR)/../pfcp_messages/pfcp_req_resp.o
SRCS-y += $(SRCDIR)/../pfcp_messages/pfcp_session.o
SRCS-y += $(SRCDIR)/../pfcp_messages/pfcp_set_ie.o
SRCS-y += $(SRCDIR)/../pfcp_messages/pfcp_util.o
SRCS-y += $(SRCDIR)/../pfcp_messages/pfcp_init.o


SRCS-y += $(SRCDIR)/../test/simu_cp/simu_cp.o
SRCS-y += $(SRCDIR)/../interface/ipc/dp_ipc_api.o
SRCS-y += $(SRCDIR)/../interface/interface.o
SRCS-y += $(SRCDIR)/../interface/udp/vepc_udp.o

SRCS-y += $(SRCDIR)/../cp_dp_api/vepc_cp_dp_api.o

SRCS-y += $(SRCDIR)/../oss_adapter/c3po_oss/gw_adapter.o
CFLAGS += -I$(SRCDIR)/../oss_adapter/c3po_oss

#ifneq (,$(findstring C3PO_OSS, $(CFLAGS)))
#SRCS-y += $(SRCDIR)/../oss_adapter/c3po_oss/cp_adapter.o
#CFLAGS += -I$(SRCDIR)/../oss_adapter/c3po_oss
#endif

CFLAGS += -Wno-psabi # suppress "The ABI for passing parameters with 64-byte alignment has changed in GCC 4.6"
CFLAGS += -Werror
CFLAGS += -Wunused-variable

CFLAGS += -I$(SRCDIR)/../cp
CFLAGS += -I$(SRCDIR)/../dp
CFLAGS += -I$(SRCDIR)/../dp/pipeline
CFLAGS += -I$(SRCDIR)/../cp_dp_api
CFLAGS += -I$(SRCDIR)/../interface
CFLAGS += -I$(SRCDIR)/../interface/ipc
CFLAGS += -I$(SRCDIR)/../interface/udp
CFLAGS += -I$(SRCDIR)/../interface/sdn
CFLAGS += -I$(SRCDIR)/../interface/zmq
CFLAGS += -I$(LIBGTPV2C_ROOT)/include
CFLAGS += -I$(LIBPFCP_ROOT)/include

CFLAGS += -I$(SRCDIR)/..
CFLAGS += -I$(SRCDIR)/../pfcp_messages
CFLAGS += -I$(SRCDIR)/state_machine

# Mandatory CFLAGS, LDFLAGS- DO NOT MODIFY
# #############################################################
CFLAGS += -DCP_BUILD

# workaround for a gcc bug with noreturn attribute
#  http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_controlplane.o += -Wno-return-type
endif

LDLIBS += -L$(LIBGTPV2C_ROOT)/lib -lgtpv2c
LDLIBS += -L$(LIBPFCP_ROOT)/lib -lpfcp

LDLIBS += -lpcap

# ngic-cp application options CFLAGS
# #############################################################

#For SDN NB interface enable SDN_ODL_BUILD OR SDN_ONOS_BUILD not both
ifneq (,$(findstring SDN_ODL_BUILD, $(CFLAGS)))
	SRCS-y += nb.c
	LDLIBS += -ljson-c
	LDLIBS += -lcurl
endif

# OSS-UTIL
CFLAGS +=  -I$(OSS_UTIL_ROOT)/include
LDFLAGS += -lstdc++
LDLIBS += -lstdc++
#LDLIBS +=  -L$(OSS_UTIL_ROOT)/lib -loss-util
LDLIBS += -lpthread
LDLIBS += -lrt
LDLIBS += -lpistache
LDLIBS += -lm

# ngic-cp debug/testing/profiling options CFLAGS
# #############################################################
#Enable'-g -O0' option for gdb
CFLAGS += -O0
#CFLAGS += -g -O0

#un-comment below line to remove all log level for testing.
CFLAGS += -DPERF_TEST

#Enable '-E' option to debug preprocessor output
#CFLAGS += -E

CFLAGS += $(WERROR_FLAGS)
CFLAGS_config.o := -D_GNU_SOURCE

#un-comment below line to generate req and resp timer stats in between
#CP<-->DP(ZMQ) and CP<-->FPC<-->DP.
#Note: Req and Resp timer stats is not supported for CP <--> DP direct comm over UDP.
#CFLAGS += -DSYNC_STATS

ifneq (,$(findstring SYNC_STATS, $(CFLAGS)))
	SRCS-y += stats_sync.c
endif

#un-comment below line to enable check peer node heartbeat.
CFLAGS += -DUSE_REST

ifneq (,$(findstring USE_REST, $(CFLAGS)))
	#VS: ECHO FILES
	CFLAGS += -I$(SRCDIR)/../restoration
	SRCS-y += $(SRCDIR)/../restoration/restoration_timer.o
	SRCS-y += restoration_peer.c
	SRCS-y += gtpv2c_echo_req.c
endif

#un-comment below line to enable FQ-CSID support in the control-plane
CFLAGS += -DUSE_CSID

ifneq (,$(findstring USE_CSID, $(CFLAGS)))
 #VS:Support partial failure FQ-CSID m/c
 SRCS-y += $(SRCDIR)/../pfcp_messages/csid_init.o
 SRCS-y += $(SRCDIR)/../pfcp_messages/csid_api.o
 SRCS-y += $(SRCDIR)/../pfcp_messages/csid_peer_init.o
 SRCS-y += $(SRCDIR)/../pfcp_messages/csid_cp_cleanup.o
endif

# Un-comment below line to read fake cp config.
#CFLAGS += -DSIMU_CP

# Un-comment below line to send fake delete session request from simulator.
#CFLAGS += -DDEL_SESS_REQ

# Comment below line to read UPF ip from cp.cfg instead of DNS query.
CFLAGS += -DUSE_DNS_QUERY

#ifneq (,$(findstring USE_DNS_QUERY, $(CFLAGS)))
	LIBDNSCLIENT_ROOT = $(SRCDIR)/../oss_adapter/c3po_oss/oss-util
	CFLAGS += -I$(LIBDNSCLIENT_ROOT)/include
	LDLIBS += $(LIBDNSCLIENT_ROOT)/lib/liboss-util.a -lstdc++ -lpistache
	LDLIBS += -L$(LIBDNSCLIENT_ROOT)/modules/c-ares -lcares
#endif

# Comment below line to build cp without GxApp.
CFLAGS += -DGX_BUILD

ifneq (,$(findstring GX_BUILD, $(CFLAGS)))
	SRCS-y += cp_app.c
	SRCS-y += ipc_api.c
	SRCS-y += state_machine/sm_gx_pcnd.o
	SRCS-y += $(SRCDIR)/gx_app/src/gx_pack.o
	SRCS-y += $(SRCDIR)/../pfcp_messages/pfcp_gx.o
	CFLAGS += -I$(SRCDIR)/../cp/gx_app/include
endif

# ngic-cp application security check CFLAGS
###############################################################
SECURITY_FLAGS = -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fexceptions  -fpie -fstack-protector-all -fstack-protector-strong -Wall -Werror=format-security -Werror=implicit-function-declaration

CFLAGS += $(SECURITY_FLAGS)

# ngic-cp include make overlays
# #############################################################
include $(RTE_SDK)/mk/rte.extapp.mk

