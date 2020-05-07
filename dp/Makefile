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
OSS_UTIL_ROOT = $(NG_CORE)/oss_adapter/c3po_oss/oss-util

include $(RTE_SDK)/mk/rte.vars.mk
include $(NG_CORE)/config/ng-core_cfg.mk

LIBPFCP_ROOT = $(SRCDIR)/../libpfcp

#DIRS-y += pipeline
# binary name
APP = ngic_dataplane

# all source are stored in SRCS-y
SRCS-y := up_main.c\
	up.c\
	gtpu.c\
	ipv4.c\
	util.c\
	stats.c\
	up_acl.c\
	up_init.c\
	up_ether.c\
	commands.c\
	gtpu_echo.c\
	up_config.c\
	pfcp_up_init.c\
	pfcp_up_llist.c\
	up_sess_table.c\
	up_pkt_handler.c\
	up_kni_pkt_handler.c\
	pipeline/epc_arp.o\
	pipeline/epc_spns_dns.o\
	pipeline/epc_packet_framework.o\
	$(SRCDIR)/../interface/interface.o\
	$(SRCDIR)/../interface/udp/vepc_udp.o\
	$(SRCDIR)/../interface/ipc/dp_ipc_api.o\
	$(SRCDIR)/../cp_dp_api/vepc_cp_dp_api.o\
	$(SRCDIR)/../pfcp_messages/pfcp_util.o\
	$(SRCDIR)/../pfcp_messages/pfcp_set_ie.o\
	$(SRCDIR)/../pfcp_messages/pfcp_up_sess.o\
	$(SRCDIR)/../pfcp_messages/pfcp_print_rule.o\
	$(SRCDIR)/../pfcp_messages/pfcp_req_resp.o\
	$(SRCDIR)/../pfcp_messages/pfcp_association.o\
	$(SRCDIR)/../pfcp_messages/pfcp_up_sess_rsp.o\
	#$(SRCDIR)/../pfcp_messages/pfcp_session.o\

SRCS-y += $(SRCDIR)/../oss_adapter/c3po_oss/gw_adapter.o
CFLAGS += -I$(SRCDIR)/../oss_adapter/c3po_oss

CFLAGS += -I$(SRCDIR)/
CFLAGS += -I$(SRCDIR)/pipeline
CFLAGS += -I$(SRCDIR)/../cp_dp_api
CFLAGS += -I$(SRCDIR)/../interface
CFLAGS += -I$(SRCDIR)/../interface/ipc
CFLAGS += -I$(SRCDIR)/../interface/udp
CFLAGS += -I$(SRCDIR)/../interface/sdn
CFLAGS += -I$(SRCDIR)/../interface/zmq
CFLAGS += -I$(SRCDIR)/../lib/libsponsdn
CFLAGS += -I$(SRCDIR)/../pfcp_messages
CFLAGS += -I$(RTE_SDK)/lib/librte_acl/
CFLAGS += -I$(LIBPFCP_ROOT)/include
CFLAGS +=  -I$(OSS_UTIL_ROOT)/include

# Mandatory CFLAGS, LDFLAGS- DO NOT MODIFY
# #############################################################
CFLAGS += -Wno-psabi # suppress "The ABI for passing parameters with 64-byte alignment has changed in GCC 4.6"

CFLAGS += -DLDB_DP	# should be included for dataplane.

CFLAGS += -DDP_BUILD

LIBDNSCLIENT_ROOT = $(SRCDIR)/../oss_adapter/c3po_oss/oss-util
CFLAGS += -I$(LIBDNSCLIENT_ROOT)/include
LDLIBS += $(LIBDNSCLIENT_ROOT)/lib/liboss-util.a -lstdc++ -lpistache
LDLIBS += -L$(LIBDNSCLIENT_ROOT)/modules/c-ares -lcares

CFLAGS += -Werror
CFLAGS += -Wunused-variable

# un-comment below line to Expose declaration of tdestroy()#
CFLAGS_config.o := -D_GNU_SOURCE

# ngic-dp application security check CFLAGS
# #############################################################
SECURITY_FLAGS = -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fexceptions -fpie -fstack-protector-all -fstack-protector-strong -Wall -Werror=format-security -Werror=implicit-function-declaration -Wno-unused-function

CFLAGS += $(SECURITY_FLAGS)

# workaround for a gcc bug with noreturn attribute
#  http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_dataplane.o += -Wno-return-type
endif

#dpdk-18.02 change build directory structure
LDFLAGS += -L$(RTE_SRCDIR)/../lib/libsponsdn/x86_64-native-linuxapp-gcc/ -lsponsdn

LDFLAGS += -L$(HYPERSCANDIR)/build/lib

LDFLAGS += -lexpressionutil -lhs -lhs_runtime -lstdc++ -lm -lcrypto

LDFLAGS += -lrte_pmd_af_packet

LDFLAGS += -lpcap

LDFLAGS += -L$(LIBPFCP_ROOT)/lib -lpfcp

# ngic-dp application options CFLAGS
# #############################################################
# ASR- Shrink pipeline COREs for Run to Completion (rtc) model
ifneq (,$(findstring NGCORE_SHRINK, $(CFLAGS)))
        SRCS-y += up_ddn.c
        SRCS-y += pipeline/epc_ul.o
        SRCS-y += pipeline/epc_dl.o
endif

ifneq (,$(findstring SDN_ODL_BUILD, $(CFLAGS)))
	SRCS-y += $(SRCDIR)/../interface/zmq/zmqsub.o
	SRCS-y += $(SRCDIR)/../interface/zmq/zmqpub.o
	LDFLAGS += -L/usr/local/lib -lzmq
endif

ifeq ($(SGX_BUILD), 1)
	SRCS-y += ssl_client.c
	CFLAGS += -DSGX_CDR
	CFLAGS += -I$(NG_CORE)/linux-sgx/common/inc
	LDFLAGS += -lssl
endif

# ngic-dp debug/testing/profiling options CFLAGS
# #############################################################
# gdb: un-comment 'CFLAGS += -g -O0' comment 'CFLAGS += -O3'
#CFLAGS += -O0
CFLAGS += -g -O0

#un-comment below line to remove all log level for preformance testing.
#CFLAGS += -DPERF_TEST

#un-comment below line to generate pcap on east-west interfaces
CFLAGS += -DPCAP_GEN

# Un-comment below line to read fake cp config.
#CFLAGS += -DSIMU_CP

# Un-comment below line to send fake delete session request from simulator.
#Note: This will impact data traffic performance.
#CFLAGS += -DDEL_SESS_REQ

# VS- Used CP counters for maintain simulator stats.
ifneq (,$(findstring SIMU_CP, $(CFLAGS)))
        SRCS-y += $(SRCDIR)/../cp/cp_stats.o
endif

# Enable STATIC ARP for testing with il_nperf
# NGCORE_SHRINK:: Un-comment below line to enable STATIC ARP
#CFLAGS += -DSTATIC_ARP

# Un-comment below line to print ADC, PCC, METER and SDF rule entry
# passed from FPC-SDN in add entry operation.
# Note : This flag works with Log level 'DEBUG'
CFLAGS += -DPRINT_NEW_RULE_ENTRY

# Un-comment below line to get packet stats on each core.
CFLAGS += -DSTATS

# Un-comment below line to enable GTP-ECHO packets count on display(For SHRINK version).
#CFLAGS += -DEXSTATS

# ASR- Un-comment below line to enable PCC, ADC, CDR, FILTERING, METERING pipeline stages.
#CFLAGS += -DINCLUDE_PIPELINE_STAGE

# Un-comment below line to enable PCC, ADC, CDR, FILTERING, METERING pipeline stages.
#CFLAGS += -DINCLUDE_ADC_STAGE

# Un-comment below line if you have 16 x 1GB hugepages.
#CFLAGS += -DHUGE_PAGE_16GB

# ngic-dp inter-op/functional options CFLAGS
# #############################################################
# Un-comment below line to enable DDN(Downlink data notification) statstics
#CFLAGS += -DDEBUG_DDN

# ASR- Un-comment below line to enable GTPU HEADER Sequence Number option.
#CFLAGS += -DGTPU_HDR_SEQNB

# Un-comment below line to enable hyperscan DPI.
# ASR- NGCORE_SHRINK for HYPERSCAN to be tested
#CFLAGS += -DHYPERSCAN_DPI

# Un-comment below line to enable ACL table creation and add default rule entry.
CFLAGS += -DDEFAULT_ACL_TABLE

# Un-comment below line to enable add default rule entry in acl table .
#CFLAGS += -DDEFAULT_ACL_RULE_ADD

# Un-comment below line to dump the acl table.
#CFLAGS += -DDEBUG_ACL

#un-comment below line to enable check peer node heartbeat.
CFLAGS += -DUSE_REST

ifneq (,$(findstring USE_REST, $(CFLAGS)))
	CFLAGS += -I$(SRCDIR)/../restoration
	SRCS-y += $(SRCDIR)/../restoration/restoration_timer.o
	SRCS-y += restoration_peer.c
	SRCS-y += gtpu_echo_req.c
endif

#un-comment below line to enable FQ-CSID support in the control-plane
CFLAGS += -DUSE_CSID

ifneq (,$(findstring USE_CSID, $(CFLAGS)))
	#VS:Support partial failure FQ-CSID m/c
	SRCS-y += $(SRCDIR)/../pfcp_messages/csid_init.o
	SRCS-y += $(SRCDIR)/../pfcp_messages/csid_api.o
	SRCS-y += $(SRCDIR)/../pfcp_messages/csid_peer_init.o
	SRCS-y += $(SRCDIR)/../pfcp_messages/csid_up_cleanup.o
endif

# ngic-dp  CFLAGS to be deprecated
# #############################################################
# Un-comment below line to get packet stats from command line.
#CFLAGS += -DCMDLINE_STATS

# Un-comment below line to enable core RX and core TX. All
# processing stages will be skipped.
#CFLAGS += -DRX_TX

# ngic-dp include make overlays
# #############################################################
include $(RTE_SDK)/mk/rte.extapp.mk
