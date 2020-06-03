# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

MAKEFLAGS += -j

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk
include $(dir $(realpath $(firstword $(MAKEFILE_LIST))))/*.mk
include $(dir $(realpath $(firstword $(MAKEFILE_LIST))))/../interface/*.mk

LIBGTPV2C_ROOT = $(SRCDIR)/../libgtpv2c

# binary name
APP = ngic_controlplane

# all source are stored in SRCS-y

SRCS-y := main.c
SRCS-y += gtpv2c.c
SRCS-y += gtpv2c_set_ie.c
SRCS-y += debug_str.c
SRCS-y += ue.c
SRCS-y += cp_stats.c
SRCS-y += packet_filters.c
SRCS-y += monitor_config.c
SRCS-y += cp_config.c

SRCS-y += gtpv2c_messages/bearer_resource_cmd.c
SRCS-y += gtpv2c_messages/create_bearer.c
SRCS-y += gtpv2c_messages/create_session.c
SRCS-y += gtpv2c_messages/create_s5s8_session.c
SRCS-y += gtpv2c_messages/delete_bearer.c
SRCS-y += gtpv2c_messages/delete_session.c
SRCS-y += gtpv2c_messages/delete_s5s8_session.c
SRCS-y += gtpv2c_messages/gtpv2c_echo.c
SRCS-y += gtpv2c_messages/modify_bearer.c
SRCS-y += gtpv2c_messages/downlink_data_notification.c
SRCS-y += gtpv2c_messages/release_access_bearer.c

SRCS-y += ../test/simu_cp/simu_cp.c
SRCS-y += ../interface/ipc/dp_ipc_api.c
SRCS-y += ../interface/interface.c
SRCS-y += ../interface/udp/vepc_udp.c

SRCS-y += ../cp_dp_api/vepc_cp_dp_api.c


CFLAGS += -Wno-psabi # suppress "The ABI for passing parameters with 64-byte alignment has changed in GCC 4.6"
CFLAGS += -Werror

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

# Mandatory CFLAGS, LDFLAGS- DO NOT MODIFY
# #############################################################
CFLAGS += -DCP_BUILD

# workaround for a gcc bug with noreturn attribute
#  http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_controlplane.o += -Wno-return-type
endif

LDLIBS += -L$(LIBGTPV2C_ROOT)/build -lgtpv2c

LDLIBS += -lpcap

# ngic-cp application options CFLAGS
# #############################################################
#validate both SDN_ODL_BUILD and ZMQ_COMM flag are not defined
ifneq (,$(findstring SDN_ODL_BUILD, $(CFLAGS), $(EXTRA_CFLAGS)))
ifneq (,$(findstring ZMQ_COMM, $(CFLAGS), $(EXTRA_CFLAGS)))
$(error "Both "SDN_ODL_BUILD" and "ZMQ_COMM" flags are defined. Exiting..")
endif
endif

#For SDN NB interface enable SDN_ODL_BUILD OR SDN_ONOS_BUILD not both
ifneq (,$(findstring SDN_ODL_BUILD, $(CFLAGS), $(EXTRA_CFLAGS)))
	SRCS-y += nb.c
	LDLIBS += -ljson-c
	LDLIBS += -lcurl
endif

ifneq (,$(findstring ZMQ_COMM, $(CFLAGS), $(EXTRA_CFLAGS)))
	SRCS-y += cp_sync.c
	SRCS-y += ../interface/zmq/zmq_push_pull.c
	LDFLAGS += -L/usr/local/lib -lzmq
endif

# ngic-cp debug/testing/profiling options CFLAGS
# #############################################################
#Enable'-g -O0' option for gdb
CFLAGS += -O3
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

ifneq (,$(findstring SYNC_STATS, $(CFLAGS), $(EXTRA_CFLAGS)))
	SRCS-y += stats_sync.c
endif

# Un-comment below line to read fake cp config.
#CFLAGS += -DSIMU_CP

# Un-comment below line to send fake delete session request from simulator.
#CFLAGS += -DDEL_SESS_REQ

# ngic-cp application security check CFLAGS
###############################################################
SECURITY_FLAGS = -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fexceptions  -fpie -fstack-protector-all -fstack-protector-strong -Wall -Werror=format-security -Werror=implicit-function-declaration

CFLAGS += $(SECURITY_FLAGS)

# ngic-cp include make overlays
# #############################################################
include $(RTE_SDK)/mk/rte.extapp.mk

