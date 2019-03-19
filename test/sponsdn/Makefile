# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = sponsdn

# all sources are stored in SRCS-y
SRCS-y := main.c

CFLAGS += -O3 $(WERROR_FLAGS) -I$(RTE_SRCDIR)/../../lib/libsponsdn/

LDFLAGS += -L$(RTE_SRCDIR)/../../lib/libsponsdn/x86_64-native-linuxapp-gcc/ -lsponsdn

LDFLAGS += -L$(HYPERSCANDIR)/build/lib

LDFLAGS += -lexpressionutil -lhs -lhs_runtime -lstdc++ -lm -lpcap


DEPDIRS-y += ../lib

include $(RTE_SDK)/mk/rte.extapp.mk
