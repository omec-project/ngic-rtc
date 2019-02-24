# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = libgtpv2c.a

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR)/include

# all source are stored in SRCS-y
SRCS-y += $(wildcard $(SRCDIR)/src/*.c)

include $(RTE_SDK)/mk/rte.extlib.mk
