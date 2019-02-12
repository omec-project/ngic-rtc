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

ifeq ($(HYPERSCANDIR),)
$(error "Please define HYPERSCANDIR environment variable")
endif

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = libsponsdn.a

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR) -I$(HYPERSCANDIR)/src


# all source are stored in SRCS-y
SRCS-y += sponsdn.c


include $(RTE_SDK)/mk/rte.extlib.mk
