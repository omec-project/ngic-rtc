# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation

DIRS-y =  lib cp dp test

#define targets
CLEANDIRS-y = $(DIRS-y:%=clean-%)
BUILDIRS-y = $(DIRS-y:%=build-%)

all: $(BUILDIRS-y)

$(BUILDIRS-y):
	$(MAKE) -C $(@:build-%=%)

clean: $(CLEANDIRS-y)

$(CLEANDIRS-y):
	$(MAKE) -C $(@:clean-%=%) clean
