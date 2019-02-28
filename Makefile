# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation

RECURSIVETARGETS := all clean
CPDEPS := libgtpv2c
DPDEPS := lib
DIRS := cp dp test
# Use 'make WHAT=cp' to compile cp only
WHAT ?= $(DIRS)

$(RECURSIVETARGETS): $(WHAT)
$(CPDEPS) $(DPDEPS):
	$(MAKE) -C $@ $(MAKECMDGOALS)
cp: $(CPDEPS)
	$(MAKE) -C $@ $(MAKECMDGOALS)
dp: $(DPDEPS)
	$(MAKE) -C $@ $(MAKECMDGOALS)
test: $(CPDEPS) $(DPDEPS)
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: $(RECURSIVETARGETS) $(WHAT) $(CPDEPS) $(DPDEPS)
