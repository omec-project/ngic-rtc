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

docker-%: ORG ?= omecproject
docker-%: COMMIT = $(shell git rev-parse --short HEAD)
docker-%: TAG_SUFFIX = $(shell (git status --porcelain | grep -q .) && echo '-dirty')
docker-%: TAG ?= $(COMMIT)$(TAG_SUFFIX)
docker-%: IMAGES ?= build cp dp

# https://docs.docker.com/engine/reference/commandline/build/#specifying-target-build-stage---target
docker-build:
	for img in $(IMAGES); do \
		docker build --rm $(DOCKER_BUILD_ARGS) --target=$$img -t $(ORG)/ngic-$$img:$(TAG) . || exit 1; \
	done;

docker-push:
	for img in $(IMAGES); do \
		docker push $(ORG)/ngic-$$img:$(TAG) || exit 1; \
	done;

.PHONY: $(RECURSIVETARGETS) $(WHAT) $(CPDEPS) $(DPDEPS) docker-build docker-push
.SILENT: docker-build docker-push
