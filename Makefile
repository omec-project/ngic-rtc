# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-present Open Networking Foundation
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

VERSION                  ?= $(shell cat ./VERSION)
DOCKER_TAG               ?= ${VERSION}
DOCKER_REGISTRY          ?=
DOCKER_REPOSITORY        ?=
DOCKER_BUILD_ARGS        ?=

## Docker labels. Only set ref and commit date if committed
DOCKER_LABEL_VCS_URL     ?= $(shell git remote get-url $(shell git remote))
DOCKER_LABEL_VCS_REF     ?= $(shell git diff-index --quiet HEAD -- && git rev-parse HEAD || echo "unknown")
DOCKER_LABEL_COMMIT_DATE ?= $(shell git diff-index --quiet HEAD -- && git show -s --format=%cd --date=iso-strict HEAD || echo "unknown" )
DOCKER_LABEL_BUILD_DATE  ?= $(shell date -u "+%Y-%m-%dT%H:%M:%SZ")

CP_NAME                  ?= cp
DP_NAME                  ?= dp
CP_IMAGENAME             ?= ${DOCKER_REGISTRY}${DOCKER_REPOSITORY}ngic-${CP_NAME}:${DOCKER_TAG}
DP_IMAGENAME             ?= ${DOCKER_REGISTRY}${DOCKER_REPOSITORY}ngic-${DP_NAME}:${DOCKER_TAG}

# https://docs.docker.com/engine/reference/commandline/build/#specifying-target-build-stage---target
docker-build:
	docker build $(DOCKER_BUILD_ARGS) \
		--target ${CP_NAME} \
		--tag ${CP_IMAGENAME} \
		--label "org.label-schema.schema-version=1.0" \
		--label "org.label-schema.name=ngic-${CP_NAME}" \
		--label "org.label-schema.version=${VERSION}" \
		--label "org.label-schema.vcs-url=${DOCKER_LABEL_VCS_URL}" \
		--label "org.label-schema.vcs-ref=${DOCKER_LABEL_VCS_REF}" \
		--label "org.label-schema.build-date=${DOCKER_LABEL_BUILD_DATE}" \
		--label "org.opencord.vcs-commit-date=${DOCKER_LABEL_COMMIT_DATE}" \
                .
	docker build $(DOCKER_BUILD_ARGS) \
		--target ${DP_NAME} \
		--tag ${DP_IMAGENAME} \
		--label "org.label-schema.schema-version=1.0" \
		--label "org.label-schema.name=ngic-${DP_NAME}" \
		--label "org.label-schema.version=${VERSION}" \
		--label "org.label-schema.vcs-url=${DOCKER_LABEL_VCS_URL}" \
		--label "org.label-schema.vcs-ref=${DOCKER_LABEL_VCS_REF}" \
		--label "org.label-schema.build-date=${DOCKER_LABEL_BUILD_DATE}" \
		--label "org.opencord.vcs-commit-date=${DOCKER_LABEL_COMMIT_DATE}" \
                .

docker-push:
	docker push ${CP_IMAGENAME}
	docker push ${DP_IMAGENAME}

.PHONY: $(RECURSIVETARGETS) $(WHAT) $(CPDEPS) $(DPDEPS) docker-build docker-push
.SILENT: docker-build docker-push
