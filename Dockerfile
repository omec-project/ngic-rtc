# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

# Multi-stage Dockerfile

ARG BASE_OS=ubuntu:18.04
ARG RUN_BASE=runtime

## Stage build: kitchen sink stage for compiling dependencies and CP/DP bins
FROM $BASE_OS as build
ARG CPUS

WORKDIR /ngic-rtc
COPY install_builddeps.sh .
RUN ./install_builddeps.sh

COPY . ./
### USE_AF_PACKET for deploying in k8s
### ggdb must be made standard to help debugging
### O2 because O3 causes DP crash https://github.com/omec-project/ngic-rtc/issues/55
RUN bash -c "source ./install_builddeps.sh && make -j $CPUS clean && make -j $CPUS EXTRA_CFLAGS='-DUSE_AF_PACKET -ggdb -O2'"

## Stage runtime: no utils
FROM $BASE_OS as runtime
COPY install_rundeps.sh .

## Stage runtime-utils: install common production runtime utils
FROM runtime as runtime-utils
RUN bash -c "source ./install_rundeps.sh && install_run_utils && cleanup_image"

## Stage cp: creates the runtime image of control plane
FROM $RUN_BASE as cp
RUN bash -c "source ./install_rundeps.sh && install_run_cp_deps && cleanup_image"
COPY --from=build /ngic-rtc/cp/build/ngic_controlplane /bin/ngic_controlplane

## Label CP image
ARG org_label_schema_version=unknown
ARG org_label_schema_vcs_url=unknown
ARG org_label_schema_vcs_ref=unknown
ARG org_label_schema_build_date=unknown
ARG org_opencord_vcs_commit_date=unknown

LABEL org.label-schema.schema-version=1.0 \
      org.label-schema.name=ngic-cp \
      org.label-schema.version=$org_label_schema_version \
      org.label-schema.vcs-url=$org_label_schema_vcs_url \
      org.label-schema.vcs-ref=$org_label_schema_vcs_ref \
      org.label-schema.build-date=$org_label_schema_build_date \
      org.opencord.vcs-commit-date=$org_opencord_vcs_commit_date

## Stage dp: creates the runtime image of data plane
FROM $RUN_BASE as dp
RUN bash -c "source ./install_rundeps.sh && install_run_dp_deps && cleanup_image"
COPY --from=build /ngic-rtc/dp/build/ngic_dataplane /bin/ngic_dataplane

## Label DP image
ARG org_label_schema_version=unknown
ARG org_label_schema_vcs_url=unknown
ARG org_label_schema_vcs_ref=unknown
ARG org_label_schema_build_date=unknown
ARG org_opencord_vcs_commit_date=unknown

LABEL org.label-schema.schema-version=1.0 \
      org.label-schema.name=ngic-dp \
      org.label-schema.version=$org_label_schema_version \
      org.label-schema.vcs-url=$org_label_schema_vcs_url \
      org.label-schema.vcs-ref=$org_label_schema_vcs_ref \
      org.label-schema.build-date=$org_label_schema_build_date \
      org.opencord.vcs-commit-date=$org_opencord_vcs_commit_date
