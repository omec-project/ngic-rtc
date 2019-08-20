#SDN_ODL_BUILD flag is set for ODL builds, unset for direct UDP or ZMQ[Direct || ODL] communication between CP and DP
#CFLAGS += -DSDN_ODL_BUILD

# ASR- Un-comment below line to shrink pipeline COREs used
CFLAGS += -DNGCORE_SHRINK

#Enable/Disable below flag to enable /disable CLI and Logger(OSS-UTILS)
CFLAGS += -DC3PO_OSS
