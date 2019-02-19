#ZMQ_COMM flag is set for direct ZMQ communication, unset for direct UDP communication
#ZMQ communication is enabled by default
#CFLAGS += -DZMQ_COMM

# ASR- Un-comment below line to shrink pipeline COREs used
CFLAGS += -DNGCORE_SHRINK
