#ZMQ_COMM flag is set for direct ZMQ communication, unset for direct UDP communication
#ZMQ communication is enabled by default
CFLAGS += -DZMQ_COMM

#Enable MULTI_UPFS only if ZMQ_COMM is enabled
ifneq (,$(findstring ZMQ_COMM, $(CFLAGS), $(EXTRA_CFLAGS)))
	CFLAGS += -DMULTI_UPFS
endif
