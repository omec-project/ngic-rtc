#!/usr/bin/python

import zmq
import sys

def main():

    try:
        context = zmq.Context(1)
        # Socket facing clients
	pull_port = "tcp://" + sys.argv[1] + ":" + sys.argv[2]
        frontend = context.socket(zmq.PULL)
        frontend.bind(pull_port)
	print "Listening to port", pull_port

        # Socket facing services
	push_port = "tcp://" + sys.argv[1] + ":" + sys.argv[3]
        backend = context.socket(zmq.PUSH)
	backend.bind(push_port);
	print "Sending to port", push_port

        zmq.device(zmq.STREAMER, frontend, backend)
    except Exception, e:
        print e
        print "bringing down zmq device"
    finally:
        pass
        frontend.close()
        backend.close()
        context.term()

if __name__ == "__main__":
    main()
