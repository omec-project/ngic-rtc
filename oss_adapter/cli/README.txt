                      C3POCLI
                      -------

Introduction
=============

The c3po command line interface (cli) is a tool to manage c3po nodes
in an homogeneous manner. The output of the commands is standard json, 
what enable extend the functionality by concatenating multiple commands. 

Internally c3pocli will convert a command into an http request and will
route it towards the url specified as a mandatory option. 

All c3po nodes will implement a REST api to be able to receive commands
from the c3pocli. 
  	  
Install c3pocli
===============

Install the python-pip package

    # apt-get install python-pip

c3pocli is delivered as a standard python module. The easiest way to install
it is by invoking pip as local installation (-r) on the requirement.txt. 
This will create a global entry point, making the c3pocli command available.

    # pip install -r requirements.txt

[Optional] Install c3pocli in a python virtual environment
==========================================================

To avoid interfering with the global python installation, c3pocli can be 
installed within a python virtual environment.

    # apt-get install python3-pip
    # apt-get install python3-virtualenv
    # virtualenv -p python3.5 venv
    # source venv/bin/activate
    # pip install -r requirements.txt

c3pocli tutorial
================

Commands within c3pocli are organized hierarchicaly. 

The first level of commands, represent the services availables under c3pocli:

- config, pcap and stats

The second level of commands, represent the actions that can be perform within
a service:
- config commands: describe-config-live, describe-perf-flag, describe-periodic-timer,
  describe-request-timeout, describe-request-tries, describe-transmit-count, describe-transmit-timer,
  set-perf-flag, set-periodic-timer, set-request-timeout, set-request-tries, set-transmit-count,
  set-transmit-timer

- stats commands: describe-stats-all, describe-stats-frequency, describe-stats-live,
  describe-stats-logging, set-stats-frequency, set-stats-logging, set-stats-reset

- pcap commands: describe-pcap-generation-status, set-pcap-generation
	  
The first level of commands corresponds to the services on which we want to 
operate. 

You can display the first level of commands by typing: 

- c3pocli http://127.0.0.1:12997 -h

This will output the following:

Usage: c3pocli [OPTIONS] C3PO_URL COMMAND [ARGS]...

  This script connects to the c3po endpoint C3PO_URL and issues rest
  commands against it

Options:
  -h, --help  Show this message and exit.

Commands:
  config
  pcap
  stats


We can see that we have 3 available commands: config, pcap and stats. 
In order to display the available operations within each command, we can type:

- c3pocli http://127.0.0.1:12997 config -h

The command will output the following:

Usage: c3pocli config [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  describe-config-live
  describe-perf-flag
  describe-periodic-timer
  describe-request-timeout
  describe-request-tries
  describe-transmit-count
  describe-transmit-timer
  set-perf-flag
  set-periodic-timer
  set-request-timeout
  set-request-tries
  set-transmit-count
  set-transmit-timer

- c3pocli http://127.0.0.1:12997 stats -h

The command will output the following:

  Usage: c3pocli stats [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  describe-stats-all
  describe-stats-frequency
  describe-stats-live
  describe-stats-logging
  set-stats-frequency
  set-stats-logging
  set-stats-reset

- c3pocli http://127.0.0.1:12997 pcap -h

The command will output the following:

Usage: c3pocli pcap [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  describe-pcap-generation-status
  set-pcap-generation

Lower level commands as set_stats_frequency require mandatory options,
you can check the required options of a given low level command by typing:

- c3pocli http://127.0.0.1:12997 stats set-stats-frequency -h

This will output:

    Usage: c3pocli stats set_stats_frequency [OPTIONS]

    Options:
      -f, --freq INTEGER  Stats generation interval in millisecond  [required]
      -h, --help          Show this message and exit.
	  
This gives us a good idea on how to modify the stat frequency generation. If we want to 
set it to 2000ms, the final command would be:

- c3pocli http://127.0.0.1:12997 stats set-stats-frequency -f 2000


List of available commands
==========================

- c3pocli http://127.0.0.1:12997 stats describe-stats-live
Displays the live stats of the interfaces.

- c3pocli http://127.0.0.1:12997 stats describe-stats-all
Displays the all supported messages on the interfaces.

- c3pocli http://127.0.0.1:12997 stats describe-stats-logging
Displays the stats logging mode to save data in log file

- c3pocli http://127.0.0.1:12997 stats set-stats-logging -n all
  c3pocli http://127.0.0.1:12997 stats set-stats-logging -n suppress
Modifies the stats logging mode to save data in log file

- c3pocli http://127.0.0.1:12997 stats describe-stats-frequency
Displays the current configured frequency value for stats adding in log file

- c3pocli http://127.0.0.1:12997 stats set-stats-frequency -f 2000
Modifies the frequency of stats generation to 2000 ms

- c3pocli http://127.0.0.1:12997 stats set-stats-reset
It will reset the value of health parameters, lastactivity and messages stats.

- c3pocli http://127.0.0.1:12997 pcap describe-pcap-generation-status
Displays the information of pcap generation flag.

- c3pocli http://127.0.0.1:12997 pcap set-pcap-generation -g start
  c3pocli http://127.0.0.1:12997 pcap set-pcap-generation -g stop
  c3pocli http://127.0.0.1:12997 pcap set-pcap-generation -g restart
Modifies the pcap generation framework mode value.
It also update the configuration file value.

- c3pocli http://127.0.0.1:12997 config describe-config-live
Displays the cp.cfg and dp.cfg configuration values in json format.

- c3pocli http://127.0.0.1:12997 config describe-perf-flag
To get the perf flag current value.

- c3pocli http://127.0.0.1:12997 config describe-periodic-timer
To get the periodic timer current value.

- c3pocli http://127.0.0.1:12997 config describe-request-timeout
To get the request timeout current value.

- c3pocli http://127.0.0.1:12997 config describe-transmit-count
To get the transmit count current value.

- c3pocli http://127.0.0.1:12997 config describe-request-tries
To get the request tries current value.

- c3pocli http://127.0.0.1:12997 config describe-transmit-timer
To get the transmit timer current value.

- c3pocli http://127.0.0.1:12997 config set-perf-flag -pf 1
  c3pocli http://127.0.0.1:12997 config set-perf-flag -pf 0
It is used for on/off to performance flag.
It also update the configuration file value.

- c3pocli http://127.0.0.1:12997 config set-periodic-timer -p 60
It modify the Periodic Timer value when user run the post command and update config file.
Note: If we fired command when P1 is running it will not effect in P1 timer and the P2 will work with
updated periodic timer value.

- c3pocli http://127.0.0.1:12997 config set-request-timeout -r 2000
It update the Request Timeout value when user run the post command.
It effect for that messages which comes after the post command and also update config file.

- c3pocli http://127.0.0.1:12997 config set-request-tries -r 5
It update the value of Request Tries when user run the post command.
It effect instant and also update the config file.

- c3pocli http://127.0.0.1:12997 config set-transmit-count -t 10
It update the Transmit Count value when user run the post command.
It effect instant and also update the config file.

- c3pocli http://127.0.0.1:12997 config set-transmit-timer -t 20
It modifies the Transmit Timer value when user run the command.
It effect instant and also update the config file.
