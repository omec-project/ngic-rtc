                      C3POCLI
                      -------

Introduction:
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

    # apt-get install python-virtualenv
    # virtualenv -p python3.5 venv
    # source venv/bin/activate
    # pip install -r requirements.txt


c3pocli deployment
==================

As the c3po node url is specified as a parameter on c3pocli commands, the only requirement 
deployment requirement for c3pocli is to run in a machine (physical or virtual) with connectivity 
to the VNF we want to manage.

c3pocli acts as an http client, converting commands into http request and routing them
towards the url specified on the command. This allows a configuration where c3pocli could 
communicate to different nodes (fig 1).


                      +----+ 
                +-----|hss |   
                |     +----+ 
                | 
 +-------+ http |     +----+
 |c3pocli|------+-----|ctf |
 +-------+      |     +----+
                |
                |     +----+ 			
                +-----|pcrf|  
                      +----+  
            fig. 1
			

An alternative configuration is to have c3pocli installed on each node (fig 2).

 +-----------+ 
 |c3po       |
 |node       |
 | +-------+ |
 | |c3pocli| |   
 | +-------+ |
 +-----------+ 
     fig. 2
     
    
Logs and Stats Configuration Parameters
=======================================

The following parameters are configurable values for hss, ctf and pcrf. 
You can find and modify these values on each corresponding /conf/app.json configuration file.

logsize:        Max size (Mb) of the application  log file
lognumber:      Number of rotatory files for application logs 
logname:        Path and filename of application logs
statlogsize:    Max size (Mb) of the stat log file 
statlognumber:  Number of rotatory files for stats logs 
statlogname:    Path and filename of stat log file 
auditlogsize:   Max size (Mb) of the audit log file
auditlognumber: Number of rotatory files for audit logs
auditlogname:   Path and filename of audit log file
statfreq:       Frequency in (ms) of stats generation


Metrics tracked
===============

The following tables show a translation of each row for the statistic csv file generated file. 
For each couple of data, the first value row represents and example of row logged in the statistic
file and the second row, (table formatted) represent the translated metric 


Metrics tracked for HSS
=======================

2018-07-18T20:28:57Z,S6A,AIR,0,0,0,0,0,0,0,0,0,0,
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| 0-ER_DIAMETER_SUCCESS| 0-ER_DIAMETER_INVALID_AVP_VALUE| 3GPP-DIAMETER_ERROR_RAT_NOT_ALLOWED| 3GPP-DIAMETER_ERROR_ROAMING_NOT_ALLOWED| 3GPP-DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE| UNKNOWN|
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:28:55Z,S6A,ULR,0,0,0,0,0,0,0,0,0,0,0
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| 0-ER_DIAMETER_INVALID_AVP_VALUE| 3GPP-DIAMETER_ERROR_USER_UNKNOWN| 3GPP-DIAMETER_ERROR_RAT_NOT_ALLOWED| 3GPP-DIAMETER_ERROR_UNKNOWN_SERVING_NODE| 3GPP-DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION| UNKNOWN|
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:28:55Z,S6A,PUR,0,0,0,0,0,0,0,0,0,,
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| 0-ER_DIAMETER_SUCCESS| 0-ER_DIAMETER_INVALID_AVP_VALUE| 3GPP-DIAMETER_ERROR_USER_UNKNOWN| 3GPP-DIAMETER_ERROR_UNKNOWN_SERVING_NODE| UNKNOWN|
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:28:55Z,S6T,CIR,0,0,0,0,0,0,0,,,,
+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| 0-ER_DIAMETER_SUCCESS| 3GPP-DIAMETER_ERROR_USER_UNKNOWN| UNKNOWN|
+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:28:57Z,S6T,NIR,0,0,0,0,0,0,0,0,,,
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| 0-ER_DIAMETER_SUCCESS| 3GPP-DIAMETER_ERROR_USER_UNKNOWN| 3GPP-DIAMETER_ERROR_USER_NO_APN_SUBSCRIPTION| UNKNOWN|
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:28:55Z,S6A,IDR,0,0,0,0,0,0,0,,,,
+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| 0-ER_DIAMETER_SUCCESS| 3GPP-DIAMETER_ERROR_USER_UNKNOWN| UNKNOWN|
+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:28:57Z,S6T,RIR,0,0,0,0,0,0,0,0,,,
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| 0-ER_DIAMETER_SUCCESS| 0-ER_DIAMETER_INVALID_AVP_VALUE| 3GPP-DIAMETER_ERROR_USER_UNKNOWN| UNKNOWN|
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:28:57Z,S6C,SRR,0,0,0,0,0,0,0,0,,,
+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| 0-ER_DIAMETER_SUCCESS| 0-ER_DIAMETER_MISSING_AVP| 3GPP-DIAMETER_ERROR_USER_UNKNOWN| 3GPP-DIAMETER_ERROR_ABSENT_USER| UNKNOWN|
+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Metrics tracked for CTF
=======================

2018-07-18T20:39:46Z,RF,ACR,0,0,0,0,0,0
+-----------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| 0-ER_DIAMETER_SUCCESS| UNKNOWN|
+-----------------------------------------------------------------------------------------------------------------------------------+

Metrics tracked for PCRF
=======================

2018-07-18T20:41:35Z,GX,CCR,0,0,0,0,0,0,0
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| ATTEMPTS| 0-ER_DIAMETER_SUCCESS| 0-ER_DIAMETER_INVALID_AVP_VALUE| UNKNOWN|
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:41:33Z,GX,RAR,0,0,0,0,0,0,0
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| ATTEMPTS| 0-ER_DIAMETER_SUCCESS| 0-ER_DIAMETER_INVALID_AVP_VALUE| UNKNOWN|
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:41:33Z,SD,TSR,0,0,0,0,0,0,0
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| ATTEMPTS| 0-ER_DIAMETER_SUCCESS| 0-ER_DIAMETER_INVALID_AVP_VALUE| UNKNOWN|
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:41:33Z,SD,RAR,0,0,0,0,0,0,0
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| ATTEMPTS| 0-ER_DIAMETER_SUCCESS| 0-ER_DIAMETER_INVALID_AVP_VALUE| UNKNOWN|
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:41:33Z,SD,CCR,0,0,0,0,0,0,0
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| 0-ER_DIAMETER_SUCCESS| 0-ER_DIAMETER_INVALID_AVP_VALUE| UNKNOWN|
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:41:33Z,ST,TSR,0,0,0,0,0,0,0
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| 0-ER_DIAMETER_SUCCESS| 0-ER_DIAMETER_INVALID_AVP_VALUE| UNKNOWN|
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------+

2018-07-18T20:41:33Z,ST,STR,0,0,0,0,0,0,0
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------+
Date-Time(ISO 8601)| Application| Command Code| Send Attempts| Send KO| Receive Attempts| Receive KO| 0-ER_DIAMETER_SUCCESS| 0-ER_DIAMETER_INVALID_AVP_VALUE| UNKNOWN|
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------+

c3pocli tutorial
================

Commands within c3pocli are organized hierarchicaly. 

The first level of commands, represent the services availables under c3pocli:

- logger and stats

The second level of commands, represent the actions that can be perform within
a service:

- describe_loggers, set_logger_level, describe_stats_frequency, describe_stats_live, set_stats_frequency
	  
The first level of commands corresponds to the services on which we want to 
operate. 

You can display the first level of commands by typing: 

- c3pocli http://127.0.0.1:8090 -h

This will output the following:


    Usage: c3pocli [OPTIONS] C3PO_URL COMMAND [ARGS]...

      This script connects to the c3po endpoint C3PO_URL and issues rest
      commands against it

    Options:
      -h, --help  Show this message and exit.

    Commands:
      logger
      stats


We can see that we have 2 available commands: logger and stats. 
In order to display the available operations within each command, we can type:

- c3pocli http://127.0.0.1:8090 logger -h

or

- c3pocli http://127.0.0.1:8090 stats -h

The first command will output the following:


    Usage: c3pocli logger [OPTIONS] COMMAND [ARGS]...

    Options:
      -h, --help  Show this message and exit.

    Commands:
      describe_loggers
      set_logger_level


The second command will output:

    Usage: c3pocli stats [OPTIONS] COMMAND [ARGS]...

    Options:
      -h, --help  Show this message and exit.

    Commands:
      describe_stats_frequency
      describe_stats_live
      set_stats_frequency

Lower level commands as set_stats_frequency and set_logger_level require mandatory options, 
you can check the required options of a given low level command by typing:

- c3pocli http://127.0.0.1:8090 stats set_stats_frequency -h

This will output:

    Usage: c3pocli stats set_stats_frequency [OPTIONS]

    Options:
      -f, --freq INTEGER  Stats generation interval in millisecond  [required]
      -h, --help          Show this message and exit.
	  
This gives us a good idea on how to modify the stat frequency generation. If we want to 
set it to 2000ms, the final command would be:

- c3pocli http://127.0.0.1:8090 stats set_stats_frequency -f 2000

If we want to set the logger level, we may display the required options for this command by 
typing:

- c3pocli http://127.0.0.1:8090 logger set_logger_level -h

This will output:

    Usage: c3pocli logger set_logger_level [OPTIONS]
    
    Options:
      -n, --name TEXT      Logger name  [required]
      -l, --level INTEGER  Logger level  [required]
      -h, --help           Show this message and exit.
	  
If we want to modify the level of the system logger, we can issue the following command:

- c3pocli http://127.0.0.1:8090 logger set_logger_level -n system -l 5

List of available commands
==========================

- c3pocli http://127.0.0.1:8090 stats describe_stats_frequency
Displays the current configured frequency value for stats generation

- c3pocli http://127.0.0.1:8090 stats describe_stats_live
Dislplays the current values of collected stats

- c3pocli http://127.0.0.1:8090 stats set_stats_frequency -f 2000
Modifies the frequency of stats generation to 2000 ms

- c3pocli http://127.0.0.1:8090 logger describe_loggers
Displays a list of loggers configured for a given c3po node and its associated logging level

- c3pocli http://127.0.0.1:8090 logger set_logger_level -n system -l 5
Modifies the level of the system logger to 5

