Copyright (c) 2017 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Next Generation Infrastructure Core (NGIC) VNF
==============================================

1. Introduction
-------------------------------------------
Evolved Packet Core (EPC) is a critical node in the wireless infrastructure,
which provides the data services to the end users. The NGIC is a
virtualized application providing the same service as the standalone node.
The SAE-GW (S-GW and P-GW)is the user plane node for the EPC which deals with
converged voice and data services on Long Term Evolution (LTE) networks. This
NGIC VNF has implements the SAE-GW. This has been developed using data plane
development kit version 16.04 (DPDK) optimized for Intel Architecture.

```text
                                       EPC Core
                             +-------------------------+
                             | +---------+ +---------+ |
                      Control| |  MME    | |  PCRF   | |
                       Signal| |         | |         | |
         +----------+  +-------+         | |         | |
+--+     |          |  |     | +-----+---+ +---+-----+ |
|UE+-----+          |  |     |       |         |       |
+--+     |          |  |     |   +-----------------+   |
         |          +--+     |   |   |s11      |Gx |   |
+--+     |  eNodeB  +--+     |   | +-------------+ |   |
|UE+-----+  (Base   |  |     |   | |    CP       | |   |
+--+     |  Station)|  |     |   | +-------------+ |   |   +--------------+
         |          |  |     |s1u| +-------------+ |sgi|   | External     |
+--+     |          |  +---------+ |    DP       | +-------+ Network      |
|UE+-----+          |  User  |   | +-------------+ |   |   |              |
+--+     +----------+  Data  |   |    NGIC NFV     |   |   |              |
              ||             |   +-----------------+   |   +--------------+
              ||             +-------------------------+
              ||
              ++
```

#### About DPDK

The DPDK IP Pipeline Framework provides a set of libraries to build a pipeline application.
In this document, NGIC will be explained in detail with its own building blocks.

This document assumes the reader possesses the knowledge of DPDK concepts and packet
framework. For more details, read DPDK's
[Getting Started Guide](http://dpdk.org/doc/guides/linux_gsg/index.html),
[Programmers Guide](http://dpdk.org/doc/guides/prog_guide/index.html),
[Sample Applications Guide](http://dpdk.org/doc/guides/sample_app_ug/index.html).

2.  Scope
----------
NGIC can be run on variety of servers running as a standalone application or on a
virtual machine using SRIOV and OVS dpdk as a NFVi layer.

3.	Feature List
----------------
The NGIC VNF currently supports the following SAE-GW features:

* PCC (Policy Control and Charging) rules configuration.
* ADC (Application Detection and control) rules configuration.
* Packet Filters for Service Data Flow (SDF) configuration.
* Packet Selectors/Filters for ADC configuration.
* UE sessions with multiple Bearer support.
* SDF and APN based Qos Metering for MBR.
* Charging by volume and asynchronous notification.
* Enable command line or display stats periodically.
* IPv4 support
* Multiport support
* Sponsored Domain Name support

4.	High Level Design
----------------------
The NGIC VNF application is divided into Control plane (CP) and Data plane (DP).
Please refer to Figure 1 for the basic blocks in the NGIC VNG.
CP is used to set the PCC rules, QoS profiles, and UE Session to DP via UDP or
ZMQ communication performed by the cp_dp_api library.
Currently ADC rules are static, and provided by the adc_rules.cfg file.

```text
        +----------------+
        |                |
+-----> |    Control     |
 S11    |    Plane       |
<-----+ |                |
        |                |
        +-------+--------+
                |
                |
                | IPC
                |
                v
        +-----------------+
        |                 |
        |                 |
+-----> |     Data        | +--->
 S1U    |     Plane       |  SGi
<-----+ |                 | <---+
        |                 |
        +-----------------+
		Figure1
```

When a packet arrives in DP, it follows the flow as mentioned in Figure 2 and appropriately sent to the output port.

```text
          +-----------------------------------------------------------------------------------------------------+
          |                        NGIC Data Plane Flow Diagram.                                                |
          |                               +---------------------------------+           +-----------------+     |        Flow1
          |  +------+  +------+  +------+ |    UE session                   |  +------+ | SDF & ADC Filter|     |    <--------------+
          |  | CDR  |  | APN  |  | PCC  | | +--------------------------+    |  | PCC  | |                 |     |        Flow2
   Flow1  |  |Charg |  | Meter|  | Meter| | |Default            sdf1   |    |  |Gating| |    sdf1         |     |    <--------------+
<-------+ |  |ing   |  |      |  |      | | |Bearer             sdf3   |    |  |      | | <-----------+   |     |
   Flow2  |  |      |  |      |  | sdf1 | | +--------------------------+    |  | sdf1 | |    sdf2         |     |
<-------+ |  |per UE|  |per UE|  | sdf2 | |                                 |  | sdf2 | | <-----------+   |     |        Flow3
   Flow3  |  |per ADC  |      |  | sdf3 | |                                 |  | sdf3 | |                 |     |    <--------------+
<-------+ |  |per   |  |      |  | sdf4 | | +--------------------------+    |  | sdf4 | |                 |     |        Flow4
   Flow4  |  | bearer  |      |  |      | | |Dedicated          sdf2   |    |  |      | | <-----------+   |     |    <--------------+
<-------+ |  |      |  |      |  |      | | |Bearer             sdf4   |    |  |      | |    sdf3         |     |
          |  +------+  +------+  +------+ | +--------------------------+    |  |      | | <-----------+   |     |
          |                               |                                 |  +------+ |    sdf4         |     |
          |                               +---------------------------------+           +-----------------+     |
          |                                                                                                     |
          +-----------------------------------------------------------------------------------------------------+

				Figure2 - explanation of DP flow with 4 flows.
```

The control plane manages session establishment and management by polling the configured S11 interface. Alternatively,
the s11 interface may be bypassed to read/write packet capture (pcap) files, as the allocation of TEID and IP addresses
are deterministic. The Control Plane manages within its own data structures all required information to process the
management of its connections, therefore tests may be performed independent on the data plane. The high level design of
the control plane is displayed in figure 3.

The control plane is limited to the types of gtpv2c messages it supports. Further, error handling is not implemented as
specified by 3gpp 29.274, specifically the MME will receive no indication of error. Messages indicating error type *may*
be displayed to console output, depending on type of error. Messages currently supported by the control plane include:

```text
  GTP Echo Request (RX) / GTP Echo Reply (TX)
  Create Session Request (RX) / Create Session Reply (TX)
  Delete Session Request (RX) / Delete Session Reply (TX)
  Modify Bearer Request (RX) / Modify Bearer Reply (TX)
  Create Bearer Request (TX) / Create Bearer Reply (RX)
  Delete Bearer Request (TX) / Delete Bearer Reply (RX)
  Bearer Resource Command (RX - on the condition TAD operation type specifies addition or deletion of packet filter)
```

Furthermore, the control plane expects the contents of these messages to contain certain Information Elements (IE). These may
differ from all corner cases allowed by 3gpp 29.274, which will be ignored, and may drop messages if some IEs are not present.

```text
                  +-------------------------------------------------------------+
                  |                     NGIC Control Plane                      |
                  |   +------------------+                 +------------+       |
                  |   | Create Session   |_________________| IP         |       |
                  |   | Parser/Responder |                 | allocation |       |
                  |   +------------------+_______________  +------------+       |
                  |    |                                 \                      |
                  |    |  +------------------+            \___+-------------+   |
                  |    |  | Modify Bearer    |________________| UE/Session/ |   |
                  |    |  | Parser/Responder |                | Bearer data |   |
                  |    |  +------------------+      __________+-------------+   |
                  |    |   |  .                    /                        |   |
          +-----> |    |   |  .                   /          +------------+ |   |
         S11/pcap |    |   |  .                  /        ___| Packet     | |   |
          <-----+ |    |   |  +------------------+       /   | Filters    | |   |
                  |    |   |  | Create Bearer    |______/    +------------+ |   |
                  |    |   |  | Parser/Responder |                          |   |
                  |    |   |  +------------------+                          |   |
                  |    |   |   |  ...                                       |   |
                  |    |   |   |    +------------------+                    |   |
                  |    |   |   |    | Delete Session   |____________________|   |
                  |    |   |   |    | Parser/Responder |                        |
                  |    |   |   |    +------------------+                        |
                  |    |   |   |     |                                          |
                  |    |   |   |     |                                          |
                  |   +------------------+                                      |
                  |   |    CP_DP_API     |                                      |
                  |   +------------------+                                      |
                  +-----------||------------------------------------------------+
                              ||
                              \/
                              DP

                  Figure3 - NGIC Control Plane
```

For low level details on the Control Plane see [CP_README.MD](docs/CP_README.MD)

5.	Build, install, configure and test
------------------------------------------

Please refer to [install_notes] (INSTALL.MD)

6.	Test Plan
------------------

*	Tested upto 1M flows (32K, 128K, 512K, 1M)
*	Tested with multicore and multithreaded configurations.
*	Tested with IXIA and pktgen(dpdk based) for traffic generation
Note: pktgen 3.0 requires additional changes to support gtpu's inner ip address setting. The patch is part of the package.
* 	Tested against ng4T traffic generator

7. Automated Testing Script
-----------------

#### 7.1 General

autotest.sh is designed for end-to-end testing and logging of NGIC against the ng40 traffic generator.

Usage: ./autotest.sh [ debug | short ]
  debug provides for line numbers to debug the script
  short performs the same tests with fewer UEs and for a shorter duration

#### 7.2 AutoTest Logging

The autotest script creates log directories $NGIC_DIR/logs/$DATE for each time
it is executed. Within this directory, four files indicate the current state of
the code and system under test.
    -   cmdline - copied from /proc/cmdline
    -   cpuinfo - copied from /proc/cpuinfo
    -   run_state.patch - generated from 'git diff' command
    -   .<git rsa-1 hash of last commit generated by 'git rev-parse HEAD'>


For each test run, 6 logs are captured
    -   *.cvs - cdr from test
    -   *.cfg - ng40 test configuration
    -   *.cp.log - redirected all ngic_controlplane output to file
    -   *.dp.log - redirected all ngic_dataplane output to file
    -   *.ng40.log - redirected all ng40test output to file
    -   *.ng40.short.log - copied log file from ng40 test/log directory

#### 7.3 AutoTest Tests Performed

Currently, three sets tests are performed:
    -   tc_userplane_mpps $subs=250000 $duration=500 $activebearerTimeinms=187000 $rate=1000 $numran=4
        * runs three times, with $pps=900000, $pps=1000000, $pps=1100000
        * runs agains 1 data plane worker
    -   tc_userplane_mpps $subs=250000 $duration=500 $activebearerTimeinms=187000 $rate=1000 $numran=4
        * runs three times, with $pps=3900000, $pps=4000000, $pps=4100000
        * runs against 4 data plane workers
    -   tc_pff_tft_mpps $subs=125000 $duration=500 $activebearerTimeinms=187000 $rate=1000 $numran=4
        * runs three times, with $pps=900000, $pps=1000000, $pps=1100000
        * runs against 1 data plane worker

#### 7.4 AutoTest Framework

The autotest.sh script was written to allow rapid yet full configuration of
batch testing. If alternate tests are desired, please see the run_testcase
syntax at the end of the file.

#### 7.5 AutoTest Configuration

To configure the autotest script for your system, please set the following
variables in the script.
    -   NGIC_DIR - root directory of ng-core
    -   NG40_DIR - ng40 test directory
    -   NG40_HOST - hostname/ip of ng40 server

8. Known Issues and limitations
-----------------------------
-       The current tested ADC rules are not fully conformant to 3GPP release 12 ADC AVPs.
-       ARP handling supported under KNI-Linux
-       ICMP supported under KNI-Linux
-       IPV4 fragmentation and option header not supported.
-       IPSec not supported.
-       Only ethernet v2 frame format is supported.
-       Logic issues found in prepare_acl_parameter() in dp/acl.c
-       ACL context's (struct rte_acl_ctx) trans_table parameter is not being checked
        for NULL by dpdk. trans_table may appear as NULL during handling of stray GTP
        packets by DP.
-       Updates to filter packets arriving at the S1U and SGI interfaces for
        processing by linux. ARP Packets OR
        packets w/ dest address = {[S1U_IP, SGI_IP]; MULTICAST ADDR; BROADCAST ADDR}
        are sent to Linux for processing. All other packets are sent to the UL or DL
        fast path cores for processing. These enhancements need to be tested for following,
                1- To be tested with targeted packets
                2- To be tested with S1U and SGI GW configuration
-       Addressed htonl byte order conversion issues, however the following items need to be addressed,
                1- Some inconsistencies continue to remain in these fields
                   @~/interface/interface.c::zmq_mbuf_process::CREATE_SESSION, MODIFY_SESSION,
                   DELETE_SESSION. These needs to be addressed over test scenarios/setups.
                2- Byte order changes to ~/cp/gtpv2c_messages/modify_bearer.c, delete_session.c need
                   to be thoroughly tested.
                3- This patch has NOT been tested for SGWC-SGWU, PGWC-PGWU, and dedicated bearer
                   configurations/test scenarios. Hence byte order changes to
                   ~/cp/gtpv2c_messages/create_bearer.c, create_s5s8_session.c,
                   delete_bearer.c, delete_s5s8_session.c have not been tested.
-		For running ngic-rtc without kni STATIC_ARP must be enabled in the Makefile.
		ether.c::construct_ether_hdr(...) needs linux (kni) support to ARP discover S1U, SGI peer MAC.

-		Without KNI option is only for preformance profiling. There is no support for:
		    - SGW-PGW separaton not suported in wokni option
		    - DP_DDN
