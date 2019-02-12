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

---------------------------------------------------------------------------------------------
Next Generation Infrastructure Core (NGIC) Release Notes
---------------------------------------------------------------------------------------------
1.	Introduction
-----------------
This is the beta release for NGIC VNF.
NGIC application can be run independently or as part of the test harness.

2.	User Guide
--------------
Refer to README.MD for further details on NGIC, HLD, features supported, test
plan. For build configurations and execution requisites please refer to
INSTALL.MD.

3. Feature for this release
----------------------------
This release supports following features as part of NGIC:
-	NGIC can run as a standalone application on bare-metal linux server or on a
	virtual machine using SRIOV and OVS dpdk.
-	Packet Filters for Service Data Flow (SDF)
-	ADC(Application Detection and control) rules
-	PCC(Policy Control and Charging) rules
-	UE sessions with multiple Bearer support
-	SDF and APN based Qos Metering for MBR
-	Gtpv2c messages supported by CP on S11 interface
-	Charging by volume and asynchronous notification.
-	Ipv4 support
-	Sponsored Domain Name support


4. OS and kernel version
------------------------
This is supported on Ubuntu 14.04 and Ubuntu 16.04 and kernel version less than 4.5

5. Known Bugs and limitations
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

6. Future Work
--------------
-	Limitations will be addressed
-	Performance optimization
-	IPV6 support
-	Neighbour Discovery and ICMPv6 stack support
