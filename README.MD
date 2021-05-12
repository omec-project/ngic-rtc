Copyright (c) 2021 T-Mobile  
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

> ## ***Feature Summary***
>> ### **E-UTRAN Feature Support (23.401 r15)**
>> Description | Reference | Git Tag
>> ------------ | :-------------: | :------------:
>> E-UTRAN Initial Attach | 5.3.2.1-1 | Stable
>> Tracking Area Update procedure with Serving GW change | 5.3.3.1-1 | Experimental
>> Tracking Area Update procedure with Serving GW change and data forwarding | 5.3.3.1A-1 | Experimental
>> E-UTRAN Tracking Area Update without S‑GW Change | 5.3.3.2-1 | Stable
>> UE triggered Service Request | 5.3.4.1-1 | Stable
>> Network Triggered Service Request | 5.3.4.3-1 | Experimental
>> eNodeB initiated Connection Suspend procedure | 5.3.4A-1 | Stable
>> MO Data transport in NAS PDU | 5.3.4B.2-1 | Experimental
>> MT Data transport in NAS PDUs | 5.3.4B.3-1 | Experimental
>> Establishment of S1-U bearer during Data Transport in Control Plane CIoT EPS Optimisation | 5.3.4B.4-1 | Experimental
>> S1 Release Procedure | 5.3.5-1 | Stable
>> UE initiated Connection Resume procedure | 5.3.5A-1 | Stable
>> MME-Initiated Detach Procedure | 5.3.8.3-1 | Stable
>> HSS-Initiated Detach Procedure | 5.3.8.4-1 | Stable
>> Dedicated Bearer Activation Procedure | 5.4.1-1 | Stable
>> Bearer Modification Procedure with Bearer QoS Update | 5.4.2.1-1 | Stable
>> HSS Initiated Subscribed QoS Modification | 5.4.2.2-1 | Experimental
>> Bearer Modification Procedure without Bearer QoS Update | 5.4.3-1 | Stable
>> PDN GW Initiated Bearer Deactivation | 5.4.4.1-1 | Stable
>> MME initiated Dedicated Bearer Deactivation | 5.4.4.2-1 | Stable
>> UE requested bearer resource modification | 5.4.5-1 | Stable
>> E-UTRAN initiated E-RAB modification procedure | 5.4.7-1 | Stable
>> X2-based handover without Serving GW relocation | 5.5.1.1.2-1 | Stable
>> X2-based handover with Serving GW relocation | 5.5.1.1.3-1 | Stable
>> S1-based handover | 5.5.1.2.2-1 | Experimental
>> S1-based handover, Reject | 5.5.1.2.3-1 | Experimental
>> Inter RAT handover Cancel | 5.5.2.5.2-1 | Experimental
>> GW Secondary RAT usage data Reporting procedure | 5.7A.3-2 | Stable
>> Notification of the ECGI, TAI and/or user CSG information changes | 5.9.2.1-1 | Stable
>> UE requested PDN connectivity | 5.10.2-1 | Stable
>> UE or MME requested PDN disconnection | 5.10.3-1 | Stable
>> MME triggered Serving GW relocation | 5.10.4-1 | Stable
>> Dedicated bearer activation in combination with the default bearer activation at attach or UE requested PDN connectivity | F.1 | Experimental
>>
>> ### **Enhancements**
>> Description | Git Tag
>> ------------ | :---:
>> User Level Packet Copying | Stable
>> Mobility (Promotion/Demotion) SAEGW <-> PGW, SAEGW <-> SGW | Stable
>> Predefined Rules | Stable
>> TEID Range Support | Stable
>> Restoration support utilizing FQ-CSID’s | Stable
>> Restoration for CP (SGW-C, PGW-C & SAEGW-C) failures | Stable
>> Gx Support for SAEGW-C and PGW-C | Stable
>> libgtpv2c for S11 and S5/S8 interfaces | Stable
>> libpfcp for Sxa, Sxb and SxaSxb interfaces | Stable
>> REST based CLI for CP & DP | Stable
>> APN and Distributed Deployment Support | Stable
>> User Plane Discovery (DNS) | Stable
>> Billing (via Sx, utilizing Redis w/SGX) | Stable
>> Event Reporting Funciton | Stable
>> IPv6, IPv4V6 support in Mobility Management | Experimental
>> IPv6 interface support for S11, S5/S8, S1-U, SGI-LAN and Sx interfaces | Experimental

Next Generation Infrastructure Core (NGIC) VNF
==============================================

1. Introduction
-------------------------------------------
Evolved Packet Core (EPC) is a critical node in the wireless infrastructure, which provides the data services to the end users. The NGIC is a virtualized application providing the same service as the standalone node. User plane node for the EPC which deals with converged voice and data services on Long Term Evolution (LTE) networks.This has been developed using data plane development kit version 18.02 (DPDK) optimized for Intel Architecture.
It supports CUPS architecture. CUPS means Control and User Plane Separation of EPC nodes and provides the architecture enhancements for the separation of functionality in the Evolved Packet Core’s SGW and PGW. This enables flexible network deployment and operation, by distributed or centralized deployment and the independent scaling between control plane and user plane functions.

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
              Figure 1. EPC Core Architecture
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
virtual machine using SRIOV and OVS dpdk as a NFVi layer. It supports SGWC, PGWC,
SGWU, PGWU, SAEGWC and SAEGWU modes of the servers. SAEGWC and PGWC communicates
with PCRF and SGWC/PGWC/SAEGWC communicates with DNS for selecting User Plane nodes.

3.	Feature List
----------------
The NGIC VNF currently supports the following features:

* IPv6 interfaces and applications support in Deployment models
* IPv6 support in Mobility Management
* User level packet copying
* TEID implementation as per "C3PO TEID Assignment and Recovery Scenarios"
* Restoration CSID implementation and UP recovery
* UPF selection by DNS
* Handover scenarios
* Predefined Rules
* libgtpv2c auto generated code on S11 and S5/S8 interfaces
* libpfcp auto generated code integration on SxaSxb, Sxa, Sxb interfaces
* CLI and statistics parameters
* Peer echo and request timers
* Multi node connectivity support in control plane and user plane
* E-UTRAN procedures
* PCC (Policy Control and Charging) rules configuration.
* Packet Filters for Service Data Flow (SDF) configuration.
* UE sessions with multiple Bearer support
* IPv4 support
* Charging by volume and time notification
* Enable command line or display stats periodically
* Promotion Demotion

4.	High Level Design
----------------------
The NGIC VNF application is divided into Control plane (CP) and Data plane (DP).
Please refer to Figures below for the basic architecture in the NGIC.

```text
         +--------------+             +---------------+
         |              |             |               |
+------->+              +------------>+               |
   S11   |    SAEGWC    |     GX      |     PCRF      |
<--------+              <-------------+               |
         |              |             |               |
         +----+-----+---+             +---------------+
              |     ^
              | SX  |
              |     |
              v     |
         +----+-----+---+
         |              |
+------->+              +------------>
   S1U   |    SAEGWU    |     SGI
<--------+              +<-----------+
         |              |
         +--------------+
		Figure 2. Combined Gateway Architecture


         +--------------+             +---------------+           +--------------+
         |              |             |               |           |              |
+------->+              +------------>+               +---------->+              |
   S11   |     SGWC     |     S5S8C   |      PGWC     |    GX     |    PCRF      |
<--------+              <-------------+               +<----------+              |
         |              |             |               |           |              |
         +----+-----+---+             +----+------+---+           +--------------+
              |     ^                      |      ^
              | SXA |                      |  SXB |
              |     |                      |      |
              v     |                      v      |
         +----+-----+---+             +----+------+---+
         |              |             |               |
+------->+              +------------>+               +---------->
   S1U   |     SGWU     |    S5S8U    |      PGWU     |  SGI
<--------+              +<------------+               +<---------+
         |              |             |               |
         +--------------+             +---------------+
		Figure 3. Split Gateway Architecture

+----------------+
|                |
|                |
|      DNS       |
|                |
|                |
+----+-------+---+
     ^       |
     |       |
     |       |
     |       |
     |       v
+----+-------+----+            +-------------------+
|                 |            |                   |
|      SGWC       +----------->+                   |
|      PGWC       |            |     REDIS-SGX     |
|     SAEGWC      |            |                   |
|                 +<-----------+                   |
+-----------------+            +-------------------+
		Figure 4. Control Plane With DNS and Redis Server

                   +--------+        +--------+          +-------+
                   |        |        |        |          |       |
                   |        +------->+        +--------->+       |
+----------+       | D-ADMF |        |  ADMF  |          | LEGACY|
|          |       |        +<-------+        +<---------+  ADMF |
| Control  +<------+        |        |        |          |       |
|  Plane   |       +--------+        +--------+          +-------+
|          |
+-----+----+
      |
      |
      |
      |             +--------+        +--------+           +-------+
      |             |        |        |        |           |       |
      |   X2 Events |        +------->+        +---------->+       |
      +------------>+ D-DF2  |        |  DF2   |           | LEGACY|
                    |        +<-------+        +<----------+  DF2  |
      +------------>+        |        |        |           |       |
      |   X2 Events +--------+        +--------+           +-------+
      |
      |
+-----+---+
|         |
|  User   |
| Plane   |          +--------+        +--------+           +-------+
|         +--------->+        |        |        |           |       |
+---------+          |        +-------->        +---------->+       |
                     |  D-DF3 |        |  DF3   |           | LEGACY|
                     |        |        |        |           |  DF3  |
                     |        +<-------+        +<----------+       |
                     +--------+        +--------+           +-------+
		Figure 5. Control Plane and User Plane with User Level Packet Copying Components
```

5.	Build, install, configure and test
------------------------------------------

Please refer to [Control and User Plane Gateway User Guide](docs/Control_User_Plane_Gateway_User_Guide_1.9.docx).

6. Known Issues and limitations
-----------------------------
-       ICMP supported under KNI-Linux
-       IPV4/IPV6 fragmentation and option header not supported.
-       IPSec not supported.
-       ARP handling supported under KNI-Linux.
-       QoS Control in User Plane is not supported.
-       ISR procedure is not supported.
-       Multimedia Priority Service is not supported
