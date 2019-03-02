# Next Generation Infrastructure Core

<!-- toc -->

- [Introduction](#introduction)
- [Feature List](#feature-list)
- [High Level Design](#high-level-design)
- [Installation](#installation)
- [Release Notes](#release-notes)

<!-- tocstop -->

## Introduction

NGIC-RTC is a Control User Plane Separated (CUPS) architecture 3GPP `TS23501`
based implementation of Evolved Packet Core (EPC) Service and Packet Gateway
functions (SGW, PGW) in a run to complete design to maximize packet processing
performance per compute core. NGIC-RTC allows runtime configurable
SGWC-SGWU <S5/S8>, PGWC-PGWU or SPGWC-SPGWU options.

Interface between Control and User/Data plane i.e. S-PGWC and S-PGWU is ZMQ
push-pull mechanism over TCP transport. Options for UDP transport or SDN
integration are available too.

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

## Feature List

The NGIC currently supports the following SAE-GW features:

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

## High Level Design

The NGIC is divided into Control plane (CP) and Data plane (DP). CP is used to
set the PCC rules, QoS profiles, and UE Session to DP via UDP or ZMQ communication
performed by the cp_dp_api library. Currently [ADC rules](config/adc_rules.cfg)
are static.

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
```

Below is a packet walk for the DP

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
```

The CP does session establishment and management by polling the configured S11
interface. Alternatively, the s11 interface may be bypassed to read/write packet
capture (pcap) files, as the allocation of TEID and IP addresses are deterministic.
The CP manages within its own data structures all required information to process the
management of its connections, therefore tests may be performed independent of
the data plane. The high level design of the control plane is shown below.

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
```

Messages currently supported by the control plane include:

```text
  GTP Echo Request (RX) / GTP Echo Reply (TX)
  Create Session Request (RX) / Create Session Reply (TX)
  Delete Session Request (RX) / Delete Session Reply (TX)
  Modify Bearer Request (RX) / Modify Bearer Reply (TX)
  Create Bearer Request (TX) / Create Bearer Reply (RX)
  Delete Bearer Request (TX) / Delete Bearer Reply (RX)
  Bearer Resource Command (RX - on the condition TAD operation type specifies addition or deletion of packet filter)
```

Error handling is not implemented as specified by 3GPP `29.274`, specifically the
MME will receive no indication of error. Messages indicating error type *may* be
displayed to console output, depending on type of error.

Furthermore, the control plane expects the contents of these messages to contain
certain Information Elements (IE). These may differ from all corner cases allowed
by 3gpp 29.274, which will be ignored, and may drop messages if some IEs are not present.

For low level details on the Control Plane see [CP_README.MD](docs/CP_README.MD)

## Installation

Please refer [INSTALL.MD](INSTALL.MD) for instructions to install and run CP and
DP

## Release Notes

Please refer [RELEASE_NOTES.MD](RELEASE_NOTES.MD)
