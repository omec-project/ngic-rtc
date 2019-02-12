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

NGIC Installation Guide
=======================

1. System Topology
------------------
```text
Deployment-1 as SPGW(Service GW and PDN GW combined):
                             +----------+
                             | MME-     |
                             | System5: |
                             | ng4t     |
                             |          |
                             +----------+
                                 |1G
                  +-----------------------------+
                  |           NGIC VNF          |
                  |                             |
                  | +-------------------------+ |
                  | |   SPGW : ControlPlane   | |
                  | |                         | |
                  | +-----+---------+---------+ |
                  | |     |         |           |
+------------+    | |     |IPC/     +fpc        |    +------------+
| Traffic    |    | |     |UDP/ZMQ   SDN        |    | Traffic    |
| Generator  |    | |     |         +zmq        |    | Generator  |
| System3:   | 10G| +-----+-------------------+ |10G | System3:   |
| ixia, ng4t,+------+   SPGW : DataPlane      +------+ ixia, ng4t,|
| pktgen etc |    | |                         | |    | pktgen etc |
+------------+    | +-------------------------+ |    +------------+
                  +-----------------------------+


Deployment-2 as SGW(Service GW) and PGW(PDN GW):
                                            +----------+
                                            | MME-     |
                                            | System5: |
                                            | ng4t     |
                                            |          |
                                            +----------+
                                                |1G
                  +-------------------------------------------------------------+
                  |                           NGIC VNF                          |
                  |                                                             |
                  | +-------------------------+     +-------------------------+ |
                  | |    SGW : ControlPlane   +-----+    PGW : ControlPlane   | |
                  | |                         |     |                         | |
                  | +-----+---------+---------+     +-----+---------+---------+ |
                  | |     |         |               |     |         |           |
+------------+    | |     |IPC/     +fpc            |     |IPC/     +fpc        |     +------------+
| Traffic    |    | |     |UDP/ZMQ   SDN            |     |UDP/ZMQ   SDN        |     | Traffic    |
| Generator  |    | |     |         +zmq            |     |         +zmq        |     | Generator  |
| System3:   | 10G| +-----+-------------------+     +-----+-------------------+ |10G  | System3:   |
| ixia, ng4t,+------+    SGW : DataPlane      +-----+    PGW : DataPlane      + ------+ ixia, ng4t,|
| pktgen etc |    | |                         |     |                         | |     | pktgen etc |
+------------+    | +-------------------------+     +-------------------------+ |     +------------+
                  +-------------------------------------------------------------+
```

* Deployment-1 shows how SPGW(Combined SGW and PGW) fits in the end to end setup. Instance of control plane
takes care of SGW and PGW handling. Same applies for Dataplane instance.
* Deployment-2 shows how SGW and PGW can be separately installed in the deployment. In this case SGW and PGW in
control plane communicate over S5S8 protocol, and same way SGW and PGW in dataplane communicate with each other.
* Data Plane(DP) and Control plane(CP) can run on three different systems using SDN, UDP or ZMQ interfaces
* CP and DP can be run in a Virtualized Environment.
* With SDN communication, CP to SDN works on FPC and SDN to DP works on ZMQ.
* System3 and System4 are the traffic generators connected to VNF over 10G interfaces.
* System5 hosts the MME. Currently NGIC VNF has been tested with ng4t MME.
* MME sends commands to ControlPlane over 1G interface. This can be higher
speed interface also.


2. Configuration
-----------------

#### 2.1 Configuration files

Following config files contain static rule information:
adc_rules.cfg - Contains Application Detection Control (ADC) rules
pcc_rules.cfg - Contains packet filters and policy, charging, & control
                information that the Control Plane uses to install PCC and
                Filters on the DP on initialization.
sdf_rules.cfg - Contains Service Data Filter rules to apply on data plane traffic.
meter_profile.cfg - Metering rules to apply on traffic. This is not used currently.

Following config files should be configured properly with ports information
and interface for communication needed by the applications:
In below file uncomment one of the section for configurating as SPGW, SGW or PGW.
cp_config.cfg - Configure port IPs and other parameters needed by control
                plane application
dp_config.cfg - Configure port IPs and MACs needed by data plane app
interface.cfg - To add interface details between CP and DP. For example, for
                UDP set ip address and ports.

Following config files are referenced only for specific use case:
rules_ipv4.cfg - Set ACL ipv4 filter if ACL_READ_CFG is to be used
rules_ipv6.cfg - Set ACL ipv6 filter if ACL_READ_CFG is to be used
simu_cp.cfg - Use this to set info in simulated control plane testing.
                See `Simulated CP config'
static_arp.cfg - Configure IP to MAC address mapping for devices whose address will not be
				resolved through ARP dynamically.

#### 2.2 CP Configuration
`static_pcc.cfg` contains packet filters and policy, charging, & control information
that the Control Plane uses to install PCC and Filters on the DP on initialization. (For this
reason, the DP must be executed prior to the CP). Currently, packet filters are static, and may
not be altered during execution, thus any bearer resource commands received by the CP from the
MME must utilize the predefined filters contained within this file.

CP dpdk run parameters:

```text
    --socket-mem X,Y           - Memory has been allocated according to NUMA-awareness,
                                 suggest using memory on socket corresponding to corelist
    --file-prefix cp           - Required for collocated Control and Dataplane
    --no-pci                   - Does not require use of DPDK bound NICs
```

CP application run parameters to be supplied in cp_config.cfg:

| ARGUMENT          | PRESENCE    | DESCRIPTION                                |
|:------------------|:------------|:-------------------------------------------|
| -SPGW_CFG         | MANDATORY   | CP run setup:01(SGWC), 02(PGWC),03(SPGWC)  |
| -s11_sgw_ip       | MANDATORY   | Local interface IP exposed to Linux        |
|                   |             | networking stack to be used by the Control |
|                   |             | Plane for messaging with the MME           |
| -s11_mme_ip       | MANDATORY   | MME IP                                     |
| -s1u_sgw_ip       | MANDATORY   | Network interface IP exposed by DP; must be|
|                   |             | equivalent to --s1u_ip parameter of DP     |
| -s5s8_sgwc_ip     | OPTIONAL    | Applicable in case of SGWC configuration   |
| -s5s8_sgwu_ip     | OPTIONAL    | Applicable in case of SGWC configuration   |
| -s5s8_pgwc_ip     | OPTIONAL    | Applicable in case of PGWC configuration   |
| -s5s8_pgwu_ip     | OPTIONAL    | Applicable in case of PGWC configuration   |
| -ip_pool_ip       | MANDATORY   | Along with mask, defines pool of IP        |
|                   |             | addresses that CP may assign to UEs        |
| -ip_pool_mask     | MANDATORY   | ip_pool_mask                               |
| -apn_name         | MANDATORY   | Access Point Name label supported by CP;   |
|                   |             | must correspond to APN referenced in create|
|                   |             | session request messages along the s11     |
| -pcap_file_in     | OPTIONAL    | Ignores s11 interface and acts as if       |
|                   |             | packets contained in input file arrived    |
|                   |             | from MME                                   |
| -pcap_file_out    | OPTIONAL    | Creates a capture of messages created by   |
|                   |             | CP. Mainly for development purposes        |
| -memory           | MANDATORY   | Memory size for hugepages setup            |
| -numa0_memory     | MANDATORY   | Socket memory related to numa0 socket      |
| -numa1_memory     | MANDATORY   | Socket memory related to numa1 socket      |
|:------------------|:------------|:-------------------------------------------|

#### 2.3 DP Configuration :
DP dpdk run parameters:

```text
        -l corelist             - Enable the cores needed by DP (5 cores for s1u rx/tx, sgi rx/tx, stats, mct and iface, plus number of worker cores)
For example, to enable 1 worker core and 5 fixed cores on socket 0, set corelist as "3-6,8"
        -n                      - Recommend using all available memory channels
        --socket-mem X,Y        - Memory has been allocated according to NUMA-awareness, suggest using memory on socket corresponding to corelist
        --file-prefix cp        - Required for collocated Control and Dataplane.
```

DP application parameters to be supplied in dp_config.cfg:

Dataplane supported command line arguments are:


| ARGUMENT          | PRESENCE    | DESCRIPTION                                |
|:------------------|:------------|:-------------------------------------------|
| --spgw_cfg        | MANDATORY   | DP run setup:01(SGWU), 02(PGWU),03(SPGWU)  |
| --s1u_ip          | MANDATORY   | S1U IP address of the SGW.                 |
| --s1u_mac         | MANDATORY   | S1U port mac address of the SGW.           |
| --sgi_ip          | MANDATORY   | SGI IP address of the SGW.                 |
| --s5s8_sgwu_port  | MANDATORY   | Port of SGWU s5s8 interface. Applicable for|
|                   |             | SGWU configuration only                    |
| --s5s8_sgwu_mac   | MANDATORY   | MAC of SGWU s5s8 interface. Applicable for |
|                   |             | SGWU configuration only                    |
| --s5s8_pgwu_port  | MANDATORY   | Port of PGWU s5s8 interface. Applicable for|
|                   |             | PGWU configuration only                    |
| --s5s8_pgwu_mac   | MANDATORY   | MAC of PGWU s5s8 interface. Applicable for |
|                   |             | PGWU configuration only                    |
| --sgi_mac         | MANDATORY   | SGI port mac address of the PGW.           |
| --s1uc            | OPTIONAL    | core number to run s1u rx/tx.              |
| --sgic            | OPTIONAL    | core number to run sgi rx/tx.              |
| --bal             | OPTIONAL    | core number to run load balancer.          |
| --mct             | OPTIONAL    | core number to run mcast pkts.             |
| --iface           | OPTIONAL    | core number to run Interface for IPC.      |
| --stats           | OPTIONAL    | core number to run timer for stats.        |
| --num_workers     | MANDATORY   | no. of worker instances.                   |
| --log             | MANDATORY   | log level, 1- Notification, 2- Debug.      |
| --memory          | MANDATORY   | Memory size for hugepages setup            |
| --numa0_memory    | MANDATORY   | Socket memory related to numa0 socket      |
| --numa1_memory    | MANDATORY   | Socket memory related to numa1 socket      |
| --corelist        | MANDATORY   | Set corelist for DP here
|:------------------|:------------|:-------------------------------------------|

* Enter the mac addresses for s1u and sgi ports obtained from step 2.1
  respectively
* ngic_dataplane application will pick the available cores as enabled by
  the corelist if the s1uc, sgic, bal, mct, iface and stats options are not
  supplied.

Please refer to `dp/run.sh` for example configuration.

#### 2.4 Interface Configuration

The file `config/interface.cfg` defines the various configurable interface
parameters. The diagram below displays the components and interfaces along the
direction of messages. Listed below the diagram is the descriptions of
[Components](./INSTALL.MD#2-4-1-components) and
[Interfaces](./INSTALL.MD#2-4-2-interfaces).

To disable CP to DP direct communication over ZMQ, disable ZMQ_COMM CFLAG in
`ng-core_cfg.mk`. In this case ZMQ push/pull model is used.

ZMQ_COMM flag (ZMQ Push Pull) is enabled by default in config/ng-core_cfg.mk
Thus, ZMQ(tcp) is the default mode of communication between CP & DP in NGIC.

```text
+-------------------------------------------------------------------------------+
|                                    CP                                          |
|     zmq_cp_ip          cp_comm_ip         +----------------------------------------------+
|push_port  pull_port        port           |  HTTP-POST    cp_nb_server_ip:port |         |
+---v----------^-----------v-----^----------|------v-^----------------v----------+         |
    v          ^           v     ^          |      v ^                v                    |
+---v----------^--+        v     ^          |      v ^ HTTP/SSE       v HTTP      <NorthBound Interface>
|   v  ZMQ     ^   |       v     ^          |      v ^                v                    |
|   v streamer ^   |       v     ^          | +----v-^----------------v-----------------+  |
|   v          ^   |       v     ^          | | fpc_ip:port    fpc_ip:fpc_topology_port |  |
+---v----------^---+       v     ^          | |                                         |  |
    v          ^           v     ^          | |               FPC - ODL                 |  |
    v          ^           v     ^          | +----v----------------------^-------------+  |
    v          ^           v     ^          |      v                      ^                |
    v          ^           v     ^          |      v ZMQ                  ^           FPC  |
    v   ZMQ    ^           v UDP ^          |      v                      ^           SDN  |
    v          ^           v     ^          |      v                      ^                |
    v          ^           v     ^          | +----v----------------------^-------+        |
    v          ^           v     ^          | |    v     ZMQ FORWARDER    ^       |        |
    v          ^           v     ^          | |    v                      ^       |        |
    v          ^           v     ^          | | zmq_sub_ip:port   zmq_pub_ip:port |        |
    v          ^           v     ^          | +----^----------------------v-------+        |
    v          ^           v     ^          |      ^                      v                |
    v          ^           v     ^          |      ^ ZMQ                  v ZMQ   <SouthBound Interface>
    v          ^           v     ^          |      ^                      v                |
+---v----------^-----------v-----^----------------------------------------v------+         |
|pull_port  push_port       port            |                COMM_ZMQ            |         |
|      zmq_cp_ip          dp_comm_ip        +----------------------------------------------+
|                                    DP                                          |
+--------------------------------------------------------------------------------+
```
##### 2.4.1 Components

- FPC - SDN Controller: Interfaces contained within this component are used
    only when NGIC is built with the `DSDN_ODL_BUILD` CFLAG set in
    `ng-core_cfg.mk`.

- ZMQ FORWARDER: the instance of the forwarder_device.py script. ***This
    component should be co-located with the FPC Karaf component.***

- FPC - Karaf: The ODL Karaf instance running the FPC protocol. ***This
    component should be co-located with the FPC Karaf component.***

- CP: Control Plane

    HTTP-POST: the component of the CP that sends HTTP POST messages to the
    fpc_ip:port of the Karaf instance.

- DP: Data Plane

    COMM_ZMQ: the component of the DP that sends/receives messages from the
    ZMQ FORWARDER

##### 2.4.2 Interfaces

- `zmq_sub_ip` & `zmq_sub_port`: the ip:port of the zmq subscriber interface of
the ZMQ FORWARDER device.

- `zmq_pub_ip` & `zmq_pub_port`: the ip:port of the zmq publisher interface of
the ZMQ FORWARDER device.

- `dp_comm_ip` & `dp_comm_port`: the ip:port of the DP UDP interface used for
    direct communication by the DP to and from the CP.

- `cp_comm_ip` & `cp_comm_port`: the ip:port of the CP UDP interface used for
    direct communication by the CP to and from the DP.

- `fpc_ip` & `fpc_port`: the ip:port of the FPC ODL plugin for use in
    communication along the NorthBound Interface.

- `fpc_topology_port`: the port used (in combination with the `fpc_ip`) to
    request the (DPN) topology from the FPC ODL plugin.

- `cp_nb_ip` & `cp_nb_port`: the ip:port of the CP component to communication
    along the NorthBound interface with with FPC ODL plugin.

- `zmq_cp_ip`, `zmq_cp_push_port` & `zmq_cp_pull_port`: the ip:port's on which zmq streamer
    listens and CP connects to this IP for push/pull requests.

- `zmq_dp_ip`, `zmq_dp_push_port` & `zmq_dp_pull_port`: the ip:port's on which zmq streamer
    listens and DP connects to this IP for push/pull requests.

Additional information on the northbound interfaces and their uses can be found
in the [CP_README.MD](docs/CP_README.MD)


##### 2.4.3 Co-located Configuration
For a co-located NGIC deployment along with the FPC Controller, each IP address
parameter in the `config/interface.cfg` file may be set to the loopback
address `127.0.0.1`.

##### 2.4.4 FPC Port Parameters
Each of the FPC port values have been defined by the FPC Agent Opendaylight
project. These values should not be changed without modification to the default
configuration ofthe FPC components. These parameters and values include
`zmq_sub_port=5560`, `zmq_pub_port=5559` and `fpc_port=8181`. More information
can be found at the [FPC GitHub page](https://github.com/opendaylight/fpc).


##### 2.4.6 NGIC Port Parameters
The `dp_comm_port`, `cp_comm_port`, and `cp_nb_server_port` parameters may
utilize any available ports on the respective systems.


#### 2.5 Simulated CP config (Optional):
This option can be used to test Dataplane with a simulated ControlPlane
without the need of MME.
Please enable SIMU_CP in dp/Makefile to use this.
Edit `config/simu_cp.cfg` with following information:

|       __Key__         |                __Value__                      |
|:----------------------|:----------------------------------------------|
|__enodeb_ip__          | eNodeB (Base station) IP address              |
|__max_ue_sess__        | Max number of UE sessions                     |
|__ue_ip_start__        | UE start ip from which max no. of UEs will be configured. Should be in sync with the traffic flow|
|__ue_ip_start_range__  | Set this to start of user equipment address.  |
|__as_ip_start__        | Application Server IP                         |
|__max_entries__        | Max SDF table entries                         |
|__max_rules__          | Number of SDF rules                           |
|__max_ul_rules__       | Number of uplink SDF rules                    |
|__max_dl_rules__       | Number of downlink SDF rules                  |
|__max_meter_profile_entries__ | maximum meter profiles to be created.  |
|__default_bearer__     | Default bearer number, this is set to 5.      |
|__dedicated_bearer__   | Set this to 0 if dedicated bearer is not reqd.|
|:----------------------|:----------------------------------------------|

Example configuration:

```conf
        enodeb_ip = 11.1.1.101
        ue_ip_start = 16.0.0.1
        ue_ip_start_range = 16.0.0.0
        as_ip_start = 13.1.1.110
        max_entries = 100
        max_rules = 24
        max_ul_rules = 12
        max_dl_rules = 12
        max_ue_sess = 1000
        max_meter_profile_entries = 100
        default_bearer = 5
        dedicated_bearer = 0
```
To test Sponsored Domain Names with SIMU CP:
Domain names should be mentioned in adc_config.cfg
Setup a "veth" pair such as

sudo ip link add s1u type veth peer name s1u_peer
sudo ip link add sgi type veth peer name sgi_peer

To work with these interfaces, the dp is launched with the
foll. arguments
 --no-pci --vdev eth_af_packet0,iface=s1u --vdev eth_af_packet1,iface=sgi

The DNS response is then sent to the sgi interface as below

sudo tcpreplay  --intf1=sgi_peer <path to>/dnsresp.pcap

The DNS response matches any of the  preconfigured domain names
you should see a message saying that the corresponding rule ID has
been added

3. Installation and Compilation
-------------------------------

###### Dependencies
* DPDK 16.11.4: Downloaded as a submodule, using `--recursive` when cloning this repo or using the `install.sh` script.
Alternatively, it can be downloaded and installed manually from [here](http://fast.dpdk.org/rel/dpdk-16.11.4.tar.gz).
Both the options are avialble as part of install.sh below.
* libpcap-dev
* libzmq
* libcurl
* libssl-dev

###### Environment variables

```shell
export RTE_SDK=<dpdk 16.11.4 directory>
export RTE_TARGET=x86_64-native-linuxapp-gcc
```

DPDK configuration file `dpdk-16.04_common_linuxapp` provided, is to be
copied/moved to `$RTE_SDK/config/common_linuxapp` before building dpdk.
This is done by install.sh script.

###### Initial Compilation

#### 3.1 Using install.sh:

Run "./install.sh" in ngic root folder.

Following are the options for setup:

```text

----------------------------------------------------------
 Step 1: Environment setup.
----------------------------------------------------------
[1] Check OS and network connection
[2] Configured Service - Collocated CP and DP

----------------------------------------------------------
 Step 2: Download and Install
----------------------------------------------------------
[3] Agree to download
[4] Download packages
[5] Download DPDK zip
[6] Install DPDK
[7] Download hyperscan

----------------------------------------------------------
Step 3: Build NGIC
----------------------------------------------------------
[8] Build NGIC

[9] Exit Script

```

[1] This will check the OS version and network connectivity and report
    any anomaly. If the system is behind a proxy, it will ask for a proxy
    and update the required environment variables.
[2] Select services to build. You will be prompted to select following options
    from sub-menu, and optionally edit the memory size:
        1. CP Only
        2. DP Only
        3. Collocated CP and DP
	For Option 2 and 3 :
	It will ask for "Do you want data-plane with Intel(R) SGX based CDR?" pop-up first,
	If accept to use DP with Intel(R) SGX then it will have additional option in main menu like below
	```
	[7] Download hyperscan
	[8] Download Intel(R) SGX SDK
	```
	option-8 will download and install Intel(R) SGX SDK

[3] Select yes in this option to be able to download the required packages.
[4] Actual download of the dependent packages like libpcap, build essentials
    etc.
[5] Download dpdk as a zip file using this option.
[6] Build and set environment variables to use DPDK.
[7] Download hyperscan library. This option is displayed in menu when
    'DP Only' or 'Collocated CP and DP' option is selected in [2].
[8] Build controlplane and dataplane applications. This sets the RTE_SDK
    environment variable and builds the applications.

#### 3.2 Manual build:

Control Pland and Data Plane applications can be built using install.sh using
"Step 3 Build NGIC" or can be done manually as follows:

1. Setup RTE_SDK and RTE_TARGET variables using ./setenv.sh.
   Point RTE_SDK to the path where dpdk is downloaded.
2. Use "make" in ngic root directory to build both CP and DP.
   OR
   Use respective "make" in CP and DP to build them individually.

Sponsered DNS setup:
Dependencies:
hyperscan-4.1.0 library is dependent on libbost version greater than 1.58. On Ubuntu 14.04,
libboost version supported is 1.55. So it is preferable to use Ubuntu 16.04 for SPONSDN setup.

a. Download and untar hyperscan-4.1.0.tar.gz
b. apt-get install cmake
c. apt-get install libboost-all-dev (Make sure it is > 1.58 version)
d. apt-get install ragel
e. cd hyperscan-4.1.0
f. mkdir build; cd build
g. cmake -DCMAKE_CXX_COMPILER=c++ ..
h. cmake --build .

4.2 Build libsponsdn
a. export HYPERSCANDIR=<path_of_hyperscan_directory>
b. cd lib/libsponsdn
c. make

#### 3.3 Setup traffic generator for dataplane traffic:

Below is sample flows to test the Uplink and Downlink flows with traffic generator:

* __Uplink__:
    -   Uplink traffic should be sent on s1u port ,say port 0.
    -   Each flow in this example is identified by dst ip from 13.1.1.110-13.1.1.121.

            SrcIP/Mask DstIP/Mask   Sport   : Sport Dport   : Dport Prot/Prot
            16.0.0.0/8 13.1.1.110/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.111/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.112/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.113/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.114/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.115/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.116/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.117/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.118/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.119/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.120/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.121/32 0      : 65535 0       : 65535 0x0/0x0

    -   For above flows to hit, all UEs IP should be with in range 16.0.0.1 - 16.255.255.255.
    -   Teid in flow should match with the teid configured, else the flow will be not be processed.
        By default teid = 1 is installed with UE ip 16.0.0.1,
        teid = 2 is installed with UE ip 16.0.0.2 and so on.

* __Downlink__:
    -   Downlink traffic should be sent on sgi port ,say port 1.
    -   Each flow in this example is identified by src ip from range 13.1.1.110 - 13.1.1.121.

            SrcIP/Mask    DstIP/Mask Sport  : Sport Dport   : Dport Prot/Prot
            13.1.1.110/32 16.0.0.0/8 11     : 11    0       : 65535 0x0/0x0
            13.1.1.111/32 16.0.0.0/8 12     : 12    0       : 65535 0x0/0x0
            13.1.1.112/32 16.0.0.0/8 13     : 13    0       : 65535 0x0/0x0
            13.1.1.113/32 16.0.0.0/8 14     : 14    0       : 65535 0x0/0x0
            13.1.1.114/32 16.0.0.0/8 15     : 15    0       : 65535 0x0/0x0
            13.1.1.115/32 16.0.0.0/8 11     : 11    0       : 65535 0x0/0x0
            13.1.1.116/32 16.0.0.0/8 12     : 12    0       : 65535 0x0/0x0
            13.1.1.117/32 16.0.0.0/8 13     : 13    0       : 65535 0x0/0x0
            13.1.1.118/32 16.0.0.0/8 14     : 14    0       : 65535 0x0/0x0
            13.1.1.119/32 16.0.0.0/8 15     : 15    0       : 65535 0x0/0x0
            13.1.1.120/32 16.0.0.0/8 11     : 11    0       : 65535 0x0/0x0
            13.1.1.121/32 16.0.0.0/8 12     : 12    0       : 65535 0x0/0x0

    -   For above flows to hit, all UEs IP should be with in range 16.0.0.1 - 16.255.255.255.
        Please refer the packet capture files `pcap/uplink_100flows.pcap` and `pcap/downlink_100flows.pcap` for other fields.

#### 3.4 Running CP and DP

a. Setup 10G ports for VNF to run:
   Two 10G ports are used for S1U and SGI interfaces by dataplane(dp).

  [FOR DPDK 16.04]
  1. cd dpdk
  2. ./tool/dpdk_nic_bind.py --status <--- List the network device
  3. Use `lshw` or `ip addr show <port>` to find the mac address
  4. ./tool/dpdk_nic_bind.py -b igb_uio <PCI Port 0> <PCI Port 1>
    OR
    Use `$RTE_SDK/tools/setup.sh` for binding the ports.
  For more details refer
  http://dpdk.org/doc/guides-16.11/linux_gsg/build_dpdk.html#binding-and-unbinding-network-ports-to-from-the-kernel-modules


  [FOR DPDK 18.02]
  1. cd dpdk
  2. ./usertools/dpdk_nic_bind.py --status <--- List the network device
  3. Use `lshw` or `ip addr show <port>` to find the mac address
  4. ./usertools/dpdk_nic_bind.py -b igb_uio <PCI Port 0> <PCI Port 1>
    OR
    Use `$RTE_SDK/usertools/dpdk-setup.sh` for binding the ports.

b. If ZMQ_COMM flag is enabled, start ZMQ Streamer before running DP and CP

  If ZMQ_COMM flag is enabled in the config file ng-core_cfg.mk, then we need to start the
  ZMQ streamer before running DP & CP. This can be done via the following script run.
  NOTE: The script needs to be started either on CP or DP or any other systems and update
        interface.cfg accordingly. No need to start on both CP and DP.

```shell
cd dev_scripts
./start-ZMQ_Streamer.sh
```

c. Add the mac addresses of port0 and port1 in config/dp_config.cfg to run ngic_dataplane.

```shell
cd dp
Edit run.sh to add corelist
./run.sh ---> start ngic_dataplane.
```

d. Run following in separate shell/terminal to enable KNI S1U/SGI interface

```shell
cd kni_ifcfg
./kni-S1Udevcfg.sh
./kni-SGIdevcfg.sh
```

e. Update cp_config.cfg with required parameters.Then start cp in the following way.

```shell
cd cp
./run.sh
```
Note: In case ZMQ_COMM CFLAGS enabled, make sure you run follwing command after
cp and dp is stopped. This command will stop ZMQ streamer.

```shell
cd  dev_scripts
./stop-ZMQ_Streamer.sh
```

f. Then start the traffic generator and MME if applicable.
#### 3.5 Standalone Virtualization:
Dataplane has been tested with SRIOV and OVS with SIMU_CP configuration:

* SRIOV Setup:
    -   OS : Ubuntu 16.04 LTS Server Edition.
    -   DPDK: 16.11.4 version
    -   Hypervisor: KVM
        Please refer [setup sriov](http://dpdk.org/doc/guides-16.11/nics/intel_vf.html)

* OVS Setup:
    -   OS : Ubuntu 16.04 LTS Server Edition.
    -   DPDK: 16.11.4 version
    -   OVS: 2.5
    -   Hypervisor: KVM
    -   Supported deployment : PHY-VM-PHY
    -   Please refer below link to setup ovs:
        *   [Using OvS with DPDK on Ubuntu](https://software.intel.com/en-us/articles/using-open-vswitch-with-dpdk-on-ubuntu)
        *   [OvS INSTALL.DPDK-ADVANCED](http://openvswitch.org/support/dist-docs/INSTALL.DPDK-ADVANCED.md.html#ovstc)

* BIOS for Standalone Virtualization:

    -   Open `/etc/default/grub` configuration file.
    -   Append `iommu=pt intel_iommu=on` to the `GRUB_CMDLINE_LINUX` entry.


4. Generating API documentation
-------------------------------

Run "doxygen doxy-api.conf" in ngic root directory to generate doxygen
documentation.
