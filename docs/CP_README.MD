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

NGIC Control Plane
==================

1. Control Plane Directory and Contents
---------------------------------------

* **gtpv2c_messages** - Each file within this directory contains a function to
                        process a particular GTPv2c message received by the
                        Control Plane along the S11 interface originating from
                        the MME. This function is named appropriately with the
                        'process' prefix and relies  on a number of static
                        helper functions. Typically, each
                        file will contain a static function to parse the
                        received message, each named with the 'parse' prefix,
                        and populating a structure defined within the same file.
                        The 'process' function prototypes are located in
                        gtpv2c.h. Upon processing of these messages, calls are
                        made to manage session data internally and to the Data
                        Plane through the cp_dp_api. Response or triggered
                        messages are then populated (if required) in the
                        gtpv2c_tx (as a parameter to the 'process' function)
                        buffers in static functions with the 'set' prefix.
    * **bearer_resource_cmd.c** - Contains the process_bearer_resource_command
                                  function to handle the "Bearer Resource
                                  Command". Currently,
                                  only those messages containing Traffic
                                  Aggregation Description operations of packet
                                  filter creation and deletion are supported.
                                  This operation determines the triggered
                                  request message, either Create Bearer or
                                  Delete Bearer respectively. In the case that
                                  a bearer is to be created, the bearer data
                                  structure is provisionally created, but not
                                  installed in the Data Plane until a response
                                  is received.
    * **create_bearer.c** - Contains the process_create_bearer_response function
                            to handle the "Create Bearer Response" message.
                            As the bearer has been provisionally created, all
                            that remains to do is to obtain the EBI from the
                            message and install the bearer in the Data Plane via
                            calls to the cp_dp_api.
    * **create_session.c** - Contains the process_create_session_request
                             function to handle the "Create Session Message".
                             Here we rely on functions in ue.[ch] to manage the
                             creation of a PDN Connection. The default bearer is
                             installed in the Data Plane via calls to the
                             cp_dp_api.
    * **delete_bearer.c** - Contains the process_delete_bearer_response function
                            to handle the "Delete Bearer Response" message. As
                            this message is a response, the bearer has already
                            been provisionally marked for deletion during
                            processing of a previous Bearer Resource Command
                            with a Traffic Aggregation Description operation
                            requesting the deletion of all traffic filters
                            installed on a particular dedicated bearer. Since
                            the bearer was already marked to be deleted, all to
                            do here is to verify the Information Elements
                            contained within this message matches what is
                            expected.
    * **delete_session.c** - Contains the process_delete_session_request
                             function to remove all bearers of a PDN Connection.
                             Bearer. The PDN data structure internal to the
                             Control Plane is removed, though the UE structure
                             remains in the ue_context_by_fteid_hash hash table
                             for (unlikely) case that a UE has connectivity with
                             multiple PDNs. Once again, Bearers are removed in
                             the Data Plane via calls to the cp_dp_api.
    * **downlink_data_notification.c** - Contains the
                            create_downlink_data_notification function to
                            create the "Downlink Data Notification" and the
                            process_ddn_ack functoin to process "Downlink Data
                            Notification Acknowledgment".
    * **echo.c** - Contains the process_echo_request function to reply to echo
                   requests.
    * **modify_bearer.c** - Contains the process_modify_bearer_request function
                            to handle the "Modify Bearer Message". As part of
                            the initial attach procedure and eNB hand-over, this
                            message creates/modifies the downlink F-TEID. This
                            requires modification of the EPS Bearer data
                            structure as well as propagating new F-TEID values
                            to the Data Plane via the cp_dp_api.
    * **release_access_bearer.c** - Contains the
                            process_release_access_bearer_request function to
                            handle the "Release Access Bearer Message".
* **debug_str.c** - Function definitions to convert the GTPv2c Cause and Message
                    type code values to strings.
* **debug_str.h** - Contains function prototypes to expose definitions in debug_str.c
* **gtpv2c.c** - Definitions of functions to iterate over  Information Element
                 contained within GTPv2c messages as well as those to populate
                 the GTPv2c message Header.
* **gtpv2c.h** - Contains definition of GTPv2c code values and message Header
                 structure. Also contains helper function/macros to iterate over
                 Information Elements contained within a GTPv2c message and
                 populate header contents. Function prototypes of 'process'
                 prefix functions defined in the gtpv2c_messages directory are
                 also declared here.
* **gtpv2c_ie.h** - Contains definitions of Information Elements as defined by
                    3GPP TS 29.274 for use in GTPv2c messages. Value codes for
                    Information Elements and their contents are located here as
                    well. All structures are defined for x86 architectures,
                    utilizing bit-fields to ease processing.
* **gtpv2c_set_ie.c** - Contains function definitions to set Information Elements
                        as defined in gtpv2c_ie.h/3GPP TS 29.274. Used by 'set'
                        functions statically defined within the gtpv2c_messages
                        directory to populate triggered/response messages.
* **gtpv2c_set_ie.h** - Contains function prototypes to set Information Elements
                        as defined in gtpv2c_ie.h/3GPP TS 29.274.
* **main.c** - Parses command line arguments, establishes the connection to the
               S11 interface, and displays statistics to console. Contains the
               lcore_control_plane function to read/write messages from the S11
               interface (or alternatively - to packet capture files).
* **packet_filters.c** - Defines functions to manage the internal packet filters
                         for use for signaling purposes. Also installs packet
                         filters in the Data Plane via the cp_dp_api. Packet
                         filters are required to be statically defined within
                         the /config/static_pcc.cfg file.
* **packet_filters.h** - Exposes packet filter structure and function prototypes
                         for use with dedicated bearers.
* **ue.c** - Defines functions to manage UE data, IP and TEID pools, and APN verification.
* **ue.h** - Defines structures for the internal maintenance of information
             storage as defined by 3GPP TS 23.401, clauses 5.7.3 and 5.7.4. Also
             exposes function declarations for the creation of the UE data
             structure, including the assignment of UE IP and verification of
             correct APN. Simplified TEID and IP pool is exposed here.


2. Low Level Code Walk-through
-----------------------------

##### 2.1 Initialization

DPDK EAL arguments are parsed first. Please refer to
[DPDK Environment Abstraction Layer documentation](
http://dpdk.org/doc/guides/prog_guide/env_abstraction_layer.html).
The parsing of Control Plane specific arguments follows. Both EAL and Control
Plane arguments are described in the installation documentation [here](INSTALL.MD).
A number of data structures are then initialized on the Data Plane via calls to
the cp_dp_api, starting with the iface_module_constructor constructor. These
data structures include the following tables:

* SDF Filter Table
* PCC Table
* Meter Profile Table
* Session Table

Packet filters are installed next, in both the Control and Data Planes, followed
by the creation of the hash table to contain UE contexts. A number of EAL
threads are spawned:

* Statistics Thread (stats) - Prints updated statistics of processed signaling
  messages every second.
* SDN Handler (if compiled with SDN_BUILD defined) - Handles CURL calls to SDN
  controller via cp_dp_api. Due to the time required to process http requests
  through the CURL library, cp_dp_api calls are offloaded to a consuming thread
  by the master (producer) thread.
* Master thread - Processes signaling messages, establishes PDN connections, and
  manages bearers.

##### 2.2 Master Thread Operation

The Master Thread processes signaling messages, which may be broken down by 3GPP
Procedure Events as described by 3GPP TS 23.401. This thread enters an infinite
loop in the lcore_control_plane function, which polls on the S11 interface. (For
the case of bypassing the S11 for reading of Packet Capture files, the loop is
broken once the file contents have been read). Upon receipt of a message and
verification of the packet length, the processing is handed off to one of the
functions defined in the gtpv2c_messages directory. These include the functions:

* process_create_session_request
* process_delete_session_request
* process_modify_bearer_request
* process_bearer_resource_command
* process_echo_request
* process_create_bearer_response
* process_delete_bearer_response

##### 2.2.1 Error Detection and Handling

Error handling is restricted to detection, and will discard messages without
notifying the MME (which contradicts protocol specifications in 3GPP TS 29.274
and is an area for future development). Errors in these message processing
functions may be one of two types, and are indicated by return value, with zero
indicating successful processing. Negative values indicate internal errors while
positive values indicate errors with descriptions defined in 3GPP Cause values
(See 3GPP TS 29.274 clause 8.4 for description). These errors will be displayed
to console prior to discarding the message.


##### 2.2.1 Attach Procedure

Per 3GPP TS 23.401 clause 5.3.2.1, an E-UTRAN Initial Attach procedure includes
two sets of Request & Response messages along the S11 between the SGW and MME.
The first being a Create Session followed by Modify Bearer. Upon receipt of each
by the lcore_control_plane function, process_create_session_request and
process_modify_bearer_request is called as appropriate with the received message
contained in the *gtpv2c_rx* buffer, and supplied with a *gtpv2c_tx* buffer to
contain the response message. Each function uses statically defined helper
parsing functions to obtain required information for the establishment of
bearers. These functions are named parse_create_session_request and
parse_modify_bearer_request respectively, and populate their respective
structures; as defined by parse_create_session_request_t and
parse_modify_bearer_request_t.

The session is created using the parsed information from the request message,
verifying the APN, acquiring an UE IP, and creating the UE context, associated
PDN connection and EPS bearer data structures. Each of these actions utilize
functions declared/defined in ue.h/ue.c. The data structures created for this
connection are then populated and a response message is generated by the
statically defined set_create_session_response. At this time the cp_dp_api call
create_session installs the default bearer on the Data Plane, and will allow for
traffic to flow in the Uplink direction only.

The modify bearer message is handled in the same way, with the obvious exception
that the connection data structures having already been created. This data must
be 'looked up', which is performed by the parsing function and included in the
parsing data structure. The eNB Fully Qualified Tunnel Endpoint Identifier
(F-TEID) data is assigned according to the contents of the request message, and
is propagated to the Data Plane via the cp_dp_api call, session_modify. At this
time Downlink traffic may flow towards the UE.

##### 2.2.2 Handover

eNB Handover procedures are supported by updating the eNB F-TEID via Modify Bearer
Request and Responses in the same sequence as the Attach Procedure.


##### 2.2.3 Dedicated Bearer Establishment (UE-initiated ONLY)

Dedicated bearers are supported as a UE-initiated procedure described in 3GPP TS
23.401 clause 5.4.5. Upon receipt of a Bearer Resource Command with a Traffic
Aggregation Description (TAD) operation "Create New Packet Filter", the Control
Plane is triggered to send a "Create Bearer Request" message to the MME. Packet
filters referenced in the Bearer Resource Command TAD Information Element must
be statically defined and installed in the Control and Data Planes at run time
by the configuration file *static_pcc.cfg*.

Upon receipt of a Bearer Resource Command message, the received buffer is passed
to the process_bearer_resource_command function by *gtpv2c_rx* parameter. Alike
previously described messages, parsing is completed in the function
parse_bearer_resource_cmd which populates the parse_bearer_resource_command_t
structure; this including UE, PDN Connection, and EPS Bearer contexts. With a
new packet filter operation in the TAD IE, create_dedicated_bearer is called
which provisionally establishes a dedicated bearer, located in the UE context's
ded_beaerer structure member. The creation of the triggered "Create Bearer
Request" message is then performed by the set_create_bearer_request function.

Upon receipt of the Create Bearer Response message, the provisionally created
dedicated bearer is installed in the Control Plane as well as Data Plane via
call to cp_dp_api calls on the condition that message contents are as expected.
Like the other files in the gtpv2c_messages directory, the function
process_create_bearer_response handles this action with the helper/parsing
function parse_create_bearer_rsp.

##### 2.2.4 Dedicated Bearer Deactivation (UE-initiated ONLY)
Bearers are deactivated according to the same UE-initiated procedure as their
establishment, described in 3GPP TS 23.401 clause 5.4.5. Therefore, processing
is similar  and is conducted in the process_bearer_resource_command function.
Deactivation is triggered by the removal of all packet filters for any dedicated
bearer. Removal of packet filters is handled by the delete_packet_filter
function. As in the establishment, the Bearer Resource Command triggers a
Request of Bearer Deletion. The creation of this message is also conducted in
the delete_packet_filter function.

Upon receipt of appropriately formulated
Delete Bearer Response message, the Control Plane then removes the bearer in its
internal information storage as well as updates the Data Plane via cp_dp_api
calls. The processing of this message is done in process_delete_bearer_response
with the helper parse_delete_bearer_response.

##### 2.2.5 Session Deletion

The UE-Initiated Detach Procedure as described in detail in 3GPP TS 24.401,
clause 5.3.8.2.1 consists of a Delete Session Request and Response pair of
messages between the Control Plane and MME. The Control Plane is responsible for
deleting all associated bearers, dedicated and default, from both its internal
information storage as well as to the Data Plane via calls to the cp_dp_api.

Delete Session Message processing occurs in the process_delete_session_request
with the help of the delete_context function. The response message is populated
by the process_delete_session_request.


3. PCAP Support
-----------------------------

##### 3.1 Packet Capture Feature Description

An optional feature included in the Control Plane is the ability to read/write
GTPv2c messages from/to pcap file, bypassing the need for an MME for development
or testing purposes. This feature is most useful for development testing of the
Control Plane (and possibly the cp_dp_api) independent of the Data Plane.

##### 3.2 Intended Use

Due to the complexity of GTPv2c messages, it has been generally helpful to
develop the Control Plane independent of a full featured MME. In order to test
expected or desired parsing and population of GTPv2c messages, the Control Plane
has been developed to read/write from pcap files, rather than a typical UDP
Linux socket.

To use, simply supply via command line parameters *--pcap_file_in* and
*--pcap_file_out* along with desired files to read and write to. Packets
contained in the *pcap_file_in* file must be appropriately  set (see 3.3),
therefore the use of this feature is most helpful when pacps are generated from
prior tests with an attached MME.

##### 3.3 Use of Packet Capture Support in Control Plane in Data Plane Tests

It is theoretically possible to use this feature in combination with a generic
packet generator (such as DPDK Pktgen), though will require a fair amount of
setup, thus has not been used. There are likely much better solutions
(simu_cp for instance) to test the data plane without an MME connection.
For example, the use of this feature to test the Data Plane
would require the following (list may be incomplete):

* Packet generator to correctly populate appropriate fields (GTP TEID, UE IP)
  according to deterministic provisioning of TEID and IP addresses by the
  Control Plane.
* The S11 SGW GTP-C TEID is assigned to UE *i*, where *i* indicates that *i*
  UEs had attached prior to *i*, according to:

          S11_SGW_GTPC_TEID(i) = byteswap(0x00c0ffee + i)
          E.g. S11_SGW_GTPC_TEID(0) = 0xeeffc000
          E.g. S11_SGW_GTPC_TEID(1) = 0xefffc000
          E.g. S11_SGW_GTPC_TEID(2) = 0xf0ffc000   ... and so on

* The Control Plane will associate this S11 SGW GTPC TEID value with the PDN
  connection. Thus, any further message received by the control plane
  referring to this PDN connection must contain this TEID in the GTPv2c
  header. This includes the Modify Bearer Message. (Note: piggybacking of
  GTPv2c messages is not currently supported.)

* The Control Plane will assign default bearers'
  S1-U SGW GTP TEIDs for some UE *i* according to

          S11_SGW_GTPC_TEID_DEF(i) = byteswap(S11_SGW_GTPC_TEID(i)) | 0xf0
          E.g. S11_SGW_GTPC_TEID_DEF(0) = 0xeeffc0f0
          E.g. S11_SGW_GTPC_TEID_DEF(1) = 0xefffc0f0
          E.g. S11_SGW_GTPC_TEID_DEF(2) = 0xf0ffc0f0   ... and so on

* The Control Plane will assign UE IP addresses according to the command line
  parameters *ip_pool_ip* and *ip_pool_mask*, starting at the highest IP
  address, decrementing for each successive UE.

          For ip_pool_ip = 16.0.0.0 and ip_pool_mask = 255.0.0.0, and UE i
          E.g. UE_IP(0) = 16.255.255.255
          E.g. UE_IP(1) = 16.255.255.254
          E.g. UE_IP(2) = 16.255.255.253   ... and so on


4. CP-FPC Lifecycle (When built with SDN_ODL_BUILD flag)
----------------------------

##### 4.1 CP-FPC Communication

The CP and FPC ODL Plugin communicate entirely over HTTP. Messages are
communicated over four different connections. Three of these connections remain
active throughout the lifespan of the CP and FPC. These connections utilize
[Server-Sent Events](https://www.w3.org/TR/eventsource/) (SSE) sending message
using [HTTP Chunked Transfer Encoding](https://tools.ietf.org/html/rfc7230#section-4.1).
The remaining connetion is a one-time HTTP-GET request for the DPN topology
made to the FPC ODL Plugin.


##### 4.2 CP-FPC Lifecycle Message Time Sequence


                            CP                                                              FPC
                            |                                                                |
                            |- 1a POST http://<fpc_ip>:<fpc_port>/resposne ----------------->|
                            |   {"client-uri":"http://<cp_ip>:<cp_port>/request"}            |
        Resposne SSE Stream |<---------------------------------------- 1b HTTP-OK -----------|
                            |                                                                |
                            |                                                                |
                            |<------------ 2a GET http://<cp_ip>:<cp_port>/resposne ---------|
                            |- 2a HTTP-OK -------------------------------------------------->| Request SSE Stream
                            |                                                                |
                            |                                                                |
                            |- 3a Bind Client ---------------------------------------------->| Request SSE Stream
        Resposne SSE Stream |<------------------------------------- 3b Bind Client Response  |
                            |                                                                |
                            |                                                                |
                            |- 4a POST http://<fpc_ip>:<fpc_port>/notification ------------->|
                            |   {"client-id":"<client_id>"}                                  |
    Notification SSE Stream |<------------------------------------------------ 4b HTTP-OK ---|
                            |                                                                |
                            |                                                                |
                            |- 5a Get http://<fpc_ip>:<fpc_topology_port>/<topology-path> -->|
                            |<----------------------------------------------- 5b Topology ---|
                            //                                                               //
                            //                 Completion of CP Lifecycle                    //
                            //                                                               //
    Notification SSE Stream |<---------------------------------------------- 6 DPN-Available-|
                            //                                                               //
                            //       DPN Installed - Ready for Session Establishment         //
                            //                                                               //
                            |                                                                |
                            |- 7a. Create Session------------------------------------------->| Request SSE Stream
        Resposne SSE Stream |<---------------------------------------- 7b OK-Notify-Follows--|
    Notification SSE Stream |<------------------------------ 7c Config-Notification-Result---|
                            |                                                                |
                            |- 8a. Create Session------------------------------------------->| Request SSE Stream
        Resposne SSE Stream |<---------------------------------------- 8b OK-Notify-Follows--|
    Notification SSE Stream |<------------------------------ 8c Config-Notification-Result---|
                            //                                                               //
    Notification SSE Stream |<-------------------------------------------- 9 DPN-Unavailable-|
                            //                                                               //
                            |- 10 Unbind Client -------------------------------------------->| Request SSE Stream



5. Control Plane Limitations
----------------------------

* Error Handling of S11 messages is restricted to detection. In many cases, 3GPP
  TS 29.274 requires the generation of responses to the MME that indicate error.
* The Control Plane expects signaling messages to arrive consisting of
  Information Elements that may be inconsistent with specification. Behavior is
  unknown with untested MMEs.
* A number of features are currently unsupported, such as unauthenticated IMSI
  device connection.
* GTPv2c Piggybacking is unsupported
* The Control Plane does not currently implement the Recovery/Restart Counter
  according to specification. Rather, this value will always be zero.
* Due to the S11 interface operating over the UDP protocol, messages may be
  dropped if the rate of message arrival exceeds processing rate. When the
  Control Plane is compiled with SDN support utilizing the CURL library, the
  processing rate drops considerably. With the Control Plane is compiled for use
  of the cp_dp_api utilizing UDP, performance has indicated that in excess of
  1000 UE's may perform an Initial Attach as well as UE-Initiated Dedicated
  Bearer Establishments per second on an Ubuntu 14.04 system with a Intel(R)
  Xeon(R) CPU E5-2699 v4 @ 2.20GHz. With the Initial Attach Procedure consisting
  of 4 messages, and UE-Initiated Dedicated Bearer Establishment consisting of
  3 messages, this results in 7000 signaling messages per second over the S11
  interface.
