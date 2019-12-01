# ArchSDN Distributed Controller

[![CircleCI](https://circleci.com/gh/ClaymorePT/ArchSDN-Controller.svg?style=svg)](https://circleci.com/gh/ClaymorePT/ArchSDN-Controller)

### Introduction
This is the source code for the ArchSDN Distributed Controller, an OpenFlow controller with distributed and autonomous 
management capabilities.

{:toc}

### Requirements
* Python 3.6 or recent
* Required Python modules (installed automatically when installing this program).
    * netaddr==0.7.19
    * networkx==2.1
    * blosc==1.5.1
    * ryu==4.27
    * scapy-python3==0.25
    * pyzmq==17.1.2


### Installation
Inside the folder to where the repository was cloned, simply execute: `$ pip install .`

The name of the package is `archsdn_controller`


### Usage
When installed, the ArchSDN Distributed Controller can be executed by calling the executable in the terminal.

Example: `$ archsdn_controller -l INFO`


#### ArchSDN Distributed Controller options
```
$ archsdn_controller -h
usage: archsdn_controller [-h] [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                          [-id UUID] [-ip IP] [-p PORT] [-cip CIP] [-cp CPORT]
                          [-ofip OFIP] [-ofp OFPORT]

optional arguments:
  -h, --help            show this help message and exit
  -l {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --logLevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Logging Level (default: INFO)
  -id UUID, --uuid UUID
                        Controller UUID (default: random)
  -ip IP, --ip IP       Controller IP (default: 0.0.0.0)
  -p PORT, --port PORT  Controller Port (default: 54321)
  -cip CIP, --cip CIP   Central Management Server IP (default: 127.0.0.1)
  -cp CPORT, --cport CPORT
                        Central Management Server Port (default: 12345)
  -ofip OFIP, --ofip OFIP
                        OpenFlow Service IP
  -ofp OFPORT, --ofport OFPORT
                        OpenFlow Service Port (default: 6631)
```

| Flag   | Type        | Details | Example |
| ------ | ----------- | ------- | ------- |
| `-l --logLevel`| DEBUG, INFO, WARNING, ERROR, CRITICAL | Set the log Level. | `$ archsdn_controller -l DEBUG` |
| `-id --uuid`| string (UUID) or int | Controller Identifier. The default is a random generated UUID | `$ archsdn_controller -id 1` or  `$ archsdn_controller -id "00000000-0000-0000-0000-000000000001"` |
| `-ip --ip` | string (IPv4) | Bind to a specific network address from where the controller will receive connection requests from other controllers | `$ archsdn_controller -ip "192.168.123.1"` |
| `-p --port` | int [1:65535] | Bind to a specific port where the controller will listen for requests coming from other controllers | `$ archsdn_controller -ip 12345` |
| `-cip --cip` | string (IPv4) | The IP address used to connect to the ArchSDN Central Manager | `$ archsdn_controller -cip "192.168.123.100"` |
| `-cp --cport` | int [1:65535] | The port used used to connect to the ArchSDN Central Manager | `$ archsdn_controller -cp 12345` |
| `-ofip --ofip` | string (IPv4) | Bind to a specific network address from where the controller will receive connection requests from OpenFlow Switches | `$ archsdn_controller -ofip "192.168.123.100"` |
| `-ofp --ofport` | int [1:65535] | The port used used to connect to the ArchSDN Central Manager | `$ archsdn_controller -ofp 12345` |


### Warnings

The ArchSDN Controller **requires the existence of an ArchSDN Central Manager** to work properly.
First, start the ArchSDN central manager service, then start the ArchSDN controllers.

ArchSDN Controllers will only serve OpenFlow Switch requests after connecting and register themselves successfully at 
the ArchSDN central manager.

If the ArchSDN controller is processing OpenFlow messages coming from the OpenFlow Switches, there's a change that the 
ArchSDN controller was not able to connect to the ArchSDN central manager.


# How everything works

### Expressions and meanings.
* **Local Sector -** the sector in question/context.
* **Local Controller -** the controller of the sector in question/context.
* **Local Switch -** the switch connected to a Local Controller.
* **Local Client -** a Network Client connected to a Local Switch


* **Adjacent Sector -** a Sector directly connected to the Local Sector.
* **Adjacent Controller -** the controller from an Adjacent Sector.
* **Adjacent Switch -** a switch connected to an Adjacent Controller and also connected to a Local Switch.
* **Adjacent Client -** a Network Client connected to an Adjacent Switch


* **Foreign Sector -** a Sector not directly connected to the Local Sector.
* **Foreign Controller -** the controller from a foreign sector.
* **Foreign Client -** a Network Client connected to a Foreign Switch

* **Remote Sector -** an Adjacent or Foreign Sector.
* **Remote Controller -** an Adjacent or Foreign Controller.
* **Remote Client -** an Adjacent or Foreign Network Client.

## ArchSDN Network

Like every SDN network, the ArchSDN Network separates the control plane from the data plane.
It provides a distributed management model, by subdividing the network into multiple sectors, each managed independently by a different controller.

The ArchSDN network is composed essentially by four types of entities:
* **ArchSDN Central Manager** (single entity)
* **ArchSDN Controller** (multiples entities in the network - one per sector)
* **OpenFlow Switch** (multiples entities)
* **Network Client** (multiples entities)


#### ArchSDN Central Manager
The central manager is responsible for:
1. Registering and maintaining the control network address of the network controllers, for P2P communication.
2. Providing and maintaining the IP address pool for network clients.
3. Client registration and providing information about registered clients for network controllers.


#### ArchSDN Controller
The ArchSDN controller is a distributed and autonomous OpenFlow controller.
The controller is responsible for controlling the switches within a specific sector. It is also responsible for 
registering new clients at the central manager, and provide and maintain network services requested by registered 
clients.

Each controller has exclusive control over its sector, and holds the possibility to request different types of services 
from other sectors, by contacting the controllers of those specific sectors.


### Network Control Structure
The ArchSDN Network control plane follows a hybrid management model, where it mixes the flat and the hierarchical management models.

The control plane is divided into two levels:
1. **Top Management Level**
2. **Bottom Management Level**


#### Top Management Level
The top management level is constituted by the network controllers, who follow the network policies provided by the central manager.
Controllers cooperate with each other to implement services that cross multiple sectors.
When it is necessary to proceed with a client registration or when it is necessary to obtain information regarding a network client, the network controllers contact the central manager.

The network controllers have the same privileges.
This means, when requesting the implementation of a service towards a specific network client, the controller receiving the request serves the requests on a first-come, first-served basis.

```
    Control communication between controllers and the central manager

  <──> Control Plane Links

                    ┌─────────┐
                    │ ArchSDN │
        ┌───────────┤ Central ├────────────┐
        │           │ Manager │            │
        │           └────┬────┘            │
        │                │                 │
        │                │                 │
        │                │                 │
 ┌──────┴─────┐    ┌─────┴──────┐    ┌─────┴──────┐
 │   ArchSDN  │    │   ArchSDN  │    │   ArchSDN  │
 │ Controller ├────┤ Controller ├────┤ Controller │
 │      1     │    │      2     │    │      3     │
 └────────────┘    └────────────┘    └────────────┘
 
```

#### Bottom Management Level
The bottom management level is the sector management.

Each local controller only knows the structure of its local sector, coordinating its actions to provide network service 
to its clients, with the adjacent controllers.

Each sector is composed by OpenFlow switches, all managed by the local controller.
The OpenFlow switches provide the connection between local clients and the clients from other sectors.


```
    Control communication between local switches and the local controller.

  <──> Control Plane Links
  <══> Data Plane Links

              ┌────────────────────────────────────────────────────────────┐
              │ Sector Boundary                                            │
              │                       ┌────────────┐                       │
              │                       │  ArchSDN   │                       │
              │          ┌────────────┤ Controller ├─────────────┐         │
              │          │            └──────┬─────┘             │         │
              │          │                   │                   │         │
              │          │                   │                   │         │
 ┌─────────┐  │          │                   │                   │         │  ┌─────────┐
 │ Adjacent│  │     ┌────┴────┐         ┌────┴────┐         ┌────┴────┐    │  │ Adjacent│
 │ Sector  ├════════┤ OF Sw 1 ├═════════┤ OF Sw 2 ├═════════┤ OF Sw 3 ├═══════┤ Sector  │
 └─────────┘  │     └┬──────┬─┘         └┬──────┬─┘         └┬──────┬─┘    │  └─────────┘
              │      ║      ║            ║      ║            ║      ║      │
              │      ║      ║            ║      ║            ║      ║      │
              │      ║      ║            ║      ║            ║      ║      │
              │      ║      ║            ║      ║            ║      ║      │
              │ ┌────┴─┐  ┌─┴────┐  ┌────┴─┐  ┌─┴────┐  ┌────┴─┐  ┌─┴────┐ │
              │ │Client│  │Client│  │Client│  │Client│  │Client│  │Client│ │
              │ └──────┘  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘ │
              └────────────────────────────────────────────────────────────┘

```

To provide communication between clients, communication paths are implemented by the local controller, with the 
cooperation of the sector controllers if necessary.
These communication paths are implemented using MPLS tunnels and are implemented as flows at the OpenFlow switch 
level.


4 Types of MPLS tunnels can exist in a Sector:
* **Client to Client** 
    * `Local Client <────> OF Local Switch <────> OF Local Switch <────> Local Client`
* **Client to Adjacent Sector**
    * `Local Client <────> OF Local Switch <────> OF Local Switch <────> Adjacent Sector`
* **Adjacent Sector to Client**
    * `Adjacent Sector <────> OF Local Switch <────> OF Local Switch <────> Local Client`
* **Adjacent Sector to Adjacent Sector**
    * `Adjacent Sector <────> OF Local Switch <────> OF Local Switch <────> Adjacent Sector`

The responsibility of deciding through where a communication path should be implemented, belongs to the decision system 
mechanism, and it is explained later in this **_README_**.



## ArchSDN Network Services

The controller provides the following services to the network clients:

* Local Sector Topology Discovery
* ARP service
* DHCP - IPv4 only
* DNS - Only for names associated to the ArchSDN network
* ICMPv4 traffic (bidirectional - Source <-> Destination)
* Generic IPv4 network traffic (unidirectional - Source -> Destination)


### How does the ArchSDN Controller provides its services?

The ArchSDN Controller services are provided on-demand, by capturing specific packets which are sent to the local 
controller for evaluation and service activation if required.

Packets are filtered according to the OpenFlow switch flow tables.
Switch flow tables are populated with flows by the local controller when required, with specific priorities.
The flows with higher priority are the first ones to be evaluated, while the flows with lower priority are the last ones to be evaluated.

When a packet is matched by a flow, the actions configured in the flow are executed.
Flows can either:
* Send the packet to another table for further inspection.
* Switch the packet to a another port
* Capture the packet and send it to the controller
* Discard the packet.

The switches flow tables have a reject-by-default flow with priority equal to zero which matches all packets received.
This means, packets that do not match any flow on the table, are discarded by default.

The flows in the tables also follow __one simple rule__. 
The **higher the matching specificity** of a flow, the **higher its priority** is.
The **more generic** the match of a flow is, the **lower its priority** is.

This hierarchical structure for the flow tables, allow a quicker response by the switch when evaluating packets, while reducing the number of flows and their matching complexity in the switch tables.


#### Controller virtual addresses
Local controllers provide network services to the local clients using virtual MAC, IPv4 and IPv6 addresses.
These virtual addresses are provided by the ArchSDN Central Manager, when the controller registers itself at the central
 manager.
 
When a client wants to resolve a name using the local controller DNS or, when the controller wants to send something to 
its clients, the virtual addresses are used to identify the local controller.


### Topology Discovery
The ArchSDN controller implements a topology discovery mechanism, broadcasting specific Layer-2 packets through the
ports of the local switches which are not associated to local clients, local switches or adjacent sectors.


#### Discovery Packet 
The topology discovery packets also use a specific the ethertype `0xAAAA` and contain the following information:
* **Controller UUID** - The local controller ID which will send the packets.
* **Hash Value** - The hash value of the following information:
    * **Datapath ID** - The switch ID through where the packet will be broadcast.
    * **Port ID** - The switch port through where the packet will be broadcast.


#### Processing Discovery Packet
When the local controller receives a discovery packet captured by a local switch, it checks for the controller UUID 
field and verifies the origin.

If the UUID is the very own local controller, then the controller registers the port of the receiving switch, as 
connected to another local switch.

If the UUID is the ID of a different controller, then the controller registers the port of the receiving switch, as 
connected to another sector.

If a DHCP Discovery packet is captured by a local switch, then the controller registers the port of the receiving 
switch, as connected to a local client.

The local controller only sends discovery packets while the port of a local switch is not bound to a local switch or 
local client.
If the port is bounded to a sector, the controller will keep sending the beacons.
The reason for this is because the adjacent switch is out of the management boundary of the local controller and so, it
will not receive link status updates from that specific switch.

Using this advertising mechanism, the local controller is capable of defining the structure and boundaries of the local 
sector, implemented by the set of local OpenFlow switches.


### ARP Service
The Address Resolution Protocol service works by having the OpenFlow local switches, intercept the ARP requests sent by 
clients and redirect them to the local controller.
Upon receiving a captured ARP packet, the local controller validates the target address which the local client wants to 
see resolved, by making a first verification for the existence of a local client registration with the same address and 
obtain its MAC address if so.

If this first verification fails, the local controller will contact the ArchSDN Central Manager to check if the address 
belongs to a client registered in the network.
If a registration is present, the local controller will obtain the target client MAC Address from the ArchSDN Central 
Manager and return it to the local client requesting the address resolution.


### DHCP Service
The DHCP service provided by the ArchSDN controller, serves three purposes:
* To provide IP addresses to the local clients.
* To populate the ArchSDN Central Manager database with local client registrations.
* Allows other controllers to resolve DNS records and to verify the existence of a network client registration.

The service is reactive, meaning it answers to client DHCP Discovery and Request packets.

When the local controller receives a DHCP Discovery packet from a client wanting to obtain an IPv4 address, the 
controller registers the client at the ArchSDN central manager, receiving in return an IPv4 address and a hostname.
The controller then sends a DHCP Offer packet to the client with the IPv4 client address, DNS address and hostname 
proposals.

When the local controller receives a DHCP Request packet from a previously registered network client, the local 
controller will send in return a DHCP ACK packet, with the registered IPv4 address
If the client is not registered, the local controller will send a DHCP NACK packet, to force the client to send a 
DHCP Discovery packet.


### DNS Service
The ArchSDN controller implements a micro-DNS server, which provides a minimal translation for Name records, under the 
`.archsdn` top-level domain.

Every client registered in the ArchSDN network, has an associated name which is given to the client using the DHCP 
Offer packets.

The DNS Name records use the structure `YYY.XXX.archsdn` where:
* `YYY` is an integer which represent the client record ID in the Sector
* `XXX` is an integer or a literal UUID, representing the Controller ID in the network.

Examples:
* `123.123.archsdn`
* `123.00000000-0000-0000-0000-00000000007B.archsdn`

All DNS Query Messages sent to the virtual IP address of the local controller, are intercepted and redirected to the 
local controller, which queries the names at the ArchSDN Central Manager.

If the names are registered, the local controller will reply to local client with the resolved IP address.
If not, it replies the local client with an empty answer.


### ICMPv4 Service


#### ICMP Echo Request from Client to Controller
ICMP Echo Requests containing the controller virtual IP address as the destination, are captured by the local switches 
are redirected to the controller.
The controller will react to this type of packet, by replying with an ICMP Echo Reply to the local client.


#### ICMP Request from Client to Client
Due to the peculiar nature of the ICMPv4 traffic, which requires for an ICMP response to travel the network using the 
same path used to send the ICMP request, the ArchSDN controller implements the ICMPv4 service using bi-directional MPLS 
tunnels.

By using bi-directional MPLS tunnels in conjunction with flows which filter ICMP requests from the origin client to the 
target client, and with flows which filter ICMP responses from the target client to the origin client.

```
 ICMP Echo Request ─────────────────────────────────>
     Origin Client <───> OF Switch <───>  OF Switch <───> Target Client
                   <───────────────────────────────────── ICMP Echo Reply
```

### Generic IPv4 service
Generic IPv4 packets which are not ICMPv4 and do not have the controller virtual IP as the destination, are treated as 
unidirectional communication.

Unidirectional communication is implemented using unidirectional MPLS paths, meaning that two different paths may be 
used when to clients want to communicate with each other.

The implementation of the generic IPv4 service is performed by implementing flows at the entry-point local switches 
where the local clients are connected, filtering the IPv4 packets using the origin and destination IPv4 addresses.

When the client sends an IP packet towards another client in the network, the lack of a specific flow that matches IPV4 packets with the specific (origin, destination) addresses, will make the switch send the packet to the controller for evaluation.

After verifying that the destination address corresponds to a client registered in the network, the controller detects the lack of a communication path between those two clients and starts the procedure to implement an unidirectional path from the local client to the remote client.

When the path is established and the packets reach the remote client, the response by the remote client will start the same procedure from the remote sector, which will be executed by the remote sector controller.

```
  IPv4 Packets ─────────────────────────────────>
 Origin Client ───> OF Switch ───> OF Switch ───> Target Client
```
```
 Origin Client <─── OF Switch <─── OF Switch <─── Target Client
               <───────────────────────────────── IPv4 Packets
```


## Switch Default Table Configuration

The sector OpenFlow switches are initially configured by the local controller, with a set of default flows. 
These flows will capture specific types of packets and redirect them to the controller, for further analysis, which could result services activation, services queries or simply being discarded.

Each OpenFlow switch in the ArchSDN network, has its flows organized in an hierarchical structure.
The hierarchical structure provides an efficient way to organize the packet filtering process, while reducing the number of flows and consequentially reducing the memory usage at the switch and the switch pipeline evaluation latency.

The flows are organized in 5 different tables:
* Port Segregation Table (**Table 0**)
* Host Filtering Table (**Table 1**)
* Sector Filtering Table (**Table 2**)
* MPLS Filtering Table (**Table 3**)
* Foreign Host Filtering Table (**Table 4**)

Packets can be evaluated in one table, and then forwarded to tables down the line, but never to previous tables.

The processing in each table, is as follows.

### Port Segregation Table
This table is used to provide an initial packet filtering and depending upon the source, send it to a specific table for further evaluation. 
Packets sent by local clients, are redirected to the Host Filtering Table. 
Packets sent by a switch located in an adjacent sector, are redirected to the Sector Filtering Table. 
Packets sent by a switch in the same sector, are redirected to the MPLS Filtering Table.

When a local client is registered, the controller adds a filtering flow with a higher priority than the default flows, redirecting the packets with the source MAC address which is equal to the local client MAC address.

When a discovery packet is received, the controller verifies if the port is still free for registration and if so, it registers the port as being connected to an adjacent switch, meaning it is connected to an adjacent sector.

Default Flows:
* Redirect:
  * DHCP Discovery packets
  * ArchSDN L2 Discovery Packets (ethertype=`0xAAAA`)
* Drop:
  * Everything else


### Host Filtering Table
This table is used to evaluate packets sent by local clients.

Packets sent by local clients could be bound to either other local clients or to remote clients.

If the packets are bounded to another local client connected to the same switch, the packet is simply switched to the port where the target local client is connected.
If the target client is connected to a different local switch or is located in a remote sector, the packet is encapsulated with an MPLS header and sent to the MPLS Filtering Table for further processing.

Default Flows:
* Redirect:
  * DHCP Discovery packets (broadcast by the client)
  * DNS packets (sent by a client to the controller virtual IP address)
  * ICMP packets (sent by a client to the controller virtual IP address or to the private network address range)
  * ARP packets (only with the private network address range, defined by the ArchSDN Central Manager)
  * Generic IPv4 packets (sent by a client to the controller virtual IP address or to the private network address range)
* Drop:
  * Irregular ICMP packets (sent by a client but with with controller virtual IP address as the source address)
  * Everything else


### Sector Filtering Table
This table is used to evaluate packets sent by an adjacent switch to a local switch.

Packets received from other sectors, are either topology discovery packets or MPLS packets.
The topology discovery packets are filtered at the Port Segregation Table, so this table will only filter MPLS packets.

The MPLS packets can either be packets bounded for clients in the receiving local switch, for another local switches or for other remote sectors.

If the MPLS packet is bounded for the receiving local switch, the MPLS header is removed and the packet is sent to the Foreign Filtering Table.

If the MPLS packet is either bounded for another local switch or to another sector, the MPLS packet label is updated with the MPLS label of the local MPLS tunnel whose destination is the target local switch.
After the packet is updated, it is sent to proper output port of the switch.

The controller adds or removes flows from this table, when it creates or destroys communication path translations between sectors.

Default Flows:
* Drop:  
  * Everything else


### MPLS Filtering Table
This table is used to evaluate packets which contain a MPLS header.
MPLS packets are evaluated according to their MPLS label ID.
The packets can either have their header removed and then sent to the Foreign Filtering Table for further evaluation, have their label ID updated and switched to another port, or simply switch the packet to another port.

The MPLS Filtering Table is the core table for MPLS communication paths.
This table provides a simple way to quickly switch MPLS packets from one port to another with low latency.

The controller adds or removes flows from this table, when it creates or destroys communication paths in the sector.

Default Flows:
* Drop:  
  * Everything else


### Foreign Filtering Table
This table is used to evaluate packets which arrive to the local sector through MPLS communication paths, having their MPLS header removed by either the Sector Filtering Table or the MPLS Filtering Table.

This table does the final evaluation before delivering the packet to the correct local client, which will be connected to the switch performing the evaluation.
The evaluation consists in verifying the MAC addresses and network addresses to check if they match any flow in table, switching the packet to the port where the target client is connected.

The controller adds or removes flows from this table, when it establishes or destroys ICMPv4 or IPv4 generic services between network clients.

Default Flows:
* Drop:
  * Everything else



## Decision Mechanism for the implementation of Communication Paths 

The ArchSDN controller uses a distributed decision mechanism which is used to establish end-to-end communication between clients present in different sectors.

Due to the nature of the ArchSDN network where controllers only know the topology of their own sector, controllers are required to communicate with the adjacent controllers to implement cross-sector communication paths.

The fact that a local controller only possesses the topological information of the sector it controls, also means that beyond the adjacent sectors, a controller does not know where foreign sectors are and to which remote sectors they are connected.

The ArchSDN controller has an exploration mechanism which takes leverage on reinforcement learning concepts, to use the available connections to adjacent sectors to explore communication paths to remote clients.
By exploring the available connections, establishing communication paths and learning from the quality of the resulting paths, the decision mechanism is capable of learning which of the available connections is providing the best results.
The mechanism is also capable of adapting itself to overcome link failures and learn alternative routes, while optimizing the quality of a path.


### Obtaining the location of a remote client

Since a remote client exists outside of the local sector, the local controller contacts the central manager to obtain the identification of the sector where the remote client resides.
The identification of the sector and the network address of the remote client, will be used during the exploration process.


### Initiating the exploration process

Upon obtaining the location of the remote client, the local controller evaluates the local sector links to the adjacent sectors to see what links can be used to explore a possible path.

A list of the available links with enough resources to provide the service is constructed and added to the local controller database as possible choices, if they are not already present.
Then, the decision mechanism chooses one connection from the list, based on its performance in the past.

Upon choosing a link, the controller will reserve a communication path between the local client and the chosen link, so that the resources for the communication path are kept on the side until the communication path is fully implemented.

The controller then proceeds to contact the adjacent controller to which the chosen link connects to, and requests from it to continue the process of implementing the communication path.

Upon receiving the request, the adjacent controller repeats the process but starting on the chosen link by the local switch and if the target client is inside the adjacent sector, then terminating on the target client.
If the target client is in another sector, then the adjacent controller will repeat the process.

During this process, the controllers involved in implementing the communication path will keep the request active in memory. 
This is necessary, to avoid loops in the network for the chain-requests.

The result of the request can either be a success or a failure.

If the result is success, the local controller will obtain the information regarding the quality of the path and use it to feed the reinforcement learning mechanism to update the quality of the chosen link, to further reinforce future decisions.

If the result is a failure, the reinforcement learning updates the link quality by reinforcing it with a penalty. 
Then, it proceeds to choose another link from the available links list and retry until there are no more available links, meaning there is no available path either by lack of resources or simply because the remote client is unreachable.

The implementation of the communication path terminates successfully when the local controller implements on the local switches the previously reserved communication path.


### Reinforcement Learning

The decision mechanism is based on reinforcement learning concepts, more specifically the SARSA algorithm.

Each different link to an adjacent sector represents a possible decision to be taken, from which a different outcome will result.
The outcome will provide feedback for the learning mechanism, which will influence future decisions on which option to take, if a new connection path is required.

The result of each decision is based on the quality of the resulted communication path.
Two things influence the result:
* The number of hops of the communication path. The more hops, the worse the resulting outcome is.
* The remaining resources available in the links used the the communication path. The less resources become available, the worse the resulting outcome is.

The reward equation is as follows:

Reward calculation variables:
* Explored Path Length (**Epl**), which  is the length of the path from the local client to the remote client.
* Known Shortest Path Distance (**Kspl**) which is the minimum known distance to the remote client by the local controller.
* Remaining Bandwidth average (**Rla**) value which represents the average percentage of available bandwidth at the local path within the sector.

```
   reward = Rla/(Epl x Kspl)
```

Each decision is reinforced with the result obtaining from the quality of the path, following the same concept of the SARSA reinforcement learning algorithm.

The SARSA learning algorithm establishes a Q-Value for each decision.
The reinforcement of the decision happens when the Q-Value is reinforced with a new result.
Reinforcing the Q-Value means, calculating a new Q-Value (post-decision) based on the old Q-Value (pre-decision) plus the reinforcement (the outcome of the decision).

The equation for the SARSA algorithm is as follows:
```
lp => local path
fp => forward path
Q-Value(lp) = Q(lp) + \alpha (reward + \gamma Q(fp) - Q(lp))
```

The equation has two fixed variables, which can take values between 0 and 1:
* *__alpha__*: The learning rate, where a value of 0 means the agent does not learn anything from new decisions, and a value of 1 means it ignores the previous decisions experience.
* *__gamma__*: The discount factor, where a value of 0 means the controller refuses the experience from the adjacent controllers, ignoring the quality of the path decided by the adjacent controller, where a value of 1 means the controller accepts in full, the experience provided by adjacent controller, giving high importance to the quality of the communication path decided by the adjacent sector.


### Learning from each decision

The Q-Value(fp) is the value returned by adjacent sectors when they implement the communication path with success.
If the adjacent sector fails to implement a communication path, the Q-Value(fp) is 0.
In that case, the local controller will use a negative reward equal to -1 to provide a penalty for the chosen link and update its Q-Value(lp).

If the adjacent sector implements a communication path with success, the Q-Value(fp) will be used to reinforce the chosen link Q--Value(lp), along with a reward calculated from the temporary reserved local path.


## Notes

This controller is experimental and was only used with mininet (2.3 development) and OpenVSwitch (v2.9).

OpenVSwitch 2.9 is required for the necessary OpenFlow 1.3 functions used by the ArchSDN controller, and OpenVSwitch 2.9 is only supported by mininet v2.3. 
The v2.2 is not compatible with ArchSDN controller.

Check the scenarios repository for a set of ready-to-use mininet scenarios.

Also, if there's something missing, confusing or that should need a rewrite, contact me using the proper channels (open an issue in this repo).

The code can also be consulted to better understand what is performed "under the hood".
