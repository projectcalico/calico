// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The proto package defines the protocol between Felix's policy
// "calculation engine", which calculates the policy that should be active
// on a given host, and the "dataplane driver", which renders that policy
// into the dataplane.
//
//	              +-----------+
//	              | Datastore |
//	              +-----+-----+
//	                    |
//	                    | <etcd/k8s/etc API>
//	                    |
//	         +----------+---------------+
//	         | libcalico-go "client"    |
//	         +---------<go API>---------+
//	         | Felix calculation engine |
//	         +----------+---------------+
//	                    |
//	                    | <this API>
//	                    |
//	         +----------+---------------+
//	         | Dataplane driver         |
//	         +----------+---------------+
//	                    |
//	                    | <dataplane-specific API>
//	                    |
//	         ======= Dataplane ==========
//
//
// Data Model Overview
//
// The data model used on the dataplane driver API uses similar concepts to
// the main "datastore" data model (such as host/workload endpoints, policies
// and profiles).  However, the calculation engine does some pre-calculation
// that simplifies the job of the dataplane driver:
//
// Rules in the datastore data model can contain selectors, such as
// "role == webserver", that refer to dynamic groups of endpoints.  The calculation
// engine computes sets of IP addresses from those selectors.  Only the sets of
// IPs are sent over the API so the dataplane driver doesn't need to compute
// selectors itself, it only needs a way to program a set of IP addresses into
// the dataplane.
//
// Policies in the datastore data model need to be filtered and sorted. The
// calculation engine takes care of that too.  When it sends an endpoint to the
// datastore driver, it adds the complete list of policies that apply to the
// endpoint (in the correct order).  If the correct list changes, it sends an
// update for the endpoint.
//
// If a resource fails validation, the calculation engine replaces it with a
// "safe" stub or it simulates a delete.
//
// This means that the dataplane driver sees the following model, filtered
// to only the resources that are active on this host:
//
//	 +------------------+
//	+------------------+|
//	| Host/Workload    ||
//	| Endpoint         ||
//	|                  ||
//	| Policy ID list --------+ refers to policies by ID
//	| List of IPs      ||    |
//	| Interface name   |+    |
//	+------------------+     |
//	                         |
//	               +---------|---------+
//	              +----------+--------+|
//	              | Policy            ||
//	              |                   ||
//	              | Inbound rules --------+ (rules embedded in the policy object)
//	              | Outbound rules --------+
//	              +-------------------+    |
//	                                       |
//	                             +---------|---------+
//	                            +----------+--------+|
//	                            | Rule              ||
//	                            |                   ||
//	                            | Match criteria    ||
//	                            | - protocol        ||
//	                            | - port            ||
//	                            | - CIDR            ||
//	                            | - ...             ||
//	                            | - IP set ID list  -----+ refers to IP sets by ID
//	                            +-------------------+    |
//	                                                     |
//	                                           +---------|---------+
//	                                          +----------+--------+|
//	                                          | IP set            ||
//	                                          |                   ||
//	                                          | 10.0.0.1          ||
//	                                          | 10.0.0.21         ||
//	                                          | 10.0.0.53         ||
//	                                          +-------------------+
//
// Protocol Overview
//
// The protocol is defined as a series of protobuf messages.  This allows for
// a dataplane driver to run either in-process or in another process.
//
// An in-process dataplane driver (such as the default one in the
// "intdataplane" package) receives the protobuf messages as Go structs
// directly.
//
// When running an external dataplane driver, the main process creates a
// pair of communication pipes, before forking to start the configured
// dataplane driver. The dataplane driver receives messages on file
// descriptor 3 and sends on descriptor 4.  The wire format is described
// in a section below.  The dataplane driver has the same lifetime as the
// main process.
//
// In either case, the protocol (described in more detail below) starts
// with a handshake to exchange configuration.  Then the calculation engine
// begins its resync with the datastore, emitting updates as it scans
// through the current state. Once complete, the calculation engine enters
// the "in-sync" state and starts sending only updates.  Updates are
// asynchronous, with no explicit acknowledgement for each message.
//
// The dataplane driver should send status updates for itself and
// the endpoints that it is controlling.
//
// Handshake
//
// Before sending its stream of updates, the calculation engine loads and resolves
// the configuration (from file, environment variables and the datastore) and
// then sends a ConfigUpdate message with the resolved configuration.  This
// ensures that the driver has the configuration before it receives any
// updates.
//
// Note: the calculation engine doesn't currently support any subsequent config
// updates.  If the config is updated after the process is running, it will
// trigger a process exit, so that the init system can restart it.
//
// Resync and updates
//
// After the initial ConfigUpdate message, the protocol is in resync state.
// The calculation engine will send a stream of updates that merges the current state
// of the datastore along with any updates that occur later.  The stream is
// guaranteed to be eventually consistent.  I.e. if a resource is updated (or
// deleted) during the resync then the calculation engine is free to skip the
// intermediate value and send only one update with the most up-to-date value
// (or none if the object was deleted).
//
// Updates are sent to the dataplane driver in dependency order.  I.e.
// dependencies are sent before the objects that depend on them.  Removes are
// sent in reverse dependency order so the dataplane driver will not receive
// a remove for an object that is still required.
//
// Once the calculation engine has finished its initial datastore scan, it sends the
// InSync message.
//
// For simplicity and robustness, most <Type>Update messages contain the
// complete current state of the resource that they refer to.  However, for
// performance, IP set updates are communicated as an initial IPSetUpdate,
// followed by a sequence of IPSetDeltaUpdate messages.
//
// Graceful restart
//
// During the resync, the dataplane driver is likely to have an incomplete
// picture of the desired state of the dataplane.  If it started programming
// the dataplane immediately, message-by-message after a restart then it may
// disrupt connectivity to already-configured workloads.  To prevent this,
// the dataplane driver should delay programming of potentially incorrect
// state until after it receives the InSync message.
//
// Driver status updates
//
// The driver should send a ProcessStatusUpdate message every 10s to verify its
// liveness.  That message flows through to the datastore and some orchestrators
// (such as OpenStack) rely on the status messages to make scheduling
// decisions.
//
// Endpoint status updates
//
// The driver should report the status for each endpoint that it is managing
// and update the status when it changes.  The driver does not need to periodically
// refresh the endpoint statuses, the "main" process caches the values and
// keeps the datastore in sync.
//
// Once an endpoint is removed, the dataplane driver should send an
// XXXEndpointStatusRemove message so the calculation engine can clear up its cache entry.
//
// Special cases
//
// Due to coalescing of updates in the calculation engine, the dataplane driver
// may receive Remove messages for resources that it didn't previously receive an
// Update for; it should ignore such Remove messages.
//
// Illustration
//
// The protocol flow is illustrated below.
//
//	+-----------+                                             +-------+
//	| dp_driver |                                             | main  |
//	+-----------+                                             +-------+
//	      |                                                       |
//	      |                                            **Create** |
//	      |<------------------------------------------------------|
//	      |               --------------------------------------\ |
//	      |               | Connects to datastore, loads config |-|
//	      |               |-------------------------------------| |
//	      |                                                       |
//	      |                         ConfigUpdate(resolved config) |
//	      |<------------------------------------------------------|
//	      | --------------------------------------------------\   |
//	      |-| Start graceful restart, avoid removing DP state |   |
//	      | |-------------------------------------------------|   |
//	      |                                                       |
//	      |                     DatastoreStatus("wait-for-ready") |
//	      |<------------------------------------------------------|
//	      |                   ----------------------------------\ |
//	      |                   | Starts  resync, sending updates |-|
//	      |                   |---------------------------------| |
//	      |                                                       |
//	      |                             DatastoreStatus("resync") |
//	      |<------------------------------------------------------|
//	      |                                                       |
//	      |                      IPSet(Update|DeltaUpdate|Remove) |
//	      |<------------------------------------------------------|
//	      |                                                       |
//	      |                 Active(Profile|Policy)(Update|Remove) |
//	      |<------------------------------------------------------|
//	      |                                                       |
//	      |                (Workload|Host)Endpoint(Update|Remove) |
//	      |<------------------------------------------------------|
//	      |                                     ----------------\ |
//	      |                                     | Finishes sync |-|
//	      |                                     |---------------| |
//	      |                                                       |
//	      |                            DatastoreStatus("in-sync") |
//	      |<------------------------------------------------------|
//	      | -----------------------------------------\            |
//	      |-| Finish graceful restart, do DP cleanup |            |
//	      | |----------------------------------------|            |
//	      |                                                       |
//	      |                      IPSet(Update|DeltaUpdate|Remove) |
//	      |<------------------------------------------------------|
//	      |                                                       |
//	      |                 Active(Profile|Policy)(Update|Remove) |
//	      |<------------------------------------------------------|
//	      |                                                       |
//	      |                (Workload|Host)Endpoint(Update|Remove) |
//	      |<------------------------------------------------------|
//	      |                                                       |
//	      |                           HostMetadata(Update|Remove) |
//	      |<------------------------------------------------------|
//	      |                                                       |
//	      |                               IPAMPool(Update|Remove) |
//	      |<------------------------------------------------------|
//	      | ------------------------------------\                 |
//	      |-| Status updates (sent at any time) |                 |
//	      | |-----------------------------------|                 |
//	      |                                                       |
//	      | ProcessStatusUpdate                                   |
//	      |------------------------------------------------------>|
//	      |                                                       |
//	      | (Workload|Host)EndpointStatus                         |
//	      |------------------------------------------------------>|
//	      |                                                       |
//
//
// Example
//
// The sequence diagram below illustrates a scenario where the initial resync finds
// one local endpoint, then a new endpoint is added, an IP set updated and the
// endpoints removed.
//
//	+-----------+                                                             +-------+
//	| dp_driver |                                                             | main  |
//	+-----------+                                                             +-------+
//	      |                                                                       |
//	      |                                                            **Create** |
//	      |<----------------------------------------------------------------------|
//	      |                                                 --------------------\ |
//	      |                                                 | Initial handshake |-|
//	      |                                                 |-------------------| |
//	      |                                                                       |
//	      |                                         ConfigUpdate(resolved config) |
//	      |<----------------------------------------------------------------------|
//	      |                                                                       |
//	      |                                     DatastoreStatus("wait-for-ready") |
//	      |<----------------------------------------------------------------------|
//	      |                                                                       |
//	      |                                             DatastoreStatus("resync") |
//	      |<----------------------------------------------------------------------|
//	      |       --------------------------------------------------------------\ |
//	      |       | Loads state: finds one active endpoint on host, one policy, |-|
//	      |       | using one IP set. Sends updates in dependency order:        | |
//	      |       |-------------------------------------------------------------| |
//	      |                             IPSetUpdate("setABCD", ["10.0.0.1", ...]) |
//	      |<----------------------------------------------------------------------|
//	      |                                                                       |
//	      |     ActivePolicyUpdate({inbound_rules: [...], outbound_rules: [...]}) |
//	      |<----------------------------------------------------------------------|
//	      |                                                                       |
//	      |                          WorkloadEndpointUpdate("endpoint1", { ... }) |
//	      |<----------------------------------------------------------------------|
//	      |                                      -------------------------------\ |
//	      |                                      | Finishes sync with datastore |-|
//	      |                                      |------------------------------| |
//	      |                                                                       |
//	      |                                            DatastoreStatus("in-sync") |
//	      |<----------------------------------------------------------------------|
//	      | ---------------------------------------------------\                  |
//	      |-| Now in sync, program dataplane for first time.   |                  |
//	      | | Do any cleanup of old state, send status updates |                  |
//	      | |--------------------------------------------------|                  |
//	      | WorkloadEndpointStatusUpdate("endpoint1", "up")                       |
//	      |---------------------------------------------------------------------->|
//	      | ---------------------------------------------\                        |
//	      |-| Every 10s, send a process status update... |                        |
//	      | |--------------------------------------------|                        |
//	      |                                                                       |
//	      | ProcessStatusUpdate({uptime=...})                                     |
//	      |---------------------------------------------------------------------->|
//	      |                        ---------------------------------------------\ |
//	      |                        | Told about new endpoint, using same policy |-|
//	      |                        |--------------------------------------------| |
//	      |                                                                       |
//	      |                          WorkloadEndpointUpdate("endpoint2", { ... }) |
//	      |<----------------------------------------------------------------------|
//	      | ---------------------\                                                |
//	      |-| Programs dataplane |                                                |
//	      | |--------------------|                                                |
//	      |                                                                       |
//	      | WorkloadEndpointStatusUpdate("endpoint2", "up")                       |
//	      |---------------------------------------------------------------------->|
//	      |                                              -----------------------\ |
//	      |                                              | New IP in the IP set |-|
//	      |                                              |----------------------| |
//	      |                                                                       |
//	      |                 IPSetDeltaUpdate("setABCD", {added_ips=["10.0.0.2"]}) |
//	      |<----------------------------------------------------------------------|
//	      | ---------------------\                                                |
//	      |-| Programs dataplane |                                                |
//	      | |--------------------|                                                |
//	      |                        ---------------------------------------------\ |
//	      |                        | Endpoints deleted, policy no longer active |-|
//	      |                        | Removes in reverse dependency order:       | |
//	      |                        |--------------------------------------------| |
//	      |                                   WorkloadEndpointRemove("endpoint1") |
//	      |<----------------------------------------------------------------------|
//	      |                                                                       |
//	      |                                   WorkloadEndpointRemove("endpoint2") |
//	      |<----------------------------------------------------------------------|
//	      |                                                                       |
//	      |                                            ActivePolicyRemove("polA") |
//	      |<----------------------------------------------------------------------|
//	      |                                                                       |
//	      |                                                IPSetRemove("setABCD") |
//	      |<----------------------------------------------------------------------|
//	      |                                                                       |
//	      | WorkloadEndpointStatusRemove("endpoint1")                             |
//	      |---------------------------------------------------------------------->|
//	      |                                                                       |
//	      | WorkloadEndpointStatusRemove("endpoint2")                             |
//	      |---------------------------------------------------------------------->|
//	      |                                                                       |
//
// Wire format for external dataplane driver
//
// The protocol between the driver and main process is protobuf based.
// On the wire, each message consists of an 8-byte, little-endian length,
// followed by a ToDataplane or FromDataplane protobuf envelope message.
// The length refers to the length of the protobuf data only, it doesn't
// include the 8-byte length header.
//
//	+---------------+--------------------------------------------+
//	| 8-byte length | Protobuf ToDataplane/FromDataplane message |
//	+---------------+--------------------------------------------+
package proto

// http://textart.io/sequence Source code for sequence diagrams above:

var _ = `
object dp_driver main
main->dp_driver: **Create**
note left of main: Connects to datastore, loads config
main->dp_driver: ConfigUpdate(resolved config)
note right of dp_driver: Start graceful restart, avoid removing DP state

main->dp_driver: DatastoreStatus("wait-for-ready")
note left of main: Starts  resync, sending updates
main->dp_driver: DatastoreStatus("resync")

main->dp_driver: IPSet(Update|DeltaUpdate|Remove)
main->dp_driver: Active(Profile|Policy)(Update|Remove)
main->dp_driver: (Workload|Host)Endpoint(Update|Remove)

note left of main: Finishes sync
main->dp_driver: DatastoreStatus("in-sync")
note right of dp_driver: Finish graceful restart, do DP cleanup

main->dp_driver: IPSet(Update|DeltaUpdate|Remove)
main->dp_driver: Active(Profile|Policy)(Update|Remove)
main->dp_driver: (Workload|Host)Endpoint(Update|Remove)
main->dp_driver: HostMetadata(Update|Remove)
main->dp_driver: IPAMPool(Update|Remove)

note right of dp_driver: Status updates (sent at any time)
dp_driver->main: ProcessStatusUpdate
dp_driver->main: (Workload|Host)EndpointStatus
`

var _ = `
object dp_driver main
main->dp_driver: **Create**

note left of main: Initial handshake

main->dp_driver: ConfigUpdate(resolved config)
main->dp_driver: DatastoreStatus("wait-for-ready")
main->dp_driver: DatastoreStatus("resync")

note left of main: Loads state: finds one active endpoint on host, one policy,\n using one IP set. Sends updates in dependency order:

main->dp_driver: IPSetUpdate("setABCD", ["10.0.0.1", ...])
main->dp_driver: ActivePolicyUpdate({inbound_rules: [...], outbound_rules: [...]})
main->dp_driver: WorkloadEndpointUpdate("endpoint1", { ... })

note left of main: Finishes sync with datastore
main->dp_driver: DatastoreStatus("in-sync")

note right of dp_driver: Now in sync, program dataplane for first time.\nDo any cleanup of old state, send status updates
dp_driver->main: WorkloadEndpointStatusUpdate("endpoint1", "up")

note right of dp_driver: Every 10s, send a process status update...
dp_driver->main: ProcessStatusUpdate({uptime=...})

note left of main: Told about new endpoint, using same policy
main->dp_driver: WorkloadEndpointUpdate("endpoint2", { ... })
note right of dp_driver: Programs dataplane
dp_driver->main: WorkloadEndpointStatusUpdate("endpoint2", "up")

note left of main: New IP in the IP set
main->dp_driver: IPSetDeltaUpdate("setABCD", {added_ips=["10.0.0.2"]})
note right of dp_driver: Programs dataplane

note left of main: Endpoints deleted, policy no longer active\nRemoves in reverse dependency order:
main->dp_driver: WorkloadEndpointRemove("endpoint1")
main->dp_driver: WorkloadEndpointRemove("endpoint2")
main->dp_driver: ActivePolicyRemove("polA")
main->dp_driver: IPSetRemove("setABCD")

dp_driver->main: WorkloadEndpointStatusRemove("endpoint1")
dp_driver->main: WorkloadEndpointStatusRemove("endpoint2")
`
