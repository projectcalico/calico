// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

// The proto package defines the protocol between the main, calico-felix,
// process (written in Golang) and the dataplane driver plugin.
//
// Overview
//
// The main process creates a pair of communication pipes, before forking
// to start the dataplane driver.  The dataplane driver receives messages on
// file descriptor 3 and sends on descriptor 4.
//
// The protocol (described in more detail below) starts with a handshake to
// exchange configuration.  Then the main process begins its resync with the
// datastore, emitting updates as it scans through the current state.
// Once complete, the main process enters the "in-sync" state and starts
// sending only updates.  The driver may send  process/endpoint status
// updates at any time after the handshake.
//
// The wire-format for the protocol uses protobuf.  It is described in
// more detail below.
//
// Handshake
//
// Before sending its stream of updates, the main process loads and resolves
// the configuration (from file, environment variables and the datastore) and
// then sends a ConfigUpdate message with the resolved configuration.  This
// ensures that the driver has the configuration before it receives any
// updates.
//
// Note: the main process doesn't currently support any subsequent config
// updates.  If the config is updated after the process is running, it will
// exit, so that the init system can restart it.
//
// Resync and updates
//
// After the initial ConfigUpdate message, the protocol is in resync state.
// The main process will send a stream of updates that merges the current state
// of the datastore along with any updates that occur later.  The stream is
// guaranteed to be eventually consistent.  I.e. if a resource is updated (or
// deleted) during the resync then the main process is free to skip the
// intermediate value and send only one update with the most up-to-date value
// (or none if the object was deleted).
//
// Once the main process has finished its initial datastore scan, it sends the
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
// Note: there are many safe updates that the dataplane driver can make during
// the resync.  For example, if it receives a profile update, it is free to
// overwrite the exsting profile state because the profile update contains a
// complete and consistent snapshot of the profile.
//
// Special cases
//
// If the main process fails to parse an update from the datastore, it
// simulates a deletion for the relevant resource.  As such the driver must be
// robust to duplicate Remove messages as well as receiving a Remove message
// for a resource that it hadn't previously been told about.
//
// The above also implies that the driver needs to be robust against
// receiving partial information.  For example,. if it receives an endpoint
// that refers to profile X but profile X is never sent or is deleted then it
// should handle that by dropping packets that would go to profile X.
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
//	      | ------------------------------------\                 |
//	      |-| Status updates (sent at any time) |                 |
//	      | |-----------------------------------|                 |
//	      |                                                       |
//	      | FelixStatusUpdate                                     |
//	      |------------------------------------------------------>|
//	      |                                                       |
//	      | (Workload|Host)EndpointStatus                         |
//	      |------------------------------------------------------>|
//	      |                                                       |
//
// Wire format
//
// The protocol between the driver and main process is protobuf based.
// On the wire, each message consists of an 8-byte, little-endian length,
// followed by a ToDataplane or FromDataplane protobuf envelope message.
// The length refers to the length of the protobuf data only, it doesn't
// include the 8-byte length header.
package proto

// http://textart.io/sequence Source code for sequence diagram above:

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

note right of dp_driver: Status updates (sent at any time)
dp_driver->main: FelixStatusUpdate
dp_driver->main: (Workload|Host)EndpointStatus
`
