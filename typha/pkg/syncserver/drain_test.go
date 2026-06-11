// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package syncserver

import (
	"context"
	"testing"
)

// addFakeConn injects a synthetic connection (with a cancellable context and a
// client hostname) into the server's connection map, returning a func that
// reports whether its context has been cancelled.
func addFakeConn(s *Server, id uint64, hostname string) func() bool {
	ctx, cancel := context.WithCancel(context.Background())
	conn := &connection{
		ID:             id,
		cxt:            ctx,
		cancelCxt:      cancel,
		clientHostname: hostname,
	}
	s.connIDToConn[id] = conn
	return func() bool { return ctx.Err() != nil }
}

// TestDrainOffNodeClients verifies that DrainOffNodeClients drops connections
// from clients on other nodes while keeping same-node clients.
func TestDrainOffNodeClients(t *testing.T) {
	s := &Server{
		config:       Config{NodeName: "node-a"},
		connIDToConn: map[uint64]*connection{},
	}

	sameNode := addFakeConn(s, 1, "node-a")     // kept
	offNode := addFakeConn(s, 2, "node-b")      // dropped
	offNode2 := addFakeConn(s, 3, "node-c")     // dropped
	emptyHost := addFakeConn(s, 4, "")          // dropped (old client, off-node)
	alsoSameNode := addFakeConn(s, 5, "node-a") // kept

	s.DrainOffNodeClients("test")

	if sameNode() {
		t.Error("same-node client (node-a) should NOT have been drained")
	}
	if alsoSameNode() {
		t.Error("second same-node client (node-a) should NOT have been drained")
	}
	if !offNode() {
		t.Error("off-node client (node-b) should have been drained")
	}
	if !offNode2() {
		t.Error("off-node client (node-c) should have been drained")
	}
	if !emptyHost() {
		t.Error("empty-hostname client should be treated as off-node and drained")
	}
}

// TestDrainOffNodeClients_NoNodeName verifies that, with no NodeName configured,
// every client is treated as off-node and drained (the same-node distinction is
// disabled).
func TestDrainOffNodeClients_NoNodeName(t *testing.T) {
	s := &Server{
		config:       Config{NodeName: ""},
		connIDToConn: map[uint64]*connection{},
	}
	c1 := addFakeConn(s, 1, "node-a")
	c2 := addFakeConn(s, 2, "node-b")

	s.DrainOffNodeClients("test")

	if !c1() || !c2() {
		t.Error("with no NodeName configured, all clients should be drained")
	}
}
