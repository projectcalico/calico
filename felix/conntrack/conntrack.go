// Copyright (c) 2016-2017,2020 Tigera, Inc. All rights reserved.
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

package conntrack

import (
	"bytes"
	"io"
	"net"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

// For TCP/UDP, each conntrack entry holds two copies of the tuple
// (src addr, dst addr, src port, dst port).  One copy for the original direction and one copy for
// the reply direction.  This is how the kernel handles NAT: by looking up the tuple for a packet
// by its original tuple and mapping onto the corresponding reply direction tuple (or vice versa).
// The reply tuple is calculated when the original outgoing packet is processed (and possibly
// NATted).
//
// When we delete conntrack entries by IP address, we need to specify which element of the tuple
// to look in.  This slice holds the flags corresponding to the fields we care about.  Since we're
// deleting entries for local workload endpoints, either the endpoint originated the traffic, or it
// received the traffic and replied to it.  In the originating case, the "original source" will be
// set to the endpoint's IP; in the other case, the "reply source". Hence, it's sufficient to only
// look in those two fields.
var deleteDirections = []string{
	"--orig-src",
	"--reply-src",
}

const numRetries = 3

type Conntrack struct {
	newCmd newCmd
}

func New() *Conntrack {
	return NewWithCmdShim(func(name string, arg ...string) CmdIface {
		return (*cmdAdapter)(exec.Command(name, arg...))
	})
}

type cmdAdapter exec.Cmd

func (c *cmdAdapter) SetStderr(w io.Writer) {
	(*exec.Cmd)(c).Stderr = w
}

func (c *cmdAdapter) Run() error {
	return (*exec.Cmd)(c).Run()
}

// NewWithCmdShim is a test constructor that allows for shimming exec.Command.
func NewWithCmdShim(newCmd newCmd) *Conntrack {
	return &Conntrack{
		newCmd: newCmd,
	}
}

type newCmd func(name string, arg ...string) CmdIface

type CmdIface interface {
	SetStderr(w io.Writer)
	Run() error
}

func (c Conntrack) RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP) {
	var family string
	switch ipVersion {
	case 4:
		family = "ipv4"
	case 6:
		family = "ipv6"
	default:
		log.WithField("version", ipVersion).Panic("Unknown IP version")
	}
	log.WithField("ip", ipAddr).Info("Removing conntrack flows")
	for _, direction := range deleteDirections {
		logCxt := log.WithFields(log.Fields{"ip": ipAddr, "direction": direction})
		// Retry a few times because the conntrack command seems to fail at random.
		for retry := 0; retry <= numRetries; retry += 1 {
			cmd := c.newCmd("conntrack",
				"--family", family,
				"--delete", direction,
				ipAddr.String())

			// The conntrack tool generates quite a lot of output on stdout (one line per flow) so we
			// only capture stderr (which is where it logs its errors).
			var stderrBuf bytes.Buffer
			cmd.SetStderr(&stderrBuf)
			err := cmd.Run()
			if err == nil {
				logCxt.Debug("Successfully removed conntrack flows.")
				break
			}

			if bytes.Contains(stderrBuf.Bytes(), []byte("0 flow entries")) {
				// Success, there were no flows.
				logCxt.Debug("IP wasn't in conntrack")
				break
			}
			if retry == numRetries {
				logCxt.WithError(err).WithField("output", stderrBuf.String()).Error("Failed to remove conntrack flows after retries.")
			} else {
				logCxt.WithError(err).WithField("output", stderrBuf.String()).Debug("Failed to remove conntrack flows, will retry...")
			}
		}
	}
}
