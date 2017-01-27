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

package ipsets

import (
	"bytes"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/set"
	"io"
	"time"
)

const MaxIPSetNameLength = 31

// IPSetType constants for the different kinds of IP set.
type IPSetType string

const (
	IPSetTypeHashIP  IPSetType = "hash:ip"
	IPSetTypeHashNet IPSetType = "hash:net"
)

func (t IPSetType) IsValid() bool {
	switch t {
	case IPSetTypeHashIP, IPSetTypeHashNet:
		return true
	}
	return false
}

// IPSetType constants for the names that the ipset command uses for the IP versions.
type IPFamily string

const (
	IPFamilyV4 = IPFamily("inet")
	IPFamilyV6 = IPFamily("inet6")
)

func (f IPFamily) IsValid() bool {
	switch f {
	case IPFamilyV4, IPFamilyV6:
		return true
	}
	return false
}

// IPSetMetadata contains the metadata for a particular IP set, such as its name, type and size.
type IPSetMetadata struct {
	SetID   string
	Type    IPSetType
	MaxSize int
}

// IPSet represents a single IP set.  In general, a Registry should be used to create and manage
// the collection of IP sets for a particular IP version.
//
// The IPSet object defers the actual updates to the IP set.  It expects a series of
// Add/Remove/ReplaceMember() calls followed by a cal to Apply(), which actually writes to the
// dataplane.
//
// For performance, the IPSet objects created by a single Registry share a cache of IP set
// existence.
type IPSet struct {
	IPSetMetadata

	IPVersionConfig *IPVersionConfig

	desiredMembers set.Set

	pendingAdds      set.Set
	pendingDeletions set.Set

	rewritePending bool

	existenceCache existenceCache

	newCmd cmdFactory
	Sleep  func(time.Duration)
}

func NewIPSet(
	versionConfig *IPVersionConfig,
	metadata IPSetMetadata,
	existenceCache existenceCache,
	cmdFactory cmdFactory,
) *IPSet {
	return &IPSet{
		IPVersionConfig:  versionConfig,
		IPSetMetadata:    metadata,
		desiredMembers:   set.New(),
		pendingAdds:      set.New(),
		pendingDeletions: set.New(),
		rewritePending:   true,
		existenceCache:   existenceCache,
		newCmd:           cmdFactory,
		Sleep:            time.Sleep,
	}
}

func (s *IPSet) ReplaceMembers(newMembers []string) {
	s.desiredMembers = set.New()
	for _, m := range newMembers {
		s.desiredMembers.Add(m)
	}
	s.rewritePending = true
	s.pendingAdds = set.New()
	s.pendingDeletions = set.New()
}

func (s *IPSet) AddMembers(newMembers []string) {
	for _, m := range newMembers {
		s.desiredMembers.Add(m)
		if !s.rewritePending {
			s.pendingAdds.Add(m)
			s.pendingDeletions.Discard(m)
		}
	}
}

func (s *IPSet) RemoveMembers(removedMembers []string) {
	for _, m := range removedMembers {
		s.desiredMembers.Discard(m)
		if !s.rewritePending {
			s.pendingAdds.Discard(m)
			s.pendingDeletions.Add(m)
		}
	}
}

func (s *IPSet) Apply() {
	// In previous versions of Felix, we've observed that, rarely, the ipset command
	// fails at random, either with a segfault or due to the kernel temporarily rejecting the
	// connection.  Allow a few retries.
	retries := 3
	for {
		if s.rewritePending {
			// We've been asked to rewrite the IP set from scratch.  We need to do this:
			// - at start of day
			// - after a failure
			// - whenever we change the parameters of the ipset.
			err := s.rewriteIPSet()
			if err != nil {
				if retries <= 0 {
					log.WithError(err).Panic("Failed to rewrite ipset after retries, giving up")
				}
				log.WithError(err).Warn("Sleeping before retrying ipset rewrite")
				s.Sleep(100 * time.Millisecond)
				// Reload the existence cache in case we're out of sync.
				s.existenceCache.Reload()
				retries--
				continue
			}
			s.rewritePending = false
			break
		} else {
			// IP set should already exist, just write deltas to the main IP set.
			err := s.flushDeltas()
			if err != nil {
				log.WithError(err).Warn("Failed to update IP set, attempting to rewrite it")
				s.rewritePending = true
				continue
			}
			break
		}
	}
	s.pendingDeletions.Clear()
	s.pendingAdds.Clear()
}

func (s *IPSet) flushDeltas() error {
	logCxt := log.WithFields(log.Fields{
		"setID":      s.SetID,
		"numMembers": s.desiredMembers.Len(),
		"numAdds":    s.pendingAdds.Len(),
		"numDeletes": s.pendingDeletions.Len(),
	})
	logCxt.Info("Applying deltas to IP set")

	// Pre-calculate the commands to issue in a buffer.
	var buf bytes.Buffer
	s.writeDeltas(&buf)
	if log.GetLevel() >= log.DebugLevel {
		// Only stringify the buffer if we're debugging.
		logCxt.WithField("input", buf.String()).Debug("About to apply deltas to IP set")
	}

	// Execute the commands via the bulk "restore" sub-command.
	if err := s.execIpsetRestore(&buf); err != nil {
		return err
	}

	logCxt.Info("Applied deltas to IP set")
	return nil
}

// rewriteIPSet does a full, atomic, idempotent rewrite of the IP set.
func (s *IPSet) rewriteIPSet() error {
	logCxt := log.WithFields(log.Fields{
		"setID":      s.SetID,
		"numMembers": s.desiredMembers.Len()},
	)
	logCxt.Info("Rewriting IP Set")

	// Pre-calculate the commands to issue in a buffer.
	var buf bytes.Buffer
	s.writeFullRewrite(&buf)
	if log.GetLevel() >= log.DebugLevel {
		// Only stringify the buffer if we're debugging.
		logCxt.WithField("input", buf.String()).Debug("About to rewrite IP set")
	}

	// Execute the commands via the bulk "restore" sub-command.
	if err := s.execIpsetRestore(&buf); err != nil {
		return err
	}

	// Success, we know the main set exists and the temp set has been deleted.
	logCxt.Info("Rewrote IP set")
	s.existenceCache.SetIPSetExists(s.MainIPSetName(), true)
	s.existenceCache.SetIPSetExists(s.TempIPSetName(), false)

	return nil
}

func (s *IPSet) execIpsetRestore(stdin io.Reader) error {
	// Execute the commands via the bulk "restore" sub-command.
	cmd := s.newCmd("ipset", "restore")
	cmd.SetStdin(stdin)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", string(output)).Warn(
			"Failed to execute 'ipset restore'.")
		return err
	}
	return nil
}

type stringWriter interface {
	io.Writer
	WriteString(s string) (n int, err error)
}

// writeFullRewrite calculates the ipset restore input required to do a full, atomic, idempotent
// rewrite of the IP set and writes it to the given io.Writer.
func (s *IPSet) writeFullRewrite(buf stringWriter) {
	// Our general approach is to create a temporary IP set with the right contents, then
	// atomically swap it into place.
	mainSetName := s.MainIPSetName()
	if !s.existenceCache.IPSetExists(mainSetName) {
		// Create empty main IP set so we can share the atomic swap logic below.
		// Note: we can't use the -exist flag (which should make the create idempotent)
		// because it still fails if the IP set was previously created with different
		// parameters.
		log.WithField("setID", s.SetID).Debug("Pre-creating main IP set")
		fmt.Fprintf(buf, "create %s %s family %s maxelem %d\n",
			mainSetName, s.Type, s.IPVersionConfig.Family, s.MaxSize)
	}
	tempSetName := s.TempIPSetName()
	if s.existenceCache.IPSetExists(tempSetName) {
		// Explicitly delete the temporary IP set so that we can recreate it with new
		// parameters.
		log.WithField("setID", s.SetID).Debug("Temp IP set exists, deleting it before rewrite")
		fmt.Fprintf(buf, "destroy %s\n", tempSetName)
	}
	// Create the temporary IP set with the current parameters.
	fmt.Fprintf(buf, "create %s %s family %s maxelem %d\n",
		tempSetName, s.Type, s.IPVersionConfig.Family, s.MaxSize)
	// Write all the members into the temporary IP set.
	s.desiredMembers.Iter(func(item interface{}) error {
		member := item.(string)
		fmt.Fprintf(buf, "add %s %s\n", tempSetName, member)
		return nil
	})
	// Atomically swap the temporary set into place.
	fmt.Fprintf(buf, "swap %s %s\n", mainSetName, tempSetName)
	// Then remove the temporary set (which was the old main set).
	fmt.Fprintf(buf, "destroy %s\n", tempSetName)
	// ipset restore input ends with "COMMIT" (but only the swap instruction is guaranteed to be
	// atomic).
	buf.WriteString("COMMIT\n")
}

// writeDeltas calculates the ipset restore input required to apply the pending adds/deletes to the
// main IP set.
func (s *IPSet) writeDeltas(buf stringWriter) {
	mainSetName := s.MainIPSetName()
	s.pendingDeletions.Iter(func(item interface{}) error {
		member := item.(string)
		fmt.Fprintf(buf, "del %s %s\n", mainSetName, member)
		return nil
	})
	s.pendingAdds.Iter(func(item interface{}) error {
		member := item.(string)
		fmt.Fprintf(buf, "add %s %s\n", mainSetName, member)
		return nil
	})
	buf.WriteString("COMMIT\n")
}

func (s *IPSet) TempIPSetName() string {
	return s.IPVersionConfig.NameForTempIPSet(s.SetID)
}

func (s *IPSet) MainIPSetName() string {
	return s.IPVersionConfig.NameForMainIPSet(s.SetID)
}
