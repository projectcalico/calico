// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	log "github.com/Sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"

	"regexp"
	"strings"

	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/set"
)

var (
	gaugeVecNumCalicoIpsets = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_ipsets_calico",
		Help: "Number of active Calico IP sets.",
	}, []string{"ip_version"})
	gaugeNumTotalIpsets = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_ipsets_total",
		Help: "Total number of active IP sets.",
	})
	countNumIPSetCalls = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipset_calls",
		Help: "Number of ipset commands executed.",
	})
	countNumIPSetErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipset_errors",
		Help: "Number of ipset command failures.",
	})
	countNumIPSetLinesExecuted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipset_lines_executed",
		Help: "Number of ipset operations executed.",
	})
	summaryExecStart = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_exec_time_micros",
		Help: "Summary of time taken to fork/exec child processes",
	})
)

func init() {
	prometheus.MustRegister(gaugeVecNumCalicoIpsets)
	prometheus.MustRegister(gaugeNumTotalIpsets)
	prometheus.MustRegister(countNumIPSetCalls)
	prometheus.MustRegister(countNumIPSetErrors)
	prometheus.MustRegister(countNumIPSetLinesExecuted)
	prometheus.MustRegister(summaryExecStart)
}

const MaxIPSetNameLength = 31

// IPSetType constants for the different kinds of IP set.
type IPSetType string

const (
	IPSetTypeHashIP  IPSetType = "hash:ip"
	IPSetTypeHashNet IPSetType = "hash:net"
)

func (t IPSetType) SetType() string {
	return string(t)
}

// CanonicaliseMember converts the string representation of an IP set member to a canonical
// object of some kind.  The object is required to by hashable.
func (t IPSetType) CanonicaliseMember(member string) ipSetMember {
	switch t {
	case IPSetTypeHashIP:
		// Convert the string into our ip.Addr type, which is backed by an array.
		ipAddr := ip.FromString(member)
		if ipAddr == nil {
			// This should be prevented by validation in libcalico-go.
			log.WithField("ip", member).Panic("Failed to parse IP")
		}
		return ipAddr
	case IPSetTypeHashNet:
		// Convert the string into our ip.CIDR type, which is backed by a struct.
		return ip.MustParseCIDR(member)
	}
	log.WithField("type", string(t)).Panic("Unknown IPSetType")
	return nil
}

type ipSetMember interface {
	String() string
}

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

// ipSet holds the state for a particular IP set.
type ipSet struct {
	IPSetMetadata

	MainIPSetName string
	TempIPSetName string

	// members either contains the members that we've programmed or is nil, indicating that
	// we're out of sync.
	members set.Set

	// pendingReplace is either nil to indicate that there is no pending replace or a set
	// containing all the entries that we want to write.
	pendingReplace set.Set
	// pendingAdds contains members that are queued up to add to the IP set.  If pendingReplace
	// is non-nil then pendingAdds is empty (and we add members directly to pendingReplace
	// instead).
	pendingAdds set.Set
	// pendingDeletions contains members that are queued up for deletion.  If pendingReplace
	// is non-nil then pendingDeletions is empty (and we delete members directly from
	// pendingReplace instead).
	pendingDeletions set.Set
}

// IPVersionConfig wraps up the metadata for a particular IP version.  It can be used by
// this and other components to calculate IP set names from IP set IDs, for example.
type IPVersionConfig struct {
	Family                IPFamily
	setNamePrefix         string
	tempSetNamePrefix     string
	mainSetNamePrefix     string
	ourNamePrefixesRegexp *regexp.Regexp
}

func NewIPVersionConfig(
	family IPFamily,
	namePrefix string,
	allHistoricPrefixes []string,
	extraUnversionedIPSets []string,
) *IPVersionConfig {
	var version string
	switch family {
	case IPFamilyV4:
		version = "4"
	case IPFamilyV6:
		version = "6"
	}
	versionedPrefix := namePrefix + version
	var versionedPrefixes []string
	versionedPrefixes = append(versionedPrefixes, namePrefix+version)
	for _, prefix := range allHistoricPrefixes {
		versionedPrefixes = append(versionedPrefixes, prefix+version)
	}
	versionedPrefixes = append(versionedPrefixes, extraUnversionedIPSets...)
	for i, pfx := range versionedPrefixes {
		versionedPrefixes[i] = regexp.QuoteMeta(pfx)
	}
	ourNamesPattern := "^(" + strings.Join(versionedPrefixes, "|") + ")"
	log.WithField("regexp", ourNamesPattern).Debug("Calculated IP set name regexp.")
	ourNamesRegexp := regexp.MustCompile(ourNamesPattern)

	return &IPVersionConfig{
		Family:                family,
		setNamePrefix:         versionedPrefix,
		tempSetNamePrefix:     versionedPrefix + "t", // Replace "-" so we maintain the same length.
		mainSetNamePrefix:     versionedPrefix + "-",
		ourNamePrefixesRegexp: ourNamesRegexp,
	}
}

// NameForTempIPSet converts the given IP set ID (example: "qMt7iLlGDhvLnCjM0l9nzxbabcd"), to
// a name for use in the dataplane.  The return value will have the configured prefix and is
// guaranteed to be short enough to use as an ipset name (example:
// "cali6ts:qMt7iLlGDhvLnCjM0l9nzxb").
func (c IPVersionConfig) NameForTempIPSet(setID string) string {
	// Since IP set IDs are chosen with a secure hash already, we can simply truncate them
	/// to length to get maximum entropy.
	return combineAndTrunc(c.tempSetNamePrefix, setID, MaxIPSetNameLength)
}

// NameForMainIPSet converts the given IP set ID (example: "qMt7iLlGDhvLnCjM0l9nzxbabcd"), to
// a name for use in the dataplane.  The return value will have the configured prefix and is
// guaranteed to be short enough to use as an ipset name (example:
// "cali6-s:qMt7iLlGDhvLnCjM0l9nzxb").
func (c IPVersionConfig) NameForMainIPSet(setID string) string {
	// Since IP set IDs are chosen with a secure hash already, we can simply truncate them
	/// to length to get maximum entropy.
	return combineAndTrunc(c.mainSetNamePrefix, setID, MaxIPSetNameLength)
}

// OwnsIPSet returns true if the given IP set name appears to belong to Felix.  i.e. whether it
// starts with an expected prefix.
func (c IPVersionConfig) OwnsIPSet(setName string) bool {
	return c.ourNamePrefixesRegexp.MatchString(setName)
}

// combineAndTrunc concatenates the given prefix and suffix and truncates the result to maxLength.
func combineAndTrunc(prefix, suffix string, maxLength int) string {
	combined := prefix + suffix
	if len(combined) > maxLength {
		return combined[0:maxLength]
	} else {
		return combined
	}
}
