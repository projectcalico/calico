// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package bpf

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
)

type ProgramGenerator struct {
	w               io.Writer
	err             error
	ruleID          int
	debug           bool
	progPrefix      []byte
	progSuffix      []byte
	ipSetIDProvider ipSetIDProvider
}

type ipSetIDProvider interface {
	GetNoAlloc(ipSetID string) uint64
}

func NewProgramGenerator(src string, ipSetIDProvider ipSetIDProvider) (*ProgramGenerator, error) {
	var prefix, suffix []byte
	if src != "" {
		template, err := ioutil.ReadFile(src)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read BPF program template from %s", src)
		}
		splits := bytes.Split(template, []byte("	RULE_START(0);\n	RULE_END(0, deny);"))
		if len(splits) != 2 {
			cwd, _ := os.Getwd()
			return nil, fmt.Errorf("failed to split BPF program template %s (cwd = %s)", src, cwd)
		}
		prefix = splits[0]
		suffix = splits[1]
	}

	return &ProgramGenerator{
		// On the critical path so it's worth skipping log entry creation if debug is not enabled.
		debug:           log.GetLevel() >= log.DebugLevel,
		progPrefix:      prefix,
		progSuffix:      suffix,
		ipSetIDProvider: ipSetIDProvider,
	}, nil
}

func (r *ProgramGenerator) printf(f string, args ...interface{}) {
	if r.err != nil {
		return
	}
	if r.debug {
		log.Debugf("Writing C program: "+strings.TrimRight(f, "\n"), args...)
	}
	_, r.err = fmt.Fprintf(r.w, f, args...)
}

func (r *ProgramGenerator) writeBytes(b []byte) {
	if r.err != nil {
		return
	}
	_, r.err = r.w.Write(b)
}

func (r *ProgramGenerator) WriteProgram(w io.Writer, tiers [][][]*proto.Rule) error {
	// XXX a quick fix to make things local
	if w == nil {
		return fmt.Errorf("no writer")
	}

	r.w = w

	r.writeBytes(r.progPrefix)
	_ = r.WriteCalicoRules(w, tiers)
	r.writeBytes(r.progSuffix)
	return r.err
}

func (r *ProgramGenerator) WriteCalicoRules(w io.Writer, tiers [][][]*proto.Rule) error {
	// XXX a quick fix to make things local
	if w == nil {
		return fmt.Errorf("no writer")
	}

	r.w = w

	for tierIdx, tier := range tiers {
		endOfTierLabel := fmt.Sprint("end_of_tier_", tierIdx)

		r.printf("// Start of tier %d\n", tierIdx)
		for polIdx, pol := range tier {
			r.printf("// Start of policy %d\n", polIdx)
			for ruleIdx, rule := range pol {
				r.printf("// Start of rule %d\n", ruleIdx)
				r.writeRule(rule, endOfTierLabel)
				r.printf("// End of rule %d\n\n", ruleIdx)
			}
			r.printf("// End of policy %d\n", polIdx)

			if r.err != nil {
				return r.err
			}
		}

		// End of tier drop rule.
		r.printf("// End of tier drop\n")
		r.writeRule(&proto.Rule{Action: "deny"}, endOfTierLabel)

		r.printf("%s:;\n\n", endOfTierLabel)
	}
	return r.err
}

func (r *ProgramGenerator) writeRule(rule *proto.Rule, passLabel string) {
	// TODO IP version
	r.writeStartOfRule()

	if rule.Protocol != nil {
		r.writeProtoMatch(false, rule.Protocol)
	}
	if rule.NotProtocol != nil {
		r.writeProtoMatch(true, rule.Protocol)
	}

	if len(rule.SrcNet) != 0 {
		r.writeCIDRSMatch(false, "saddr", rule.SrcNet)
	}
	if len(rule.NotSrcNet) != 0 {
		r.writeCIDRSMatch(true, "saddr", rule.NotSrcNet)
	}

	if len(rule.DstNet) != 0 {
		r.writeCIDRSMatch(false, "daddr", rule.DstNet)
	}
	if len(rule.NotDstNet) != 0 {
		r.writeCIDRSMatch(true, "daddr", rule.NotDstNet)
	}

	if len(rule.SrcIpSetIds) > 0 {
		r.writeIPSetMatch(false, "saddr", rule.SrcIpSetIds)
	}
	if len(rule.NotSrcIpSetIds) > 0 {
		r.writeIPSetMatch(true, "saddr", rule.NotSrcIpSetIds)
	}

	if len(rule.DstIpSetIds) > 0 {
		r.writeIPSetMatch(false, "daddr", rule.DstIpSetIds)
	}
	if len(rule.NotDstIpSetIds) > 0 {
		r.writeIPSetMatch(true, "daddr", rule.NotDstIpSetIds)
	}

	if len(rule.SrcPorts) > 0 || len(rule.SrcNamedPortIpSetIds) > 0 {
		r.writePortsMatch(false, "saddr", "sport", rule.SrcPorts, rule.SrcNamedPortIpSetIds)
	}
	if len(rule.NotSrcPorts) > 0 || len(rule.NotSrcNamedPortIpSetIds) > 0 {
		r.writePortsMatch(true, "saddr", "sport", rule.NotSrcPorts, rule.NotSrcNamedPortIpSetIds)
	}

	if len(rule.DstPorts) > 0 || len(rule.DstNamedPortIpSetIds) > 0 {
		r.writePortsMatch(false, "daddr", "dport", rule.DstPorts, rule.DstNamedPortIpSetIds)
	}
	if len(rule.NotDstPorts) > 0 || len(rule.NotDstNamedPortIpSetIds) > 0 {
		r.writePortsMatch(true, "daddr", "dport", rule.NotDstPorts, rule.NotDstNamedPortIpSetIds)
	}

	// TODO ICMP

	r.writeEndOfRule(rule, passLabel)
	r.ruleID++
}

func (r *ProgramGenerator) writeStartOfRule() {
	r.printf("RULE_START(%d);\n", r.ruleID)
}

func (r *ProgramGenerator) writeEndOfRule(rule *proto.Rule, passLabel string) {
	// TODO log and log-and-xxx actions
	action := strings.ToLower(rule.Action)
	if action == "pass" {
		action = passLabel
	}
	r.printf("RULE_END(%d, %s);\n", r.ruleID, action)
}

func (r *ProgramGenerator) writeProtoMatch(negate bool, protocol *proto.Protocol) {
	r.printf("RULE_MATCH_PROTOCOL(%d, %t, %d);\n", r.ruleID, negate, protocolToNumber(protocol))
}

func (r *ProgramGenerator) writeCIDRSMatch(negate bool, field string, cidrs []string) {
	r.printf("RULE_MATCH_CIDRS(%d, %t, %s", r.ruleID, negate, field)
	for _, cidrStr := range cidrs {
		cidr := ip.MustParseCIDROrIP(cidrStr)
		addrU32 := cidr.Addr().(ip.V4Addr).AsUint32() // TODO IPv6
		maskU32 := math.MaxUint32 << (32 - cidr.Prefix()) & math.MaxUint32
		r.printf(", {%#x, %#x}", maskU32, addrU32)
	}
	r.printf(");\n")
}

func (r *ProgramGenerator) writePortsMatch(negate bool, addrField, portField string, ports []*proto.PortRange, namedPorts []string) {
	r.printf("RULE_MATCH_PORT_RANGES(%d, %t, %s, %s", r.ruleID, negate, addrField, portField)
	for _, portRange := range ports {
		r.printf(", {0, %d, %d}", portRange.First, portRange.Last)
	}
	for _, ipSetID := range namedPorts {
		id := r.ipSetIDProvider.GetNoAlloc(ipSetID)
		if id == 0 {
			log.WithField("setID", ipSetID).Panic("Failed to look up IP set ID.")
		}
		r.printf(", {%#x, 0, 0}", id)
	}
	r.printf(");\n")
}

func (r *ProgramGenerator) writeIPSetMatch(negate bool, field string, ipSets []string) {
	for _, ipSetID := range ipSets {
		id := r.ipSetIDProvider.GetNoAlloc(ipSetID)
		if id == 0 {
			log.WithField("setID", ipSetID).Panic("Failed to look up IP set ID.")
		}
		r.printf("RULE_MATCH_IP_SET(%d, %t, %s, %#x);\n", r.ruleID, negate, field, id)
	}
}

func protocolToNumber(protocol *proto.Protocol) uint8 {
	var pcol uint8
	switch p := protocol.NumberOrName.(type) {
	case *proto.Protocol_Name:
		switch strings.ToLower(p.Name) {
		case "tcp":
			pcol = 6
		case "udp":
			pcol = 17
		case "icmp":
			pcol = 1
		case "sctp":
			pcol = 132
		}
	case *proto.Protocol_Number:
		pcol = uint8(p.Number)
	}
	return pcol
}
