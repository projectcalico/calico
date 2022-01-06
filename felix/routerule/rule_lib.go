// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package routerule

import (
	"net"

	"github.com/projectcalico/calico/felix/ip"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Rule is a wrapper structure around netlink rule.
// Currently it supports FWMark, Source match and table action.
type Rule struct {
	nlRule *netlink.Rule
}

func NewRule(ipVersion, priority int) *Rule {
	r := &Rule{nlRule: netlink.NewRule()}
	r.nlRule.Family = ipVersionToNetlinkFamily(ipVersion)
	r.nlRule.Priority = priority
	return r
}

func FromNetlinkRule(nlRule *netlink.Rule) *Rule {
	return &Rule{nlRule: nlRule}
}

func (r *Rule) NetLinkRule() *netlink.Rule {
	return r.nlRule
}

func (r *Rule) LogCxt() *log.Entry {
	var src interface{}
	if r.nlRule.Src != nil {
		src = r.nlRule.Src
	}
	return log.WithFields(log.Fields{
		"ipFamily": r.nlRule.Family,
		"priority": r.nlRule.Priority,
		"invert":   r.nlRule.Invert,
		"Mark":     r.nlRule.Mark,
		"Mask":     r.nlRule.Mask,
		"src":      src,
		"Table":    r.nlRule.Table,
	})
}

func (r *Rule) markMatchesWithMask(mark, mask uint32) *Rule {
	logCxt := log.WithFields(log.Fields{
		"mark": mark,
		"mask": mask,
	})
	if mask == 0 {
		logCxt.Panic("Bug: mask is 0.")
	}
	if mark&mask != mark {
		logCxt.Panic("Bug: mark is not contained in mask")
	}
	r.nlRule.Mask = int(mask)
	r.nlRule.Mark = int(mark)

	return r
}

func (r *Rule) MatchFWMark(fwmark uint32) *Rule {
	return r.markMatchesWithMask(fwmark, fwmark)
}

func (r *Rule) MatchFWMarkWithMask(fwmark, mask uint32) *Rule {
	return r.markMatchesWithMask(fwmark, mask)
}

func (r *Rule) MatchSrcAddress(ip net.IPNet) *Rule {
	if r.nlRule.Family == unix.AF_INET {
		ones, _ := ip.Mask.Size()
		if ip.IP.To4() == nil || ones > 32 {
			r.LogCxt().WithField("ip", ip).Warn("Source IP is not IPv4, ignoring")
			return r
		}
	}

	r.nlRule.Src = &ip
	return r
}

func (r *Rule) Not() *Rule {
	r.nlRule.Invert = true
	return r
}

func (r *Rule) GoToTable(index int) *Rule {
	r.nlRule.Table = index
	return r
}

func (r *Rule) Copy() *Rule {
	nlRule := *r.NetLinkRule()
	return &Rule{nlRule: &nlRule}
}

// Functions to check if two rules has same matching condition (and table index to go to).
type RulesMatchFunc func(r, p *Rule) bool

func RulesMatchSrcFWMark(r, p *Rule) bool {
	return (r.nlRule.Priority == p.nlRule.Priority) &&
		(r.nlRule.Family == p.nlRule.Family) &&
		(r.nlRule.Invert == p.nlRule.Invert) &&
		(r.nlRule.Mark == p.nlRule.Mark) &&
		(r.nlRule.Mask == p.nlRule.Mask) &&
		ip.IPNetsEqual(r.nlRule.Src, p.nlRule.Src)
}

func RulesMatchSrcFWMarkTable(r, p *Rule) bool {
	return RulesMatchSrcFWMark(r, p) && (r.nlRule.Table == p.nlRule.Table)
}
