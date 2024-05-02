// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package nftables

import (
	"fmt"
	"strings"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/sirupsen/logrus"
)

type namespaceable interface {
	Namespace(string) generictables.Action
}

func ActionSet() generictables.ActionSet {
	return &actionSet{}
}

type actionSet struct{}

func (s *actionSet) AllowAction() generictables.Action {
	return AcceptAction{}
}

func (s *actionSet) GoToAction(target string) generictables.Action {
	return &GotoAction{Target: target}
}

func (s *actionSet) ReturnAction() generictables.Action {
	return ReturnAction{}
}

func (s *actionSet) SetMaskedMarkAction(mark, mask uint32) generictables.Action {
	return SetMaskedMarkAction{
		Mark: mark,
		Mask: mask,
	}
}

func (s *actionSet) SetMarkAction(mark uint32) generictables.Action {
	return SetMarkAction{
		Mark: mark,
	}
}

func (s *actionSet) ClearMarkAction(mark uint32) generictables.Action {
	return ClearMarkAction{Mark: mark}
}

func (s *actionSet) JumpAction(target string) generictables.Action {
	return &JumpAction{Target: target}
}

func (s *actionSet) NoTrackAction() generictables.Action {
	return NoTrackAction{}
}

func (s *actionSet) LogAction(prefix string) generictables.Action {
	return LogAction{Prefix: prefix}
}

func (s *actionSet) SNATAction(ip string) generictables.Action {
	return SNATAction{ToAddr: ip}
}

func (s *actionSet) DNATAction(ip string, port uint16) generictables.Action {
	return DNATAction{DestAddr: ip, DestPort: port}
}

func (s *actionSet) MasqAction(toPorts string) generictables.Action {
	return MasqAction{ToPorts: toPorts}
}

func (s *actionSet) DropAction() generictables.Action {
	return DropAction{}
}

func (s *actionSet) SetConnmarkAction(mark, mask uint32) generictables.Action {
	return SetConnMarkAction{
		Mark: mark,
		Mask: mask,
	}
}

type Referrer interface {
	ReferencedChain() string
}

type GotoAction struct {
	Target   string
	TypeGoto struct{}
}

func (g GotoAction) ToFragment(features *environment.Features) string {
	return "goto " + g.Target
}

func (g GotoAction) String() string {
	return "Goto->" + g.Target
}

func (g GotoAction) ReferencedChain() string {
	logrus.WithField("referencedChain", g.Target).Info("GotoAction.ReferencedChain")
	return g.Target
}

func (g GotoAction) Namespace(ns string) generictables.Action {
	if strings.HasPrefix(g.Target, ns) {
		return g
	}

	n := g
	n.Target = ns + "-" + g.Target
	return n
}

var (
	_ Referrer      = GotoAction{}
	_ namespaceable = GotoAction{}
)

type JumpAction struct {
	Target   string
	TypeJump struct{}
}

func (g JumpAction) ToFragment(features *environment.Features) string {
	return "jump " + g.Target
}

func (g JumpAction) String() string {
	return "Jump->" + g.Target
}

func (g JumpAction) ReferencedChain() string {
	return g.Target
}

func (g JumpAction) Namespace(ns string) generictables.Action {
	if strings.HasPrefix(g.Target, ns) {
		return g
	}

	n := g
	n.Target = ns + "-" + g.Target
	return n
}

var (
	_ Referrer      = &JumpAction{}
	_ namespaceable = &JumpAction{}
)

type ReturnAction struct {
	TypeReturn struct{}
}

func (r ReturnAction) ToFragment(features *environment.Features) string {
	return "return"
}

func (r ReturnAction) String() string {
	return "Return"
}

type DropAction struct {
	TypeDrop struct{}
}

func (g DropAction) ToFragment(features *environment.Features) string {
	return "drop"
}

func (g DropAction) String() string {
	return "Drop"
}

type RejectAction struct {
	TypeReject struct{}
}

func (g RejectAction) ToFragment(features *environment.Features) string {
	return "reject"
}

func (g RejectAction) String() string {
	return "Reject"
}

type LogAction struct {
	Prefix  string
	TypeLog struct{}
}

func (g LogAction) ToFragment(features *environment.Features) string {
	return fmt.Sprintf(`log prefix %s level info`, g.Prefix)
}

func (g LogAction) String() string {
	return "Log"
}

type AcceptAction struct {
	TypeAccept struct{}
}

func (g AcceptAction) ToFragment(features *environment.Features) string {
	return "accept"
}

func (g AcceptAction) String() string {
	return "Accept"
}

type DNATAction struct {
	DestAddr string
	DestPort uint16
	TypeDNAT struct{}
}

func (g DNATAction) ToFragment(features *environment.Features) string {
	if g.DestPort == 0 {
		return fmt.Sprintf("dnat to %s", g.DestAddr)
	} else {
		return fmt.Sprintf("dnat to %s:%d", g.DestAddr, g.DestPort)
	}
}

func (g DNATAction) String() string {
	return fmt.Sprintf("DNAT->%s:%d", g.DestAddr, g.DestPort)
}

type SNATAction struct {
	ToAddr   string
	TypeSNAT struct{}
}

func (g SNATAction) ToFragment(features *environment.Features) string {
	fullyRand := ""
	if features.SNATFullyRandom {
		fullyRand = " fully-random"
	}
	return fmt.Sprintf("snat to %s%s", g.ToAddr, fullyRand)
}

func (g SNATAction) String() string {
	return fmt.Sprintf("SNAT->%s", g.ToAddr)
}

type MasqAction struct {
	ToPorts  string
	TypeMasq struct{}
}

func (g MasqAction) ToFragment(features *environment.Features) string {
	fullyRand := ""
	if features.MASQFullyRandom {
		fullyRand = " fully-random"
	}
	if g.ToPorts != "" {
		// e.g., masquerade to :1024-65535
		return fmt.Sprintf("masquerade to %s"+fullyRand, g.ToPorts)
	}
	return "masquerade" + fullyRand
}

func (g MasqAction) String() string {
	return "Masq"
}

type ClearMarkAction struct {
	Mark          uint32
	TypeClearMark struct{}
}

func (c ClearMarkAction) ToFragment(features *environment.Features) string {
	return fmt.Sprintf("meta mark set mark & %#x", (c.Mark ^ 0xffffffff))
}

func (c ClearMarkAction) String() string {
	return fmt.Sprintf("Clear:%#x", c.Mark)
}

type SetMarkAction struct {
	Mark        uint32
	TypeSetMark struct{}
}

func (c SetMarkAction) ToFragment(features *environment.Features) string {
	return fmt.Sprintf("meta mark set %#x", c.Mark)
}

func (c SetMarkAction) String() string {
	return fmt.Sprintf("Set:%#x", c.Mark)
}

type SetMaskedMarkAction struct {
	Mark              uint32
	Mask              uint32
	TypeSetMaskedMark struct{}
}

func (c SetMaskedMarkAction) ToFragment(features *environment.Features) string {
	return fmt.Sprintf("meta mark set mark or %#x", (c.Mark & c.Mask))
}

func (c SetMaskedMarkAction) String() string {
	return fmt.Sprintf("Set:%#x", c.Mark)
}

type NoTrackAction struct {
	TypeNoTrack struct{}
}

func (g NoTrackAction) ToFragment(features *environment.Features) string {
	return "notrack"
}

func (g NoTrackAction) String() string {
	return "NOTRACK"
}

type SaveConnMarkAction struct {
	SaveMask     uint32
	TypeConnMark struct{}
}

func (c SaveConnMarkAction) ToFragment(features *environment.Features) string {
	if c.SaveMask == 0 {
		return "ct mark set mark"
	}
	return fmt.Sprintf("ct mark set and %#x", c.SaveMask)
}

func (c SaveConnMarkAction) String() string {
	return fmt.Sprintf("SaveConnMarkWithMask:%#x", c.SaveMask)
}

type RestoreConnMarkAction struct {
	RestoreMask  uint32
	TypeConnMark struct{}
}

func (c RestoreConnMarkAction) ToFragment(features *environment.Features) string {
	if c.RestoreMask == 0 {
		// If Mask field is ignored, restore full mark.
		return "meta mark set ct mark"
	}
	return fmt.Sprintf("meta mark set ct mark and %#x", c.RestoreMask)
}

func (c RestoreConnMarkAction) String() string {
	return fmt.Sprintf("RestoreConnMarkWithMask:%#x", c.RestoreMask)
}

type SetConnMarkAction struct {
	Mark         uint32
	Mask         uint32
	TypeConnMark struct{}
}

func (c SetConnMarkAction) ToFragment(features *environment.Features) string {
	if c.Mask == 0 {
		// If Mask field is ignored, default to full mark.
		return fmt.Sprintf("ct mark set %#x", c.Mark)
	}
	notMask := c.Mask ^ 0xffffffff
	return fmt.Sprintf("ct mark set ct mark xor %#x and %#x", c.Mark, notMask)
}

func (c SetConnMarkAction) String() string {
	return fmt.Sprintf("SetConnMarkWithMask:%#x/%#x", c.Mark, c.Mask)
}
