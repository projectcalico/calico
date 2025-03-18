// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
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

package iptables

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
)

func Actions() generictables.ActionFactory {
	return &actionFactory{}
}

type actionFactory struct{}

func (s *actionFactory) Allow() generictables.Action {
	return AcceptAction{}
}

func (s *actionFactory) GoTo(target string) generictables.Action {
	return GotoAction{Target: target}
}

func (s *actionFactory) Return() generictables.Action {
	return ReturnAction{}
}

func (s *actionFactory) Reject(with generictables.RejectWith) generictables.Action {
	return RejectAction{With: with}
}

func (s *actionFactory) SetMaskedMark(mark, mask uint32) generictables.Action {
	return SetMaskedMarkAction{
		Mark: mark,
		Mask: mask,
	}
}

func (s *actionFactory) SetMark(mark uint32) generictables.Action {
	return SetMarkAction{
		Mark: mark,
	}
}

func (s *actionFactory) ClearMark(mark uint32) generictables.Action {
	return ClearMarkAction{Mark: mark}
}

func (s *actionFactory) Jump(target string) generictables.Action {
	return JumpAction{Target: target}
}

func (s *actionFactory) NoTrack() generictables.Action {
	return NoTrackAction{}
}

func (s *actionFactory) Log(prefix string) generictables.Action {
	return LogAction{Prefix: prefix}
}

func (s *actionFactory) SNAT(ip string) generictables.Action {
	return SNATAction{ToAddr: ip}
}

func (s *actionFactory) DNAT(ip string, port uint16) generictables.Action {
	return DNATAction{DestAddr: ip, DestPort: port}
}

func (s *actionFactory) Masq(toPorts string) generictables.Action {
	return MasqAction{ToPorts: toPorts}
}

func (s *actionFactory) Drop() generictables.Action {
	return DropAction{}
}

func (s *actionFactory) SetConnmark(mark, mask uint32) generictables.Action {
	return SetConnMarkAction{
		Mark: mark,
		Mask: mask,
	}
}

func (s *actionFactory) Nflog(group uint16, prefix string, size int) generictables.Action {
	return NflogAction{
		Group:  group,
		Prefix: prefix,
		Size:   size,
	}
}

func (a *actionFactory) LimitPacketRate(rate int64, mark uint32) generictables.Action {
	return LimitPacketRateAction{
		Rate: rate,
		Mark: mark,
	}
}

func (a *actionFactory) LimitNumConnections(num int64, rejectWith generictables.RejectWith) generictables.Action {
	return LimitNumConnectionsAction{
		Num:        num,
		RejectWith: rejectWith,
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
	return "--goto " + g.Target
}

func (g GotoAction) String() string {
	return "Goto->" + g.Target
}

func (g GotoAction) ReferencedChain() string {
	return g.Target
}

var _ Referrer = GotoAction{}

type JumpAction struct {
	Target   string
	TypeJump struct{}
}

func (g JumpAction) ToFragment(features *environment.Features) string {
	return "--jump " + g.Target
}

func (g JumpAction) String() string {
	return "Jump->" + g.Target
}

func (g JumpAction) ReferencedChain() string {
	return g.Target
}

var (
	_ Referrer                         = JumpAction{}
	_ generictables.ReturnActionMarker = ReturnAction{}
)

type ReturnAction struct {
	TypeReturn struct{}
}

func (r ReturnAction) IsReturnAction() {
}

func (r ReturnAction) ToFragment(features *environment.Features) string {
	return "--jump RETURN"
}

func (r ReturnAction) String() string {
	return "Return"
}

type DropAction struct {
	TypeDrop struct{}
}

func (g DropAction) ToFragment(features *environment.Features) string {
	return "--jump DROP"
}

func (g DropAction) String() string {
	return "Drop"
}

type RejectAction struct {
	TypeReject struct{}
	With       generictables.RejectWith
}

func (g RejectAction) ToFragment(features *environment.Features) string {
	if g.With != "" {
		return fmt.Sprintf("--jump REJECT --reject-with %s", g.With)
	}
	return "--jump REJECT"
}

func (g RejectAction) String() string {
	return "Reject"
}

type LogAction struct {
	Prefix  string
	TypeLog struct{}
}

func (g LogAction) ToFragment(features *environment.Features) string {
	return fmt.Sprintf(`--jump LOG --log-prefix "%s: " --log-level 5`, g.Prefix)
}

func (g LogAction) String() string {
	return "Log"
}

type AcceptAction struct {
	TypeAccept struct{}
}

func (g AcceptAction) ToFragment(features *environment.Features) string {
	return "--jump ACCEPT"
}

func (g AcceptAction) String() string {
	return "Accept"
}

type NflogAction struct {
	Group  uint16
	Prefix string
	Size   int
}

func (n NflogAction) ToFragment(features *environment.Features) string {
	size := 80
	if n.Size != 0 {
		size = n.Size
	}
	if n.Size < 0 {
		return fmt.Sprintf("--jump NFLOG --nflog-group %d --nflog-prefix %s", n.Group, n.Prefix)
	} else if features.NFLogSize {
		return fmt.Sprintf("--jump NFLOG --nflog-group %d --nflog-prefix %s --nflog-size %d", n.Group, n.Prefix, size)
	} else {
		return fmt.Sprintf("--jump NFLOG --nflog-group %d --nflog-prefix %s --nflog-range %d", n.Group, n.Prefix, size)
	}
}

func (n NflogAction) String() string {
	return fmt.Sprintf("Nflog:g=%d,p=%s", n.Group, n.Prefix)
}

type DNATAction struct {
	DestAddr string
	DestPort uint16
	TypeDNAT struct{}
}

func (g DNATAction) ToFragment(features *environment.Features) string {
	if g.DestPort == 0 {
		return fmt.Sprintf("--jump DNAT --to-destination %s", g.DestAddr)
	} else {
		return fmt.Sprintf("--jump DNAT --to-destination %s:%d", g.DestAddr, g.DestPort)
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
		fullyRand = " --random-fully"
	}
	return fmt.Sprintf("--jump SNAT --to-source %s%s", g.ToAddr, fullyRand)
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
		fullyRand = " --random-fully"
	}
	if g.ToPorts != "" {
		return fmt.Sprintf("--jump MASQUERADE --to-ports %s"+fullyRand, g.ToPorts)
	}
	return "--jump MASQUERADE" + fullyRand
}

func (g MasqAction) String() string {
	return "Masq"
}

type ClearMarkAction struct {
	Mark          uint32
	TypeClearMark struct{}
}

func (c ClearMarkAction) ToFragment(features *environment.Features) string {
	return fmt.Sprintf("--jump MARK --set-mark 0/%#x", c.Mark)
}

func (c ClearMarkAction) String() string {
	return fmt.Sprintf("Clear:%#x", c.Mark)
}

type SetMarkAction struct {
	Mark        uint32
	TypeSetMark struct{}
}

func (c SetMarkAction) ToFragment(features *environment.Features) string {
	return fmt.Sprintf("--jump MARK --set-mark %#x/%#x", c.Mark, c.Mark)
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
	return fmt.Sprintf("--jump MARK --set-mark %#x/%#x", c.Mark, c.Mask)
}

func (c SetMaskedMarkAction) String() string {
	return fmt.Sprintf("Set:%#x", c.Mark)
}

type NoTrackAction struct {
	TypeNoTrack struct{}
}

func (g NoTrackAction) ToFragment(features *environment.Features) string {
	return "--jump NOTRACK"
}

func (g NoTrackAction) String() string {
	return "NOTRACK"
}

type SaveConnMarkAction struct {
	SaveMask     uint32
	TypeConnMark struct{}
}

func (c SaveConnMarkAction) ToFragment(features *environment.Features) string {
	var mask uint32
	if c.SaveMask == 0 {
		// If Mask field is ignored, save full mark.
		mask = 0xffffffff
	} else {
		mask = c.SaveMask
	}
	return fmt.Sprintf("--jump CONNMARK --save-mark --mask %#x", mask)
}

func (c SaveConnMarkAction) String() string {
	return fmt.Sprintf("SaveConnMarkWithMask:%#x", c.SaveMask)
}

type RestoreConnMarkAction struct {
	RestoreMask  uint32
	TypeConnMark struct{}
}

func (c RestoreConnMarkAction) ToFragment(features *environment.Features) string {
	var mask uint32
	if c.RestoreMask == 0 {
		// If Mask field is ignored, restore full mark.
		mask = 0xffffffff
	} else {
		mask = c.RestoreMask
	}
	return fmt.Sprintf("--jump CONNMARK --restore-mark --mask %#x", mask)
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
	var mask uint32
	if c.Mask == 0 {
		// If Mask field is ignored, default to full mark.
		mask = 0xffffffff
	} else {
		mask = c.Mask
	}
	return fmt.Sprintf("--jump CONNMARK --set-mark %#x/%#x", c.Mark, mask)
}

func (c SetConnMarkAction) String() string {
	return fmt.Sprintf("SetConnMarkWithMask:%#x/%#x", c.Mark, c.Mask)
}

type LimitPacketRateAction struct {
	Rate                int64
	Mark                uint32
	TypeLimitPacketRate struct{}
}

func (a LimitPacketRateAction) ToFragment(features *environment.Features) string {
	if a.Mark == 0 {
		logrus.WithField("mark", a.Mark).Panic("Invalid mark")
	}
	if a.Rate < 0 {
		logrus.WithField("rate", a.Rate).Panic("Invalid rate")
	}
	return fmt.Sprintf("-m limit --limit %d/sec --jump MARK --set-mark %#x/%#x", a.Rate, a.Mark, a.Mark)
}

func (a LimitPacketRateAction) String() string {
	return fmt.Sprintf("LimitPacketRate:%d/s", a.Rate)
}

type LimitNumConnectionsAction struct {
	Num                     int64
	RejectWith              generictables.RejectWith
	TypeLimitNumConnections struct{}
}

func (a LimitNumConnectionsAction) ToFragment(features *environment.Features) string {
	if a.Num < 0 {
		logrus.WithField("rate", a.Num).Panic("Invalid limit")
	}
	// '-m tcp --tcp-flags FIN,SYN,RST,ACK SYN' is equivalent to '--syn' but the long form is shown on the output of 'iptables-*-save', so use the long form too for consistency
	return fmt.Sprintf("-p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above %d --connlimit-mask 0 -j REJECT --reject-with %s", a.Num, a.RejectWith)
}

func (a LimitNumConnectionsAction) String() string {
	return fmt.Sprintf("LimitNumConnectionsAction:%d, rejectWith:%s", a.Num, a.RejectWith)
}
