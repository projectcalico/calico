// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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

package tc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

type AttachPoint struct {
	bpf.AttachPoint

	Type                 tcdefs.EndpointType
	ToOrFrom             tcdefs.ToOrFromEp
	HookLayout4          hook.Layout
	HookLayout6          hook.Layout
	HostIP               net.IP
	HostTunnelIP         net.IP
	IntfIP               net.IP
	FIB                  bool
	ToHostDrop           bool
	DSR                  bool
	DSROptoutCIDRs       bool
	TunnelMTU            uint16
	VXLANPort            uint16
	WgPort               uint16
	ExtToServiceConnmark uint32
	PSNATStart           uint16
	PSNATEnd             uint16
	IPv6Enabled          bool
	RPFEnforceOption     uint8
	NATin                uint32
	NATout               uint32
}

var ErrDeviceNotFound = errors.New("device not found")
var ErrInterrupted = errors.New("dump interrupted")
var prefHandleRe = regexp.MustCompile(`pref ([^ ]+) .* handle ([^ ]+)`)

func (ap *AttachPoint) Log() *log.Entry {
	return log.WithFields(log.Fields{
		"iface": ap.Iface,
		"type":  ap.Type,
		"hook":  ap.Hook,
	})
}

func (ap *AttachPoint) loadObject(ipVer int, file string) (*libbpf.Obj, error) {
	obj, err := libbpf.OpenObject(file)
	if err != nil {
		return nil, err
	}

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		// In case of global variables, libbpf creates an internal map <prog_name>.rodata
		// The values are read only for the BPF programs, but can be set to a value from
		// userspace before the program is loaded.
		if m.IsMapInternal() {
			if err := ap.ConfigureProgram(m); err != nil {
				return nil, fmt.Errorf("failed to configure %s: %w", file, err)
			}
			continue
		}

		pinDir := bpf.MapPinDir(m.Type(), m.Name(), ap.Iface, ap.Hook)
		if err := m.SetPinPath(path.Join(pinDir, m.Name())); err != nil {
			return nil, fmt.Errorf("error pinning map %s: %w", m.Name(), err)
		}
	}

	if err := obj.Load(); err != nil {
		return nil, fmt.Errorf("error loading program: %w", err)
	}

	return obj, nil
}

// AttachProgram attaches a BPF program from a file to the TC attach point
func (ap *AttachPoint) AttachProgram() (int, error) {
	logCxt := log.WithField("attachPoint", ap)

	// By now the attach type specific generic set of programs is loaded and we
	// only need to load and configure the preamble that will pass the
	// configuration further to the selected set of programs.
	binaryToLoad := path.Join(bpfdefs.ObjectDir, "tc_preamble.o")

	/* XXX we should remember the tag of the program and skip the rest if the tag is
	* still the same */
	progsToClean, err := ap.listAttachedPrograms(true)
	if err != nil {
		return -1, err
	}

	obj, err := ap.loadObject(4, binaryToLoad)
	if err != nil {
		logCxt.Warn("Failed to load program")
		return -1, fmt.Errorf("object v4: %w", err)
	}
	defer obj.Close()

	progId, err := obj.AttachClassifier("cali_tc_preamble", ap.Iface, ap.Hook == hook.Ingress)
	if err != nil {
		logCxt.Warnf("Failed to attach to TC section cali_tc_preamble")
		return -1, err
	}
	logCxt.Info("Program attached to TC.")

	if err := ap.detachPrograms(progsToClean); err != nil {
		return -1, err
	}

	return progId, nil
}

func (ap *AttachPoint) DetachProgram() error {
	progsToClean, err := ap.listAttachedPrograms(true)
	if err != nil {
		return err
	}

	return ap.detachPrograms(progsToClean)
}

func (ap *AttachPoint) detachPrograms(progsToClean []attachedProg) error {
	var progErrs []error
	for _, p := range progsToClean {
		log.WithField("prog", p).Debug("Cleaning up old calico program")
		attemptCleanup := func() error {
			_, err := ExecTC("filter", "del", "dev", ap.Iface, ap.Hook.String(), "pref", p.pref, "handle", p.handle, "bpf")
			return err
		}
		err := attemptCleanup()
		if errors.Is(err, ErrInterrupted) {
			// This happens if the interface is deleted in the middle of calling tc.
			log.Debug("First cleanup hit 'Dump was interrupted', retrying (once).")
			err = attemptCleanup()
		}
		if errors.Is(err, ErrDeviceNotFound) {
			continue
		}
		if err != nil {
			log.WithError(err).WithField("prog", p).Warn("Failed to clean up old calico program.")
			progErrs = append(progErrs, err)
		}
	}

	if len(progErrs) != 0 {
		return fmt.Errorf("failed to clean up one or more old calico programs: %v", progErrs)
	}

	return nil
}

func ExecTC(args ...string) (out string, err error) {
	tcCmd := exec.Command("tc", args...)
	outBytes, err := tcCmd.Output()
	if err != nil {
		if isCannotFindDevice(err) {
			err = ErrDeviceNotFound
		} else if isDumpInterrupted(err) {
			err = ErrInterrupted
		} else if err2, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("failed to execute tc %v: rc=%v stderr=%v (%w)",
				args, err2.ExitCode(), string(err2.Stderr), err)
		} else {
			err = fmt.Errorf("failed to execute tc %v: %w", args, err)
		}
	}
	out = string(outBytes)
	return
}

func isCannotFindDevice(err error) bool {
	if errors.Is(err, ErrDeviceNotFound) {
		return true
	}
	if err, ok := err.(*exec.ExitError); ok {
		stderr := string(err.Stderr)
		if strings.Contains(stderr, "Cannot find device") ||
			strings.Contains(stderr, "No such device") {
			return true
		}
	}
	return false
}

func isDumpInterrupted(err error) bool {
	if errors.Is(err, ErrInterrupted) {
		return true
	}
	if err, ok := err.(*exec.ExitError); ok {
		stderr := string(err.Stderr)
		if strings.Contains(stderr, "Dump was interrupted") {
			return true
		}
	}
	return false
}

type attachedProg struct {
	pref   string
	handle string
}

func (ap *AttachPoint) listAttachedPrograms(includeLegacy bool) ([]attachedProg, error) {
	out, err := ExecTC("filter", "show", "dev", ap.Iface, ap.Hook.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list tc filters on interface: %w", err)
	}
	// Lines look like this; the section name always includes calico.
	// filter protocol all pref 49152 bpf chain 0 handle 0x1 to_hep_no_log.o:[calico_to_host_ep] direct-action not_in_hw id 821 tag ee402594f8f85ac3 jited
	var progsToClean []attachedProg
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "cali_tc_preambl") && (!includeLegacy || !strings.Contains(line, "calico")) {
			continue
		}
		// find the pref and the handle
		if sm := prefHandleRe.FindStringSubmatch(line); len(sm) > 0 {
			p := attachedProg{
				pref:   sm[1],
				handle: sm[2],
			}
			log.WithField("prog", p).Debug("Found old calico program")
			progsToClean = append(progsToClean, p)
		}
	}
	return progsToClean, nil
}

// ProgramName returns the name of the program associated with this AttachPoint
func (ap *AttachPoint) ProgramName() string {
	return tcdefs.SectionName(ap.Type, ap.ToOrFrom)
}

var ErrNoTC = errors.New("no TC program attached")

// TODO: we should try to not get the program ID via 'tc' binary and rather
// we should use libbpf to obtain it.
func (ap *AttachPoint) ProgramID() (int, error) {
	out, err := ExecTC("filter", "show", "dev", ap.IfaceName(), ap.Hook.String())
	if err != nil {
		return -1, fmt.Errorf("Failed to check interface %s program ID: %w", ap.Iface, err)
	}

	s := strings.Fields(string(out))
	for i := range s {
		// Example of output:
		//
		// filter protocol all pref 49152 bpf chain 0
		// filter protocol all pref 49152 bpf chain 0 handle 0x1 calico_from_hos:[61] direct-action not_in_hw id 61 tag 4add0302745d594c jited
		if s[i] == "id" && len(s) > i+1 {
			progID, err := strconv.Atoi(s[i+1])
			if err != nil {
				return -1, fmt.Errorf("Couldn't parse ID in 'tc filter' command err=%w out=\n%v", err, string(out))
			}

			return progID, nil
		}
	}
	return -1, fmt.Errorf("Couldn't find 'id <ID> in 'tc filter' command out=\n%v err=%w", string(out), ErrNoTC)
}

func (ap *AttachPoint) IsAttached() (bool, error) {
	hasQ, err := HasQdisc(ap.Iface)
	if err != nil {
		return false, err
	}
	if !hasQ {
		return false, nil
	}
	progs, err := ap.listAttachedPrograms(false)
	if err != nil {
		return false, err
	}
	return len(progs) > 0, nil
}

// EnsureQdisc makes sure that qdisc is attached to the given interface
func EnsureQdisc(ifaceName string) error {
	hasQdisc, err := HasQdisc(ifaceName)
	if err != nil {
		return err
	}
	if hasQdisc {
		log.WithField("iface", ifaceName).Debug("Already have a clsact qdisc on this interface")
		return nil
	}
	return libbpf.CreateQDisc(ifaceName)
}

func HasQdisc(ifaceName string) (bool, error) {
	out, err := ExecTC("qdisc", "show", "dev", ifaceName, "clsact")
	if err != nil {
		return false, fmt.Errorf("failed to check if interface '%s' has qdisc: %w", ifaceName, err)
	}
	if strings.Contains(out, "qdisc clsact") {
		return true, nil
	}
	return false, nil
}

// RemoveQdisc makes sure that there is no qdisc attached to the given interface
func RemoveQdisc(ifaceName string) error {
	hasQdisc, err := HasQdisc(ifaceName)
	if err != nil {
		return err
	}
	if !hasQdisc {
		return nil
	}

	// Remove the json files of the programs attached to the interface for both directions
	if err = bpf.ForgetAttachedProg(ifaceName, hook.Ingress); err != nil {
		return fmt.Errorf("Failed to remove runtime json file of ingress direction: %w", err)
	}
	if err = bpf.ForgetAttachedProg(ifaceName, hook.Egress); err != nil {
		return fmt.Errorf("Failed to remove runtime json file of egress direction: %w", err)
	}

	return libbpf.RemoveQDisc(ifaceName)
}

func (ap *AttachPoint) Config() string {
	return fmt.Sprintf("%+v", ap)
}

func (ap *AttachPoint) ConfigureProgram(m *libbpf.Map) error {
	globalData := libbpf.TcGlobalData{
		ExtToSvcMark: ap.ExtToServiceConnmark,
		VxlanPort:    ap.VXLANPort,
		Tmtu:         ap.TunnelMTU,
		PSNatStart:   ap.PSNATStart,
		PSNatLen:     ap.PSNATEnd,
		WgPort:       ap.WgPort,
		NatIn:        ap.NATin,
		NatOut:       ap.NATout,
	}
	var err error
	globalData.HostIP, err = convertIPToUint32(ap.HostIP)
	if err != nil {
		return err
	}
	if globalData.VxlanPort == 0 {
		globalData.VxlanPort = 4789
	}

	globalData.IntfIP, err = convertIPToUint32(ap.IntfIP)
	if err != nil {
		return err
	}

	if ap.IPv6Enabled {
		globalData.Flags |= libbpf.GlobalsIPv6Enabled
	}

	if ap.DSROptoutCIDRs {
		globalData.Flags |= libbpf.GlobalsNoDSRCidrs
	}

	switch ap.RPFEnforceOption {
	case tcdefs.RPFEnforceOptionStrict:
		globalData.Flags |= libbpf.GlobalsRPFOptionEnabled
		globalData.Flags |= libbpf.GlobalsRPFOptionStrict
	case tcdefs.RPFEnforceOptionLoose:
		globalData.Flags |= libbpf.GlobalsRPFOptionEnabled
	}

	globalData.HostTunnelIP = globalData.HostIP

	if ap.HostTunnelIP != nil {
		globalData.HostTunnelIP, err = convertIPToUint32(ap.HostTunnelIP)
		if err != nil {
			return err
		}
	}

	if ap.HookLayout4 != nil {
		for p, i := range ap.HookLayout4 {
			globalData.Jumps[p] = uint32(i)
		}
		globalData.Jumps[tcdefs.ProgIndexPolicy] = uint32(ap.PolicyIdx(4))
	}

	if ap.HookLayout6 != nil {
		for p, i := range ap.HookLayout6 {
			globalData.Jumps[p] = uint32(i)
		}
		globalData.Jumps[tcdefs.ProgIndexV6Policy] = uint32(ap.PolicyIdx(6))
	}

	return ConfigureProgram(m, ap.Iface, &globalData)
}

func ConfigureProgram(m *libbpf.Map, iface string, globalData *libbpf.TcGlobalData) error {
	in := []byte("---------------")
	copy(in, iface)
	globalData.IfaceName = string(in)

	return libbpf.TcSetGlobals(m, globalData)
}

func convertIPToUint32(ip net.IP) (uint32, error) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("ip addr nil")
	}
	return binary.LittleEndian.Uint32([]byte(ipv4)), nil
}
