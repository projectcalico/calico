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
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfutils"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

type AttachPoint struct {
	Type                 EndpointType
	ToOrFrom             ToOrFromEp
	Hook                 bpf.Hook
	Iface                string
	LogLevel             string
	HostIP               net.IP
	HostTunnelIP         net.IP
	IntfIP               net.IP
	FIB                  bool
	ToHostDrop           bool
	DSR                  bool
	TunnelMTU            uint16
	VXLANPort            uint16
	WgPort               uint16
	ExtToServiceConnmark uint32
	PSNATStart           uint16
	PSNATEnd             uint16
	IPv6Enabled          bool
	MapSizes             map[string]uint32
	RPFStrictEnabled     bool
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

func (ap *AttachPoint) loadLogging() bool {
	return strings.ToLower(ap.LogLevel) != "off"
}

func (ap *AttachPoint) AlreadyAttached(object string) (int, bool) {
	logCxt := log.WithField("attachPoint", ap)
	progID, err := ap.ProgramID()
	if err != nil {
		logCxt.WithError(err).Debugf("Couldn't get the attached TC program ID.")
		return -1, false
	}

	progsToClean, err := ap.listAttachedPrograms()
	if err != nil {
		logCxt.WithError(err).Debugf("Couldn't get the list of already attached TC programs")
		return -1, false
	}

	isAttached, err := bpf.AlreadyAttachedProg(ap, object, progID)
	if err != nil {
		logCxt.WithError(err).Debugf("Failed to check if BPF program was already attached.")
		return -1, false
	}

	if isAttached && len(progsToClean) == 1 {
		return progID, true
	}
	return -1, false
}

// AttachProgram attaches a BPF program from a file to the TC attach point
func (ap *AttachPoint) AttachProgram() (int, error) {
	logCxt := log.WithField("attachPoint", ap)

	tempDir, err := ioutil.TempDir("", "calico-tc")
	if err != nil {
		return -1, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	filename := ap.FileName()
	preCompiledBinary := path.Join(bpf.ObjectDir, filename)
	binaryToLoad := preCompiledBinary

	if ap.loadLogging() {
		tempBinary := path.Join(tempDir, filename)

		err = ap.patchLogPrefix(logCxt, preCompiledBinary, tempBinary)
		if err != nil {
			logCxt.WithError(err).Error("Failed to patch binary")
			return -1, err
		}

		binaryToLoad = tempBinary
	}

	progsToClean, err := ap.listAttachedPrograms()
	if err != nil {
		return -1, err
	}
	obj, err := libbpf.OpenObject(binaryToLoad)
	if err != nil {
		return -1, err
	}
	defer obj.Close()

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		// In case of global variables, libbpf creates an internal map <prog_name>.rodata
		// The values are read only for the BPF programs, but can be set to a value from
		// userspace before the program is loaded.
		if m.IsMapInternal() {
			if err := ap.ConfigureProgram(m); err != nil {
				return -1, fmt.Errorf("failed to configure %s: %w", filename, err)
			}
			continue
		}

		if err := ap.setMapSize(m); err != nil {
			return -1, fmt.Errorf("error setting map size %s : %w", m.Name(), err)
		}
		pinPath := bpf.MapPinPath(m.Type(), m.Name(), ap.Iface, ap.Hook)
		if err := m.SetPinPath(pinPath); err != nil {
			return -1, fmt.Errorf("error pinning map %s: %w", m.Name(), err)
		}
	}

	// Check if the bpf object is already attached, and we should skip
	// re-attaching it if the binary and its configuration are the same.
	progID, isAttached := ap.AlreadyAttached(preCompiledBinary)
	if isAttached {
		logCxt.Infof("Program already attached to TC, skip reattaching %s", filename)
		return progID, nil
	}
	logCxt.Debugf("Continue with attaching BPF program %s", filename)

	if err := obj.Load(); err != nil {
		logCxt.Warn("Failed to load program")
		return -1, fmt.Errorf("error loading program: %w", err)
	}

	err = ap.updateJumpMap(obj)
	if err != nil {
		logCxt.Warn("Failed to update jump map")
		return -1, fmt.Errorf("error updating jump map %v", err)
	}

	progId, err := obj.AttachClassifier(SectionName(ap.Type, ap.ToOrFrom), ap.Iface, string(ap.Hook))
	if err != nil {
		logCxt.Warnf("Failed to attach to TC section %s", SectionName(ap.Type, ap.ToOrFrom))
		return -1, err
	}
	logCxt.Info("Program attached to TC.")

	if err := ap.detachPrograms(progsToClean); err != nil {
		return -1, err
	}

	// Store information of object in a json file so in future we can skip reattaching it.
	// If the process fails, the json file with the correct name and program details
	// is not stored on disk, and during Felix restarts the same program will be reattached
	// which leads to an unnecessary load time
	if err = bpf.RememberAttachedProg(ap, preCompiledBinary, progId); err != nil {
		logCxt.WithError(err).Error("Failed to record hash of BPF program on disk; ignoring.")
	}

	return progId, nil
}

func (ap *AttachPoint) patchLogPrefix(logCtx *log.Entry, ifile, ofile string) error {
	b, err := bpf.BinaryFromFile(ifile)
	if err != nil {
		return fmt.Errorf("failed to read pre-compiled BPF binary: %w", err)
	}

	b.PatchLogPrefix(ap.Iface)

	err = b.WriteToFile(ofile)
	if err != nil {
		return fmt.Errorf("failed to write pre-compiled BPF binary: %w", err)
	}
	return nil
}

func (ap *AttachPoint) DetachProgram() error {
	progsToClean, err := ap.listAttachedPrograms()
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
			_, err := ExecTC("filter", "del", "dev", ap.Iface, string(ap.Hook), "pref", p.pref, "handle", p.handle, "bpf")
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

func (ap *AttachPoint) listAttachedPrograms() ([]attachedProg, error) {
	out, err := ExecTC("filter", "show", "dev", ap.Iface, string(ap.Hook))
	if err != nil {
		return nil, fmt.Errorf("failed to list tc filters on interface: %w", err)
	}
	// Lines look like this; the section name always includes calico.
	// filter protocol all pref 49152 bpf chain 0 handle 0x1 to_hep_no_log.o:[calico_to_host_ep] direct-action not_in_hw id 821 tag ee402594f8f85ac3 jited
	var progsToClean []attachedProg
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "calico") {
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
	return SectionName(ap.Type, ap.ToOrFrom)
}

var ErrNoTC = errors.New("no TC program attached")

// TODO: we should try to not get the program ID via 'tc' binary and rather
// we should use libbpf to obtain it.
func (ap *AttachPoint) ProgramID() (int, error) {
	out, err := ExecTC("filter", "show", "dev", ap.IfaceName(), string(ap.Hook))
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

// FileName return the file the AttachPoint will load the program from
func (ap *AttachPoint) FileName() string {
	return ProgFilename(ap.Type, ap.ToOrFrom, ap.ToHostDrop, ap.FIB, ap.DSR, ap.LogLevel, bpfutils.BTFEnabled)
}

func (ap *AttachPoint) IsAttached() (bool, error) {
	hasQ, err := HasQdisc(ap.Iface)
	if err != nil {
		return false, err
	}
	if !hasQ {
		return false, nil
	}
	progs, err := ap.listAttachedPrograms()
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
	if err = bpf.ForgetAttachedProg(ifaceName, "ingress"); err != nil {
		return fmt.Errorf("Failed to remove runtime json file of ingress direction: %w", err)
	}
	if err = bpf.ForgetAttachedProg(ifaceName, "egress"); err != nil {
		return fmt.Errorf("Failed to remove runtime json file of egress direction: %w", err)
	}

	return libbpf.RemoveQDisc(ifaceName)
}

// Return a key that uniquely identifies this attach point, amongst all of the possible attach
// points associated with a single given interface.
func (ap *AttachPoint) JumpMapFDMapKey() string {
	return string(ap.Hook)
}

func (ap *AttachPoint) IfaceName() string {
	return ap.Iface
}

func (ap *AttachPoint) HookName() bpf.Hook {
	return ap.Hook
}

func (ap *AttachPoint) Config() string {
	return fmt.Sprintf("%+v", ap)
}

func (ap *AttachPoint) ConfigureProgram(m *libbpf.Map) error {
	globalData := libbpf.TcGlobalData{ExtToSvcMark: ap.ExtToServiceConnmark,
		VxlanPort:  ap.VXLANPort,
		Tmtu:       ap.TunnelMTU,
		PSNatStart: ap.PSNATStart,
		PSNatLen:   ap.PSNATEnd,
		WgPort:     ap.WgPort,
		NatIn:      ap.NATin,
		NatOut:     ap.NATout,
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
	if ap.RPFStrictEnabled {
		globalData.Flags |= libbpf.GlobalsRPFStrictEnabled
	}

	globalData.HostTunnelIP = globalData.HostIP

	if ap.HostTunnelIP != nil {
		globalData.HostTunnelIP, err = convertIPToUint32(ap.HostTunnelIP)
		if err != nil {
			return err
		}
	}

	return libbpf.TcSetGlobals(m, &globalData)
}

func (ap *AttachPoint) setMapSize(m *libbpf.Map) error {
	if size, ok := ap.MapSizes[m.Name()]; ok {
		return m.SetMapSize(size)
	}
	return nil
}

func (ap *AttachPoint) hasPolicyProg() bool {
	switch ap.Type {
	case EpTypeHost, EpTypeNAT, EpTypeLO:
		return false
	}

	return true
}

func (ap *AttachPoint) hasHostConflictProg() bool {
	switch ap.Type {
	case EpTypeWorkload:
		return false
	}

	return ap.ToOrFrom == ToEp
}

func (ap *AttachPoint) updateJumpMap(obj *libbpf.Obj) error {
	ipVersions := []string{"IPv4"}
	if ap.IPv6Enabled {
		ipVersions = append(ipVersions, "IPv6")
	}

	mapName := bpf.JumpMapName()

	for _, ipFamily := range ipVersions {
		for _, idx := range tcdefs.JumpMapIndexes[ipFamily] {
			if (idx == tcdefs.ProgIndexPolicy || idx == tcdefs.ProgIndexV6Policy) && !ap.hasPolicyProg() {
				continue
			}
			if idx == tcdefs.ProgIndexHostCtConflict && !ap.hasHostConflictProg() {
				continue
			}
			err := obj.UpdateJumpMap(mapName, tcdefs.ProgramNames[idx], idx)
			if err != nil {
				return fmt.Errorf("error updating %v %s program: %w", ipFamily, tcdefs.ProgramNames[idx], err)
			}
		}
	}

	return nil
}

func convertIPToUint32(ip net.IP) (uint32, error) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("ip addr nil")
	}
	return binary.LittleEndian.Uint32([]byte(ipv4)), nil
}
