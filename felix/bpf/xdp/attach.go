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

package xdp

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

var JumpMapIndexes = map[string]map[int]string{
	"IPv4": map[int]string{
		tcdefs.ProgIndexPolicy:  "calico_xdp_norm_pol_tail",
		tcdefs.ProgIndexAllowed: "calico_xdp_accepted_entrypoint",
		tcdefs.ProgIndexDrop:    "calico_xdp_drop",
	},
}

const DetachedID = 0

type AttachPoint struct {
	Iface    string
	LogLevel string
	Modes    []bpf.XDPMode
}

func (ap *AttachPoint) IfaceName() string {
	return ap.Iface
}

func (ap *AttachPoint) HookName() bpf.Hook {
	return bpf.HookXDP
}

func (ap *AttachPoint) Config() string {
	return fmt.Sprintf("%+v", ap)
}

func (ap *AttachPoint) JumpMapFDMapKey() string {
	return string(bpf.HookXDP)
}

func (ap *AttachPoint) FileName() string {
	logLevel := strings.ToLower(ap.LogLevel)
	if logLevel == "off" {
		logLevel = "no_log"
	}
	return "xdp_" + logLevel + ".o"
}

func (ap *AttachPoint) ProgramName() string {
	return "xdp_calico_entry"
}

func (ap *AttachPoint) Log() *log.Entry {
	return log.WithFields(log.Fields{
		"iface":    ap.Iface,
		"modes":    ap.Modes,
		"logLevel": ap.LogLevel,
	})
}

func (ap *AttachPoint) AlreadyAttached(object string) (int, bool) {
	progID, err := ap.ProgramID()
	if err != nil {
		ap.Log().Debugf("Couldn't get the attached XDP program ID. err=%v", err)
		return -1, false
	}

	somethingAttached, err := ap.IsAttached()
	if err != nil {
		ap.Log().Debugf("Failed to verify if any program is attached to interface. err=%v", err)
		return -1, false
	}

	isAttached, err := bpf.AlreadyAttachedProg(ap, object, progID)
	if err != nil {
		ap.Log().Debugf("Failed to check if BPF program was already attached. err=%v", err)
		return -1, false
	}

	if isAttached && somethingAttached {
		return progID, true
	}
	return -1, false
}

func ConfigureProgram(m *libbpf.Map, iface string) error {
	var globalData libbpf.XDPGlobalData

	in := []byte("---------------")
	copy(in, iface)
	globalData.IfaceName = string(in)

	if err := libbpf.XDPSetGlobals(m, &globalData); err != nil {
		return fmt.Errorf("failed to configure xdp: %w", err)
	}

	return nil
}

func (ap *AttachPoint) AttachProgram() (int, error) {
	tempDir, err := ioutil.TempDir("", "calico-xdp")
	if err != nil {
		return -1, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	filename := ap.FileName()
	preCompiledBinary := path.Join(bpf.ObjectDir, filename)

	obj, err := libbpf.OpenObject(preCompiledBinary)
	if err != nil {
		return -1, err
	}
	defer obj.Close()

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		if m.IsMapInternal() {
			if err := ConfigureProgram(m, ap.Iface); err != nil {
				return -1, err
			}
			continue
		}
		// TODO: We need to set map size here like tc.
		pinPath := bpf.MapPinPath(m.Type(), m.Name(), ap.Iface, bpf.HookXDP)
		if err := m.SetPinPath(pinPath); err != nil {
			return -1, fmt.Errorf("error pinning map %s: %w", m.Name(), err)
		}
	}

	// Check if the bpf object is already attached, and we should skip re-attaching it
	progID, isAttached := ap.AlreadyAttached(preCompiledBinary)
	if isAttached {
		ap.Log().Infof("Programs already attached, skip reattaching %s", filename)
		return progID, nil
	}
	ap.Log().Infof("Continue with attaching BPF program %s", filename)

	if err := obj.Load(); err != nil {
		ap.Log().Warn("Failed to load program")
		return -1, fmt.Errorf("error loading program: %w", err)
	}

	// TODO: Add support for IPv6
	err = updateJumpMap(obj)
	if err != nil {
		ap.Log().Warn("Failed to update jump map")
		return -1, fmt.Errorf("error updating jump map %v", err)
	}

	oldID, err := ap.ProgramID()
	if err != nil {
		return -1, fmt.Errorf("failed to get the attached XDP program ID: %w", err)
	}

	attachmentSucceeded := false
	for _, mode := range ap.Modes {
		ap.Log().Debugf("Trying to attach XDP program in mode %v - old id: %v", mode, oldID)
		// Force attach the program. If there is already a program attached, the replacement only
		// succeed in the same mode of the current program.
		progID, err = obj.AttachXDP(ap.Iface, ap.ProgramName(), oldID, unix.XDP_FLAGS_REPLACE|uint(mode))
		if err != nil || progID == DetachedID || progID == oldID {
			ap.Log().WithError(err).Warnf("Failed to attach to XDP program %s mode %v", ap.ProgramName(), mode)
		} else {
			ap.Log().Debugf("Successfully attached XDP program in mode %v. ID: %v", mode, progID)
			attachmentSucceeded = true
			break
		}
	}

	if !attachmentSucceeded {
		return -1, fmt.Errorf("failed to attach XDP program with program name %v to interface %v",
			ap.ProgramName(), ap.Iface)
	}

	// program is now attached. Now we should store its information to prevent unnecessary reloads in future
	if err = bpf.RememberAttachedProg(ap, preCompiledBinary, progID); err != nil {
		ap.Log().Errorf("Failed to record hash of BPF program on disk; Ignoring. err=%v", err)
	}

	return progID, nil
}

func (ap *AttachPoint) DetachProgram() error {
	// Get the current XDP program ID, if any.
	progID, err := ap.ProgramID()
	if err != nil {
		return fmt.Errorf("failed to get the attached XDP program ID: %w", err)
	}
	if progID == DetachedID {
		ap.Log().Debugf("No XDP program attached.")
		return nil
	}

	ourProg, err := bpf.AlreadyAttachedProg(ap, path.Join(bpf.ObjectDir, ap.FileName()), progID)
	if err != nil || !ourProg {
		return fmt.Errorf("XDP expected program ID does match with current one: %w", err)
	}

	// Try to remove our XDP program in all modes, until the program ID is 0
	removalSucceeded := false
	for _, mode := range ap.Modes {
		err = libbpf.DetachXDP(ap.Iface, uint(mode))
		ap.Log().Debugf("Trying to detach XDP program in mode %v.", mode)
		if err != nil {
			ap.Log().Debugf("Failed to detach XDP program in mode %v: %v.", mode, err)
			continue
		}
		curProgId, err := ap.ProgramID()
		if err != nil {
			return fmt.Errorf("failed to get the attached XDP program ID: %w", err)
		}

		if curProgId == DetachedID {
			removalSucceeded = true
			ap.Log().Debugf("Successfully detached XDP program.")
			break
		}
	}
	if !removalSucceeded {
		return fmt.Errorf("couldn't remove our XDP program. program ID: %v", progID)
	}

	ap.Log().Infof("XDP program detached. program ID: %v", progID)

	// Program is detached, now remove the json file we saved for it
	if err = bpf.ForgetAttachedProg(ap.IfaceName(), "xdp"); err != nil {
		return fmt.Errorf("failed to delete hash of BPF program from disk: %w", err)
	}
	return nil
}

func (ap *AttachPoint) IsAttached() (bool, error) {
	_, err := ap.ProgramID()
	return err == nil, err
}

func (ap *AttachPoint) ProgramID() (int, error) {
	progID, err := libbpf.GetXDPProgramID(ap.Iface)
	if err != nil {
		return -1, fmt.Errorf("Couldn't check for XDP program on iface %v: %w", ap.Iface, err)
	}
	return progID, nil
}

func updateJumpMap(obj *libbpf.Obj) error {
	ipVersions := []string{"IPv4"}

	for _, ipFamily := range ipVersions {
		if err := UpdateJumpMap(obj, JumpMapIndexes[ipFamily]); err != nil {
			return fmt.Errorf("proto %s: %w", ipFamily, err)
		}
	}

	return nil
}

func UpdateJumpMap(obj *libbpf.Obj, progs map[int]string) error {
	mapName := bpf.JumpMapName()

	for idx, name := range progs {
		err := obj.UpdateJumpMap(mapName, name, idx)
		if err != nil {
			return fmt.Errorf("failed to update program '%s' at index %d: %w", name, idx, err)
		}
	}

	return nil
}
