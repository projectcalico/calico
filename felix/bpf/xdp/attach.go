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
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

const DetachedID = 0

type AttachPoint struct {
	bpf.AttachPoint
	HookLayoutV4 hook.Layout
	HookLayoutV6 hook.Layout

	Modes []bpf.XDPMode
}

func (ap *AttachPoint) PolicyAllowJumpIdx(family int) int {
	if family == 4 && ap.HookLayoutV4 != nil {
		return ap.HookLayoutV4[hook.SubProgXDPAllowed]
	}
	if family == 6 && ap.HookLayoutV6 != nil {
		return ap.HookLayoutV6[hook.SubProgXDPAllowed]
	}
	return -1
}

func (ap *AttachPoint) PolicyDenyJumpIdx(family int) int {
	if family == 4 && ap.HookLayoutV4 != nil {
		return ap.HookLayoutV4[hook.SubProgXDPDrop]
	}

	if family == 6 && ap.HookLayoutV6 != nil {
		return ap.HookLayoutV6[hook.SubProgXDPDrop]
	}
	return -1
}

func (ap *AttachPoint) Config() string {
	return fmt.Sprintf("%+v", ap)
}

func (ap *AttachPoint) FileName() string {
	logLevel := strings.ToLower(ap.LogLevel)
	if logLevel == "off" {
		logLevel = "no_log"
	}
	return "xdp_" + logLevel + ".o"
}

func (ap *AttachPoint) ProgramName() string {
	return "cali_xdp_preamble"
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

func ConfigureProgram(m *libbpf.Map, iface string, globalData *libbpf.XDPGlobalData) error {
	in := []byte("---------------")
	copy(in, iface)
	globalData.IfaceName = string(in)

	if err := libbpf.XDPSetGlobals(m, globalData); err != nil {
		return fmt.Errorf("failed to configure xdp: %w", err)
	}

	return nil
}

type AttachResult int

func (ar AttachResult) ProgID() int {
	return int(ar)
}

func (ap *AttachPoint) AttachProgram() (bpf.AttachResult, error) {
	// By now the attach type specific generic set of programs is loaded and we
	// only need to load and configure the preamble that will pass the
	// configuration further to the selected set of programs.

	binaryToLoad := path.Join(bpfdefs.ObjectDir, "xdp_preamble.o")

	obj, err := libbpf.OpenObject(binaryToLoad)
	if err != nil {
		return nil, err
	}
	defer obj.Close()

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		mapName := m.Name()
		if m.IsMapInternal() {
			if strings.HasPrefix(mapName, ".rodata") {
				continue
			}
			var globals libbpf.XDPGlobalData

			if ap.HookLayoutV4 != nil {
				for p, i := range ap.HookLayoutV4 {
					globals.Jumps[p] = uint32(i)
				}
				globals.Jumps[tcdefs.ProgIndexPolicy] = uint32(ap.PolicyIdxV4)
			}
			if ap.HookLayoutV6 != nil {
				for p, i := range ap.HookLayoutV6 {
					globals.JumpsV6[p] = uint32(i)
				}
				globals.JumpsV6[tcdefs.ProgIndexPolicy] = uint32(ap.PolicyIdxV6)
			}

			if err := ConfigureProgram(m, ap.Iface, &globals); err != nil {
				return nil, err
			}
			continue
		}
		// TODO: We need to set map size here like tc.
		pinDir := bpf.MapPinDir(m.Type(), mapName, ap.Iface, hook.XDP)
		if err := m.SetPinPath(path.Join(pinDir, mapName)); err != nil {
			return nil, fmt.Errorf("error pinning map %s: %w", mapName, err)
		}
	}

	// Check if the bpf object is already attached, and we should skip re-attaching it
	progID, isAttached := ap.AlreadyAttached(binaryToLoad)
	if isAttached {
		ap.Log().Infof("Programs already attached, skip reattaching %s", binaryToLoad)
		return AttachResult(progID), nil
	}
	ap.Log().Infof("Continue with attaching BPF program %s", binaryToLoad)

	if err := obj.Load(); err != nil {
		ap.Log().Warn("Failed to load program")
		return nil, fmt.Errorf("error loading program: %w", err)
	}

	oldID, err := ap.ProgramID()
	if err != nil {
		return nil, fmt.Errorf("failed to get the attached XDP program ID: %w", err)
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
		return nil, fmt.Errorf("failed to attach XDP program with program name %v to interface %v",
			ap.ProgramName(), ap.Iface)
	}

	return AttachResult(progID), nil
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

	prog, err := bpf.GetProgByID(progID)
	if err != nil {
		return fmt.Errorf("failed to get prog by id %d: %w", progID, err)
	}

	if !strings.HasPrefix(prog.Name, "cali_xdp_preamb") {
		ap.Log().Debugf("Program id %d name %s not ours.", progID, prog.Name)
		return nil
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
	if err = bpf.ForgetAttachedProg(ap.IfaceName(), hook.XDP); err != nil {
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
