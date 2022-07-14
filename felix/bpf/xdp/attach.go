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
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
)

type ProgName string

var programNames = []ProgName{
	"calico_xdp_norm_pol_tail",
	"calico_xdp_accepted_entrypoint",
}

const DetachedID = 0

type AttachPoint struct {
	Iface    string
	LogLevel string
	Modes    []bpf.XDPMode
	ProgID   int
}

func (ap *AttachPoint) IfaceName() string {
	return ap.Iface
}

func (ap *AttachPoint) HookName() string {
	return "xdp"
}

func (ap *AttachPoint) Config() string {
	return fmt.Sprintf("%+v", ap)
}

func (ap *AttachPoint) JumpMapFDMapKey() string {
	return "xdp"
}

func (ap *AttachPoint) FileName() string {
	logLevel := strings.ToLower(ap.LogLevel)
	if logLevel == "off" {
		logLevel = "no_log"
	}
	return "xdp_" + logLevel + ".o"
}

func (ap *AttachPoint) SectionName() string {
	return "xdp/calico_entrypoint"
}

func (ap *AttachPoint) Log() *log.Entry {
	return log.WithFields(log.Fields{
		"iface":    ap.Iface,
		"modes":    ap.Modes,
		"logLevel": ap.LogLevel,
	})
}

func (ap *AttachPoint) AlreadyAttached(object string) (string, bool) {
	progID, err := ap.ProgramID()
	if err != nil {
		ap.Log().Debugf("Couldn't get the attached XDP program ID. err=%v", err)
		return "", false
	}

	somethingAttached, err := ap.IsAttached()
	if err != nil {
		ap.Log().Debugf("Failed to verify if any program is attached to interface. err=%v", err)
		return "", false
	}

	isAttached, err := bpf.AlreadyAttachedProg(ap, object, progID)
	if err != nil {
		ap.Log().Debugf("Failed to check if BPF program was already attached. err=%v", err)
		return "", false
	}

	if isAttached && somethingAttached {
		return progID, true
	}
	return "", false
}

func (ap *AttachPoint) AttachProgram() (string, error) {
	tempDir, err := ioutil.TempDir("", "calico-xdp")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	filename := ap.FileName()
	preCompiledBinary := path.Join(bpf.ObjectDir, filename)
	tempBinary := path.Join(tempDir, filename)

	// Patch the binary so that its log prefix is like "eth0------X".
	err = ap.patchBinary(preCompiledBinary, tempBinary)
	if err != nil {
		ap.Log().WithError(err).Error("Failed to patch binary")
		return "", err
	}

	obj, err := libbpf.OpenObject(tempBinary)
	if err != nil {
		return "", err
	}
	defer obj.Close()

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		// TODO: We need to set map size here like tc.
		pinPath := bpf.MapPinPath(m.Type(), m.Name(), ap.Iface, bpf.HookXDP)
		if err := m.SetPinPath(pinPath); err != nil {
			return "", fmt.Errorf("error pinning map %s: %w", m.Name(), err)
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
		return "", fmt.Errorf("error loading program: %w", err)
	}

	// TODO: Add support for IPv6
	err = updateJumpMap(obj)
	if err != nil {
		ap.Log().Warn("Failed to update jump map")
		return "", fmt.Errorf("error updating jump map %v", err)
	}

	// Note that there are a few considerations here.
	//
	// Firstly, we force program attachment, so as to minimise any flap in the XDP program when
	// restarting or upgrading Felix.
	//
	// Secondly, we need to consider any other XDP programs that might be there at start of day.
	// (Either 3rd party, or maybe some earlier version of Felix.)  We fundamentally have to
	// clean those up, as our XDP usage cannot coexist with anyone else's.
	//
	// Thirdly, for a given host interface, is it possible for our best attachment mode to
	// change, other than at start of day?  In principle it's possible if we do a patch that
	// alters some conditionally included code.  We don't have that for XDP right now, but we
	// conceivably could in future.  So safest to assume it's possible for the attachment mode
	// to improve, which means needing to do `off` for subsequent modes.
	//
	// Hence this logic:
	// - Loop through the modes.
	//   - If we haven't yet successfully attached (for this loop), do the attachment.
	//   - If that failed, or we attached with an earlier mode, do `off` to remove any existing
	//     program with this mode.
	//   - Continue through remaining modes even if attachment already successful.
	attachmentSucceeded := false
	for _, mode := range ap.Modes {
		progId, err := obj.AttachXDP(ap.SectionName(), ap.Iface, uint(mode))
		if err != nil {
			ap.Log().WithError(err).Warnf("Failed to attach to XDP section %s", ap.SectionName())
			continue
		}

		attachmentSucceeded = true
		ap.ProgID = progId
		break
	}

	if !attachmentSucceeded {
		return "", fmt.Errorf("failed to attach XDP program with section name %v to interface %v",
			ap.SectionName(), ap.Iface)
	}
	ap.Log().Info("Program attached to XDP.")

	// program is now attached. Now we should store its information to prevent unnecessary reloads in future
	if err = bpf.RememberAttachedProg(ap, preCompiledBinary, strconv.Itoa(ap.ProgID)); err != nil {
		ap.Log().Errorf("Failed to record hash of BPF program on disk; Ignoring. err=%v", err)
	}

	return strconv.Itoa(ap.ProgID), nil
}

func (ap AttachPoint) DetachProgram() error {
	// Get the current XDP program ID, if any.
	curProgId, err := ap.ProgramID()
	if err != nil {
		return fmt.Errorf("failed to get the attached XDP program ID: %w", err)
	}
	if curProgId == strconv.Itoa(DetachedID) {
		ap.Log().Debugf("No XDP program attached.")
		return nil
	}
	if strconv.Itoa(ap.ProgID) != curProgId {
		return fmt.Errorf("XDP expected program ID does match with current one.")
	}

	removalSucceeded := false
	for _, mode := range ap.Modes {
		err = libbpf.DetachXDP(ap.Iface, ap.ProgID, uint(mode))
		if err != nil {
			ap.Log().Debugf("Failed to detach XDP program in mode %v: %v", mode, err)
			continue
		}
		removalSucceeded = true
		break
	}
	if !removalSucceeded {
		return fmt.Errorf("Couldn't remove our XDP program.")
	}

	ap.Log().Infof("XDP program detached. ID: %v", ap.ProgID)
	ap.ProgID = DetachedID

	// Program is detached, now remove the json file we saved for it
	if err = bpf.ForgetAttachedProg(ap.IfaceName(), "xdp"); err != nil {
		return fmt.Errorf("Failed to delete hash of BPF program from disk: %w", err)
	}
	return nil
}

func (ap *AttachPoint) patchBinary(ifile, ofile string) error {
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

func (ap *AttachPoint) IsAttached() (bool, error) {
	_, err := ap.ProgramID()
	return err == nil, err
}

func (ap *AttachPoint) ProgramID() (string, error) {
	progID, err := libbpf.GetXDPProgramID(ap.Iface)
	if err != nil {
		return "", fmt.Errorf("Couldn't check for XDP program on iface %v: %w", ap.Iface, err)
	}
	return fmt.Sprintf("%d", progID), nil
}

func updateJumpMap(obj *libbpf.Obj) error {
	ipVersions := []string{"IPv4"}

	for _, ipFamily := range ipVersions {
		pIndex := 0
		err := obj.UpdateJumpMap(bpf.JumpMapName(), string(programNames[pIndex]), pIndex)
		if err != nil {
			return fmt.Errorf("error updating %v policy program: %v", ipFamily, err)
		}

		eIndex := 1
		err = obj.UpdateJumpMap(bpf.JumpMapName(), string(programNames[eIndex]), eIndex)
		if err != nil {
			return fmt.Errorf("error updating %v epilogue program: %v", ipFamily, err)
		}
	}

	return nil
}
