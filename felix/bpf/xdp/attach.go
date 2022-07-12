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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
)

type ProgName string

var programNames = []ProgName{
	"calico_xdp_norm_pol_tail",
	"calico_xdp_accepted_entrypoint",
}

type AttachPoint struct {
	Iface    string
	LogLevel string
	Modes    []bpf.XDPMode
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
	ap.Log().Infof("mahnaz")

	obj, err := libbpf.OpenObject(tempBinary, unix.BPF_PROG_TYPE_XDP)
	if err != nil {
		ap.Log().Infof("mahnaz0 err: %v", err)
		return "", err
	}
	defer obj.Close()
	ap.Log().Infof("mahnaz1")

	baseDir := "/sys/fs/bpf/tc"
	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		// In case of global variables, libbpf creates an internal map <prog_name>.rodata
		// The values are read only for the BPF programs, but can be set to a value from
		// userspace before the program is loaded.

		// TODO: Configure the internal map, i.e. <prog_name>.rodata here, similar to tc.

		subDir := "globals"
		if m.Type() == libbpf.MapTypeProgrArray && strings.Contains(m.Name(), bpf.JumpMapName()) {
			// Remove period in the interface name if any
			ifName := strings.ReplaceAll(ap.Iface, ".", "")
			subDir = ifName + "_xdp/"
		}
		ap.Log().Infof("mahnaz2")

		// TODO: We need to set map size here like tc.
		pinPath := path.Join(baseDir, subDir, m.Name())
		ap.Log().Infof("marmar iface: %s pinpath: %v", ap.IfaceName(), pinPath)
		if err := m.SetPinPath(pinPath); err != nil {
			ap.Log().Infof("mahnaz3")
			return "", fmt.Errorf("error pinning map %s: %w", m.Name(), err)
		}
	}
	ap.Log().Infof("mahnaz4")

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
	ap.Log().Infof("mahnaz5")

	// TODO: Add support for IPv6
	err = updateJumpMap(obj)
	if err != nil {
		ap.Log().Warn("Failed to update jump map")
		return "", fmt.Errorf("error updating jump map %v", err)
	}
	ap.Log().Infof("mahnaz6")

	progId, err := obj.AttachXDP(ap.SectionName(), ap.Iface)
	if err != nil {
		ap.Log().WithError(err).Warnf("Failed to attach to XDP section %s", ap.SectionName())
		return "", err
	}
	ap.Log().Info("Program attached to XDP.")
	ap.Log().Infof("mahnaz7")

	// Note that there are a few considerations here.
	//
	// Firstly, we use -force when attaching, so as to minimise any flap in the XDP program when
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
	//   - If we haven't yet successfully attached (for this loop), do the attachment (with
	//     -force).
	//   - If that failed, or we attached with an earlier mode, do `off` to remove any existing
	//     program with this mode.
	//   - Continue through remaining modes even if attachment already successful.
	/*var errs []error
	attachmentSucceeded := false
	for _, mode := range ap.Modes {
		ap.Log().Debugf("XDP remove/attach with mode %v", mode)

		// We will need to do "ip link set dev <dev> xdp off" if we've successfully attached
		// with an earlier mode, or if we fail to attach with this mode.  So we only _don't_
		// need "off" if we successfully attach in this iteration.
		offNeeded := true

		if !attachmentSucceeded {
			// Try to attach our XDP program in this mode.
			cmd := exec.Command("ip", "-force", "link", "set", "dev", ap.Iface, mode.String(), "object", tempBinary, "section", sectionName)
			ap.Log().Debugf("Running: %v %v", cmd.Path, cmd.Args)
			out, err := cmd.CombinedOutput()
			ap.Log().WithField("mode", mode).Debugf("Result: err=%v out=\n%v", err, string(out))
			if err == nil {
				ap.Log().Infof("Successful XDP attachment with mode %v", mode)
				attachmentSucceeded = true
				offNeeded = false
			} else {
				errs = append(errs, err)
			}
		}

		if offNeeded {
			// Remove any existing program for this mode.
			cmd := exec.Command("ip", "link", "set", "dev", ap.Iface, mode.String(), "off")
			ap.Log().Debugf("Running: %v %v", cmd.Path, cmd.Args)
			out, err := cmd.CombinedOutput()
			ap.Log().WithField("mode", mode).Debugf("Result: err=%v out=\n%v", err, string(out))
		}
	}
	if !attachmentSucceeded {
		return "", fmt.Errorf("Couldn't attach XDP program %v section %v to iface %v; modes=%v errs=%v", tempBinary, sectionName, ap.Iface, ap.Modes, errs)
	}
	progID, err = ap.ProgramID()
	if err != nil {
		return "", fmt.Errorf("couldn't get the attached XDP program ID err=%v", err)
	}*/

	// program is now attached. Now we should store its information to prevent unnecessary reloads in future
	if err = bpf.RememberAttachedProg(ap, preCompiledBinary, strconv.Itoa(progId)); err != nil {
		ap.Log().Errorf("Failed to record hash of BPF program on disk; Ignoring. err=%v", err)
	}

	return strconv.Itoa(progId), nil
}

func (ap AttachPoint) DetachProgram() error {
	// Get the current XDP program ID, if any.
	progID, err := ap.ProgramID()
	if err != nil {
		if errors.Is(err, ErrNoXDP) {
			// Interface has no XDP attached - that's what we want.
			return nil
		}
		// Some other error: return it to trigger a retry.
		return fmt.Errorf("Couldn't get XDP program ID for %v: %w", ap.Iface, err)
	}

	// Get the map IDs that the program is using.
	out, err := exec.Command("bpftool", "prog", "show", "id", progID, "-j").CombinedOutput()
	if err != nil {
		return fmt.Errorf("Couldn't query XDP prog id=%v iface=%v out=\n%v err=%w", progID, ap.Iface, string(out), err)
	}
	var progJSON struct {
		Maps []int `json:"map_ids"`
	}
	err = json.Unmarshal(out, &progJSON)
	if err != nil {
		ap.Log().WithError(err).Debugf("Failed to parse bpftool output out=\n%v.  Assume not our XDP program.", string(out))
		return nil
	}

	ourProgram := false
	for _, mapID := range progJSON.Maps {
		// Check if this map is one of ours.
		ap.Log().Debugf("Check if map id %v is one of ours", mapID)
		out, err = exec.Command("bpftool", "map", "show", "id", fmt.Sprintf("%v", mapID), "-j").CombinedOutput()
		if err != nil {
			return fmt.Errorf("Couldn't query map id=%v iface=%v out=\n%v err=%w", progID, ap.Iface, string(out), err)
		}
		var mapJSON struct {
			Name string `json:"name"`
		}
		err = json.Unmarshal(out, &mapJSON)
		if err != nil {
			ap.Log().WithError(err).Debugf("Failed to parse bpftool output out=\n%v.  Assume not our map.", string(out))
		} else if strings.HasPrefix(mapJSON.Name, "cali_") {
			ourProgram = true
			break
		}
	}

	if ourProgram {
		// It's our XDP program; remove it.
		ap.Log().Debug("Removing our XDP program")
		removalSucceeded := false
		for _, mode := range ap.Modes {
			cmd := exec.Command("ip", "link", "set", "dev", ap.Iface, mode.String(), "off")
			ap.Log().Debugf("Running: %v %v", cmd.Path, cmd.Args)
			out, err := cmd.CombinedOutput()
			ap.Log().WithField("mode", mode).Debugf("Result: err=%v out=\n%v", err, string(out))
			if err == nil {
				removalSucceeded = true
			}
		}
		if !removalSucceeded {
			return fmt.Errorf("Couldn't remove our XDP program from iface %v", ap.Iface)
		}
	}

	// Program is detached, now remove the json file we saved for it
	if err = bpf.ForgetAttachedProg(ap.IfaceName(), "xdp"); err != nil {
		return fmt.Errorf("Failed to delete hash of BPF program from disk. err=%w", err)
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

var ErrNoXDP = errors.New("no XDP program attached")

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
		logrus.Infof("damon jump map: %v, program name: %v", bpf.JumpMapName(), string(programNames[eIndex]))
		if err != nil {
			return fmt.Errorf("error updating %v epilogue program: %v", ipFamily, err)
		}
	}

	return nil
}
