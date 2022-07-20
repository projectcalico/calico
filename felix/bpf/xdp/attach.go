// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
)

type AttachPoint struct {
	Iface    string
	LogLevel string
	Modes    []bpf.XDPMode
}

func (ap AttachPoint) IfaceName() string {
	return ap.Iface
}

func (ap AttachPoint) HookName() string {
	return "xdp"
}

func (ap AttachPoint) Config() string {
	return fmt.Sprintf("%+v", ap)
}

func (ap AttachPoint) JumpMapFDMapKey() string {
	return "xdp"
}

func (ap AttachPoint) FileName() string {
	logLevel := strings.ToLower(ap.LogLevel)
	if logLevel == "off" {
		logLevel = "no_log"
	}
	return "xdp_" + logLevel + ".o"
}

func (ap AttachPoint) SectionName() string {
	return "calico_entrypoint_xdp"
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

func (ap *AttachPoint) AttachProgram() (int, error) {
	preCompiledBinary := path.Join(bpf.ObjectDir, ap.FileName())
	sectionName := ap.SectionName()

	// Patch the binary so that its log prefix is like "eth0------X".
	tempDir, err := ioutil.TempDir("", "calico-xdp")
	if err != nil {
		return -1, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()
	tempBinary := path.Join(tempDir, ap.FileName())
	err = ap.patchBinary(preCompiledBinary, tempBinary)
	if err != nil {
		ap.Log().WithError(err).Error("Failed to patch binary")
		return -1, err
	}

	// Check if the bpf object is already attached, and we should skip re-attaching it
	progID, isAttached := ap.AlreadyAttached(preCompiledBinary)
	if isAttached {
		ap.Log().Infof("Programs already attached, skip reattaching %s", ap.FileName())
		return progID, nil
	}
	ap.Log().Infof("Continue with attaching BPF program %s", ap.FileName())

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
	var errs []error
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
		return -1, fmt.Errorf("Couldn't attach XDP program %v section %v to iface %v; modes=%v errs=%v", tempBinary, sectionName, ap.Iface, ap.Modes, errs)
	}
	progID, err = ap.ProgramID()
	if err != nil {
		return -1, fmt.Errorf("couldn't get the attached XDP program ID err=%v", err)
	}

	// program is now attached. Now we should store its information to prevent unnecessary reloads in future
	if err = bpf.RememberAttachedProg(ap, preCompiledBinary, progID); err != nil {
		ap.Log().Errorf("Failed to record hash of BPF program on disk; Ignoring. err=%v", err)
	}

	return progID, nil
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
	out, err := exec.Command("bpftool", "prog", "show", "id", strconv.Itoa(progID), "-j").CombinedOutput()
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

// TODO: we should try to not get the program ID via 'ip' binary and rather
// we should use libbpf to obtain it.
func (ap *AttachPoint) ProgramID() (int, error) {
	cmd := exec.Command("ip", "link", "show", "dev", ap.Iface)
	ap.Log().Debugf("Running: %v %v", cmd.Path, cmd.Args)
	out, err := cmd.CombinedOutput()
	ap.Log().Debugf("Result: err=%v out=\n%v", err, string(out))
	if err != nil {
		return -1, fmt.Errorf("Couldn't check for XDP program on iface %v: %w", ap.Iface, err)
	}
	s := strings.Fields(string(out))
	for i := range s {
		// Example of output:
		//
		// 196: test_A@test_B: <BROADCAST,MULTICAST> mtu 1500 xdpgeneric qdisc noop state DOWN mode DEFAULT group default qlen 1000
		//    link/ether 1a:d0:df:a5:12:59 brd ff:ff:ff:ff:ff:ff
		//    prog/xdp id 175 tag 5199fa060702bbff jited
		if s[i] == "prog/xdp" && len(s) > i+2 && s[i+1] == "id" {
			progID, err := strconv.Atoi(s[i+2])
			if err != nil {
				return -1, fmt.Errorf("Couldn't parse ID following 'prog/xdp' err=%w out=\n%v", err, string(out))
			}
			return progID, nil
		}
	}
	return -1, fmt.Errorf("Couldn't find 'prog/xdp id <ID>' out=\n%v err=%w", string(out), ErrNoXDP)
}
