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
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/projectcalico/felix/bpf"
	log "github.com/sirupsen/logrus"
)

type AttachPoint struct {
	Iface    string
	LogLevel string
	Modes    []bpf.XDPMode
}

func (ap *AttachPoint) IfaceName() string {
	return ap.Iface
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
	return "calico_entrypoint_xdp"
}

func (ap *AttachPoint) Log() *log.Entry {
	return log.WithFields(log.Fields{
		"iface":    ap.Iface,
		"modes":    ap.Modes,
		"logLevel": ap.LogLevel,
	})
}

func (ap *AttachPoint) AttachProgram() error {
	preCompiledBinary := path.Join(bpf.ObjectDir, ap.FileName())
	sectionName := ap.SectionName()

	// Patch the binary so that its log prefix is like "eth0------X".
	tempDir, err := ioutil.TempDir("", "calico-tc")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()
	tempBinary := path.Join(tempDir, ap.FileName())
	err = ap.patchBinary(preCompiledBinary, tempBinary)
	if err != nil {
		ap.Log().WithError(err).Error("Failed to patch binary")
		return err
	}

	var errs []error
	for _, mode := range ap.Modes {
		ap.Log().Infof("Attempt XDP attach with mode %v", mode)

		// First remove any existing program.
		cmd := exec.Command("ip", "link", "set", "dev", ap.Iface, mode.String(), "off")
		ap.Log().Infof("Running: %v %v", cmd.Path, cmd.Args)
		out, err := cmd.CombinedOutput()
		ap.Log().WithField("mode", mode).Infof("Result: err=%v out=\n%v", err, string(out))

		// Now attach the program we want.
		cmd = exec.Command("ip", "link", "set", "dev", ap.Iface, mode.String(), "object", tempBinary, "section", sectionName)
		ap.Log().Infof("Running: %v %v", cmd.Path, cmd.Args)
		out, err = cmd.CombinedOutput()
		ap.Log().WithField("mode", mode).Infof("Result: err=%v out=\n%v", err, string(out))
		if err == nil {
			ap.Log().Infof("Successful attachment with mode %v", mode)
			return nil
		}
		errs = append(errs, err)
	}
	return fmt.Errorf("Couldn't attach XDP program %v section %v to iface %v; modes=%v errs=%v", tempBinary, sectionName, ap.Iface, ap.Modes, errs)
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
	cmd := exec.Command("ip", "link", "show", "dev", ap.Iface)
	ap.Log().Infof("Running: %v %v", cmd.Path, cmd.Args)
	out, err := cmd.CombinedOutput()
	ap.Log().Infof("Result: err=%v out=\n%v", err, string(out))
	if err != nil {
		return "", fmt.Errorf("Couldn't check for XDP program on iface %v: %v", ap.Iface, err)
	}
	s := strings.Fields(string(out))
	for i := range s {
		// Example of output:
		//
		// 196: test_A@test_B: <BROADCAST,MULTICAST> mtu 1500 xdpgeneric qdisc noop state DOWN mode DEFAULT group default qlen 1000
		//    link/ether 1a:d0:df:a5:12:59 brd ff:ff:ff:ff:ff:ff
		//    prog/xdp id 175 tag 5199fa060702bbff jited
		if s[i] == "prog/xdp" && len(s) > i+2 && s[i+1] == "id" {
			_, err := strconv.Atoi(s[i+2])
			if err != nil {
				return "", fmt.Errorf("Couldn't parse ID following 'prog/xdp' err=%v out=\n%v", err, string(out))
			}
			return s[i+2], nil
		}
	}
	return "", fmt.Errorf("Couldn't find 'prog/xdp id <ID>' err=%v out=\n%v", err, string(out))
}
