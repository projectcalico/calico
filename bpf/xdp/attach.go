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

func (ap *AttachPoint) AttachProgram() error {
	objPath := path.Join(bpf.ObjectDir, ap.FileName())
	sectionName := ap.SectionName()
	var errs []error
	for _, mode := range ap.Modes {
		log.Infof("Attempt XDP attach for %v with mode %v", ap.Iface, mode)
		cmd := exec.Command("ip", "link", "set", "dev", ap.Iface, mode.String(), "object", objPath, "section", sectionName)
		log.Infof("Running: %v %v", cmd.Path, cmd.Args)
		out, err := cmd.CombinedOutput()
		log.Infof("Result: err=%v out=\n%v", err, string(out))
		if err == nil {
			log.Infof("Successful attachment with mode %v", mode)
			return nil
		}
		errs = append(errs, err)
	}
	return fmt.Errorf("Couldn't attach XDP program %v section %v to iface %v; modes=%v errs=%v", objPath, sectionName, ap.Iface, ap.Modes, errs)
}

func (ap *AttachPoint) IsAttached() (bool, error) {
	progID, err := ap.ProgramID()
	return err == nil, err
}

func (ap *AttachPoint) ProgramID() (string, error) {
	cmd := exec.Command("ip", "link", "show", "dev", ap.Iface)
	log.Infof("Running: %v %v", cmd.Path, cmd.Args)
	out, err := cmd.CombinedOutput()
	log.Infof("Result: err=%v out=\n%v", err, string(out))
	if err != nil {
		return "", fmt.Errorf("Couldn't check for XDP program on iface %v: %v", ap.Iface, err)
	}
	s := strings.Fields(string(output))
	for i := range s {
		// Example of output:
		//
		// 196: test_A@test_B: <BROADCAST,MULTICAST> mtu 1500 xdpgeneric qdisc noop state DOWN mode DEFAULT group default qlen 1000
		//    link/ether 1a:d0:df:a5:12:59 brd ff:ff:ff:ff:ff:ff
		//    prog/xdp id 175 tag 5199fa060702bbff jited
		if s[i] == "prog/xdp" && len(s) > i+2 && s[i+1] == "id" {
			id, err := strconv.Atoi(s[i+2])
			if err != nil {
				return "", fmt.Errorf("Couldn't parse ID following 'prog/xdp' err=%v out=\n%v", err, string(output))
			}
			return id, nil
		}
	}
	return "", fmt.Errorf("Couldn't find 'prog/xdp id <ID>' err=%v out=\n%v", err, string(output))
}
