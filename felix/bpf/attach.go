// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
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

package bpf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// AttachedProgInfo describes what we store about an attached program.
type AttachedProgInfo struct {
	Object string `json:"object"`
	Hash   string `json:"hash"`
	ID     int    `json:"id"`
	Config string `json:"config"`
}

// AttachPointInfo describes what we need to know about an attach point
type AttachPointInfo interface {
	IfaceName() string
	HookName() hook.Hook
	Config() string
}

type AttachPoint struct {
	Hook        hook.Hook
	PolicyIdxV4 int
	PolicyIdxV6 int
	Iface       string
	LogLevel    string
}

func (ap *AttachPoint) LogVal() string {
	return ap.LogLevel
}

func (ap *AttachPoint) IfaceName() string {
	return ap.Iface
}

func (ap *AttachPoint) HookName() hook.Hook {
	return ap.Hook
}

func (ap *AttachPoint) PolicyJmp(ipFamily proto.IPVersion) int {
	if ipFamily == proto.IPVersion_IPV6 {
		return ap.PolicyIdxV6
	}
	return ap.PolicyIdxV4
}

type AttachResult interface {
	ProgID() int
}

// AlreadyAttachedProg checks that the program we are going to attach has the
// same parameters as what we remembered about the currently attached.
func AlreadyAttachedProg(a AttachPointInfo, object string, id int) (bool, error) {
	bytesToRead, err := os.ReadFile(RuntimeJSONFilename(a.IfaceName(), a.HookName()))
	if err != nil {
		// If file does not exist, just ignore the err code, and return false
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	var progInfo AttachedProgInfo
	if err = json.Unmarshal(bytesToRead, &progInfo); err != nil {
		return false, err
	}

	hash, err := sha256OfFile(object)
	if err != nil {
		return false, err
	}

	if log.GetLevel() >= log.DebugLevel {
		log.WithFields(log.Fields{
			"iface":  a.IfaceName(),
			"hook":   a.HookName(),
			"hash":   progInfo.Hash == hash,
			"object": progInfo.Object == object,
			"id":     progInfo.ID == id,
			"config": progInfo.Config == a.Config(),
		}).Debugf("AlreadyAttachedProg result %t", progInfo.Hash == hash &&
			progInfo.Object == object && progInfo.ID == id &&
			progInfo.Config == a.Config())
	}

	return progInfo.Hash == hash &&
			progInfo.Object == object &&
			progInfo.ID == id &&
			progInfo.Config == a.Config(),
		nil
}

// RememberAttachedProg stores the attached programs parameters in a file.
func RememberAttachedProg(a AttachPointInfo, object string, id int) error {
	hash, err := sha256OfFile(object)
	if err != nil {
		return err
	}

	var progInfo = AttachedProgInfo{
		Object: object,
		Hash:   hash,
		ID:     id,
		Config: a.Config(),
	}

	if err := os.MkdirAll(RuntimeProgDir, 0600); err != nil {
		return err
	}

	bytesToWrite, err := json.Marshal(progInfo)
	if err != nil {
		return err
	}

	if err = os.WriteFile(RuntimeJSONFilename(a.IfaceName(), a.HookName()), bytesToWrite, 0600); err != nil {
		return err
	}

	return nil
}

// ForgetAttachedProg removes what we store about the iface/hook
// program.
func ForgetAttachedProg(iface string, hook hook.Hook) error {
	err := os.Remove(RuntimeJSONFilename(iface, hook))
	// If the hash file does not exist, just ignore the err code, and return false
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ForgetIfaceAttachedProg removes information we store about any programs
// associated with an iface.
func ForgetIfaceAttachedProg(iface string) error {
	for _, hook := range hook.All {
		err := ForgetAttachedProg(iface, hook)
		if err != nil {
			return err
		}
	}
	return nil
}

// CleanAttachedProgDir makes sure /var/run/calico/bpf/prog exists and removes
// json files related to interfaces that do not exist.
func CleanAttachedProgDir() {
	if err := os.MkdirAll(RuntimeProgDir, 0600); err != nil {
		log.Errorf("Failed to create BPF hash directory. err=%v", err)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Errorf("Failed to get list of interfaces. err=%v", err)
	}

	expectedJSONFiles := set.New[string]()
	for _, iface := range interfaces {
		for _, hook := range hook.All {
			expectedJSONFiles.Add(RuntimeJSONFilename(iface.Name, hook))
		}
	}

	err = filepath.Walk(RuntimeProgDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if p == RuntimeProgDir {
			return nil
		}
		if !expectedJSONFiles.Contains(p) {
			err := os.Remove(p)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
		}

		return nil
	})

	if err != nil {
		log.Debugf("Error in cleaning up %s. err=%v", RuntimeProgDir, err)
	}
}

// RuntimeJSONFilename returns filename where we store information about
// attached program. The filename is [iface name]_[hook].json, for
// example, eth0_egress.json
func RuntimeJSONFilename(iface string, hook hook.Hook) string {
	return path.Join(RuntimeProgDir, fmt.Sprintf("%s_%s.json", iface, hook))
}

func sha256OfFile(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", fmt.Errorf("failed to open BPF object to calculate its hash: %w", err)
	}
	defer f.Close()
	hasher := sha256.New()
	_, err = io.Copy(hasher, f)
	if err != nil {
		return "", fmt.Errorf("failed to read BPF object to calculate its hash: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// EPAttachInfo tells what programs are attached to an endpoint.
type EPAttachInfo struct {
	Ingress int
	Egress  int
	XDP     int
	XDPMode string
}

// ListCalicoAttached list all programs that are attached to TC or XDP and are
// related to Calico. That is, they have jumpmap pinned in our dir hierarchy.
func ListCalicoAttached() (map[string]EPAttachInfo, error) {
	aTC, aXDP, err := ListTcXDPAttachedProgs()
	if err != nil {
		return nil, err
	}

	ai := make(map[string]EPAttachInfo)

	for _, p := range aTC {
		if strings.HasPrefix(p.Name, "cali") {
			info := ai[p.DevName]
			if p.Kind == "clsact/egress" {
				info.Egress = p.ID
			} else {
				info.Ingress = p.ID
			}
			ai[p.DevName] = info
		}
	}

	for _, p := range aXDP {
		if strings.HasPrefix(p.Name, "cali") {
			info := ai[p.DevName]
			info.XDP = p.ID
			info.XDPMode = p.Mode
			ai[p.DevName] = info
		}
	}

	return ai, nil
}
