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
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

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
	HookName() string
	Config() string
}

var (
	// These are possible hooks for a bpf program. "ingress" and "egress" imply TC program
	// and each one reflects traffic direction. "xdp" implies xdp programs.
	runtimeJSONsuffixes = []string{"ingress", "egress", "xdp"}
)

// AlreadyAttachedProg checks that the program we are going to attach has the
// same parameters as what we remembered about the currently attached.
func AlreadyAttachedProg(a AttachPointInfo, object string, id int) (bool, error) {
	bytesToRead, err := ioutil.ReadFile(RuntimeJSONFilename(a.IfaceName(), a.HookName()))
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

	if err = ioutil.WriteFile(RuntimeJSONFilename(a.IfaceName(), a.HookName()), bytesToWrite, 0600); err != nil {
		return err
	}

	return nil
}

// ForgetAttachedProg removes what we store about the iface/hook
// program.
func ForgetAttachedProg(iface, hook string) error {
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
	for _, hook := range runtimeJSONsuffixes {
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
		for _, hook := range runtimeJSONsuffixes {
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
// attached program. The filename is [iface name]_[tc_hook name | xdp].json, for
// example, eth0_tc_egress.json
func RuntimeJSONFilename(iface, hook string) string {
	filename := path.Join(RuntimeProgDir, iface+"_tc_"+hook+".json")
	if strings.ToLower(hook) == "xdp" {
		return path.Join(RuntimeProgDir, iface+"_xdp.json")
	}
	return filename
}

func sha256OfFile(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", fmt.Errorf("failed to open BPF object to calculate its hash: %w", err)
	}
	hasher := sha256.New()
	_, err = io.Copy(hasher, f)
	if err != nil {
		return "", fmt.Errorf("failed to read BPF object to calculate its hash: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
