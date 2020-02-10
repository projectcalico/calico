// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

// Copyright (c) 2020  All rights reserved.

package tc

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
)

type AttachPoint struct {
	Section  string
	Hook     Hook
	Iface    string
	Filename string
}

var tcLock sync.Mutex

type ErrAttachFailed struct {
	ExitCode int
	Stderr   string
}

func (e ErrAttachFailed) Error() string {
	return fmt.Sprintf("tc failed with exit code %d; stderr=%v", e.ExitCode, e.Stderr)
}

// AttachProgram attaches a BPF program from a file to the TC attach point
func AttachProgram(attachPoint AttachPoint, hostIP net.IP) error {
	// FIXME we use this lock so that two copies of tc running in parallel don't re-use the same jump map.
	// This can happen if tc incorrectly decides the two programs are identical (when if fact they differ by attach
	// point).
	tcLock.Lock()
	defer tcLock.Unlock()

	// Work around tc map name collision: when we load two identical BPF programs onto different interfaces, tc
	// pins object-local maps to a namespace based on the hash of the BPF program, which is the same for both
	// interfaces.  Since we want one map per interface instead, we search for such maps and rename them before we
	// release the tc lock.
	//
	// For our purposes, it should work to simply delete the map.  However, when we tried that, the contents of the
	// map get deleted even though it is in use by a BPF program.
	defer repinJumpMaps()

	tempDir, err := ioutil.TempDir("", "calico-tc")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary directory")
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	preCompiledBinary := path.Join(bpf.ObjectDir, attachPoint.Filename)
	tempBinary := path.Join(tempDir, attachPoint.Filename)

	exeData, err := ioutil.ReadFile(preCompiledBinary)
	if err != nil {
		return errors.Wrap(err, "failed to read pre-compiled BPF binary")
	}

	hostIP = hostIP.To4()
	if len(hostIP) == 4 {
		logrus.WithField("ip", hostIP).Debug("Patching in host IP")
		replacement := make([]byte, 6)
		copy(replacement[2:], hostIP)
		exeData = bytes.ReplaceAll(exeData, []byte("\x00\x00HOST"), replacement)
	}

	// Patch in the log prefix; since this gets loaded as immediate values by the compiler, we know it'll be
	// preceded by a 2-byte 0 offset so we include that in the match.
	iface := []byte(attachPoint.Iface + "--------") // Pad on the right to make sure its long enough.
	logBytes := make([]byte, 6)
	copy(logBytes[2:], iface)
	exeData = bytes.ReplaceAll(exeData, []byte("\x00\x00CALI"), logBytes)
	copy(logBytes[2:], iface[4:8])
	exeData = bytes.ReplaceAll(exeData, []byte("\x00\x00COLO"), logBytes)

	err = ioutil.WriteFile(tempBinary, exeData, 0600)
	if err != nil {
		return errors.Wrap(err, "failed to write patched BPF binary")
	}

	tcCmd := exec.Command("tc",
		"filter", "add", "dev", attachPoint.Iface,
		string(attachPoint.Hook),
		"bpf", "da", "obj", tempBinary,
		"sec", attachPoint.Section)

	out, err := tcCmd.Output()
	if err != nil {
		if strings.Contains(err.Error(), "Cannot find device") {
			// Avoid a big, spammy log when the issue is that the interface isn't present.
			logrus.WithField("iface", attachPoint.Iface).Info(
				"Failed to attach BPF program; interface not found.  Will retry if it show up.")
			return nil
		}
		logrus.WithError(err).WithFields(logrus.Fields{"out": string(out)}).
			WithField("command", tcCmd).Error("Failed to attach BPF program")
		if err, ok := err.(*exec.ExitError); ok {
			// ExitError is really unhelpful dumped to the log, swap it for a custom one.
			return ErrAttachFailed{
				ExitCode: err.ExitCode(),
				Stderr:   string(err.Stderr),
			}
		}
		return errors.Wrap(err, "failed to attach TC program")
	}

	return nil
}

func repinJumpMaps() {
	// Find the maps we care about by walking the BPF filesystem.
	err := filepath.Walk("/sys/fs/bpf/tc", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Name() == "cali_jump" {
			logrus.WithField("path", path).Debug("Queueing deletion of map")

			out, err := exec.Command("bpftool", "map", "dump", "pinned", path).Output()
			if err != nil {
				logrus.WithError(err).Panic("Failed to dump map")
			}
			logrus.WithField("dump", string(out)).Info("Map dump before deletion")

			out, err = exec.Command("bpftool", "map", "show", "pinned", path).Output()
			if err != nil {
				logrus.WithError(err).Panic("Failed to show map")
			}
			logrus.WithField("dump", string(out)).Info("Map show before deletion")
			id := string(bytes.Split(out, []byte(":"))[0])

			newPath := path + fmt.Sprint(rand.Uint32())
			out, err = exec.Command("bpftool", "map", "pin", "id", id, newPath).Output()
			if err != nil {
				logrus.WithError(err).Panic("Failed to repin map")
			}
			logrus.WithField("dump", string(out)).Debug("Repin output")

			err = os.Remove(path)
			if err != nil {
				logrus.WithError(err).Panic("Failed to remove old map pin")
			}

			out, err = exec.Command("bpftool", "map", "dump", "pinned", newPath).Output()
			if err != nil {
				logrus.WithError(err).Panic("Failed to show map")
			}
			logrus.WithField("dump", string(out)).Info("Map show after repin")
		}
		return nil
	})
	if os.IsNotExist(err) {
		logrus.WithError(err).Warn("tc directory missing from BPF file system?")
		return
	}
	if err != nil {
		logrus.WithError(err).Panic("Failed to walk BPF filesystem")
	}
	logrus.Debug("Finished moving map pins that we don't need.")
}

// EnsureQdisc makes sure that qdisc is attached to the given interface
func EnsureQdisc(ifaceName string) {
	// FIXME Avoid flapping the tc program and qdisc
	cmd := exec.Command("tc", "qdisc", "del", "dev", ifaceName, "clsact")
	_ = cmd.Run()
	cmd = exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact")
	_ = cmd.Run()
}
