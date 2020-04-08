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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/set"

	"github.com/projectcalico/felix/bpf"
)

type AttachPoint struct {
	Type       EndpointType
	ToOrFrom   ToOrFromEp
	Hook       Hook
	Iface      string
	LogLevel   string
	IP         net.IP
	FIB        bool
	ToHostDrop bool
	DSR        bool
	TunnelMTU  uint16
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
func (ap AttachPoint) AttachProgram() error {
	// FIXME we use this lock so that two copies of tc running in parallel don't re-use the same jump map.
	// This can happen if tc incorrectly decides the two programs are identical (when in fact they differ by attach
	// point).
	log.Debug("AttachProgram waiting for lock...")
	tcLock.Lock()
	defer tcLock.Unlock()
	log.Debug("AttachProgram got lock.")

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

	filename := ap.FileName()
	preCompiledBinary := path.Join(bpf.ObjectDir, filename)
	tempBinary := path.Join(tempDir, filename)

	err = ap.patchBinary(preCompiledBinary, tempBinary)
	if err != nil {
		log.WithError(err).Error("Failed to patch binary")
		return err
	}

	tcCmd := exec.Command("tc",
		"filter", "add", "dev", ap.Iface,
		string(ap.Hook),
		"bpf", "da", "obj", tempBinary,
		"sec", SectionName(ap.Type, ap.ToOrFrom))

	out, err := tcCmd.Output()
	if err != nil {
		if strings.Contains(err.Error(), "Cannot find device") {
			// Avoid a big, spammy log when the issue is that the interface isn't present.
			log.WithField("iface", ap.Iface).Info(
				"Failed to attach BPF program; interface not found.  Will retry if it show up.")
			return nil
		}
		log.WithError(err).WithFields(log.Fields{"out": string(out)}).
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

func (ap AttachPoint) patchBinary(ifile, ofile string) error {
	b, err := bpf.BinaryFromFile(ifile)
	if err != nil {
		return errors.Wrap(err, "failed to read pre-compiled BPF binary")
	}

	log.WithField("ip", ap.IP).Debug("Patching in IP")
	err = b.PatchIPv4(ap.IP)
	if err != nil {
		return errors.WithMessage(err, "patching in IPv4")
	}

	b.PatchLogPrefix(ap.Iface)
	b.PatchTunnelMTU(ap.TunnelMTU)

	err = b.WriteToFile(ofile)
	if err != nil {
		return errors.Wrap(err, "failed to write patched BPF binary")
	}

	return nil
}

// ProgramName returnt the name of the program associated with this AttachPoint
func (ap AttachPoint) ProgramName() string {
	return SectionName(ap.Type, ap.ToOrFrom)
}

// FileName returnthe file the AttachPoint will load the program from
func (ap AttachPoint) FileName() string {
	return ProgFilename(ap.Type, ap.ToOrFrom, ap.ToHostDrop, ap.FIB, ap.DSR, ap.LogLevel)
}

func repinJumpMaps() {
	// Find the maps we care about by walking the BPF filesystem.
	err := filepath.Walk("/sys/fs/bpf/tc", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Name() == "cali_jump" {
			log.WithField("path", path).Debug("Queueing deletion of map")

			if log.GetLevel() >= log.DebugLevel {
				out, err := exec.Command("bpftool", "map", "dump", "pinned", path).Output()
				if err != nil {
					log.WithError(err).Panic("Failed to dump map")
				}
				log.WithField("dump", string(out)).Debug("Map dump before deletion")
			}

			out, err := exec.Command("bpftool", "map", "show", "pinned", path).Output()
			if err != nil {
				log.WithError(err).Panic("Failed to show map")
			}
			log.WithField("dump", string(out)).Debug("Map show before deletion")
			id := string(bytes.Split(out, []byte(":"))[0])

			newPath := path + fmt.Sprint(rand.Uint32())
			out, err = exec.Command("bpftool", "map", "pin", "id", id, newPath).Output()
			if err != nil {
				log.WithError(err).Panic("Failed to repin map")
			}
			log.WithField("dump", string(out)).Debug("Repin output")

			err = os.Remove(path)
			if err != nil {
				log.WithError(err).Panic("Failed to remove old map pin")
			}

			if log.GetLevel() >= log.DebugLevel {
				out, err = exec.Command("bpftool", "map", "dump", "pinned", newPath).Output()
				if err != nil {
					log.WithError(err).Panic("Failed to show map")
				}
				log.WithField("dump", string(out)).Debug("Map show after repin")
			}
		}
		return nil
	})
	if os.IsNotExist(err) {
		log.WithError(err).Warn("tc directory missing from BPF file system?")
		return
	}
	if err != nil {
		log.WithError(err).Panic("Failed to walk BPF filesystem")
	}
	log.Debug("Finished moving map pins that we don't need.")
}

// tcDirRegex matches tc's auto-created directory names so we can clean them up when removing maps without accidentally
// removing other user-created dirs..
var tcDirRegex = regexp.MustCompile(`[0-9a-f]{40}`)

// CleanUpJumpMaps scans for cali_jump maps that are still pinned to the filesystem but no longer referenced by
// our BPF programs.
func CleanUpJumpMaps() {
	// So that we serialise with AttachProgram()
	log.Debug("CleanUpJumpMaps waiting for lock...")
	tcLock.Lock()
	defer tcLock.Unlock()
	log.Debug("CleanUpJumpMaps got lock, cleaning up...")

	// Find the maps we care about by walking the BPF filesystem.
	mapIDToPath := make(map[int]string)
	err := filepath.Walk("/sys/fs/bpf/tc", func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(info.Name(), "cali_jump") {
			log.WithField("path", p).Debug("Examining map")

			out, err := exec.Command("bpftool", "map", "show", "pinned", p).Output()
			if err != nil {
				log.WithError(err).Panic("Failed to show map")
			}
			log.WithField("dump", string(out)).Debug("Map show before deletion")
			idStr := string(bytes.Split(out, []byte(":"))[0])
			id, err := strconv.Atoi(idStr)
			if err != nil {
				log.WithError(err).WithField("dump", string(out)).Error("Failed to parse bpftool output.")
				return err
			}
			mapIDToPath[id] = p
		}
		return nil
	})
	if os.IsNotExist(err) {
		log.WithError(err).Warn("tc directory missing from BPF file system?")
		return
	}
	if err != nil {
		log.WithError(err).Error("Error while looking for maps.")
	}

	// Find all the programs that are attached to interfaces.
	out, err := exec.Command("bpftool", "net", "-j").Output()
	if err != nil {
		log.WithError(err).Panic("Failed to list attached bpf programs")
	}
	log.WithField("dump", string(out)).Debug("Attached BPF programs")

	var attached []struct {
		TC []struct {
			DevName string `json:"devname"`
			ID      int    `json:"id"`
		} `json:"tc"`
	}
	err = json.Unmarshal(out, &attached)
	if err != nil {
		log.WithError(err).WithField("dump", string(out)).Error("Failed to parse list of attached BPF programs")
	}
	attachedProgs := set.New()
	for _, prog := range attached[0].TC {
		log.WithField("prog", prog).Debug("Adding prog to attached set")
		attachedProgs.Add(prog.ID)
	}

	// Find all the maps that the attached programs refer to and remove them from consideration.
	progsJSON, err := exec.Command("bpftool", "prog", "list", "--json").Output()
	if err != nil {
		log.WithError(err).Info("Failed to list BPF programs, assuming there's nothing to clean up.")
		return
	}
	var progs []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
		Maps []int  `json:"map_ids"`
	}
	err = json.Unmarshal(progsJSON, &progs)
	if err != nil {
		log.WithError(err).Info("Failed to parse bpftool output.  Assuming nothing to clean up.")
		return
	}
	for _, p := range progs {
		if !attachedProgs.Contains(p.ID) {
			log.WithField("prog", p).Debug("Prog is not in the attached set, skipping")
			continue
		}
		for _, id := range p.Maps {
			log.WithField("mapID", id).WithField("prog", p).Debug("Map is still in use")
			delete(mapIDToPath, id)
		}
	}

	// Remove the pins.
	for id, p := range mapIDToPath {
		log.WithFields(log.Fields{"id": id, "path": p}).Debug("Removing stale BPF map pin.")
		err := os.Remove(p)
		if err != nil {
			log.WithError(err).Warn("Removed stale BPF map pin.")
		}
		log.WithFields(log.Fields{"id": id, "path": p}).Info("Removed stale BPF map pin.")
	}

	// Look for empty dirs.
	emptyAutoDirs := set.New()
	err = filepath.Walk("/sys/fs/bpf/tc", func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && tcDirRegex.MatchString(info.Name()) {
			p := path.Clean(p)
			log.WithField("path", p).Debug("Found tc auto-created dir.")
			emptyAutoDirs.Add(p)
		} else {
			dirPath := path.Clean(path.Dir(p))
			log.WithField("path", dirPath).Debug("tc dir is not empty.")
			emptyAutoDirs.Discard(dirPath)
		}
		return nil
	})
	if os.IsNotExist(err) {
		log.WithError(err).Warn("tc directory missing from BPF file system?")
		return
	}
	if err != nil {
		log.WithError(err).Error("Error while looking for maps.")
	}

	emptyAutoDirs.Iter(func(item interface{}) error {
		p := item.(string)
		log.WithField("path", p).Debug("Removing empty dir.")
		err := os.Remove(p)
		if err != nil {
			log.WithError(err).Error("Error while removing empty dir.")
		}
		return nil
	})
}

// EnsureQdisc makes sure that qdisc is attached to the given interface
func EnsureQdisc(ifaceName string) {
	// FIXME Avoid flapping the tc program and qdisc
	cmd := exec.Command("tc", "qdisc", "del", "dev", ifaceName, "clsact")
	_ = cmd.Run()
	cmd = exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact")
	_ = cmd.Run()
}
