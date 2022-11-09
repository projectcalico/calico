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

package tc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfutils"
	"github.com/projectcalico/calico/felix/bpf/filter"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

type AttachPoint struct {
	Type                 EndpointType
	ToOrFrom             ToOrFromEp
	Hook                 bpf.Hook
	Iface                string
	LogLevel             string
	LogFilter            string
	HostIP               net.IP
	HostTunnelIP         net.IP
	IntfIP               net.IP
	FIB                  bool
	ToHostDrop           bool
	DSR                  bool
	TunnelMTU            uint16
	VXLANPort            uint16
	WgPort               uint16
	ExtToServiceConnmark uint32
	PSNATStart           uint16
	PSNATEnd             uint16
	IPv6Enabled          bool
	MapSizes             map[string]uint32
	RPFStrictEnabled     bool
	NATin                uint32
	NATout               uint32
}

const (
	JumpFDRegularV4 = iota
	JumpFDDebugV4
	JumpFDCount
)

var tcLock sync.RWMutex
var ErrDeviceNotFound = errors.New("device not found")
var ErrInterrupted = errors.New("dump interrupted")
var prefHandleRe = regexp.MustCompile(`pref ([^ ]+) .* handle ([^ ]+).*id ([^ ]+) tag ([^ ]+)`)

func (ap *AttachPoint) Log() *log.Entry {
	return log.WithFields(log.Fields{
		"iface": ap.Iface,
		"type":  ap.Type,
		"hook":  ap.Hook,
	})
}

func (ap *AttachPoint) loadLogging() bool {
	return ap.LogLevel == "debug-filters"
}

func (ap *AttachPoint) Debug() bool {
	return ap.loadLogging()
}

func (ap *AttachPoint) AlreadyAttached(object string) (int, bool) {
	logCxt := log.WithField("attachPoint", ap)
	progID, err := ap.programID()
	if err != nil {
		logCxt.WithError(err).Debugf("Couldn't get the attached TC program ID.")
		return -1, false
	}

	progsToClean, err := ap.ListAttachedPrograms()
	if err != nil {
		logCxt.WithError(err).Debugf("Couldn't get the list of already attached TC programs")
		return -1, false
	}

	isAttached, err := bpf.AlreadyAttachedProg(ap, object, progID)
	if err != nil {
		logCxt.WithError(err).Debugf("Failed to check if BPF program was already attached.")
		return -1, false
	}

	if isAttached && len(progsToClean) == 1 {
		return progID, true
	}
	return -1, false
}

func (ap *AttachPoint) loadProgram(obj *libbpf.Obj, filename string, debug bool) error {
	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		// In case of global variables, libbpf creates an internal map <prog_name>.rodata
		// The values are read only for the BPF programs, but can be set to a value from
		// userspace before the program is loaded.
		if m.IsMapInternal() {
			if err := ap.ConfigureProgram(m); err != nil {
				return fmt.Errorf("failed to configure %s: %w", filename, err)
			}
			continue
		}

		if err := ap.setMapSize(m); err != nil {
			return fmt.Errorf("error setting map size %s : %w", m.Name(), err)
		}
		pinPath := bpf.MapPinPath(m.Type(), m.Name(), ap.Iface, ap.Hook, debug)
		if err := m.SetPinPath(pinPath); err != nil {
			return fmt.Errorf("error pinning map %s: %w", m.Name(), err)
		}
	}

	if err := obj.Load(); err != nil {
		return fmt.Errorf("error loading program: %w", err)
	}

	return nil
}

func (ap *AttachPoint) loadObject(debugPath bool) (*libbpf.Obj, error) {
	var objfile string

	if debugPath || ap.LogLevel == "debug" {
		tempDir, err := ioutil.TempDir("", "calico-tc")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary directory: %w", err)
		}
		defer func() {
			_ = os.RemoveAll(tempDir)
		}()

		filename := ap.FileName(true)
		preCompiledBinary := path.Join(bpf.ObjectDir, filename)
		objfile = path.Join(tempDir, filename)

		err = ap.patchLogPrefix(preCompiledBinary, objfile)
		if err != nil {
			return nil, fmt.Errorf("patch binary: %w", err)
		}
	} else {
		filename := ap.FileName(false)
		objfile = path.Join(bpf.ObjectDir, filename)
	}

	obj, err := libbpf.OpenObject(objfile)
	if err != nil {
		return nil, fmt.Errorf("open object file \"%s\": %w", objfile, err)
	}

	if err := ap.loadProgram(obj, objfile, debugPath); err != nil {
		return nil, fmt.Errorf("loading programs: %w", err)
	}

	err = ap.updateJumpMap(obj)
	if err != nil {
		return nil, fmt.Errorf("updating jump map %w", err)
	}

	return obj, nil
}

// AttachPrograms attaches a BPF program from a file to the TC attach point
func (ap *AttachPoint) AttachPrograms() ([]bpf.MapFD, error) {
	logCxt := log.WithField("attachPoint", ap)

	filename := ap.FileName(false)
	preCompiledBinary := path.Join(bpf.ObjectDir, filename)

	// Using the RLock allows multiple attach calls to proceed in parallel unless
	// CleanUpMaps() (which takes the writer lock) is running.
	logCxt.Debug("AttachProgram waiting for lock...")
	tcLock.RLock()
	defer tcLock.RUnlock()
	logCxt.Debug("AttachProgram got lock.")

	// Check if the bpf object is already attached, and we should skip
	// re-attaching it if the binary and its configuration are the same.
	progID, isAttached := ap.AlreadyAttached(preCompiledBinary)
	if isAttached {
		logCxt.Infof("Program already attached to TC, skip reattaching %s", filename)

		fd, err := findJumpMap(progID, ap.Iface)
		if err != nil {
			return nil, fmt.Errorf("cannot find regular prog jump map: %w", err)
		}

		fds := []bpf.MapFD{bpf.MapFD(fd), 0}

		if ap.Debug() {
			debugProgID, err := jump.GetEntry(fd, tcdefs.ProgIndexDebug)
			if err != nil {
				return nil, fmt.Errorf("cannot read debug prog id from jump map: %w", err)
			}

			if debugProgID == 0 {
				logCxt.Debug("Attach point is debuging but the attached program does not jump " +
					"to debug path")
				goto attach
			}

			fd, err = findJumpMap(debugProgID, ap.Iface)
			if err != nil {
				return nil, fmt.Errorf("cannot find debug prog jump map: %w", err)
			}

			fds[JumpFDDebugV4] = bpf.MapFD(fd)
		}

		return fds, nil
	}

attach:

	logCxt.Debugf("Continue with attaching BPF program %s", filename)

	progsToClean, err := ap.ListAttachedPrograms()
	if err != nil {
		return nil, err
	}

	var objDebug *libbpf.Obj

	loadLogging := ap.loadLogging()

	if loadLogging {
		objDebug, err = ap.loadObject(true)
		if err != nil {
			logCxt.WithError(err).Warn("Failed to load debug path")
			return nil, err
		}
		defer objDebug.Close()
		logCxt.WithError(err).Debug("Loaded debug path")
	}

	obj, err := ap.loadObject(false)
	if err != nil {
		logCxt.WithError(err).Warn("Failed to load regular path")
		return nil, err
	}
	defer obj.Close()
	logCxt.WithError(err).Debug("Loaded regular path")

	var progId int

	fds := make([]bpf.MapFD, 2)
	fd, err := obj.GetJumpMapFd(bpf.JumpMapName())
	if err != nil {
		return nil, fmt.Errorf("failed to get jump map fd: %w", err)
	}
	// Closing the object also closes the FD so duplicate it
	fd, err = syscall.Dup(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to dup jump map fd: %w", err)
	}
	fds[JumpFDRegularV4] = bpf.MapFD(fd)

	if !loadLogging {
		var err error
		progId, err = obj.AttachClassifier(SectionName(ap.Type, ap.ToOrFrom), ap.Iface, string(ap.Hook))
		if err != nil {
			logCxt.Warnf("Failed to attach to TC section %s", SectionName(ap.Type, ap.ToOrFrom))
			return nil, err
		}
		// Make sure that if there was a debug filter before, pointers to the tc
		// programs are removed from the jump map to release the old programs.
		err = jump.DeleteEntry(fds[JumpFDRegularV4], tcdefs.ProgIndexNoDebug)
		if err != nil && (os.IsNotExist(err) || err == unix.ENOENT) {
			logCxt.WithError(err).Warnf("Failed to clear entry %d in jump map - possible leak!", tcdefs.ProgIndexNoDebug)
		}
		err = jump.DeleteEntry(fds[JumpFDRegularV4], tcdefs.ProgIndexDebug)
		if err != nil && (os.IsNotExist(err) || err == unix.ENOENT) {
			logCxt.WithError(err).Warnf("Failed to clear entry %d in jump map - possible leak!", tcdefs.ProgIndexDebug)
		}
		logCxt.Info("Program attached to TC.")
	} else {
		// We piggy back on the primary path jump map
		jumpMapFd := fds[JumpFDRegularV4]

		tcName := SectionName(ap.Type, ap.ToOrFrom)
		tcFD, err := obj.GetProgramFd(tcName)
		if err != nil {
			return nil, fmt.Errorf("did not find %s program: %w", tcName, err)
		}

		mapName := bpf.JumpMapName()
		err = obj.UpdateJumpMapFd(mapName, tcFD, tcdefs.ProgIndexNoDebug)
		if err != nil {
			return nil, fmt.Errorf("error updating jump map with %s program: %w", tcName, err)
		}
		logCxt.WithError(err).Debug("Updated regular path jump")

		tcFD, err = objDebug.GetProgramFd(tcName)
		if err != nil {
			return nil, fmt.Errorf("did not find debug %s program: %w", tcName, err)
		}

		err = obj.UpdateJumpMapFd(mapName, tcFD, tcdefs.ProgIndexDebug)
		if err != nil {
			return nil, fmt.Errorf("error updating jump map with %s debug program: %w", tcName, err)
		}
		logCxt.WithError(err).Debug("Updated debug path")

		linkType := layers.LinkTypeEthernet

		if ap.Type == EpTypeL3Device {
			linkType = layers.LinkTypeIPv4
		}

		fexp := ap.LogFilter
		logFilter, err := filter.New(linkType, 64, fexp, bpf.MapFD(jumpMapFd))
		if err != nil {
			logCxt.WithError(err).Warnf("Failed to compile log filter program (%s) no logging for this ep.", ap.LogFilter)

			fexp := ""
			logFilter, err = filter.New(linkType, 64, fexp, bpf.MapFD(jumpMapFd))
			if err != nil {
				return nil, fmt.Errorf("failed to compile log filter all program: %w", err)
			}
		}
		filterFD, err := bpf.LoadBPFProgramFromInsns(logFilter, "calico_log_filter",
			"Apache-2.0", uint32(unix.BPF_PROG_TYPE_SCHED_CLS))
		if err != nil {
			return nil, fmt.Errorf("failed to load BPF log filter program: %w", err)
		}
		logCxt.WithError(err).Debugf("Loaded filter \"%s\"", fexp)

		defer filterFD.Close()

		progId, err = libbpf.AttachClassifier(int(filterFD), ap.Iface, string(ap.Hook))
		if err != nil {
			logCxt.Warn("Failed to attach BPF log filter")
			return nil, err
		}

		fd, err := objDebug.GetJumpMapFd(bpf.JumpMapName())
		if err != nil {
			return nil, fmt.Errorf("failed to get debug jump map fd: %w", err)
		}

		// Closing the object also closes the FD so duplicate it
		fd, err = syscall.Dup(fd)
		if err != nil {
			return nil, fmt.Errorf("failed to dup debug jump map fd: %w", err)
		}
		fds[JumpFDDebugV4] = bpf.MapFD(fd)

		logCxt.Info("Log filter program attached to TC.")
	}

	var progErrs []error
	for _, p := range progsToClean {
		log.WithField("prog", p).Debug("Cleaning up old calico program")
		attemptCleanup := func() error {
			_, err := ExecTC("filter", "del", "dev", ap.Iface, string(ap.Hook), "pref", p.pref, "handle", p.handle, "bpf")
			return err
		}
		err = attemptCleanup()
		if errors.Is(err, ErrInterrupted) {
			// This happens if the interface is deleted in the middle of calling tc.
			log.Debug("First cleanup hit 'Dump was interrupted', retrying (once).")
			err = attemptCleanup()
		}
		if errors.Is(err, ErrDeviceNotFound) {
			log.WithError(err).WithField("prog", p).Debug("Failed to clean up old calico program.")
			continue
		}
		if err != nil {
			log.WithError(err).WithField("prog", p).Warn("Failed to clean up old calico program.")
			progErrs = append(progErrs, err)
		}
	}

	if len(progErrs) != 0 {
		return nil, fmt.Errorf("failed to clean up one or more old calico programs: %v", progErrs)
	}

	// Store information of object in a json file so in future we can skip reattaching it.
	// If the process fails, the json file with the correct name and program details
	// is not stored on disk, and during Felix restarts the same program will be reattached
	// which leads to an unnecessary load time
	if err = bpf.RememberAttachedProg(ap, preCompiledBinary, progId); err != nil {
		logCxt.WithError(err).Error("Failed to record hash of BPF program on disk; ignoring.")
	}

	return fds, nil
}

func (ap *AttachPoint) patchLogPrefix(ifile, ofile string) error {
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

func (ap *AttachPoint) DetachPrograms() error {
	// We never detach TC programs, so this should not be called.
	ap.Log().Panic("DetachProgram is not implemented for TC")
	return nil
}

func ExecTC(args ...string) (out string, err error) {
	tcCmd := exec.Command("tc", args...)
	outBytes, err := tcCmd.Output()
	if err != nil {
		if isCannotFindDevice(err) {
			err = ErrDeviceNotFound
		} else if isDumpInterrupted(err) {
			err = ErrInterrupted
		} else if err2, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("failed to execute tc %v: rc=%v stderr=%v (%w)",
				args, err2.ExitCode(), string(err2.Stderr), err)
		} else {
			err = fmt.Errorf("failed to execute tc %v: %w", args, err)
		}
	}
	out = string(outBytes)
	return
}

func isCannotFindDevice(err error) bool {
	if errors.Is(err, ErrDeviceNotFound) {
		return true
	}
	if err, ok := err.(*exec.ExitError); ok {
		stderr := string(err.Stderr)
		if strings.Contains(stderr, "Cannot find device") ||
			strings.Contains(stderr, "No such device") {
			return true
		}
	}
	return false
}

func isDumpInterrupted(err error) bool {
	if errors.Is(err, ErrInterrupted) {
		return true
	}
	if err, ok := err.(*exec.ExitError); ok {
		stderr := string(err.Stderr)
		if strings.Contains(stderr, "Dump was interrupted") {
			return true
		}
	}
	return false
}

type AttachedProg struct {
	pref   string
	handle string
	id     string
	tag    string
}

func (ap AttachedProg) ID() string {
	return ap.id
}

func (ap *AttachPoint) ExpectedJumpMaps(fds []bpf.MapFD) bool {
	if len(fds) != 2 {
		return false
	}

	if ap.Debug() {
		return fds[JumpFDRegularV4] != 0 && fds[JumpFDDebugV4] != 0
	}

	return fds[JumpFDRegularV4] != 0 && fds[JumpFDDebugV4] == 0
}

func (ap *AttachPoint) ListAttachedPrograms() ([]AttachedProg, error) {
	out, err := ExecTC("filter", "show", "dev", ap.Iface, string(ap.Hook))
	if err != nil {
		return nil, fmt.Errorf("failed to list tc filters on interface: %w", err)
	}
	// Lines look like this; the section name always includes calico.
	// filter protocol all pref 49152 bpf chain 0 handle 0x1 to_hep_no_log.o:[calico_to_host_ep] direct-action not_in_hw id 821 tag ee402594f8f85ac3 jited
	var progsToClean []AttachedProg
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "calico") {
			continue
		}
		// find the pref and the handle
		if sm := prefHandleRe.FindStringSubmatch(line); len(sm) > 0 {
			p := AttachedProg{
				pref:   sm[1],
				handle: sm[2],
				id:     sm[3],
				tag:    sm[4],
			}
			log.WithField("prog", p).Debug("Found old calico program")
			progsToClean = append(progsToClean, p)
		}
	}
	log.WithField("progsToClean", progsToClean).Info("ListAttachedPrograms")
	return progsToClean, nil
}

// ProgramName returns the name of the program associated with this AttachPoint
func (ap *AttachPoint) ProgramName() string {
	return SectionName(ap.Type, ap.ToOrFrom)
}

var ErrNoTC = errors.New("no TC program attached")

// TODO: we should try to not get the program ID via 'tc' binary and rather
// we should use libbpf to obtain it.
func (ap *AttachPoint) programID() (int, error) {
	out, err := ExecTC("filter", "show", "dev", ap.IfaceName(), string(ap.Hook))
	if err != nil {
		return -1, fmt.Errorf("Failed to check interface %s program ID: %w", ap.Iface, err)
	}

	s := strings.Fields(string(out))
	for i := range s {
		// Example of output:
		//
		// filter protocol all pref 49152 bpf chain 0
		// filter protocol all pref 49152 bpf chain 0 handle 0x1 calico_from_hos:[61] direct-action not_in_hw id 61 tag 4add0302745d594c jited
		if s[i] == "id" && len(s) > i+1 {
			progID, err := strconv.Atoi(s[i+1])
			if err != nil {
				return -1, fmt.Errorf("Couldn't parse ID in 'tc filter' command err=%w out=\n%v", err, string(out))
			}

			return progID, nil
		}
	}
	return -1, fmt.Errorf("Couldn't find 'id <ID> in 'tc filter' command out=\n%v err=%w", string(out), ErrNoTC)
}

func (ap *AttachPoint) JumpMaps() ([]bpf.MapFD, error) {
	progID, err := ap.programID()
	if err != nil {
		return nil, err
	}

	fd, err := findJumpMap(progID, ap.Iface)
	if err != nil {
		return nil, err
	}

	return []bpf.MapFD{fd}, nil
}

func findJumpMap(progID int, ifaceName string) (mapFD bpf.MapFD, err error) {
	logCtx := log.WithField("progID", progID).WithField("iface", ifaceName)
	logCtx.Debugf("Looking up jump map")

	fd, err := bpf.GetMapFD(progID, unix.BPF_MAP_TYPE_PROG_ARRAY)

	if err != nil {
		return 0, fmt.Errorf("failed to find jump map for iface=%s progID=%d: %w", ifaceName, progID, err)
	}
	logCtx.WithField("fd", fd).Debug("Found jump map")

	return fd, nil
}

// FileName return the file the AttachPoint will load the program from
func (ap *AttachPoint) FileName(debugPath bool) string {
	ll := ap.LogLevel

	if ap.LogLevel == "debug-filters" {
		if !debugPath {
			ll = "off"
		} else {
			ll = "debug"
		}
	}

	return ProgFilename(ap.Type, ap.ToOrFrom, ap.ToHostDrop, ap.FIB, ap.DSR, ll, bpfutils.BTFEnabled)
}

func (ap *AttachPoint) IsAttached() (bool, error) {
	hasQ, err := HasQdisc(ap.Iface)
	if err != nil {
		return false, err
	}
	if !hasQ {
		return false, nil
	}
	progs, err := ap.ListAttachedPrograms()
	if err != nil {
		return false, err
	}
	return len(progs) > 0, nil
}

// tcDirRegex matches tc's and xdp's auto-created directory names, directories created when using libbpf
// so we can clean them up when removing maps without accidentally removing other user-created dirs..
var tcDirRegex = regexp.MustCompile(`([0-9a-f]{40})|(.*_(igr|egr|xdp))`)

// CleanUpMaps scans for cali_jump maps that are still pinned to the filesystem but no longer referenced by
// our BPF programs.
func CleanUpMaps() {
	// So that we serialise with AttachProgram()
	log.Debug("CleanUpMaps waiting for lock...")
	tcLock.Lock()
	defer tcLock.Unlock()
	log.Debug("CleanUpMaps got lock, cleaning up...")

	// Find the maps we care about by walking the BPF filesystem.
	mapIDToPath := make(map[int]string)
	err := filepath.Walk("/sys/fs/bpf/tc", func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(info.Name(), bpf.JumpMapName()) ||
			strings.HasPrefix(info.Name(), bpf.CountersMapName()) {
			log.WithField("path", p).Debug("Examining map")

			out, err := exec.Command("bpftool", "map", "show", "pinned", p).Output()
			if err != nil {
				log.WithError(err).Panic("Failed to show map")
			}
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
		XDP []struct {
			DevName string `json:"devname"`
			IfIndex int    `json:"ifindex"`
			Mode    string `json:"mode"`
			ID      int    `json:"id"`
		} `json:"xdp"`
	}
	err = json.Unmarshal(out, &attached)
	if err != nil {
		log.WithError(err).WithField("dump", string(out)).Error("Failed to parse list of attached BPF programs")
	}
	attachedProgs := set.New[int]()
	for _, prog := range attached[0].TC {
		log.WithField("prog", prog).Debug("Adding TC prog to attached set")
		attachedProgs.Add(prog.ID)
	}
	for _, prog := range attached[0].XDP {
		log.WithField("prog", prog).Debug("Adding XDP prog to attached set")
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
			log.WithField("mapID", id).WithField("prog", p).Debugf("Map is still in use: %v", mapIDToPath[id])
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
	emptyAutoDirs := set.New[string]()
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
			if emptyAutoDirs.Contains(dirPath) {
				log.WithField("path", dirPath).Debug("tc dir is not empty.")
				emptyAutoDirs.Discard(dirPath)
			}
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

	emptyAutoDirs.Iter(func(p string) error {
		log.WithField("path", p).Debug("Removing empty dir.")
		err := os.Remove(p)
		if err != nil {
			log.WithError(err).Error("Error while removing empty dir.")
		}
		return nil
	})
}

// EnsureQdisc makes sure that qdisc is attached to the given interface
func EnsureQdisc(ifaceName string) error {
	hasQdisc, err := HasQdisc(ifaceName)
	if err != nil {
		return err
	}
	if hasQdisc {
		log.WithField("iface", ifaceName).Debug("Already have a clsact qdisc on this interface")
		return nil
	}
	return libbpf.CreateQDisc(ifaceName)
}

func HasQdisc(ifaceName string) (bool, error) {
	out, err := ExecTC("qdisc", "show", "dev", ifaceName, "clsact")
	if err != nil {
		return false, fmt.Errorf("failed to check if interface '%s' has qdisc: %w", ifaceName, err)
	}
	if strings.Contains(out, "qdisc clsact") {
		return true, nil
	}
	return false, nil
}

// RemoveQdisc makes sure that there is no qdisc attached to the given interface
func RemoveQdisc(ifaceName string) error {
	hasQdisc, err := HasQdisc(ifaceName)
	if err != nil {
		return err
	}
	if !hasQdisc {
		return nil
	}

	// Remove the json files of the programs attached to the interface for both directions
	if err = bpf.ForgetAttachedProg(ifaceName, "ingress"); err != nil {
		return fmt.Errorf("Failed to remove runtime json file of ingress direction: %w", err)
	}
	if err = bpf.ForgetAttachedProg(ifaceName, "egress"); err != nil {
		return fmt.Errorf("Failed to remove runtime json file of egress direction: %w", err)
	}

	return libbpf.RemoveQDisc(ifaceName)
}

// Return a key that uniquely identifies this attach point, amongst all of the possible attach
// points associated with a single given interface.
func (ap *AttachPoint) JumpMapFDMapKey(family int, debug bool) string {
	return fmt.Sprintf(string(ap.Hook)+"-%d-debug-%v", family, debug)
}

func (ap *AttachPoint) IfaceName() string {
	return ap.Iface
}

func (ap *AttachPoint) HookName() bpf.Hook {
	return ap.Hook
}

func (ap *AttachPoint) Config() string {
	return fmt.Sprintf("%+v", ap)
}

func (ap *AttachPoint) ConfigureProgram(m *libbpf.Map) error {
	hostIP, err := convertIPToUint32(ap.HostIP)
	if err != nil {
		return err
	}
	vxlanPort := ap.VXLANPort
	if vxlanPort == 0 {
		vxlanPort = 4789
	}

	intfIP, err := convertIPToUint32(ap.IntfIP)
	if err != nil {
		return err
	}

	var flags uint32
	if ap.IPv6Enabled {
		flags |= libbpf.GlobalsIPv6Enabled
	}
	if ap.RPFStrictEnabled {
		flags |= libbpf.GlobalsRPFStrictEnabled
	}

	hostTunnelIP := hostIP

	if ap.HostTunnelIP != nil {
		hostTunnelIP, err = convertIPToUint32(ap.HostTunnelIP)
		if err != nil {
			return err
		}
	}

	return libbpf.TcSetGlobals(m, hostIP, intfIP,
		ap.ExtToServiceConnmark, ap.TunnelMTU, vxlanPort, ap.PSNATStart, ap.PSNATEnd, hostTunnelIP,
		flags, ap.WgPort, ap.NATin, ap.NATout,
	)
}

func (ap *AttachPoint) setMapSize(m *libbpf.Map) error {
	if size, ok := ap.MapSizes[m.Name()]; ok {
		return m.SetMapSize(size)
	}
	return nil
}

func (ap *AttachPoint) hasPolicyProg() bool {
	switch ap.Type {
	case EpTypeHost, EpTypeNAT, EpTypeLO:
		return false
	}

	return true
}

func (ap *AttachPoint) hasHostConflictProg() bool {
	switch ap.Type {
	case EpTypeWorkload:
		return false
	}

	return ap.ToOrFrom == ToEp
}

func (ap *AttachPoint) updateJumpMap(obj *libbpf.Obj) error {
	ipVersions := []string{"IPv4"}
	if ap.IPv6Enabled {
		ipVersions = append(ipVersions, "IPv6")
	}

	mapName := bpf.JumpMapName()

	for _, ipFamily := range ipVersions {
		for _, idx := range tcdefs.JumpMapIndexes[ipFamily] {
			if (idx == tcdefs.ProgIndexPolicy || idx == tcdefs.ProgIndexV6Policy) && !ap.hasPolicyProg() {
				continue
			}
			if idx == tcdefs.ProgIndexHostCtConflict && !ap.hasHostConflictProg() {
				continue
			}
			err := obj.UpdateJumpMap(mapName, tcdefs.ProgramNames[idx], idx)
			if err != nil {
				return fmt.Errorf("error updating %v %s program: %w", ipFamily, tcdefs.ProgramNames[idx], err)
			}
		}
	}

	return nil
}

func convertIPToUint32(ip net.IP) (uint32, error) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("ip addr nil")
	}
	return binary.LittleEndian.Uint32([]byte(ipv4)), nil
}
