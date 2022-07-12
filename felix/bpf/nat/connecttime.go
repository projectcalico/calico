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

package nat

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfutils"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
)

type cgroupProgs struct {
	ID          int    `json:"id"`
	AttachType  string `json:"attach_type"`
	AttachFlags string `json:"attach_flags"`
	Name        string `json:"name"`
}

func RemoveConnectTimeLoadBalancer(cgroupv2 string) error {
	if os.Getenv("FELIX_DebugSkipCTLBCleanup") == "true" {
		log.Info("FV special case: skipping CTLB cleanup")
		return nil
	}

	cgroupPath, err := ensureCgroupPath(cgroupv2)
	if err != nil {
		return errors.Wrap(err, "failed to set-up cgroupv2")
	}

	cmd := exec.Command("bpftool", "-j", "-p", "cgroup", "show", cgroupPath)
	log.WithField("args", cmd.Args).Info("Running bpftool to look up programs attached to cgroup")
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		log.WithError(err).WithField("output", string(out)).Info(
			"Failed to list BPF programs.  Assuming not supported/nothing to clean up.")
		return err
	}

	var progs []cgroupProgs

	err = json.Unmarshal(out, &progs)
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("BPF program list not json.")
		return err
	}

	for _, p := range progs {
		if !strings.HasPrefix(p.Name, "cali_") {
			continue
		}

		cmd = exec.Command("bpftool", "cgroup", "detach", cgroupPath, p.AttachType, "id", strconv.Itoa(p.ID))
		log.WithField("args", cmd.Args).Info("Running bpftool to detach program")
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.WithError(err).WithField("output", string(out)).Error(
				"Failed to detach connect-time load balancing program.")
			return err
		}
	}

	bpf.CleanUpCalicoPins("/sys/fs/bpf/calico_connect4")

	return nil
}

func installProgram(name, ipver, bpfMount, cgroupPath, logLevel string, udpNotSeen time.Duration, maxEntries map[string]uint32) error {

	progPinDir := path.Join(bpfMount, "calico_connect4")
	_ = os.RemoveAll(progPinDir)

	var filename string
	if ipver == "6" {
		filename = path.Join(bpf.ObjectDir, ProgFileName(logLevel, 6))
	} else {
		filename = path.Join(bpf.ObjectDir, ProgFileName(logLevel, 4))
	}

	progName := "calico_" + name + "_v" + ipver

	log.WithField("filename", filename).Debug("Loading object file")
	obj, err := libbpf.OpenObject(filename, unix.BPF_PROG_TYPE_CGROUP_SOCK)
	if err != nil {
		return fmt.Errorf("failed to load program %s from %s: %w", progName, filename, err)
	}
	defer obj.Close()

	baseDir := "/sys/fs/bpf/tc/globals/"
	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		// In case of global variables, libbpf creates an internal map <prog_name>.rodata
		// The values are read only for the BPF programs, but can be set to a value from
		// userspace before the program is loaded.
		if m.IsMapInternal() {
			if err := libbpf.CTLBSetGlobals(m, udpNotSeen); err != nil {
				return fmt.Errorf("error setting globals: %w", err)
			}
			continue
		}

		if size, ok := maxEntries[m.Name()]; ok {
			err := m.SetMapSize(size)
			if err != nil {
				return fmt.Errorf("error set map size %s: %w", m.Name(), err)
			}
		}
		pinPath := baseDir + m.Name()
		if err := m.SetPinPath(pinPath); err != nil {
			return fmt.Errorf("error pinning map %s: %w", m.Name(), err)
		}
		log.WithFields(log.Fields{"program": progName, "map": m.Name()}).Debug("Pinned map")
	}

	if err := obj.Load(); err != nil {
		return fmt.Errorf("error loading program %s: %w", progName, err)
	}

	// N.B. no need to remember the link since we are never going to detach
	// these programs unless Felix restarts.
	if _, err := obj.AttachCGroup(cgroupPath, progName); err != nil {
		return fmt.Errorf("failed to attach program %s: %w", progName, err)
	}

	log.WithFields(log.Fields{"program": progName, "cgroup": cgroupPath}).Info("Loaded cgroup program")

	return nil
}

func InstallConnectTimeLoadBalancer(cgroupv2 string, logLevel string, udpNotSeen time.Duration, bpfMc *bpf.MapContext) error {
	bpfMount, err := bpf.MaybeMountBPFfs()
	if err != nil {
		log.WithError(err).Error("Failed to mount bpffs, unable to do connect-time load balancing")
		return err
	}

	cgroupPath, err := ensureCgroupPath(cgroupv2)
	if err != nil {
		return errors.Wrap(err, "failed to set-up cgroupv2")
	}

	err = installProgram("connect", "4", bpfMount, cgroupPath, logLevel, udpNotSeen, bpfMc.MapSizes)
	if err != nil {
		return err
	}

	err = installProgram("sendmsg", "4", bpfMount, cgroupPath, logLevel, udpNotSeen, bpfMc.MapSizes)
	if err != nil {
		return err
	}

	err = installProgram("recvmsg", "4", bpfMount, cgroupPath, logLevel, udpNotSeen, bpfMc.MapSizes)
	if err != nil {
		return err
	}

	err = installProgram("sendmsg", "6", bpfMount, cgroupPath, logLevel, udpNotSeen, bpfMc.MapSizes)
	if err != nil {
		return err
	}

	err = installProgram("recvmsg", "6", bpfMount, cgroupPath, logLevel, udpNotSeen, bpfMc.MapSizes)
	if err != nil {
		return err
	}

	return nil
}

func ProgFileName(logLevel string, ipver int) string {
	logLevel = strings.ToLower(logLevel)
	if logLevel == "off" {
		logLevel = "no_log"
	}

	btf := ""
	if bpfutils.BTFEnabled {
		btf = "_co-re"
	}

	switch ipver {
	case 4:
		return fmt.Sprintf("connect_time_%s_v4%s.o", logLevel, btf)
	case 6:
		return fmt.Sprintf("connect_time_%s_v6%s.o", logLevel, btf)
	}

	log.WithField("ipver", ipver).Fatal("Invalid IP version")
	return ""
}

func ensureCgroupPath(cgroupv2 string) (string, error) {
	cgroupRoot, err := bpf.MaybeMountCgroupV2()
	if err != nil {
		return "", err
	}
	cgroupPath := cgroupRoot
	if cgroupv2 != "" {
		cgroupPath = path.Clean(path.Join(cgroupRoot, cgroupv2))
		if !strings.HasPrefix(cgroupPath, path.Clean(cgroupRoot)) {
			log.Panic("Invalid cgroup path outside the root")
		}
		err = os.MkdirAll(cgroupPath, 0766)
		if err != nil {
			log.WithError(err).Error("Failed to make cgroup")
			return "", errors.Wrap(err, "failed to create cgroup")
		}
	}
	return cgroupPath, nil
}
