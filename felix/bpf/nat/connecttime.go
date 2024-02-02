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

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/bpfutils"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/utils"
)

type cgroupProgs struct {
	ID          int    `json:"id"`
	AttachType  string `json:"attach_type"`
	AttachFlags string `json:"attach_flags"`
	Name        string `json:"name"`
}

const (
	CTLBConnectV6 = iota
	CTLBSendV6
	CTLBRecvV6
)

var ProgramsMapParameters = maps.MapParameters{
	Type:       "prog_array",
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: 3,
	Name:       "cali_ctlb_progs",
}

func NewProgramsMap() maps.Map {
	return maps.NewPinnedMap(ProgramsMapParameters)
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
	ctlbProgsMap := NewProgramsMap()
	os.Remove(ctlbProgsMap.Path())

	return nil
}

func loadProgram(logLevel, ipver string, udpNotSeen time.Duration, excludeUDP bool) (*libbpf.Obj, error) {
	filename := path.Join(bpfdefs.ObjectDir, ProgFileName(logLevel, ipver))

	log.WithField("filename", filename).Debug("Loading object file")
	obj, err := libbpf.OpenObject(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s: %w", filename, err)
	}

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		// In case of global variables, libbpf creates an internal map <prog_name>.rodata
		// The values are read only for the BPF programs, but can be set to a value from
		// userspace before the program is loaded.
		mapName := m.Name()
		if m.IsMapInternal() {
			if strings.HasPrefix(mapName, ".rodata") {
				continue
			}
			if err := libbpf.CTLBSetGlobals(m, udpNotSeen, excludeUDP); err != nil {
				return nil, fmt.Errorf("error setting globals: %w", err)
			}
			continue
		}

		if size := maps.Size(mapName); size != 0 {
			err := m.SetSize(size)
			if err != nil {
				return nil, fmt.Errorf("error set map size %s: %w", m.Name(), err)
			}
		}
		if err := m.SetPinPath(path.Join(bpfdefs.GlobalPinDir, mapName)); err != nil {
			return nil, fmt.Errorf("error pinning map %s: %w", mapName, err)
		}
		log.WithFields(log.Fields{"obj": filename, "map": mapName}).Debug("Pinned map")
	}

	if err := obj.Load(); err != nil {
		return nil, fmt.Errorf("error loading object %s: %w", filename, err)
	}
	return obj, nil
}

func attachProgram(name, ipver, bpfMount, cgroupPath string, udpNotSeen time.Duration, excludeUDP bool, obj *libbpf.Obj) error {

	progPinDir := path.Join(bpfMount, "calico_connect4")
	_ = os.RemoveAll(progPinDir)

	progName := "calico_" + name + "_v" + ipver

	// N.B. no need to remember the link since we are never going to detach
	// these programs unless Felix restarts.
	if _, err := obj.AttachCGroup(cgroupPath, progName); err != nil {
		return fmt.Errorf("failed to attach program %s: %w", progName, err)
	}

	log.WithFields(log.Fields{"program": progName, "cgroup": cgroupPath}).Info("Loaded cgroup program")

	return nil
}

func updateCTLBJumpMap(name string, obj *libbpf.Obj) error {
	err := obj.UpdateJumpMap(name, "calico_connect_v6", CTLBConnectV6)
	if err != nil {
		log.WithError(err).Errorf("Failed to update %s map at index %d", name, CTLBConnectV6)
		return err
	}

	err = obj.UpdateJumpMap(name, "calico_sendmsg_v6", CTLBSendV6)
	if err != nil {
		log.WithError(err).Errorf("Failed to update %s map at index %d", name, CTLBSendV6)
		return err
	}

	err = obj.UpdateJumpMap(name, "calico_recvmsg_v6", CTLBRecvV6)
	if err != nil {
		log.WithError(err).Errorf("Failed to update %s map at index %d", name, CTLBRecvV6)
		return err
	}
	return nil
}

func InstallConnectTimeLoadBalancer(ipv4Enabled, ipv6Enabled bool, cgroupv2 string, logLevel string, udpNotSeen time.Duration, excludeUDP bool) error {

	bpfMount, err := utils.MaybeMountBPFfs()
	if err != nil {
		log.WithError(err).Error("Failed to mount bpffs, unable to do connect-time load balancing")
		return err
	}

	cgroupPath, err := ensureCgroupPath(cgroupv2)
	if err != nil {
		return errors.Wrap(err, "failed to set-up cgroupv2")
	}

	ctlbProgsMap := NewProgramsMap()
	var v4Obj, v46Obj, v6Obj *libbpf.Obj

	// Load the v6 CTLB program.
	if ipv6Enabled {
		v6Obj, err = loadProgram(logLevel, "6", udpNotSeen, excludeUDP)
		if err != nil {
			return err
		}
		defer v6Obj.Close()
	}

	// Load and attach v4, v46 CTLB program.
	if ipv4Enabled {
		v4Obj, err = loadProgram(logLevel, "4", udpNotSeen, excludeUDP)
		if err != nil {
			return err
		}
		defer v4Obj.Close()

		v46Obj, err = loadProgram(logLevel, "46", udpNotSeen, excludeUDP)
		if err != nil {
			return err
		}
		defer v46Obj.Close()
		err = attachProgram("connect", "4", bpfMount, cgroupPath, udpNotSeen, excludeUDP, v4Obj)
		if err != nil {
			return err
		}
		err = attachProgram("connect", "46", bpfMount, cgroupPath, udpNotSeen, excludeUDP, v46Obj)
		if err != nil {
			return err
		}

		if !excludeUDP {
			err = attachProgram("sendmsg", "4", bpfMount, cgroupPath, udpNotSeen, false, v4Obj)
			if err != nil {
				return err
			}

			err = attachProgram("recvmsg", "4", bpfMount, cgroupPath, udpNotSeen, false, v4Obj)
			if err != nil {
				return err
			}

			err = attachProgram("sendmsg", "46", bpfMount, cgroupPath, udpNotSeen, false, v46Obj)
			if err != nil {
				return err
			}

			err = attachProgram("recvmsg", "46", bpfMount, cgroupPath, udpNotSeen, false, v46Obj)
			if err != nil {
				return err
			}
		}
		// If dual-stack, populate the jump maps with v6 ctlb programs.
		if v6Obj != nil {
			if err := ctlbProgsMap.EnsureExists(); err != nil {
				log.WithError(err).Error("Failed to create CTLB programs maps")
				return err
			}
			err = updateCTLBJumpMap(ctlbProgsMap.GetName(), v6Obj)
			if err != nil {
				return err
			}
		} else {
			//delete the jump map
			os.Remove(ctlbProgsMap.Path())
		}
		return nil
	}
	err = attachProgram("connect", "6", bpfMount, cgroupPath, udpNotSeen, excludeUDP, v6Obj)
	if err != nil {
		return err
	}

	if !excludeUDP {
		err = attachProgram("sendmsg", "6", bpfMount, cgroupPath, udpNotSeen, false, v6Obj)
		if err != nil {
			return err
		}

		err = attachProgram("recvmsg", "6", bpfMount, cgroupPath, udpNotSeen, false, v6Obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func ProgFileName(logLevel string, ipver string) string {
	logLevel = strings.ToLower(logLevel)
	if logLevel == "off" {
		logLevel = "no_log"
	}

	btf := ""
	if bpfutils.BTFEnabled {
		btf = "_co-re"
	}

	return fmt.Sprintf("connect_time_%s_v%s%s.o", logLevel, ipver, btf)
}

func ensureCgroupPath(cgroupv2 string) (string, error) {
	cgroupRoot, err := utils.MaybeMountCgroupV2()
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
