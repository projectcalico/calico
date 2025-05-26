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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/bpfutils"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/utils"
)

const (
	ProgIndexCTLBConnectV6 = iota
	ProgIndexCTLBSendV6
	ProgIndexCTLBRecvV6
)

var ctlbProgToIndex = map[string]int{
	"calico_connect_v6": ProgIndexCTLBConnectV6,
	"calico_sendmsg_v6": ProgIndexCTLBSendV6,
	"calico_recvmsg_v6": ProgIndexCTLBRecvV6,
}

var ProgramsMapParameters = maps.MapParameters{
	Type:       "prog_array",
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: 3,
	Name:       "cali_ctlb_progs",
}

func newProgramsMap() maps.Map {
	return maps.NewPinnedMap(ProgramsMapParameters)
}

func RemoveConnectTimeLoadBalancer(cgroupv2 string) error {
	if os.Getenv("FELIX_DebugSkipCTLBCleanup") == "true" {
		log.Info("FV special case: skipping CTLB cleanup")
		return nil
	}

	bpfMount, err := utils.MaybeMountBPFfs()
	if err != nil {
		return fmt.Errorf("failed to mount bpffs: %w", err)
	}

	pinDir := path.Join(bpfMount, bpfdefs.CtlbPinDir)
	defer bpf.CleanUpCalicoPins(pinDir)
	ctlbProgsMap := newProgramsMap()
	defer os.Remove(ctlbProgsMap.Path())

	if err := detachCtlbPrograms(pinDir, cgroupv2); err != nil {
		return err
	}
	bpf.CleanUpCalicoPins(pinDir)
	return nil
}

func detachCtlbPrograms(pinDir, cgroupv2 string) error {
	numLinksDetached := 0
	err := filepath.Walk(pinDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(info.Name(), "cali_") || strings.HasPrefix(info.Name(), "calico_") {
			numLinksDetached++
			log.WithField("path", path).Debug("Detaching pinned link")
			link, err := libbpf.OpenLink(path)
			if err != nil {
				log.WithField("path", path).Error("Error opening link")
				return err
			}
			defer link.Close()
			err = link.Detach()
			if err != nil {
				log.WithField("path", path).Error("Error detaching link")
				return err
			}
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		log.WithError(err).Error("error detaching link")
		return err
	}
	if numLinksDetached == 0 {
		return detachLegacyCtlb(cgroupv2)
	}
	return nil
}

func detachLegacyCtlb(cgroupv2 string) error {
	cgroupPath, err := ensureCgroupPath(cgroupv2)
	if err != nil {
		return fmt.Errorf("failed to set-up cgroupv2: %w", err)
	}
	return libbpf.DetachCTLBProgramsLegacy(cgroupPath)
}

func loadProgram(logLevel, ipver string, udpNotSeen time.Duration, excludeUDP bool) (*libbpf.Obj, error) {
	filename := path.Join(bpfdefs.ObjectDir, ProgFileName(logLevel, ipver))
	obj, err := bpf.LoadObject(filename, &libbpf.CTLBGlobalData{UDPNotSeen: udpNotSeen, ExcludeUDP: excludeUDP})
	if err != nil {
		return nil, fmt.Errorf("error loading %s:%w", filename, err)
	}
	return obj, nil
}

func attachProgram(name, ipver, bpfMount, cgroupPath string, udpNotSeen time.Duration, excludeUDP bool, obj *libbpf.Obj, legacy bool) error {
	progName := "calico_" + name + "_v" + ipver
	progPinPath := path.Join(bpfMount, progName)
	if _, err := os.Stat(progPinPath); err == nil {
		link, err := libbpf.OpenLink(progPinPath)
		if err != nil {
			return fmt.Errorf("error opening link %s : %w", progPinPath, err)
		}
		defer link.Close()
		if err := link.Update(obj, progName); err != nil {
			return fmt.Errorf("error updating program %s : %w", progName, err)
		}
		return nil
	}

	// Used only for UT to test legacy way to attach.
	if legacy {
		err := obj.AttachCGroupLegacy(cgroupPath, progName)
		if err != nil {
			return fmt.Errorf("failed to attach program %s: %w", progName, err)
		}
		return nil
	}

	// Tries non-legacy and fallsback to legacy if non-legacy fails.
	link, err := obj.AttachCGroup(cgroupPath, progName)
	if err != nil {
		err = obj.AttachCGroupLegacy(cgroupPath, progName)
		if err != nil {
			return fmt.Errorf("failed to attach program %s: %w", progName, err)
		}
		link = nil
	} else if link != nil {
		defer link.Close()
		err := link.Pin(progPinPath)
		if err != nil {
			return fmt.Errorf("failed to pin program %s:%w", progName, err)
		}
	}
	log.WithFields(log.Fields{"program": progName, "cgroup": cgroupPath}).Info("Loaded cgroup program")
	return nil
}

func updateCTLBJumpMap(jumpMap maps.Map, obj *libbpf.Obj) error {
	for prog, index := range ctlbProgToIndex {
		fd, err := obj.ProgramFD(prog)
		if err != nil {
			return fmt.Errorf("failed to get prog FD. Program = %s: %w", prog, err)
		}

		err = maps.UpdateMapEntry(jumpMap.MapFD(), jump.Key(index), jump.Value(uint32(fd)))
		if err != nil {
			log.WithError(err).Errorf("Failed to update %s map at index %d", prog, index)
			return err
		}
	}
	return nil
}

func installCTLB(ipv4Enabled, ipv6Enabled bool, cgroupv2 string, logLevel string, udpNotSeen time.Duration, excludeUDP, legacy bool) error {
	bpfMount, err := utils.MaybeMountBPFfs()
	if err != nil {
		log.WithError(err).Error("Failed to mount bpffs, unable to do connect-time load balancing")
		return err
	}

	pinDir := path.Join(bpfMount, bpfdefs.CtlbPinDir)
	if err = os.MkdirAll(pinDir, 0700); err != nil {
		log.WithError(err).Error("Failed to create pin dir, unable to do connect-time load balancing")
		return err
	}

	cgroupPath, err := ensureCgroupPath(cgroupv2)
	if err != nil {
		return fmt.Errorf("failed to set-up cgroupv2: %w", err)
	}

	ctlbProgsMap := newProgramsMap()
	var v4Obj, v46Obj, v6Obj *libbpf.Obj

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
		err = attachProgram("connect", "4", pinDir, cgroupPath, udpNotSeen, excludeUDP, v4Obj, legacy)
		if err != nil {
			return err
		}
		err = attachProgram("connect", "46", pinDir, cgroupPath, udpNotSeen, excludeUDP, v46Obj, legacy)
		if err != nil {
			return err
		}

		if !excludeUDP {
			err = attachProgram("sendmsg", "4", pinDir, cgroupPath, udpNotSeen, false, v4Obj, legacy)
			if err != nil {
				return err
			}

			err = attachProgram("recvmsg", "4", pinDir, cgroupPath, udpNotSeen, false, v4Obj, legacy)
			if err != nil {
				return err
			}

			err = attachProgram("sendmsg", "46", pinDir, cgroupPath, udpNotSeen, false, v46Obj, legacy)
			if err != nil {
				return err
			}

			err = attachProgram("recvmsg", "46", pinDir, cgroupPath, udpNotSeen, false, v46Obj, legacy)
			if err != nil {
				return err
			}
		}
		if !ipv6Enabled {
			//delete the jump map
			os.Remove(ctlbProgsMap.Path())
		}
	}
	// Load the v6 CTLB program.
	if ipv6Enabled {
		v6Obj, err = loadProgram(logLevel, "6", udpNotSeen, excludeUDP)
		if err != nil {
			return err
		}
		defer v6Obj.Close()
		// If dual-stack, populate the jump maps with v6 ctlb programs.
		if ipv4Enabled {
			if err := ctlbProgsMap.EnsureExists(); err != nil {
				log.WithError(err).Error("Failed to create CTLB programs maps")
				return err
			}
			err = updateCTLBJumpMap(ctlbProgsMap, v6Obj)
			if err != nil {
				return err
			}
		} else {
			err = attachProgram("connect", "6", bpfMount, cgroupPath, udpNotSeen, excludeUDP, v6Obj, legacy)
			if err != nil {
				return err
			}

			if !excludeUDP {
				err = attachProgram("sendmsg", "6", bpfMount, cgroupPath, udpNotSeen, false, v6Obj, legacy)
				if err != nil {
					return err
				}

				err = attachProgram("recvmsg", "6", bpfMount, cgroupPath, udpNotSeen, false, v6Obj, legacy)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func InstallConnectTimeLoadBalancer(ipv4Enabled, ipv6Enabled bool, cgroupv2 string, logLevel string, udpNotSeen time.Duration, excludeUDP bool) error {
	return installCTLB(ipv4Enabled, ipv6Enabled, cgroupv2, logLevel, udpNotSeen, excludeUDP, false)
}

func InstallConnectTimeLoadBalancerLegacy(ipv4Enabled, ipv6Enabled bool, cgroupv2 string, logLevel string, udpNotSeen time.Duration, excludeUDP bool) error {
	return installCTLB(ipv4Enabled, ipv6Enabled, cgroupv2, logLevel, udpNotSeen, excludeUDP, true)
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

	return fmt.Sprintf("connect_balancer_%s%s_v%s.o", logLevel, btf, ipver)
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
			return "", fmt.Errorf("failed to create cgroup: %w", err)
		}
	}
	return cgroupPath, nil
}
