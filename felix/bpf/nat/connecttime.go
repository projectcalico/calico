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

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
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

func installProgram(name, ipver, bpfMount, cgroupPath, logLevel string, maps ...bpf.Map) error {

	progPinDir := path.Join(bpfMount, "calico_connect4")
	_ = os.RemoveAll(progPinDir)

	var filename string

	if ipver == "6" {
		filename = path.Join(bpf.ObjectDir, ProgFileName(logLevel, 6))
	} else {
		filename = path.Join(bpf.ObjectDir, ProgFileName(logLevel, 4))
	}
	args := []string{"prog", "loadall", filename, progPinDir, "type", "cgroup/" + name + ipver}
	for _, m := range maps {
		args = append(args, "map", "name", m.GetName(), "pinned", m.Path())
	}

	cmd := exec.Command("bpftool", args...)
	log.WithField("args", cmd.Args).Info("About to run bpftool")
	progName := "calico_" + name + "_v" + ipver
	out, err := cmd.CombinedOutput()
	if err != nil {
		err = errors.Wrapf(err, "failed to load program %s", progName)
		goto out
	}

	cmd = exec.Command("bpftool", "cgroup", "attach", cgroupPath,
		name+ipver, "pinned", path.Join(progPinDir, progName))
	log.WithField("args", cmd.Args).Info("About to run bpftool")
	out, err = cmd.CombinedOutput()
	if err != nil {
		err = errors.Wrapf(err, "failed to attach program %s", progName)
		goto out
	}

out:
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("Failed install cgroup program.")
	}

	return nil
}

func InstallConnectTimeLoadBalancer(frontendMap, backendMap, rtMap bpf.Map, cgroupv2 string, logLevel string) error {
	bpfMount, err := bpf.MaybeMountBPFfs()
	if err != nil {
		log.WithError(err).Error("Failed to mount bpffs, unable to do connect-time load balancing")
		return err
	}

	cgroupPath, err := ensureCgroupPath(cgroupv2)
	if err != nil {
		return errors.Wrap(err, "failed to set-up cgroupv2")
	}

	repin := false
	if pm, ok := frontendMap.(*bpf.PinnedMap); ok {
		repin = pm.RepinningEnabled()
	}

	sendrecvMap := SendRecvMsgMap(&bpf.MapContext{
		RepinningEnabled: repin,
	})
	err = sendrecvMap.EnsureExists()
	if err != nil {
		return errors.WithMessage(err, "failed to create sendrecv BPF Map")
	}
	allNATsMap := AllNATsMsgMap(&bpf.MapContext{
		RepinningEnabled: repin,
	})
	err = allNATsMap.EnsureExists()
	if err != nil {
		return errors.WithMessage(err, "failed to create all-NATs BPF Map")
	}

	maps := []bpf.Map{frontendMap, backendMap, rtMap, sendrecvMap, allNATsMap}

	err = installProgram("connect", "4", bpfMount, cgroupPath, logLevel, maps...)
	if err != nil {
		return err
	}

	err = installProgram("sendmsg", "4", bpfMount, cgroupPath, logLevel, maps...)
	if err != nil {
		return err
	}

	err = installProgram("recvmsg", "4", bpfMount, cgroupPath, logLevel, maps...)
	if err != nil {
		return err
	}

	err = installProgram("sendmsg", "6", bpfMount, cgroupPath, logLevel)
	if err != nil {
		return err
	}

	err = installProgram("recvmsg", "6", bpfMount, cgroupPath, logLevel, sendrecvMap)
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

	switch ipver {
	case 4:
		return fmt.Sprintf("connect_time_%s_v4.o", logLevel)
	case 6:
		return fmt.Sprintf("connect_time_%s_v6.o", logLevel)
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
