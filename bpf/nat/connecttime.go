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

package nat

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/tc"
)

type cgroupProgs struct {
	ID          int    `json:"id"`
	AttachType  string `json:"attach_type"`
	AttachFlags string `json:"attach_flags"`
	Name        string `json:"name"`
}

func RemoveConnectTimeLoadBalancer(cgroupv2 string) error {
	cgroupPath, err := ensureCgroupPath(cgroupv2)
	if err != nil {
		return errors.Wrap(err, "failed to set-up cgroupv2")
	}

	cmd := exec.Command("bpftool", "-j", "-p", "cgroup", "show", cgroupPath)
	log.WithField("args", cmd.Args).Info("Running bpftool to look up programs attached to cgroup")
	out, err := cmd.Output()
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("Failed to list BPF programs.")
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

	progPinDir := path.Join(bpfMount, "calico_connect4")

	_ = os.RemoveAll(progPinDir)

	filename := path.Join("/code/bpf/bin", ProgFileName(logLevel))
	cmd := exec.Command("bpftool", "prog", "loadall", filename, progPinDir,
		"type", "cgroup/connect4",
		"map", "name", frontendMap.GetName(), "pinned", frontendMap.Path(),
		"map", "name", backendMap.GetName(), "pinned", backendMap.Path(),
		"map", "name", rtMap.GetName(), "pinned", rtMap.Path(),
	)
	log.WithField("args", cmd.Args).Info("About to run bpftool")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("Failed to load connect-time load balancing program.")
		return err
	}

	cmd = exec.Command("bpftool", "cgroup", "attach", cgroupPath, "connect4", "pinned", path.Join(progPinDir, "calico_connect_v4"))
	log.WithField("args", cmd.Args).Info("About to run bpftool")
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("Failed to attach connect-time load balancing program.")
		return errors.Wrap(err, "failed to attach connect-time load balancing program")
	}

	return nil
}

func ProgFileName(logLevel string) string {
	logLevel = strings.ToLower(logLevel)
	if logLevel == "off" {
		logLevel = "no_log"
	}
	return fmt.Sprintf("connect_time_%s.o", logLevel)
}

func CompileConnectTimeLoadBalancer(logLevel string, outFile string) error {
	args := []string{
		"-x",
		"c",
		"-D__KERNEL__",
		"-D__ASM_SYSREG_H",
		"-D__BPFTOOL_LOADER__",
		"-DCALI_LOG_LEVEL=CALI_LOG_LEVEL_" + strings.ToUpper(logLevel),
		fmt.Sprintf("-DCALI_COMPILE_FLAGS=%d", tc.CompileFlagCgroup),
		"-DCALI_LOG_PFX=CGROUP",
		"-Wno-unused-value",
		"-Wno-pointer-sign",
		"-Wno-compare-distinct-pointer-types",
		"-Wunused",
		"-Wall",
		"-Werror",
		"-fno-stack-protector",
		"-O2",
		"-emit-llvm",
		"-c", "bpf/cgroup/connect_balancer.c",
		"-o", "-",
	}

	clang := exec.Command("clang", args...)
	clangStdout, err := clang.StdoutPipe()
	if err != nil {
		return err
	}
	clangStderr, err := clang.StderrPipe()
	if err != nil {
		return err
	}
	err = clang.Start()
	if err != nil {
		log.WithError(err).Panic("Failed to start clang.")
		return err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(clangStderr)
		for scanner.Scan() {
			log.Warnf("clang stderr: %s", scanner.Text())
		}
		if err != nil {
			log.WithError(err).Error("Error while reading clang stderr")
		}
	}()
	llc := exec.Command("llc", "-march=bpf", "-filetype=obj", "-o", outFile)
	llc.Stdin = clangStdout
	out, err := llc.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("out", string(out)).Error("Failed to compile C program (llc step)")
		return err
	}
	err = clang.Wait()
	if err != nil {
		log.WithError(err).Error("Clang failed.")
		return err
	}
	wg.Wait()

	return nil
}

func ensureCgroupPath(cgroupv2 string) (string, error) {
	cgroupRoot, err := bpf.MaybeMountCgroupV2()
	if err != nil {
		log.WithError(err).Error("Failed to mount cgroupv2, unable to do connect-time load balancing")
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
