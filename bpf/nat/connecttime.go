// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
)

func InstallConnectTimeLoadBalancer(frontendMap, backendMap bpf.Map, cgroupv2 string) error {
	args := []string{
		"-x",
		"c",
		"-D__KERNEL__",
		"-D__ASM_SYSREG_H",
		"-D__BPFTOOL_LOADER__",
		"-DCALI_LOG_LEVEL=CALI_LOG_LEVEL_DEBUG",
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
		"-c", "/code/bpf/cgroup/connect_balancer.c",
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
		log.WithError(err).Panic("Failed to write C file.")
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
	llc := exec.Command("llc", "-march=bpf", "-filetype=obj", "-o", "/tmp/calico_connect4.o")
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

	bpfMount, err := bpf.MaybeMountBPFfs()
	if err != nil {
		log.WithError(err).Error("Failed to mount bpffs, unable to do connect-time load balancing")
		return err
	}

	cgroupRoot, err := bpf.MaybeMountCgroupV2()
	if err != nil {
		log.WithError(err).Error("Failed to mount cgroupv2, unable to do connect-time load balancing")
		return err
	}

	progPinDir := path.Join(bpfMount, "calico_connect4")

	_ = os.RemoveAll(progPinDir)

	cmd := exec.Command("bpftool", "prog", "loadall", "/tmp/calico_connect4.o", progPinDir,
		"type", "cgroup/connect4",
		"map", "name", "cali_nat_v4", "pinned", frontendMap.Path(),
		"map", "name", "cali_natbe_v4", "pinned", backendMap.Path(),
	)
	log.WithField("args", cmd.Args).Info("About to run bpftool")
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("Failed to load connect-time load balancing program.")
		return err
	}

	cgroupPath := cgroupRoot
	if cgroupv2 != "" {
		cgroupPath = path.Clean(path.Join(cgroupRoot, cgroupv2))
		if !strings.HasPrefix(cgroupPath, path.Clean(cgroupRoot)) {
			log.Panic("Invalid cgroup path")
		}
		err = os.MkdirAll(cgroupPath, 0766)
		if err != nil {
			log.WithError(err).Panic("Failed to make cgroup")
		}
	}
	cmd = exec.Command("bpftool", "cgroup", "attach", cgroupPath, "connect4", "pinned", path.Join(progPinDir, "calico_connect_v4"))
	log.WithField("args", cmd.Args).Info("About to run bpftool")
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("Failed to attach connect-time load balancing program.")
		return err
	}

	return nil
}
