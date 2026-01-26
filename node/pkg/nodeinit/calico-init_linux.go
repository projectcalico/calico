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

// Package nodeinit contains the calico-node -init command, which is intended to be run from
// an init container to do privileged pre-flight initialisation.  At present, it mounts
// the BPF filesystem so it is only useful for BPF mode.
package nodeinit

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/maps"
	bpfnat "github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup"
)

type IPPort struct {
	IP     net.IP
	Port   uint16
	IsIPv4 bool
}

func Run(bestEffort bool) {
	// Check $CALICO_STARTUP_LOGLEVEL to capture early log statements
	startup.ConfigureLogging()

	err := ensureBPFFilesystem()
	if err != nil {
		logrus.WithError(err).Error("Failed to mount BPF filesystem.")
		if !bestEffort {
			os.Exit(2) // Using 2 just to distinguish from the usage error case.
		}
	}

	err = ensureCgroupV2Filesystem()
	if err != nil {
		logrus.WithError(err).Error("Failed to mount cgroup2 filesystem.")
		if !bestEffort {
			os.Exit(3)
		}
	}
	serviceAddr := os.Getenv("KUBERNETES_SERVICE_IPS_PORTS")
	endpointAddrs := os.Getenv("KUBERNETES_APISERVER_ENDPOINTS")
	if serviceAddr != "" && endpointAddrs != "" {
		_, err = initBPFNetwork(serviceAddr, endpointAddrs)
		if err != nil {
			logrus.WithError(err).Error("Failed to initialize BPF network.")
			if !bestEffort {
				os.Exit(4)
			}
		}
	}
}

func initBPFNetwork(serviceAddr, endpointAddrs string) (*bpfmap.Maps, error) {
	logrus.Info("Initializing BPF network.")

	servicesIPPort, err := parseCommaSeparatedIPPorts(serviceAddr)
	if err != nil {
		return nil, err
	}
	endpointsIPPort, err := parseCommaSeparatedIPPorts(endpointAddrs)
	if err != nil {
		return nil, err
	}

	hasIPv4, hasIPv6 := hasIPv4AndIPv6(servicesIPPort)

	bpfMaps, err := bpfmap.CreateBPFMaps(hasIPv6)
	if err != nil {
		logrus.WithError(err).Error("Failed to create bpf maps.")
		return nil, err
	}

	id := uint32(0)
	countIPv4, countIPv6 := 0, 0
	for _, endpoint := range endpointsIPPort {
		if endpoint.IsIPv4 {
			err = updateBackendMap(bpfMaps.V4.BackendMap, bpfnat.NewNATBackendKey, bpfnat.NewNATBackendValueIntf, endpoint, id, uint32(countIPv4))
			countIPv4++
		} else {
			err = updateBackendMap(bpfMaps.V6.BackendMap, bpfnat.NewNATBackendKeyV6, bpfnat.NewNATBackendValueV6Intf, endpoint, id, uint32(countIPv6))
			countIPv6++
		}
		if err != nil {
			logrus.WithError(err).Error("Failed to add IP set entry in the backend map.")
			return nil, err
		}
	}

	for _, service := range servicesIPPort {
		if service.IsIPv4 {
			err = updateFrontendMap(bpfMaps.V4.FrontendMap, bpfnat.NewNATKeyIntf, bpfnat.NewNATValue, service, id, uint32(countIPv4))
		} else {
			err = updateFrontendMap(bpfMaps.V6.FrontendMap, bpfnat.NewNATKeyV6Intf, bpfnat.NewNATValueV6, service, id, uint32(countIPv6))
		}
		if err != nil {
			logrus.WithError(err).Error("Failed to add IP set entry in the frontend map.")
			return nil, err
		}
	}
	logrus.Infof("Included kubernetes service (%s) and endpoints (%s) in the Nat Maps.", serviceAddr, endpointAddrs)

	// Activate the connect-time load balancer.
	err = bpfnat.InstallConnectTimeLoadBalancer(hasIPv4, hasIPv6, "", "debug", 60*time.Second, true, bpfMaps.CommonMaps.CTLBProgramsMaps)
	if err != nil {
		logrus.WithError(err).Error("Failed to attach connect-time load balancer.")
		return nil, err
	}
	logrus.Info("Connect-time load balancer enabled.")

	return bpfMaps, nil
}

func updateBackendMap(backendMap maps.Map, newNATKeyFn func(uint32, uint32) bpfnat.BackendKey, newNATValueFn func(net.IP, uint16) bpfnat.BackendValueInterface, endpoint IPPort, id uint32, ordinal uint32) error {
	return backendMap.Update(
		newNATKeyFn(id, ordinal).AsBytes(),
		newNATValueFn(endpoint.IP, endpoint.Port).AsBytes(),
	)
}

func updateFrontendMap(frontendMap maps.Map, newNATKeyFn func(net.IP, uint16, uint8) bpfnat.FrontendKeyInterface, newNATValueFn func(uint32, uint32, uint32, uint32) bpfnat.FrontendValue, service IPPort, id uint32, count uint32) error {
	return frontendMap.Update(
		newNATKeyFn(service.IP, service.Port, uint8(layers.IPProtocolTCP)).AsBytes(),
		newNATValueFn(id, count, 0, 0).AsBytes(),
	)
}

// parseIPPort parses a string in the format "IP:Port" (IPv4 or IPv6).
func parseIPPort(addr string) (IPPort, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return IPPort{}, fmt.Errorf("invalid address format: %v", err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return IPPort{}, fmt.Errorf("invalid IP address: %s", host)
	}

	portInt, err := strconv.Atoi(portStr)
	if err != nil || portInt < 0 || portInt > 65535 {
		return IPPort{}, fmt.Errorf("invalid port: %s", portStr)
	}

	return IPPort{
		IP:     ip,
		Port:   uint16(portInt),
		IsIPv4: ip.To4() != nil,
	}, nil
}

// parseCommaSeparatedIPPorts parses a comma-separated list of "IP:Port" strings.
func parseCommaSeparatedIPPorts(input string) ([]IPPort, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("input string is empty")
	}

	entries := strings.Split(input, ",")
	results := make([]IPPort, 0, len(entries))

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		ipPort, err := parseIPPort(entry)
		if err != nil {
			return nil, fmt.Errorf("failed to parse entry %s: %v", entry, err)
		}
		results = append(results, ipPort)
	}

	return results, nil
}

// hasIPv4AndIPv6 checks if the IPPort slice contains at least one IPv4 and/or IPv6 address.
func hasIPv4AndIPv6(addrs []IPPort) (bool, bool) {
	var hasIPv4, hasIPv6 bool
	for _, addr := range addrs {
		if addr.IsIPv4 {
			hasIPv4 = true
		} else {
			hasIPv6 = true
		}
		// Early return if both are found
		if hasIPv4 && hasIPv6 {
			return hasIPv4, hasIPv6
		}
	}
	return hasIPv4, hasIPv6
}

func ensureBPFFilesystem() error {
	// Check if the BPF filesystem is mounted at the expected location.
	logrus.Info("Checking if BPF filesystem is mounted.")
	mounts, err := os.Open("/proc/mounts")
	if err != nil {
		return fmt.Errorf("failed to open /proc/mounts: %w", err)
	}
	scanner := bufio.NewScanner(mounts)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), " ")
		mountPoint := parts[1]
		fs := parts[2]

		if mountPoint == bpfdefs.DefaultBPFfsPath && fs == "bpf" {
			logrus.Info("BPF filesystem is mounted.")
			return nil
		}
	}
	if scanner.Err() != nil {
		return fmt.Errorf("failed to read /proc/mounts: %w", scanner.Err())
	}

	// If we get here, the BPF filesystem is not mounted.  Try to mount it.
	logrus.Info("BPF filesystem is not mounted. Trying to mount it...")
	err = syscall.Mount(bpfdefs.DefaultBPFfsPath, bpfdefs.DefaultBPFfsPath, "bpf", 0, "")
	if err != nil {
		return fmt.Errorf("failed to mount BPF filesystem: %w", err)
	}
	logrus.Info("Mounted BPF filesystem.")
	return nil
}

// ensureCgroupV2Filesystem() enters the cgroup and mount namespace of the process
// with PID 1 running on a host to allow felix running in calico-node to access the root of cgroup namespace.
// This is needed by felix to attach CTLB programs and implement k8s services correctly.
func ensureCgroupV2Filesystem() error {
	// Check if the Cgroup2 filesystem is mounted at the expected location.
	logrus.Info("Checking if cgroup2 filesystem is mounted.")
	mountInfoFile := "/nodeproc/1/mountinfo"
	mounts, err := os.Open(mountInfoFile)
	if err != nil {
		return fmt.Errorf("failed to open %s. err: %w", mountInfoFile, err)
	}
	scanner := bufio.NewScanner(mounts)
	cgroupV2Path := bpfdefs.GetCgroupV2Path()
	for scanner.Scan() {
		// An example line in mountinfo file:
		// 35 24 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
		line := scanner.Text()
		mountPoint := strings.Split(line, " ")[4] // 4 is the index to mount points in mountinfo files

		extraInfo := strings.Split(line, " - ")
		if len(extraInfo) > 1 {
			fsType := strings.Split(extraInfo[1], " ")[0] // fsType is the first string after -

			if mountPoint == cgroupV2Path && fsType == "cgroup2" {
				logrus.Info("Cgroup2 filesystem is mounted.")
				return nil
			}
		}
	}
	if scanner.Err() != nil {
		return fmt.Errorf("failed to read %s: %w", mountInfoFile, scanner.Err())
	}

	// If we get here, the Cgroup2 filesystem is not mounted.  Try to mount it.
	logrus.Info("Cgroup2 filesystem is not mounted. Trying to mount it...")

	err = os.MkdirAll(cgroupV2Path, 0700)
	if err != nil {
		return fmt.Errorf("failed to prepare mount point: %v. err: %w", cgroupV2Path, err)
	}
	logrus.Infof("Mount point %s is ready for mounting root cgroup2 fs", cgroupV2Path)

	mountCmd := exec.Command("mountns", cgroupV2Path)
	out, err := mountCmd.Output()
	logrus.Debugf("Executed %v. err:%v out:\n%s", mountCmd, err, out)
	if err != nil {
		return fmt.Errorf("failed to mount cgroup2 filesystem: %w", err)
	}

	logrus.Infof("Mounted root cgroup2 filesystem.")
	return nil
}
