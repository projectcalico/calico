// Copyright (c) 2015-2020 Tigera, Inc. All rights reserved.
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
package testutils

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/types"
	types020 "github.com/containernetworking/cni/pkg/types/020"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	je "github.com/juju/errors"
	"github.com/mcuadros/go-version"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega/gexec"

	k8sconversion "github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/names"

	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetResultForCurrent takes the output with cniVersion and returns the Result in cniv1.Result format.
func GetResultForCurrent(session *gexec.Session, cniVersion string) (*cniv1.Result, error) {

	// Check if the version is older than 0.3.0.
	// Convert it to Current standard spec version if that is the case.
	if version.Compare(cniVersion, "0.3.0", "<") {
		r020 := types020.Result{}

		if err := json.Unmarshal(session.Out.Contents(), &r020); err != nil {
			log.Errorf("Error unmarshaling output to Result: %v\n", err)
			return nil, err
		}

		rCurrent, err := cniv1.NewResultFromResult(&r020)
		if err != nil {
			return nil, err
		}

		return rCurrent, nil
	}

	r := cniv1.Result{}

	if err := json.Unmarshal(session.Out.Contents(), &r); err != nil {
		log.Errorf("Error unmarshaling output to Result: %v\n", err)
		return nil, err
	}
	return &r, nil
}

// RunIPAMPlugin sets ENV vars required then calls the IPAM plugin
// specified in the config and returns the result and exitCode.
func RunIPAMPlugin(netconf, command, args, cid, cniVersion string) (*cniv1.Result, types.Error, int) {
	conf := types.NetConf{}
	if err := json.Unmarshal([]byte(netconf), &conf); err != nil {
		panic(fmt.Errorf("failed to load netconf: %v", err))
	}

	// Run the CNI plugin passing in the supplied netconf
	cmd := &exec.Cmd{
		Env: []string{
			fmt.Sprintf("CNI_CONTAINERID=%s", cid),
			"CNI_NETNS=b",
			"CNI_IFNAME=c",
			"CNI_PATH=d",
			fmt.Sprintf("CNI_COMMAND=%s", command),
			fmt.Sprintf("CNI_ARGS=%s", args),
		},
		Path: fmt.Sprintf("%s/%s", os.Getenv("BIN"), conf.IPAM.Type),
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		panic("some error found")
	}

	_, err = io.WriteString(stdin, netconf)
	if err != nil {
		panic(err)
	}
	_, err = io.WriteString(stdin, "\n")
	if err != nil {
		panic(err)
	}

	err = stdin.Close()
	if err != nil {
		panic(err)
	}

	session, err := gexec.Start(cmd, ginkgo.GinkgoWriter, ginkgo.GinkgoWriter)
	if err != nil {
		panic("some error found")
	}
	session.Wait(5)
	exitCode := session.ExitCode()

	result := &cniv1.Result{}
	e := types.Error{}
	stdout := session.Out.Contents()
	if exitCode == 0 {
		if command == "ADD" {
			result, err = GetResultForCurrent(session, cniVersion)
			if err != nil {
				log.Errorf("Error getting result from the session: %v \n %v\n", session, err)
				panic(err)
			}
		}
	} else {
		if err := json.Unmarshal(stdout, &e); err != nil {
			panic(fmt.Errorf("failed to load error: %s %v", stdout, err))
		}
	}

	return result, e, exitCode
}

func CreateContainerNamespace() (containerNs ns.NetNS, containerId string, err error) {
	containerNs, err = testutils.NewNS()
	if err != nil {
		return nil, "", err
	}

	containerId = netnsToContainerID(containerNs.Path())

	err = containerNs.Do(func(_ ns.NetNS) error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		return netlink.LinkSetUp(lo)
	})

	return
}

func CreateContainer(netconf, podName, podNamespace, ip string) (containerID string, result *cniv1.Result, contVeth netlink.Link, contAddr []netlink.Addr, contRoutes []netlink.Route, targetNs ns.NetNS, err error) {
	ginkgo.By("creating a container netns to run the CNI plugin against", func() {
		targetNs, containerID, err = CreateContainerNamespace()
	})
	if err != nil {
		return "", nil, nil, nil, nil, nil, err
	}

	result, contVeth, contAddr, contRoutes, err = RunCNIPluginWithId(netconf, podName, podNamespace, ip, containerID, "", targetNs)
	return
}

// Create container with the giving containerId when containerId is not empty
func CreateContainerWithId(netconf, podName, podNamespace, ip, overrideContainerID string) (containerID string, result *cniv1.Result, contVeth netlink.Link, contAddr []netlink.Addr, contRoutes []netlink.Route, targetNs ns.NetNS, err error) {
	targetNs, containerID, err = CreateContainerNamespace()
	if err != nil {
		return "", nil, nil, nil, nil, nil, err
	}

	if overrideContainerID != "" {
		containerID = overrideContainerID
	}

	result, contVeth, contAddr, contRoutes, err = RunCNIPluginWithId(netconf, podName, podNamespace, ip, containerID, "", targetNs)
	return
}

// RunCNIPluginWithId calls CNI plugin with a containerID and targetNs passed to it.
// This is for when you want to call CNI for an existing container.
func RunCNIPluginWithId(
	netconf,
	podName,
	podNamespace,
	ip,
	containerId,
	ifName string,
	targetNs ns.NetNS,
) (
	result *cniv1.Result,
	contVeth netlink.Link,
	contAddr []netlink.Addr,
	contRoutes []netlink.Route,
	err error,
) {
	// Set up the env for running the CNI plugin
	k8sEnv := ""
	if podName != "" {
		k8sEnv = fmt.Sprintf("CNI_ARGS=K8S_POD_NAME=%s;K8S_POD_NAMESPACE=%s;K8S_POD_INFRA_CONTAINER_ID=whatever", podName, podNamespace)

		// Append IP=<ip> to CNI_ARGS only if it's not an empty string.
		if ip != "" {
			k8sEnv = fmt.Sprintf("%s;IP=%s", k8sEnv, ip)
		}
	}

	if ifName == "" {
		ifName = "eth0"
	}

	env := []string{
		"CNI_COMMAND=ADD",
		fmt.Sprintf("CNI_IFNAME=%s", ifName),
		fmt.Sprintf("CNI_PATH=%s", os.Getenv("BIN")),
		fmt.Sprintf("CNI_CONTAINERID=%s", containerId),
		fmt.Sprintf("CNI_NETNS=%s", targetNs.Path()),
		k8sEnv,
	}
	args := &cniArgs{env}

	// Create a new exec implementation that captures stderr (CNI plugin logs) so we can
	// properly emit them with ginkgo.
	var customExec = &invoke.DefaultExec{
		RawExec: &invoke.RawExec{Stderr: ginkgo.GinkgoWriter},
	}

	// Invoke the CNI plugin, returning any errors to the calling code to handle.
	log.Debugf("Calling CNI plugin with the following env vars: %v", env)
	var r types.Result
	pluginPath := fmt.Sprintf("%s/%s", os.Getenv("BIN"), os.Getenv("PLUGIN"))

	ginkgo.By("running the CNI plugin against the namespace")
	r, err = invoke.ExecPluginWithResult(context.Background(), pluginPath, []byte(netconf), args, customExec)
	if err != nil {
		log.Debugf("config is: %s", netconf)
		err = je.Trace(err)
		return
	}

	// Extract the target CNI version from the provided network config.
	var nc types.NetConf
	if err = json.Unmarshal([]byte(netconf), &nc); err != nil {
		panic(err)
	}

	// Parse the result as the target CNI version.
	if version.Compare(nc.CNIVersion, "0.3.0", "<") {
		// Special case for older CNI versions.
		var out []byte
		out, err = json.Marshal(r)
		r020 := types020.Result{}
		if err = json.Unmarshal(out, &r020); err != nil {
			log.WithField("out", out).Errorf("Error unmarshaling output to Result: %v\n", err)
			err = je.Wrap(je.Trace(err), je.Errorf("cniVersion is: %s\n", nc.CNIVersion))
			return
		}

		result, err = cniv1.NewResultFromResult(&r020)
		if err != nil {
			return
		}

	} else {
		result, err = cniv1.GetResult(r)
		if err != nil {
			return
		}
	}

	err = targetNs.Do(func(_ ns.NetNS) error {
		contVeth, err = netlink.LinkByName(ifName)
		if err != nil {
			return err
		}

		contAddr, err = netlink.AddrList(contVeth, syscall.AF_INET)
		if err != nil {
			return err
		}
		v6Addrs, err := netlink.AddrList(contVeth, syscall.AF_INET6)
		if err != nil {
			return err
		}
		for _, addr := range v6Addrs {
			// Also return IPv6 addresses, except for link local ones.
			if !strings.HasPrefix(addr.IPNet.String(), "fe80:") {
				contAddr = append(contAddr, addr)
			}
		}

		contRoutes, err = netlink.RouteList(contVeth, syscall.AF_INET)
		if err != nil {
			return err
		}

		return nil
	})
	return
}

// Create veth pair on host
func CreateHostVeth(containerId, k8sName, k8sNamespace, nodename string) error {
	hostVethName := "cali" + containerId[:min(11, len(containerId))]
	if k8sName != "" {
		ids := names.WorkloadEndpointIdentifiers{
			Node:         nodename,
			Orchestrator: "k8s",
			Endpoint:     "eth0",
			Pod:          k8sName,
			ContainerID:  containerId,
		}

		workloadName, err := ids.CalculateWorkloadEndpointName(false)
		if err != nil {
			return err
		}

		hostVethName = k8sconversion.NewConverter().VethNameForWorkload(k8sNamespace, workloadName)
	}

	peerVethName := "calipeer"

	// Clean up if peer Veth exists.
	if oldPeerVethName, err := netlink.LinkByName(peerVethName); err == nil {
		if err = netlink.LinkDel(oldPeerVethName); err != nil {
			return fmt.Errorf("failed to delete old peer Veth %v: %v", oldPeerVethName, err)
		}
	}

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  hostVethName,
			Flags: net.FlagUp,
			MTU:   1500,
		},
		PeerName: peerVethName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return err
	}

	return nil
}

// Executes the Calico CNI plugin and return the error code of the command.
func DeleteContainer(netconf, netnspath, podName, podNamespace string) (exitCode int, err error) {
	return DeleteContainerWithId(netconf, netnspath, podName, podNamespace, "")
}

func DeleteContainerWithId(netconf, netnspath, podName, podNamespace, containerId string) (exitCode int, err error) {
	return DeleteContainerWithIdAndIfaceName(netconf, netnspath, podName, podNamespace, containerId, "eth0")
}

func DeleteContainerWithIdAndIfaceName(netconf, netnspath, podName, podNamespace, containerId, ifaceName string) (exitCode int, err error) {
	container_id := netnsToContainerID(netnspath)
	if containerId != "" {
		container_id = containerId
	}
	k8sEnv := ""
	if podName != "" {
		k8sEnv = fmt.Sprintf("CNI_ARGS=K8S_POD_NAME=%s;K8S_POD_NAMESPACE=%s;K8S_POD_INFRA_CONTAINER_ID=whatever", podName, podNamespace)
	}

	// Set up the env for running the CNI plugin
	env := []string{
		"CNI_COMMAND=DEL",
		fmt.Sprintf("CNI_CONTAINERID=%s", container_id),
		fmt.Sprintf("CNI_NETNS=%s", netnspath),
		"CNI_IFNAME=" + ifaceName,
		fmt.Sprintf("CNI_PATH=%s", os.Getenv("BIN")),
		k8sEnv,
	}

	log.Debugf("Deleting container with ID %v CNI plugin with the following env vars: %v", containerId, env)

	// Run the CNI plugin passing in the supplied netconf
	subProcess := exec.Command(fmt.Sprintf("%s/%s", os.Getenv("BIN"), os.Getenv("PLUGIN")), netconf)
	subProcess.Env = env
	stdin, err := subProcess.StdinPipe()
	if err != nil {
		return
	}

	_, err = io.WriteString(stdin, netconf)
	if err != nil {
		return 1, err
	}
	_, err = io.WriteString(stdin, "\n")
	if err != nil {
		return 1, err
	}

	err = stdin.Close()
	if err != nil {
		return 1, err
	}

	session, err := gexec.Start(subProcess, ginkgo.GinkgoWriter, ginkgo.GinkgoWriter)
	if err != nil {
		return
	}

	// Call the plugin. Will force a test failure if it hangs longer than 5s.
	session.Wait(5)

	exitCode = session.ExitCode()
	return
}

func Cmd(cmd string) string {
	_, _ = ginkgo.GinkgoWriter.Write([]byte(fmt.Sprintf("Running command [%s]\n", cmd)))
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		_, writeErr := ginkgo.GinkgoWriter.Write(out)
		if writeErr != nil {
			panic(writeErr)
		}
		_, writeErr = ginkgo.GinkgoWriter.Write(err.(*exec.ExitError).Stderr)
		if writeErr != nil {
			panic(writeErr)
		}
		ginkgo.Fail("Command failed")
	}
	return strings.TrimSpace(string(out))
}

// CheckSysctlValue is a utility function to assert sysctl value is set to what is expected.
func CheckSysctlValue(sysctlPath, value string) error {
	fh, err := os.Open(sysctlPath)
	if err != nil {
		return err
	}

	f := bufio.NewReader(fh)

	// Ignoring second output (isPrefix) since it's not necessary
	buf, _, err := f.ReadLine()
	if err != nil {
		// EOF without a match
		return err
	}

	if string(buf) != value {
		return fmt.Errorf("error asserting sysctl value: expected: %s, got: %s for sysctl path: %s", value, string(buf), sysctlPath)
	}

	err = fh.Close()
	if err != nil {
		return err
	}

	return nil
}

// Convert the netns name to a container ID.
func netnsToContainerID(netns string) string {
	u := uuid.NewV5(uuid.NamespaceURL, netns)
	buf := make([]byte, 10)
	hex.Encode(buf, u[0:5])
	return string(buf)
}
