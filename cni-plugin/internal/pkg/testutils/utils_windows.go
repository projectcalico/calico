// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/projectcalico/calico/cni-plugin/pkg/dataplane/windows"

	"github.com/Microsoft/hcsshim"
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types020 "github.com/containernetworking/cni/pkg/types/020"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/mcuadros/go-version"
	log "github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/cni-plugin/pkg/k8s"
	plugintypes "github.com/projectcalico/calico/cni-plugin/pkg/types"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"

	"golang.org/x/sys/windows/registry"
)

const HnsNoneNs = "none"

// Delete all K8s pods from the "test" namespace
func WipeK8sPods(netconf string) {
	conf := plugintypes.NetConf{}
	if err := json.Unmarshal([]byte(netconf), &conf); err != nil {
		panic(err)
	}
	logger := log.WithFields(log.Fields{
		"Namespace": HnsNoneNs,
	})
	clientset, err := k8s.NewK8sClient(conf, logger)
	if err != nil {
		panic(err)
	}

	log.WithField("clientset:", clientset).Info("DEBUG")
	pods, err := clientset.CoreV1().Pods(K8S_TEST_NS).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}

	for _, pod := range pods.Items {
		err = clientset.CoreV1().Pods(K8S_TEST_NS).Delete(context.Background(), pod.Name, metav1.DeleteOptions{})

		if err != nil {
			if kerrors.IsNotFound(err) {
				continue
			}
			panic(err)
		}
	}
	log.Info("WipeK8sPods Success")
}

func CreateContainerUsingDocker() (string, error) {
	var image string
	if os.Getenv("WINDOWS_OS") == "Windows1903container" {
		image = "mcr.microsoft.com/windows/servercore/insider:10.0.18317.1000"
	} else if os.Getenv("WINDOWS_OS") == "Windows1809container" {
		image = "mcr.microsoft.com/windows/servercore:1809"
	}

	command := fmt.Sprintf("docker run --net none -d %s powershell.exe -command start-sleep -s 300", image)
	cmd := exec.Command("powershell.exe", command)

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn(err)
		return "", err
	}

	temp := strings.TrimSpace(string(out))
	log.Debugf("container ID: %s", temp)
	return temp, nil
}

// CreateContainerByIdUsingContainerd creates a container with containerd with the specified
// container ID and returns the container ID and netns.
func CreateContainerByIdUsingContainerd(overrideContainerID string) (string, string, error) {
	return createContainerUsingContainerd(overrideContainerID)
}

// CreateContainerUsingContainerd creates a container with containerd and
// returns the container ID and netns.
func CreateContainerUsingContainerd() (string, string, error) {
	containerId := fmt.Sprintf("ctr%d", rand.Uint32())
	return createContainerUsingContainerd(containerId)
}

// GetContainerNamespace gets the namespace that is associated with the container.
func GetContainerNamespace(containerId string) (string, error) {
	command := fmt.Sprintf("Get-HnsNamespace | Where Containers -eq %v | Select-Object -expandproperty ID", containerId)
	cmd := exec.Command("powershell.exe", command)

	log.Infof("Running powershell command: %v", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).Info("could not get namespace for container")
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func createContainerUsingContainerd(containerId string) (string, string, error) {
	// Create the container with ctr.exe that is shipped with containerd.
	// When 'ctr run' is invoked, a running container is started with no
	// networking.
	image := "k8s.gcr.io/pause:3.5"

	command := fmt.Sprintf(`& 'C:\Program Files\containerd\ctr.exe' images pull %v`, image)
	cmd := exec.Command("powershell.exe", command)

	log.Infof("Running powershell command: %v", command)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", errors.New(fmt.Sprintf("failed to pull image: %v", err))
	}
	command = fmt.Sprintf(`& 'C:\Program Files\containerd\ctr.exe' run --detach %v %v`, image, containerId)
	cmd = exec.Command("powershell.exe", command)

	log.Infof("Running powershell command: %v", command)
	_, err = cmd.CombinedOutput()
	if err != nil {
		return "", "", errors.New(fmt.Sprintf("failed to create container: %v", err))
	}

	// Next, get the namespace that is associated with the container
	ns, err := GetContainerNamespace(containerId)
	if err != nil {
		return "", "", errors.New(fmt.Sprintf("failed to get container namespace: %v", err))
	}

	log.Infof("ctr namespace: %s", ns)
	return containerId, ns, nil
}

func DeleteRunningContainer(containerId string) error {
	if os.Getenv("CONTAINER_RUNTIME") != "containerd" {
		command := fmt.Sprintf("docker rm -f %s", containerId)
		cmd := exec.Command("powershell.exe", command)
		_, err := cmd.CombinedOutput()
		if err != nil {
			log.WithError(err).WithField("id", containerId).Error("Failed to stop docker container")
			return err
		}
		return nil
	}

	// Delete the running task and container with ctr.exe that is shipped with containerd.
	cmds := []string{
		fmt.Sprintf(`& 'C:\Program Files\containerd\ctr.exe' tasks kill %v`, containerId),
		fmt.Sprintf(`& 'C:\Program Files\containerd\ctr.exe' containers delete %v`, containerId),
	}

	for _, c := range cmds {
		cmd := exec.Command("powershell.exe", c)
		log.Infof("Running powershell command: %v", c)
		_, err := cmd.CombinedOutput()
		if err != nil {
			log.WithError(err).WithField("id", containerId).Warn("Failed to stop docker container")
			return err
		}
	}
	return nil
}

func CreateContainer(netconf, podName, podNamespace, ip, k8sNs string) (containerID string, result *cniv1.Result, contVeth string, contAddr []string, contRoutes []string, err error) {
	// Create a container using dockershim.
	if os.Getenv("CONTAINER_RUNTIME") != "containerd" {
		containerID, err = CreateContainerUsingDocker()
		if err != nil {
			return "", nil, "", []string{}, []string{}, err
		}
		result, contVeth, contAddr, contRoutes, err = RunCNIPluginWithId(netconf, podName, podNamespace, ip, containerID, "", k8sNs)
		if err != nil {
			return containerID, nil, "", []string{}, []string{}, err
		}
		return
	}

	// Otherwise create a container using containerd.
	containerID, targetNs, err := CreateContainerUsingContainerd()
	if err != nil {
		return "", nil, "", []string{}, []string{}, err
	}
	result, contVeth, contAddr, contRoutes, err = RunCNIPluginWithId(netconf, podName, targetNs, ip, containerID, "", k8sNs)
	if err != nil {
		return containerID, nil, "", []string{}, []string{}, err
	}
	return
}

// Create container with the giving containerId when containerId is not empty
//
// Deprecated: Please call CreateContainerNamespace and then RunCNIPluginWithID directly.
func CreateContainerWithId(netconf, podName, podNamespace, ip, overrideContainerID, k8sNs string) (containerID string, result *cniv1.Result, contVeth string, contAddr []string, contRoutes []string, err error) {
	// Create a container using dockershim.
	if os.Getenv("CONTAINER_RUNTIME") != "containerd" {
		containerID, err = CreateContainerUsingDocker()
		if err != nil {
			return "", nil, "", []string{}, []string{}, err
		}

		if overrideContainerID != "" {
			containerID = overrideContainerID
		}

		result, contVeth, contAddr, contRoutes, err = RunCNIPluginWithId(netconf, podName, podNamespace, ip, containerID, "", k8sNs)
		if err != nil {
			log.Errorf("Error: ", err)
			return containerID, nil, "", []string{}, []string{}, err
		}
	}

	// Otherwise create a container using containerd.
	containerID, targetNs, err := CreateContainerByIdUsingContainerd(overrideContainerID)
	if err != nil {
		return "", nil, "", []string{}, []string{}, err
	}

	result, contVeth, contAddr, contRoutes, err = RunCNIPluginWithId(netconf, podName, podNamespace, ip, containerID, "", targetNs)
	if err != nil {
		log.Errorf("Error: ", err)
		return containerID, nil, "", []string{}, []string{}, err
	}
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
	ifName,
	k8sNs string,
) (
	result *cniv1.Result,
	contVeth string,
	contAddr []string,
	contRoutes []string,
	err error,
) {
	// Set up the env for running the CNI plugin
	k8sEnv := ""
	if podName != "" {
		k8sEnv = fmt.Sprintf("CNI_ARGS=K8S_POD_NAME=%s;K8S_POD_NAMESPACE=%s;K8S_POD_INFRA_CONTAINER_ID=whatever", podName, k8sNs)

		// Append IP=<ip> to CNI_ARGS only if it's not an empty string.
		if ip != "" {
			k8sEnv = fmt.Sprintf("%s;IP=%s", k8sEnv, ip)
		}
	}

	if ifName == "" {
		ifName = "eth0"
	}

	env := os.Environ()
	env = append(env, []string{
		"CNI_COMMAND=ADD",
		fmt.Sprintf("CNI_IFNAME=%s", ifName),
		fmt.Sprintf("CNI_PATH=%s", os.Getenv("BIN")),
		fmt.Sprintf("CNI_CONTAINERID=%s", containerId),
		fmt.Sprintf("CNI_NETNS=%s", podNamespace),
		k8sEnv,
	}...)
	args := &cniArgs{env}

	// Invoke the CNI plugin, returning any errors to the calling code to handle.
	var r types.Result
	pluginPath := fmt.Sprintf("%s\\%s", os.Getenv("BIN"), os.Getenv("PLUGIN"))
	log.Debugf("pluginPath: %v", pluginPath)
	r, err = invoke.ExecPluginWithResult(context.Background(), pluginPath, []byte(netconf), args, nil)
	if err != nil {
		log.Errorf("error from invoke.ExecPluginWithResult %v", err)
		_ = DeleteRunningContainer(containerId)
		return
	}

	// Extract the target CNI version from the provided network config.
	var nc types.NetConf
	if err = json.Unmarshal([]byte(netconf), &nc); err != nil {
		log.Errorf("unmarshal err: ", err)
		panic(err)
	}
	// Parse the result as the target CNI version.
	if version.Compare(nc.CNIVersion, "0.3.0", "<") {
		// Special case for older CNI versions.
		var out []byte
		out, err = json.Marshal(r)
		log.Infof("CNI output: %s", out)
		r020 := types020.Result{}
		if err = json.Unmarshal(out, &r020); err != nil {
			log.Errorf("Error unmarshaling output to Result: %v", err)
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

	return
}

// Executes the Calico CNI plugin and return the error code of the command.
func DeleteContainer(netconf, podName, podNamespace, k8sNs string) (exitCode int, err error) {
	return DeleteContainerWithId(netconf, podName, podNamespace, "", k8sNs)
}

//func DeleteContainerWithId(netconf, netnspath, podName, podNamespace, containerId string) (exitCode int, err error) {
func DeleteContainerWithId(netconf, podName, podNamespace, containerId, k8sNs string) (exitCode int, err error) {
	return DeleteContainerWithIdAndIfaceName(netconf, podName, podNamespace, containerId, "eth0", k8sNs)
}

//func DeleteContainerWithIdAndIfaceName(netconf, netnspath, podName, podNamespace, containerId, ifaceName string) (exitCode int, err error) {
func DeleteContainerWithIdAndIfaceName(netconf, podName, podNamespace, containerId, ifaceName, k8sNs string) (exitCode int, err error) {
	k8sEnv := ""
	if podName != "" {
		k8sEnv = fmt.Sprintf("CNI_ARGS=K8S_POD_NAME=%s;K8S_POD_NAMESPACE=%s;K8S_POD_INFRA_CONTAINER_ID=whatever", podName, k8sNs)
	}

	// Set up the env for running the CNI plugin
	env := os.Environ()

	// For containerd: override the podNamespace with the actual namespace for the container.
	if os.Getenv("CONTAINER_RUNTIME") == "containerd" {
		podNamespace, err = GetContainerNamespace(containerId)
		if err != nil {
			log.Errorf("Error deleting container %s", containerId)
			return
		}
	}

	env = append(env, []string{
		"CNI_COMMAND=DEL",
		fmt.Sprintf("CNI_CONTAINERID=%s", containerId),
		fmt.Sprintf("CNI_NETNS=%s", podNamespace),
		"CNI_IFNAME=" + ifaceName,
		fmt.Sprintf("CNI_PATH=%s", os.Getenv("BIN")),
		k8sEnv,
	}...)

	log.Infof("Deleting container with ID %v CNI plugin with the following env vars: %v", containerId, env)
	//now delete the container
	if containerId != "" {
		log.Debugf("calling DeleteRunningContainer with ContainerID %v", containerId)
		err = DeleteRunningContainer(containerId)
		if err != nil {
			log.Errorf("Error deleting container %s", containerId)
		}
	}

	// Run the CNI plugin passing in the supplied netconf
	args := &cniArgs{env}
	pluginPath := fmt.Sprintf("%s\\%s", os.Getenv("BIN"), os.Getenv("PLUGIN"))
	log.Debugf("pluginPath: %v", pluginPath)
	err = invoke.ExecPluginWithoutResult(context.Background(), pluginPath, []byte(netconf), args, nil)
	if err != nil {
		log.Errorf("error from invoke.ExecPluginWithoutResult %v", err)
		return
	}

	return
}

func NetworkPod(
	netconf string,
	podName string,
	ip string,
	ctx context.Context,
	calicoClient client.Interface,
	result *cniv1.Result,
	containerID string,
	netns string,
	k8sNs string,
) (err error) {

	k8sEnv := ""
	if podName != "" {
		k8sEnv = fmt.Sprintf("CNI_ARGS=K8S_POD_NAME=%s;K8S_POD_NAMESPACE=%s;K8S_POD_INFRA_CONTAINER_ID=whatever", podName, k8sNs)
		// Append IP=<ip> to CNI_ARGS only if it's not an empty string.
		if ip != "" {
			k8sEnv = fmt.Sprintf("%s;IP=%s", k8sEnv, ip)
		}
	}

	var args *skel.CmdArgs
	args = &skel.CmdArgs{
		ContainerID: containerID,
		Netns:       netns,
		IfName:      "eth0",
		Args:        k8sEnv,
		Path:        os.Getenv("BIN"),
		StdinData:   []byte(netconf),
	}
	conf := plugintypes.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	var logger *log.Entry

	logger = log.WithFields(log.Fields{
		"ContainerID": containerID,
		"Pod":         podName,
		"Namespace":   netns,
	})
	d := windows.NewWindowsDataplane(conf, logger)
	_, _, err = d.DoNetworking(ctx, calicoClient, args, result, "", nil, nil, nil)
	return err
}

func CreateNetwork(netconf string) (*hcsshim.HNSNetwork, error) {
	var conf plugintypes.NetConf
	if err := json.Unmarshal([]byte(netconf), &conf); err != nil {
		log.Errorf("unmarshal err: ", err)
		panic(err)
	}

	_, subNet, _ := net.ParseCIDR(conf.IPAM.Subnet)

	var logger *log.Entry
	logger = log.WithFields(log.Fields{
		"Name": conf.Name,
	})

	var networkName string
	if conf.WindowsUseSingleNetwork {
		logger.WithField("name", conf.Name).Info("Overriding network name, only a single IPAM block will be supported on this host")
		networkName = conf.Name
	} else {
		networkName = windows.CreateNetworkName(conf.Name, subNet)
	}

	hnsNetwork, err := windows.EnsureNetworkExists(networkName, subNet, logger)
	if err != nil {
		logger.Errorf("Unable to create hns network %s", networkName)
		return nil, err
	}

	return hnsNetwork, nil
}

func CreateEndpoint(hnsNetwork *hcsshim.HNSNetwork, netconf string) (*hcsshim.HNSEndpoint, error) {
	var conf plugintypes.NetConf
	if err := json.Unmarshal([]byte(netconf), &conf); err != nil {
		log.Errorf("unmarshal err: ", err)
		panic(err)
	}

	_, subNet, _ := net.ParseCIDR(conf.IPAM.Subnet)

	var logger *log.Entry
	logger = log.WithFields(log.Fields{
		"Name": conf.Name,
	})

	epName := hnsNetwork.Name + "_ep"
	hnsEndpoint, err := windows.CreateAndAttachHostEP(epName, hnsNetwork, subNet, logger)
	if err != nil {
		logger.Errorf("Unable to create host hns endpoint %s", epName)
		return nil, err
	}

	return hnsEndpoint, nil
}

// Return true if a key exists.
func CheckRegistryKeyExists(path string) (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err == registry.ErrNotExist {
		return false, nil
	} else if err != nil {
		return false, err
	}
	defer k.Close()

	return true, nil
}

// Return a timestamp value.
func GetTimestampValue(key, id string) (time.Time, error) {
	zTime := time.Time{}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return zTime, err
	}
	defer k.Close()

	val, _, err := k.GetStringValue(id)
	if err != nil {
		return zTime, err
	}

	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return zTime, err
	}

	return t, nil
}

func DeleteSubKey(key, subkeyName string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key+`\`+subkeyName, registry.QUERY_VALUE)
	if err == registry.ErrNotExist {
		return nil
	} else if err != nil {
		return err
	}

	k, err = registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	err = registry.DeleteKey(k, subkeyName)
	if err != nil {
		return err
	}
	return nil
}
