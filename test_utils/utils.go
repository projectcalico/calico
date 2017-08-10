package test_utils

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/020"
	"github.com/containernetworking/cni/pkg/types/current"
	etcdclient "github.com/coreos/etcd/client"
	version "github.com/mcuadros/go-version"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega/gexec"
	k8sbackend "github.com/projectcalico/libcalico-go/lib/backend/k8s"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var kapi etcdclient.KeysAPI

const K8S_TEST_NS = "test"

func init() {
	cfg := etcdclient.Config{Endpoints: []string{"http://127.0.0.1:2379"}}
	c, _ := etcdclient.New(cfg)
	kapi = etcdclient.NewKeysAPI(c)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Delete everything under /calico from etcd
func WipeEtcd() {
	_, err := kapi.Delete(context.Background(), "/calico", &etcdclient.DeleteOptions{Dir: true, Recursive: true})
	if err != nil && !etcdclient.IsKeyNotFound(err) {
		panic(err)
	}
}

// GetResultForCurrent takes the session output with cniVersion and returns the Result in current.Result format.
func GetResultForCurrent(session *gexec.Session, cniVersion string) (*current.Result, error) {

	// Check if the version is older than 0.3.0.
	// Convert it to Current standard spec version if that is the case.
	if version.Compare(cniVersion, "0.3.0", "<") {
		r020 := types020.Result{}

		if err := json.Unmarshal(session.Out.Contents(), &r020); err != nil {
			log.Fatalf("Error unmarshaling session output to Result: %v\n", err)
		}

		rCurrent, err := current.NewResultFromResult(&r020)
		if err != nil {
			return nil, err
		}

		return rCurrent, nil
	}

	r := current.Result{}

	if err := json.Unmarshal(session.Out.Contents(), &r); err != nil {
		log.Fatalf("Error unmarshaling session output to Result: %v\n", err)
	}
	return &r, nil

}

// Delete all K8s pods from the "test" namespace
func WipeK8sPods() {
	config, err := clientcmd.DefaultClientConfig.ClientConfig()
	if err != nil {
		panic(err)
	}
	clientset, err := kubernetes.NewForConfig(config)

	if err != nil {
		panic(err)
	}
	pods, err := clientset.Pods(K8S_TEST_NS).List(metav1.ListOptions{})
	if err != nil {
		panic(err)
	}

	for _, pod := range pods.Items {
		err = clientset.Pods(K8S_TEST_NS).Delete(pod.Name, &metav1.DeleteOptions{})

		if err != nil {
			panic(err)
		}
	}
}

// RunIPAMPlugin sets ENV vars required then calls the IPAM plugin
// specified in the config and returns the result and exitCode.
func RunIPAMPlugin(netconf, command, args, cniVersion string) (*current.Result, types.Error, int) {
	conf := types.NetConf{}
	if err := json.Unmarshal([]byte(netconf), &conf); err != nil {
		panic(fmt.Errorf("failed to load netconf: %v", err))
	}

	// Run the CNI plugin passing in the supplied netconf
	cmd := &exec.Cmd{
		Env: []string{
			"CNI_CONTAINERID=a",
			"CNI_NETNS=b",
			"CNI_IFNAME=c",
			"CNI_PATH=d",
			fmt.Sprintf("CNI_COMMAND=%s", command),
			fmt.Sprintf("CNI_ARGS=%s", args),
		},
		Path: "dist/" + conf.IPAM.Type,
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		panic("some error found")
	}

	io.WriteString(stdin, netconf)
	io.WriteString(stdin, "\n")
	stdin.Close()

	session, err := gexec.Start(cmd, ginkgo.GinkgoWriter, ginkgo.GinkgoWriter)
	if err != nil {
		panic("some error found")
	}
	session.Wait(5)
	exitCode := session.ExitCode()

	result := &current.Result{}
	error := types.Error{}
	stdout := session.Out.Contents()
	if exitCode == 0 {
		if command == "ADD" {
			result, err = GetResultForCurrent(session, cniVersion)
			if err != nil {
				log.Fatalf("Error getting result from the session: %v \n %v\n", session, err)
			}
		}
	} else {
		if err := json.Unmarshal(stdout, &error); err != nil {
			panic(fmt.Errorf("failed to load error: %s %v", stdout, err))
		}
	}

	return result, error, exitCode
}

func CreateContainerNamespace() (containerNs ns.NetNS, containerId string, err error) {
	return CreateContainerNamespaceWithCid("")
}

func CreateContainerNamespaceWithCid(container_id string) (containerNs ns.NetNS, containerId string, err error) {
	containerNs, err = ns.NewNS()
	if err != nil {
		return nil, "", err
	}

	netnsname := path.Base(containerNs.Path())
	containerId = netnsname[:10]

	if container_id != "" {
		containerId = container_id
	}

	err = containerNs.Do(func(_ ns.NetNS) error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		return netlink.LinkSetUp(lo)
	})

	return
}

func CreateContainer(netconf string, k8sName string, ip string) (container_id string, session *gexec.Session, contVeth netlink.Link, contAddr []netlink.Addr, contRoutes []netlink.Route, targetNs ns.NetNS, err error) {
	return CreateContainerWithId(netconf, k8sName, ip, "")
}

// Create container with the giving containerId when containerId is not empty
func CreateContainerWithId(netconf string, k8sName string, ip string, containerId string) (container_id string, session *gexec.Session, contVeth netlink.Link, contAddr []netlink.Addr, contRoutes []netlink.Route, targetNs ns.NetNS, err error) {
	targetNs, container_id, err = CreateContainerNamespaceWithCid(containerId)

	if err != nil {
		return "", nil, nil, nil, nil, nil, err
	}

	session, contVeth, contAddr, contRoutes, err = RunCNIPluginWithId(netconf, k8sName, ip, container_id, targetNs)

	return
}

// RunCNIPluginWithId calls CNI plugin with a containerID and targetNs passed to it.
// This is for when you want to call CNI for an existing container.
func RunCNIPluginWithId(netconf, k8sName, ip, containerId string, targetNs ns.NetNS) (session *gexec.Session, contVeth netlink.Link, contAddr []netlink.Addr, contRoutes []netlink.Route, err error) {

	// Set up the env for running the CNI plugin
	k8sEnv := ""
	if k8sName != "" {
		k8sEnv = fmt.Sprintf("CNI_ARGS=K8S_POD_NAME=%s;K8S_POD_NAMESPACE=test;K8S_POD_INFRA_CONTAINER_ID=whatever", k8sName)

		// Append IP=<ip> to CNI_ARGS only if it's not an empty string.
		if ip != "" {
			k8sEnv = fmt.Sprintf("%s;IP=%s", k8sEnv, ip)
		}
	}

	env := []string{
		"CNI_COMMAND=ADD",
		"CNI_IFNAME=eth0",
		"CNI_PATH=dist",
		fmt.Sprintf("CNI_CONTAINERID=%s", containerId),
		fmt.Sprintf("CNI_NETNS=%s", targetNs.Path()),
		k8sEnv,
	}

	log.Debugf("Calling CNI plugin with the following env vars: %v", env)

	// Run the CNI plugin passing in the supplied netconf
	// TODO - Get rid of this PLUGIN thing and use netconf instead
	subProcess := exec.Command(fmt.Sprintf("dist/%s", os.Getenv("PLUGIN")), netconf)
	subProcess.Env = env
	stdin, err := subProcess.StdinPipe()
	if err != nil {
		panic("some error found")
	}

	io.WriteString(stdin, netconf)
	io.WriteString(stdin, "\n")
	stdin.Close()

	session, err = gexec.Start(subProcess, ginkgo.GinkgoWriter, ginkgo.GinkgoWriter)
	session.Wait(5)

	err = targetNs.Do(func(_ ns.NetNS) error {
		contVeth, err = netlink.LinkByName("eth0")
		if err != nil {
			return err
		}

		contAddr, err = netlink.AddrList(contVeth, syscall.AF_INET)
		if err != nil {
			return err
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
func CreateHostVeth(containerId string, k8sName string, k8sNamespace string) error {
	hostVethName := "cali" + containerId[:min(11, len(containerId))]
	if k8sName != "" {
		workload := fmt.Sprintf("%s.%s", k8sNamespace, k8sName)
		hostVethName = k8sbackend.VethNameForWorkload(workload)
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
func DeleteContainer(netconf, netnspath, name string) (exitCode int, err error) {
	return DeleteContainerWithId(netconf, netnspath, name, "")
}

func DeleteContainerWithId(netconf, netnspath, name, containerId string) (exitCode int, err error) {
	netnsname := path.Base(netnspath)
	container_id := netnsname[:10]
	if containerId != "" {
		container_id = containerId
	}
	k8sEnv := ""
	if name != "" {
		k8sEnv = fmt.Sprintf("CNI_ARGS=K8S_POD_NAME=%s;K8S_POD_NAMESPACE=test;K8S_POD_INFRA_CONTAINER_ID=whatever", name)
	}

	// Set up the env for running the CNI plugin
	env := []string{
		"CNI_COMMAND=DEL",
		fmt.Sprintf("CNI_CONTAINERID=%s", container_id),
		fmt.Sprintf("CNI_NETNS=%s", netnspath),
		"CNI_IFNAME=eth0",
		"CNI_PATH=dist",
		k8sEnv,
	}

	log.Debugf("Calling CNI plugin with the following env vars: %v", env)

	// Run the CNI plugin passing in the supplied netconf
	subProcess := exec.Command(fmt.Sprintf("dist/%s", os.Getenv("PLUGIN")), netconf)
	subProcess.Env = env
	stdin, err := subProcess.StdinPipe()
	if err != nil {
		return
	}
	io.WriteString(stdin, netconf)
	io.WriteString(stdin, "\n")
	stdin.Close()

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
	ginkgo.GinkgoWriter.Write([]byte(fmt.Sprintf("Running command [%s]\n", cmd)))
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		ginkgo.GinkgoWriter.Write(out)
		ginkgo.GinkgoWriter.Write(err.(*exec.ExitError).Stderr)
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
	defer fh.Close()

	// Ignoring second output (isPrefix) since it's not necessory
	buf, _, err := f.ReadLine()
	if err != nil {
		// EOF without a match
		return err
	}

	if string(buf) != value {
		return fmt.Errorf("error asserting sysctl value: expected: %s, got: %s for sysctl path: %s", value, string(buf), sysctlPath)
	}

	return nil
}
