package test_utils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/clientcmd"

	"path"

	"encoding/json"

	"syscall"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/types"
	etcdclient "github.com/coreos/etcd/client"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega/gexec"
	"github.com/vishvananda/netlink"
)

var kapi etcdclient.KeysAPI

const K8S_TEST_NS = "test"

func init() {
	cfg := etcdclient.Config{Endpoints: []string{"http://127.0.0.1:2379"}}
	c, _ := etcdclient.New(cfg)
	kapi = etcdclient.NewKeysAPI(c)
}

// Delete everything under /calico from etcd
func WipeEtcd() {
	_, err := kapi.Delete(context.Background(), "/calico", &etcdclient.DeleteOptions{Dir: true, Recursive: true})
	if err != nil && !etcdclient.IsKeyNotFound(err) {
		panic(err)
	}
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
	pods, err := clientset.Pods(K8S_TEST_NS).List(v1.ListOptions{})
	if err != nil {
		panic(err)
	}

	for _, pod := range pods.Items {
		err = clientset.Pods(K8S_TEST_NS).Delete(pod.Name, &v1.DeleteOptions{})

		if err != nil {
			panic(err)
		}
	}
}

func RunIPAMPlugin(netconf, command, args string) (types.Result, types.Error, int) {
	conf := types.NetConf{}
	if err := json.Unmarshal([]byte(netconf), &conf); err != nil {
		panic(fmt.Errorf("failed to load netconf: %v", err))
	}

	// Run the CNI plugin passing in the supplied netconf
	cmd := &exec.Cmd{
		Env:  []string{"CNI_COMMAND=" + command, "CNI_CONTAINERID=a", "CNI_NETNS=b", "CNI_IFNAME=c", "CNI_PATH=d", "CNI_ARGS=" + args},
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
	result := types.Result{}
	error := types.Error{}
	stdout := session.Out.Contents()
	if exitCode == 0 {
		if command == "ADD" {
			if err := json.Unmarshal(stdout, &result); err != nil {
				panic(fmt.Errorf("failed to load result: %s %v", stdout, err))
			}
		}
	} else {
		if err := json.Unmarshal(stdout, &error); err != nil {
			panic(fmt.Errorf("failed to load error: %s %v", stdout, err))
		}
	}

	return result, error, exitCode
}

func CreateContainer(netconf string, k8sName string) (container_id, netnspath string, session *gexec.Session, contVeth netlink.Link, contAddr []netlink.Addr, contRoutes []netlink.Route, err error) {
	targetNs, err := ns.NewNS()
	if err != nil {
		return "", "", nil, nil, nil, nil, err
	}

	// Create a random "container ID"
	netnspath = targetNs.Path()
	netnsname := path.Base(netnspath)
	container_id = netnsname[:10]

	err = targetNs.Do(func(_ ns.NetNS) error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		err = netlink.LinkSetUp(lo)
		return err

		return nil
	})

	// Set up the env for running the CNI plugin
	//TODO pass in the env properly
	var k8s_env = ""
	if k8sName != "" {
		k8s_env = fmt.Sprintf("CNI_ARGS=\"K8S_POD_NAME=%s;K8S_POD_NAMESPACE=test;K8S_POD_INFRA_CONTAINER_ID=whatever\"", k8sName)
	}
	cni_env := fmt.Sprintf("CNI_COMMAND=ADD CNI_CONTAINERID=%s CNI_NETNS=%s CNI_IFNAME=eth0 CNI_PATH=dist %s", container_id, netnspath, k8s_env)

	// Run the CNI plugin passing in the supplied netconf
	//TODO - Get rid of this PLUGIN thing and use netconf instead
	subProcess := exec.Command("bash", "-c", fmt.Sprintf("%s dist/%s", cni_env, os.Getenv("PLUGIN")), netconf)
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

func DeleteContainer(netconf, netnspath, name string) (session *gexec.Session, err error) {
	netnsname := path.Base(netnspath)
	container_id := netnsname[:10]
	var k8s_env = ""
	if name != "" {

		k8s_env = fmt.Sprintf("CNI_ARGS=\"K8S_POD_NAME=%s;K8S_POD_NAMESPACE=test;K8S_POD_INFRA_CONTAINER_ID=whatever\"", name)
	}

	// Set up the env for running the CNI plugin
	cni_env := fmt.Sprintf("CNI_COMMAND=DEL CNI_CONTAINERID=%s CNI_NETNS=%s CNI_IFNAME=eth0 CNI_PATH=dist %s", container_id, netnspath, k8s_env)

	// Run the CNI plugin passing in the supplied netconf
	subProcess := exec.Command("bash", "-c", fmt.Sprintf("%s dist/%s", cni_env, os.Getenv("PLUGIN")), netconf)
	stdin, err := subProcess.StdinPipe()
	if err != nil {
		panic("some error found")
	}

	io.WriteString(stdin, netconf)
	io.WriteString(stdin, "\n")
	stdin.Close()

	session, err = gexec.Start(subProcess, ginkgo.GinkgoWriter, ginkgo.GinkgoWriter)
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

func CmdWithStdin(cmd, stdin_string string) string {
	//fmt.Println("Running command:", cmd)
	//fmt.Println("stdin:", stdin_string)
	subProcess := exec.Command("bash", "-c", cmd)
	stdin, err := subProcess.StdinPipe()
	if err != nil {
		panic("some error found")
	}

	stdout_buf := new(bytes.Buffer)
	stderr_buf := new(bytes.Buffer)

	subProcess.Stdout = stdout_buf
	subProcess.Stderr = stderr_buf

	io.WriteString(stdin, stdin_string)
	io.WriteString(stdin, "\n")
	stdin.Close()

	if err = subProcess.Start(); err != nil {
		fmt.Println("An error occured: ", err)
	}

	err = subProcess.Wait()
	//if err != nil || stderr_buf.Len() != 0 {
	//	fmt.Println(err)
	//	fmt.Println(stdout_buf.String())
	//	fmt.Println("Processes completed STDERR:", stderr_buf.String())
	//	panic("some error found")
	//}

	return stdout_buf.String()
}
