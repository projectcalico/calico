// Flexvolume driver that is invoked by kubelet when a pod installs a flexvolume drive
// of type nodeagent/uds
// This driver communicates to the nodeagent/idagent using protos/nodeagementmgmt.proto
// and shares the properties of the pod with nodeagent/idagent.
//
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	nagent "github.com/colabsaumoh/proto-udsuspver/nodeagentmgmt"
	pb "github.com/colabsaumoh/proto-udsuspver/protos/mgmtintf_v1"
)

type Resp struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	// Is attached resp.
	Attached bool `json:"attached,omitempty"`
	// Dev mount resp.
	Device string `json:"device,omitempty"`
	// Volumen name resp.
	VolumeName string `json:"volumename,omitempty"`
}

// Response to the 'init' command.
// We want to explicitly set and send Attach: false
// that is why it is separated from the Resp struct.
type InitResp struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	// Capability resp.
	Attach bool `json:"attach"`
}

// ConfigurationOptions to setup the driver
type ConfigurationOptions struct {
	// Version of the Kubernetes cluster on which the driver is running.
	K8sVersion string `json:"k8s_version,omitempty"`
	// Location on the node's filesystem where the driver will host the
	// per workload directory and the credentials for the workload.
	// Default: /var/run/nodeagent
	NodeAgentManagementHomeDir string `json:"nodeagent_management_home,omitempty"`
	// Relative location to NodeAgentManagementHomeDir where per workload directory
	// will be created.
	// Default: /mount
	// For example: /mount here implies /var/run/nodeagent/mount/ directory
	// on the node.
	NodeAgentWorkloadHomeDir string `json:"nodeagent_workload_home,omitempty"`
	// Relative location to NodeAgentManagementHomeDir where per workload credential
	// files will be created.
	// Default: /creds
	// For example: /creds here implies /var/run/nodeagent/creds/ directory
	NodeAgentCredentialsHomeDir string `json:"nodeagent_credentials_home,omitempty"`
	// Whether node agent will be notified of workload using gRPC or by creating files in
	// NodeAgentCredentialsHomeDir.
	// Default: false
	UseGrpc bool `json:"use_grpc,omitempty"`
	// If UseGrpc is true then host the UDS socket here.
	// This is relative to NodeAgentManagementHomeDir
	// Default: mgmt.sock
	// For example: /mgmt/mgmt.sock implies /var/run/nodeagement/mgmt/mgmt.sock
	NodeAgentManagementApi string `json:"nodeagent_management_api,omitempty"`
	// Log level for loggint to node syslog. Options: INFO|WARNING
	// Default: WARNING
	LogLevel string `json:"log_level,omitempty"`
}

type NodeAgentInputs struct {
	Uid            string `json:"kubernetes.io/pod.uid"`
	Name           string `json:"kubernetes.io/pod.name"`
	Namespace      string `json:"kubernetes.io/pod.namespace"`
	ServiceAccount string `json:"kubernetes.io/serviceAccount.name"`
}

const (
	SYSLOGTAG      string = "FlexVolNodeAgent"
	VER_K8S        string = "1.8"
	VER            string = "0.1"
	CONFIG_FILE    string = "/etc/flexvolume/nodeagent.json"
	NODEAGENT_HOME string = "/var/run/nodeagent"
	MOUNT_DIR      string = "/mount"
	CREDS_DIR      string = "/creds"
	MGMT_SOCK      string = "/mgmt.sock"
	LOG_LEVEL_WARN string = "WARNING"
)

var (
	configuration        *ConfigurationOptions
	defaultConfiguration ConfigurationOptions = ConfigurationOptions{
		K8sVersion:                  VER_K8S,
		NodeAgentManagementHomeDir:  NODEAGENT_HOME,
		NodeAgentWorkloadHomeDir:    NODEAGENT_HOME + MOUNT_DIR,
		NodeAgentCredentialsHomeDir: NODEAGENT_HOME + CREDS_DIR,
		UseGrpc:                     false,
		NodeAgentManagementApi:      NODEAGENT_HOME + MGMT_SOCK,
		LogLevel:                    LOG_LEVEL_WARN,
	}
)

var (
	logWrt *syslog.Writer

	RootCmd = &cobra.Command{
		Use:           "flexvoldrv",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	InitCmd = &cobra.Command{
		Use:   "init",
		Short: "Flex volume init command.",
		Long:  "Flex volume init command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("init takes no arguments.")
			}
			return Init()
		},
	}

	MountCmd = &cobra.Command{
		Use:   "mount",
		Short: "Flex volume unmount command.",
		Long:  "Flex volume unmount command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("mount takes 2 args.")
			}
			return Mount(args[0], args[1])
		},
	}

	UnmountCmd = &cobra.Command{
		Use:   "unmount",
		Short: "Flex volume unmount command.",
		Long:  "Flex volume unmount command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("mount takes 1 args.")
			}
			return Unmount(args[0])
		},
	}

	VersionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Long:  "Flex volume driver version",
		RunE: func(c *cobra.Command, args []string) error {
			fmt.Printf("Version is %s\n", VER)
			return nil
		},
	}
)

func Init() error {
	if configuration.K8sVersion == "1.8" {
		resp, err := json.Marshal(&InitResp{Status: "Success", Message: "Init ok.", Attach: false})
		if err != nil {
			return err
		}
		fmt.Println(string(resp))
		return nil
	}
	return genericSucc("init", "", "Init ok.")
}

// checkValidMountOpts checks if there are sufficient inputs to
// call Nodeagent.
func checkValidMountOpts(opts string) (*pb.WorkloadInfo, bool) {
	ninputs := NodeAgentInputs{}
	err := json.Unmarshal([]byte(opts), &ninputs)
	if err != nil {
		return nil, false
	}

	wlInfo := pb.WorkloadInfo{
		Attrs: &pb.WorkloadInfo_WorkloadAttributes{
			Uid:            ninputs.Uid,
			Workload:       ninputs.Name,
			Namespace:      ninputs.Namespace,
			Serviceaccount: ninputs.ServiceAccount,
		},
		Workloadpath: ninputs.Uid,
	}
	return &wlInfo, true
}

func doMount(dstDir string, ninputs *pb.WorkloadInfo) error {
	newDir := configuration.NodeAgentWorkloadHomeDir + "/" + ninputs.Workloadpath
	err := os.MkdirAll(newDir, 0777)
	if err != nil {
		return err
	}

	// Not really needed but attempt to workaround:
	// https://github.com/kubernetes/kubernetes/blob/61ac9d46382884a8bd9e228da22bca5817f6d226/pkg/util/mount/mount_linux.go
	cmdMount := exec.Command("/bin/mount", "-t", "tmpfs", "-o", "size=8K", "tmpfs", dstDir)
	err = cmdMount.Run()
	if err != nil {
		os.RemoveAll(newDir)
		return err
	}

	newDstDir := dstDir + "/nodeagent"
	err = os.MkdirAll(newDstDir, 0777)
	if err != nil {
		cmd := exec.Command("/bin/unmount", dstDir)
		cmd.Run()
		os.RemoveAll(newDir)
		return err
	}

	// Do a bind mount
	cmd := exec.Command("/bin/mount", "--bind", newDir, newDstDir)
	err = cmd.Run()
	if err != nil {
		cmd = exec.Command("/bin/umount", dstDir)
		cmd.Run()
		os.RemoveAll(newDir)
		return err
	}

	return nil
}

func doUnmount(dir string) error {
	cmd := exec.Command("/bin/umount", dir)
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func Mount(dir, opts string) error {
	inp := dir + "|" + opts

	ninputs, s := checkValidMountOpts(opts)
	if s == false {
		return Failure("mount", inp, "Incomplete inputs")
	}

	if err := doMount(dir, ninputs); err != nil {
		sErr := "Failure to mount: " + err.Error()
		return Failure("mount", inp, sErr)
	}

	if configuration.UseGrpc == true {
		if err := AddListener(ninputs); err != nil {
			sErr := "Failure to notify nodeagent: " + err.Error()
			return Failure("mount", inp, sErr)
		}
	} else {
		if err := AddCredentialFile(ninputs); err != nil {
			sErr := "Failure to create credentials: " + err.Error()
			return Failure("mount", inp, sErr)
		}
	}

	return genericSucc("mount", inp, "Mount ok.")
}

func Unmount(dir string) error {
	var emsgs []string
	// Stop the listener.
	// /var/lib/kubelet/pods/20154c76-bf4e-11e7-8a7e-080027631ab3/volumes/nodeagent~uds/test-volume/
	// /var/lib/kubelet/pods/2dc75e9a-cbec-11e7-b158-0800270da466/volumes/nodeagent~uds/test-volume
	comps := strings.Split(dir, "/")
	if len(comps) < 6 {
		sErr := fmt.Sprintf("Failure to notify nodeagent dir %v", dir)
		return Failure("unmount", dir, sErr)
	}

	uid := comps[5]
	// TBD: Check if uid is the correct format.
	naInp := &pb.WorkloadInfo{
		Attrs:        &pb.WorkloadInfo_WorkloadAttributes{Uid: uid},
		Workloadpath: uid,
	}
	if configuration.UseGrpc == true {
		if err := DelListener(naInp); err != nil {
			sErr := "Failure to notify nodeagent: " + err.Error()
			return Failure("unmount", dir, sErr)
		}
	} else {
		if err := RemvoeCredentialFile(naInp); err != nil {
			// Go ahead and finish the unmount; no need to hold up kubelet.
			emsgs = append(emsgs, "Failure to delete credentials file: "+err.Error())
		}
	}

	// unmount the bind mount
	doUnmount(dir + "/nodeagent")
	// unmount the tmpfs
	doUnmount(dir)
	// delete the directory that was created.
	delDir := configuration.NodeAgentWorkloadHomeDir + "/" + uid
	err := os.Remove(delDir)
	if err != nil {
		emsgs = append(emsgs, fmt.Sprintf("unmount del failure %s: %s", delDir, err.Error()))
		// go head and return ok.
	}

	if len(emsgs) == 0 {
		emsgs = append(emsgs, "Unmount Ok")
	}

	return genericSucc("unmount", dir, strings.Join(emsgs, ","))
}

func printAndLog(caller, inp, s string) {
	fmt.Println(s)
	logToSys(caller, inp, s)
}

func genericSucc(caller, inp, msg string) error {
	resp, err := json.Marshal(&Resp{Status: "Success", Message: msg})
	if err != nil {
		return err
	}

	printAndLog(caller, inp, string(resp))
	return nil
}

func Failure(caller, inp, msg string) error {
	resp, err := json.Marshal(&Resp{Status: "Failure", Message: msg})
	if err != nil {
		return err
	}

	printAndLog(caller, inp, string(resp))
	return nil
}

func genericUnsupported(caller, inp, msg string) error {
	resp, err := json.Marshal(&Resp{Status: "Not supported", Message: msg})
	if err != nil {
		return err
	}

	printAndLog(caller, inp, string(resp))
	return nil
}

func logToSys(caller, inp, opts string) {
	if logWrt == nil {
		return
	}

	opt := strings.Join([]string{caller, inp, opts}, "|")
	if configuration.LogLevel == LOG_LEVEL_WARN {
		logWrt.Warning(opt)
	} else {
		logWrt.Info(opt)
	}
}

func AddListener(ninputs *pb.WorkloadInfo) error {
	client := nagent.ClientUds(configuration.NodeAgentManagementApi)
	if client == nil {
		return errors.New("Failed to create Nodeagent client.")
	}

	_, err := client.WorkloadAdded(ninputs)
	if err != nil {
		return err
	}

	client.Close()

	return nil
}

func AddCredentialFile(ninputs *pb.WorkloadInfo) error {
	//Make the directory and then write the ninputs as json to it.
	var err error
	err = os.MkdirAll(configuration.NodeAgentCredentialsHomeDir, 755)
	if err != nil {
		return err
	}

	var attrs []byte
	attrs, err = json.Marshal(ninputs.Attrs)
	if err != nil {
		return err
	}

	credsFileTmp := strings.Join([]string{configuration.NodeAgentManagementHomeDir, ninputs.Attrs.Uid + ".json"}, "/")
	err = ioutil.WriteFile(credsFileTmp, attrs, 0644)

	// Move it to the right location now.
	credsFile := strings.Join([]string{configuration.NodeAgentCredentialsHomeDir, ninputs.Attrs.Uid + ".json"}, "/")
	return os.Rename(credsFileTmp, credsFile)
}

func RemvoeCredentialFile(ninputs *pb.WorkloadInfo) error {
	credsFile := strings.Join([]string{configuration.NodeAgentCredentialsHomeDir, ninputs.Attrs.Uid + ".json"}, "/")
	err := os.Remove(credsFile)
	return err
}

func DelListener(ninputs *pb.WorkloadInfo) error {
	client := nagent.ClientUds(configuration.NodeAgentManagementApi)
	if client == nil {
		return errors.New("Failed to create Nodeagent client.")
	}

	_, err := client.WorkloadDeleted(ninputs)
	if err != nil {
		return err
	}

	client.Close()
	return nil
}

// If available read the configuration file and initialize the configuration options
// of the driver.
func initConfiguration() {
	configuration = &defaultConfiguration
	if _, err := os.Stat(CONFIG_FILE); err != nil {
		// Return quietly
		return
	}

	bytes, err := ioutil.ReadFile(CONFIG_FILE)
	if err != nil {
		logWrt.Warning(fmt.Sprintf("Not able to read %s: %s\n", CONFIG_FILE, err.Error()))
		return
	}

	var config ConfigurationOptions
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		logWrt.Warning(fmt.Sprintf("Not able to parst %s: %s\n", CONFIG_FILE, err.Error()))
		return
	}

	//fill in if missing configurations
	if len(config.NodeAgentManagementHomeDir) == 0 {
		config.NodeAgentManagementHomeDir = NODEAGENT_HOME
	}

	if len(config.NodeAgentWorkloadHomeDir) == 0 {
		config.NodeAgentWorkloadHomeDir = MOUNT_DIR
	}

	if len(config.NodeAgentCredentialsHomeDir) == 0 {
		config.NodeAgentCredentialsHomeDir = CREDS_DIR
	}

	if len(config.NodeAgentManagementApi) == 0 {
		config.NodeAgentManagementApi = MGMT_SOCK
	}

	if len(config.LogLevel) == 0 {
		config.LogLevel = LOG_LEVEL_WARN
	}

	if len(config.K8sVersion) == 0 {
		config.K8sVersion = VER_K8S
	}

	// Convert to absolute paths.
	var prefix string = ""
	if !strings.HasPrefix(config.NodeAgentWorkloadHomeDir, "/") {
		prefix = "/"
	}
	config.NodeAgentWorkloadHomeDir = strings.Join([]string{config.NodeAgentManagementHomeDir, config.NodeAgentWorkloadHomeDir}, prefix)

	prefix = ""
	if !strings.HasPrefix(config.NodeAgentCredentialsHomeDir, "/") {
		prefix = "/"
	}
	config.NodeAgentCredentialsHomeDir = strings.Join([]string{config.NodeAgentManagementHomeDir, config.NodeAgentCredentialsHomeDir}, prefix)

	prefix = ""
	if !strings.HasPrefix(config.NodeAgentManagementApi, "/") {
		prefix = "/"
	}
	config.NodeAgentManagementApi = strings.Join([]string{config.NodeAgentManagementHomeDir, config.NodeAgentManagementApi}, prefix)

	configuration = &config
}

func init() {
	RootCmd.AddCommand(VersionCmd)
	RootCmd.AddCommand(InitCmd)
	RootCmd.AddCommand(MountCmd)
	RootCmd.AddCommand(UnmountCmd)
}

func main() {
	var err error
	logWrt, err = syslog.New(syslog.LOG_WARNING|syslog.LOG_DAEMON, SYSLOGTAG)
	if err != nil {
		log.Fatal(err)
	}
	defer logWrt.Close()

	initConfiguration()

	if err = RootCmd.Execute(); err != nil {
		genericUnsupported("not supported", "", err.Error())
	}
}
