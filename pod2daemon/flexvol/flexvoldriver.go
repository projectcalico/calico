// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

// Flexvolume driver that is invoked by kubelet when a pod installs a flexvolume drive
// of type nodeagent/uds
// This driver communicates to the nodeagent using either
//   * (Default) writing credentials of workloads to a file or
//   * gRPC message defined at protos/nodeagementmgmt.proto,
// to shares the properties of the pod with nodeagent.
//
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log/syslog"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	creds "github.com/projectcalico/calico/pod2daemon/flexvol/creds"
)

// Response is the output of Flex volume driver to the kubelet.
type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	// Is attached resp.
	Attached bool `json:"attached,omitempty"`
	// Dev mount resp.
	Device string `json:"device,omitempty"`
	// Volumen name resp.
	VolumeName string `json:"volumename,omitempty"`
}

type Capabilities struct {
	Attach bool `json:"attach"`
}

// Response to the 'init' command.
// We want to explicitly set and send Attach: false
// that is why it is separated from the Response struct.
type InitResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	// Capability resp.
	Capabilities *Capabilities `json:"capabilities"`
}

// ConfigurationOptions may be used to setup the driver.
// These are optional and most users will not depend on them and will instead use the defaults.
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
	// Log level for loggint to node syslog. Options: INFO|WARNING
	// Default: WARNING
	LogLevel string `json:"log_level,omitempty"`
}

// FlexVolumeInputs is the structure used by kubelet to notify it of
// volume mounts/unmounts.
type FlexVolumeInputs struct {
	Uid            string `json:"kubernetes.io/pod.uid"`
	Name           string `json:"kubernetes.io/pod.name"`
	Namespace      string `json:"kubernetes.io/pod.namespace"`
	ServiceAccount string `json:"kubernetes.io/serviceAccount.name"`
}

const (
	SYSLOGTAG       string = "FlexVolNodeAgent"
	VER_K8S         string = "1.8"
	VER             string = "0.1"
	CONFIG_FILE     string = "/etc/flexvolume/nodeagent.json"
	NODEAGENT_HOME  string = "/var/run/nodeagent"
	MOUNT_DIR       string = "/mount"
	CREDS_DIR       string = "/creds"
	LOG_LEVEL_WARN  string = "WARNING"
	syslogOnlyTrue  bool   = true
	syslogOnlyFalse bool   = false
)

var (
	// logWriter is used to notify syslog of the functionality of the driver.
	logWriter *syslog.Writer
	// configuration is the active configuration that is being used by the driver.
	configuration *ConfigurationOptions
	// defaultConfiguration is the default configuration for the driver.
	defaultConfiguration ConfigurationOptions = ConfigurationOptions{
		K8sVersion:                  VER_K8S,
		NodeAgentManagementHomeDir:  NODEAGENT_HOME,
		NodeAgentWorkloadHomeDir:    NODEAGENT_HOME + MOUNT_DIR,
		NodeAgentCredentialsHomeDir: NODEAGENT_HOME + CREDS_DIR,
		LogLevel:                    LOG_LEVEL_WARN,
	}

	rootCmd = &cobra.Command{
		Use:           "flexvoldrv",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	initCmd = &cobra.Command{
		Use:   "init",
		Short: "Flex volume init command.",
		Long:  "Flex volume init command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("init takes no arguments.")
			}
			return initCommand()
		},
	}

	mountCmd = &cobra.Command{
		Use:   "mount",
		Short: "Flex volume mount command.",
		Long:  "Flex volume mount command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("mount takes 2 args.")
			}
			return mount(args[0], args[1])
		},
	}

	unmountCmd = &cobra.Command{
		Use:   "unmount",
		Short: "Flex volume unmount command.",
		Long:  "Flex volume unmount command.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("unmount takes 1 args.")
			}
			return unmount(args[0])
		},
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Long:  "Flex volume driver version",
		RunE: func(c *cobra.Command, args []string) error {
			fmt.Printf("Version is %s\n", VER)
			return nil
		},
	}
)

// initCommand handles the init command for the driver.
func initCommand() error {
	if configuration.K8sVersion == "1.8" {
		resp, err := json.Marshal(&InitResponse{Status: "Success", Message: "Init ok.", Capabilities: &Capabilities{Attach: false}})
		if err != nil {
			return err
		}
		fmt.Println(string(resp))
		return nil
	}
	return genericSuccess("init", "", "Init ok.")
}

// checkValidMountOpts checks if there are sufficient inputs to
// call node agent.
func checkValidMountOpts(opts string) (*creds.Credentials, string, bool) {
	ninputs := FlexVolumeInputs{}
	err := json.Unmarshal([]byte(opts), &ninputs)
	if err != nil {
		return nil, "", false
	}

	return &creds.Credentials{
		UID:            ninputs.Uid,
		Workload:       ninputs.Name,
		Namespace:      ninputs.Namespace,
		ServiceAccount: ninputs.ServiceAccount,
	}, ninputs.Uid, true
}

// doMount handles a new workload mounting the flex volume drive. It will:
// * mount a tmpfs at the destinationDir(ectory) of the workload created by the kubelet.
// * create a sub-directory ('nodeagent') there
// * do a bind mount of the nodeagent's directory on the node to the destinationDir/nodeagent.
func doMount(destinationDir string, ninputs *creds.Credentials, workloadPath string) error {
	inp := strings.Join([]string{destinationDir, workloadPath}, "|")
	newDir := configuration.NodeAgentWorkloadHomeDir + "/" + workloadPath
	err := os.MkdirAll(newDir, 0777)
	if err != nil {
		logError("doMount", inp, fmt.Sprintf("failed to create directory %s\n", newDir), syslogOnlyTrue)
		return err
	}

	// Not really needed but attempt to workaround:
	// https://github.com/kubernetes/kubernetes/blob/61ac9d46382884a8bd9e228da22bca5817f6d226/pkg/util/mount/mount_linux.go
	cmdMount := exec.Command("/bin/mount", "-t", "tmpfs", "-o", "size=8K", "tmpfs", destinationDir)
	err = cmdMount.Run()
	if err != nil {
		os.RemoveAll(newDir)
		return err
	}

	newDestianationDir := destinationDir + "/nodeagent"
	err = os.MkdirAll(newDestianationDir, 0777)
	if err != nil {
		cmd := exec.Command("/bin/umount", destinationDir)
		e := cmd.Run()
		if e != nil {
			logError("doMount", inp, fmt.Sprintf("failed to unmount %s\n", destinationDir), syslogOnlyTrue)
		}
		e = os.RemoveAll(newDir)
		if e != nil {
			logError("doMount", inp, fmt.Sprintf("failed to clear %s\n", newDir), syslogOnlyTrue)
		}
		return err
	}

	// Do a bind mount
	cmd := exec.Command("/bin/mount", "--bind", newDir, newDestianationDir)
	err = cmd.Run()
	if err != nil {
		cmd = exec.Command("/bin/umount", destinationDir)
		e := cmd.Run()
		if e != nil {
			logError("doMount", inp, fmt.Sprintf("failed to unmount %s\n", destinationDir), syslogOnlyTrue)
		}
		e = os.RemoveAll(newDir)
		if e != nil {
			logError("doMount", inp, fmt.Sprintf("failed to clear %s\n", newDir), syslogOnlyTrue)
		}
		return err
	}

	return nil
}

// doUnmount will unmount the directory
func doUnmount(dir string) error {
	cmd := exec.Command("/bin/umount", dir)
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

// mount handles the mount command to the driver.
func mount(dir, opts string) error {
	inp := strings.Join([]string{dir, opts}, "|")

	ninputs, workloadPath, s := checkValidMountOpts(opts)
	if !s {
		logError("mount", inp, "Incomplete inputs", syslogOnlyFalse)
		return fmt.Errorf("invalid mount options")
	}

	if err := doMount(dir, ninputs, workloadPath); err != nil {
		sErr := "Failure to mount: " + err.Error()
		logError("mount", inp, sErr, syslogOnlyFalse)
		return err
	}

	if err := addCredentialFile(ninputs); err != nil {
		sErr := "Failure to create credentials: " + err.Error()
		logError("mount", inp, sErr, syslogOnlyFalse)
		return err
	}

	return genericSuccess("mount", inp, "Mount ok.")
}

// unmount handles the unmount command to the driver.
func unmount(dir string) error {
	var emsgs []string
	// Stop the listener.
	// /var/lib/kubelet/pods/20154c76-bf4e-11e7-8a7e-080027631ab3/volumes/nodeagent~uds/test-volume/
	// /var/lib/kubelet/pods/2dc75e9a-cbec-11e7-b158-0800270da466/volumes/nodeagent~uds/test-volume
	comps := strings.Split(dir, "/")
	if len(comps) < 6 {
		sErr := fmt.Sprintf("Failure to notify nodeagent dir %v", dir)
		logError("unmount", dir, sErr, syslogOnlyFalse)
		return fmt.Errorf("invalid path to unmount")
	}

	uid := comps[5]
	// TBD: Check if uid is the correct format.
	naInp := &creds.Credentials{UID: uid}
	if err := removeCredentialFile(naInp); err != nil {
		// Go ahead and finish the unmount; no need to hold up kubelet.
		emsgs = append(emsgs, "Failure to delete credentials file: "+err.Error())
	}

	// unmount the bind mount
	err := doUnmount(dir + "/nodeagent")
	if err != nil {
		logError("umount", dir, fmt.Sprintf("failed to unmount %s/nodeagent\n", dir), syslogOnlyTrue)
	}
	// unmount the tmpfs
	err = doUnmount(dir)
	if err != nil {
		logError("unmount", dir, fmt.Sprintf("failed to unmount %s\n", dir), syslogOnlyTrue)
	}
	// delete the directory that was created.
	delDir := strings.Join([]string{configuration.NodeAgentWorkloadHomeDir, uid}, "/")
	err = os.Remove(delDir)
	if err != nil {
		emsgs = append(emsgs, fmt.Sprintf("unmount del failure %s: %s", delDir, err.Error()))
		// go ahead and return indicating success
	}

	if len(emsgs) == 0 {
		emsgs = append(emsgs, "Unmount Ok")
	}

	return genericSuccess("unmount", dir, strings.Join(emsgs, ","))
}

// genericSuccess prints a success message to the kubelet.
func genericSuccess(caller, inp, msg string) error {
	resp, err := json.Marshal(&Response{Status: "Success", Message: msg})
	if err != nil {
		return err
	}

	fmt.Println(string(resp))
	logToSys(caller, inp, string(resp))
	return nil
}

// logError prints an error message to the kubelet and the system log. The 'syslogOnly' argument can be used to prevent messages from
// getting sent to kubelet. This option should be used if a type of error can lead to a flood of similar messages, such as in
// periodic activity or in retry loops.
func logError(caller, inp, msg string, syslogOnly bool) {
	resp, err := json.Marshal(&Response{Status: "Failure", Message: msg})
	if err == nil {
		if !syslogOnly {
			fmt.Println(string(resp))
		}
		logToSys(caller, inp, string(resp))
	}
}

// genericUnsupported is to print a un-supported response to the kubelet.
func genericUnsupported(caller, inp, msg string) error {
	resp, err := json.Marshal(&Response{Status: "Not supported", Message: msg})
	if err != nil {
		return err
	}

	fmt.Println(string(resp))
	logToSys(caller, inp, string(resp))
	return nil
}

// logToSys is a helper routine to genericSuccess(), logError() and genericUnsupported().
// Routines needing to log messages should call those functions and NOT logToSys() or logWriter methods directly.
func logToSys(caller, inp, opts string) {
	if logWriter == nil {
		return
	}

	opt := strings.Join([]string{caller, inp, opts}, "|")

	if configuration.LogLevel == LOG_LEVEL_WARN {
		_ = logWriter.Warning(opt)
	} else {
		_ = logWriter.Info(opt)
	}
}

// addCredentialFile is used to create a credential file when a workload with the flex-volume volume mounted is created.
func addCredentialFile(ninputs *creds.Credentials) error {
	//Make the directory and then write the ninputs as json to it.
	err := os.MkdirAll(configuration.NodeAgentCredentialsHomeDir, 0755)
	if err != nil {
		return err
	}

	var attrs []byte
	attrs, err = json.Marshal(ninputs)
	if err != nil {
		return err
	}

	credsFileTmp := strings.Join([]string{configuration.NodeAgentManagementHomeDir, ninputs.UID + ".json"}, "/")
	_ = ioutil.WriteFile(credsFileTmp, attrs, 0644)

	// Move it to the right location now.
	credsFile := strings.Join([]string{configuration.NodeAgentCredentialsHomeDir, ninputs.UID + ".json"}, "/")
	return os.Rename(credsFileTmp, credsFile)
}

// removeCredentialFile is used to delete a credential file when a workload with the flex-volume volume mounted is deleted.
func removeCredentialFile(ninputs *creds.Credentials) error {
	credsFile := strings.Join([]string{configuration.NodeAgentCredentialsHomeDir, ninputs.UID + ".json"}, "/")
	err := os.Remove(credsFile)
	return err
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
		logError("initConfiguration", "", fmt.Sprintf("Not able to read %s: %s\n", CONFIG_FILE, err.Error()), syslogOnlyTrue)
		return
	}

	var config ConfigurationOptions
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		logError("initConfiguration", "", fmt.Sprintf("Not able to parst %s: %s\n", CONFIG_FILE, err.Error()), syslogOnlyTrue)
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

	configuration = &config
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(mountCmd)
	rootCmd.AddCommand(unmountCmd)
}

func main() {
	// Note that we ignore the error from syslog.New() and continue without the capability to log to syslog.
	var err error
	logWriter, err = syslog.New(syslog.LOG_WARNING|syslog.LOG_DAEMON, SYSLOGTAG)
	if err == nil {
		defer logWriter.Close()
	}

	initConfiguration()

	if err = rootCmd.Execute(); err != nil {
		_ = genericUnsupported("not supported", "", err.Error())
	}
}
