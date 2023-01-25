// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.

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

package node

import (
	"bufio"
	"fmt"
	gonet "net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	ETCD_KEY_NODE_FILE                  = "/etc/calico/certs/key.pem"
	ETCD_CERT_NODE_FILE                 = "/etc/calico/certs/cert.crt"
	ETCD_CA_CERT_NODE_FILE              = "/etc/calico/certs/ca_cert.crt"
	FELIX_CONFIG_NODE_FILE              = "/etc/calico/felix.cfg"
	AUTODETECTION_METHOD_FIRST          = "first-found"
	AUTODETECTION_METHOD_CAN_REACH      = "can-reach="
	AUTODETECTION_METHOD_INTERFACE      = "interface="
	AUTODETECTION_METHOD_SKIP_INTERFACE = "skip-interface="
)

var (
	checkLogTimeout = 10 * time.Second
	backendMatch    = regexp.MustCompile("^(none|bird)$")
)

// Run function collects diagnostic information and logs
func Run(args []string) error {
	var err error
	doc := `Usage:
  <BINARY_NAME> node run [--ip=<IP>] [--ip6=<IP6>] [--as=<AS_NUM>]
                     [--name=<NAME>]
                     [--ip-autodetection-method=<IP_AUTODETECTION_METHOD>]
                     [--ip6-autodetection-method=<IP6_AUTODETECTION_METHOD>]
                     [--log-dir=<LOG_DIR>]
                     [--node-image=<DOCKER_IMAGE_NAME>]
                     [--backend=(bird|none)]
                     [--config=<CONFIG>]
                     [--felix-config=<CONFIG>]
                     [--no-default-ippools]
                     [--dryrun]
                     [--init-system]
                     [--allow-version-mismatch]

Options:
  -h --help                Show this screen.
     --name=<NAME>         The name of the Calico node.  If this is not
                           supplied it defaults to the host name.
     --as=<AS_NUM>         Set the AS number for this node.  If omitted, it
                           will use the value configured on the node resource.
                           If there is no configured value and --as option is
                           omitted, the node will inherit the global AS number
     --ip=<IP>             Set the local IPv4 routing address for this node.
                           If omitted, it will use the value configured on the
                           node resource.  If there is no configured value
                           and the --ip option is omitted, the node will
                           attempt to autodetect an IP address to use.  Use a
                           value of 'autodetect' to always force autodetection
                           of the IP each time the node starts.
     --ip6=<IP6>           Set the local IPv6 routing address for this node.
                           If omitted, it will use the value configured on the
                           node resource.  If there is no configured value
                           and the --ip6 option is omitted, the node will not
                           route IPv6.  Use a value of 'autodetect' to force
                           autodetection of the IP each time the node starts.
     --ip-autodetection-method=<IP_AUTODETECTION_METHOD>
                           Specify the autodetection method for detecting the
                           local IPv4 routing address for this node.  The valid
                           options are:
                           > first-found
                             Use the first valid IP address on the first
                             enumerated interface (common known exceptions are
                             filtered out, e.g. the docker bridge).  It is not
                             recommended to use this if you have multiple
                             external interfaces on your host.
                           > can-reach=<IP OR DOMAINNAME>
                             Use the interface determined by your host routing
                             tables that will be used to reach the supplied
                             destination IP or domain name.
                           > interface=<IFACE NAME REGEX LIST>
                             Use the first valid IP address found on interfaces
                             named as per the first matching supplied interface
			     name regex. Regexes are separated by commas
			     (e.g. eth.*,enp0s.*).
			   > skip-interface=<IFACE NAME REGEX LIST>
			     Use the first valid IP address on the first
			     enumerated interface (same logic as first-found
			     above) that does NOT match with any of the
			     specified interface name regexes. Regexes are
			     separated by commas (e.g. eth.*,enp0s.*).
                           [default: first-found]
     --ip6-autodetection-method=<IP6_AUTODETECTION_METHOD>
                           Specify the autodetection method for detecting the
                           local IPv6 routing address for this node.  See
                           ip-autodetection-method flag for valid options.
                           [default: first-found]
     --log-dir=<LOG_DIR>   The directory containing Calico logs.
                           [default: /var/log/calico]
     --node-image=<DOCKER_IMAGE_NAME>
                           Docker image to use for Calico's per-node container.
                           [default: quay.io/calico/node:latest]
     --backend=(bird|none)
                           Specify which networking backend to use.  When set
                           to "none", Calico node runs in policy only mode.
                           [default: bird]
     --dryrun              Output the appropriate command, without starting the
                           container.
     --init-system         Run the appropriate command to use with an init
                           system.
     --no-default-ippools  Do not create default pools upon startup.
                           Default IP pools will be created if this is not set
                           and there are no pre-existing Calico IP pools.
  -c --config=<CONFIG>     Path to the file containing connection
                           configuration in YAML or JSON format.
                           [default: ` + constants.DefaultConfigPath + `]
     --felix-config=<CONFIG>
                           Path to the file containing Felix
                           configuration in YAML or JSON format.
     --allow-version-mismatch
	                       Allow client and cluster versions mismatch.

Description:
  This command is used to start a calico/node container instance which provides
  Calico networking and network policy on your compute host.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	binaryName, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", binaryName)

	arguments, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		log.Info(err)
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(arguments) == 0 {
		return nil
	}

	// Note: Intentionally not check version mismatch for this command

	// Extract all the parameters.
	ipv4 := argutils.ArgStringOrBlank(arguments, "--ip")
	ipv6 := argutils.ArgStringOrBlank(arguments, "--ip6")
	ipv4ADMethod := argutils.ArgStringOrBlank(arguments, "--ip-autodetection-method")
	ipv6ADMethod := argutils.ArgStringOrBlank(arguments, "--ip6-autodetection-method")
	logDir := argutils.ArgStringOrBlank(arguments, "--log-dir")
	asNumber := argutils.ArgStringOrBlank(arguments, "--as")
	img := argutils.ArgStringOrBlank(arguments, "--node-image")
	backend := argutils.ArgStringOrBlank(arguments, "--backend")
	dryrun := argutils.ArgBoolOrFalse(arguments, "--dryrun")
	name := argutils.ArgStringOrBlank(arguments, "--name")
	nopools := argutils.ArgBoolOrFalse(arguments, "--no-default-ippools")
	config := argutils.ArgStringOrBlank(arguments, "--config")
	felixConfig := argutils.ArgStringOrBlank(arguments, "--felix-config")
	initSystem := argutils.ArgBoolOrFalse(arguments, "--init-system")

	// Validate parameters.
	if ipv4 != "" && ipv4 != "autodetect" {
		ip := argutils.ValidateIP(ipv4)
		if ip.Version() != 4 {
			return fmt.Errorf("Error executing command: --ip is wrong IP version")
		}
	}
	if ipv6 != "" && ipv6 != "autodetect" {
		ip := argutils.ValidateIP(ipv6)
		if ip.Version() != 6 {
			return fmt.Errorf("Error executing command: --ip6 is wrong IP version")
		}
	}
	if asNumber != "" {
		// The calico/node image does not accept dotted notation for
		// the AS number, so convert.
		asNumber = argutils.ValidateASNumber(asNumber).String()
	}

	if !backendMatch.MatchString(backend) {
		return fmt.Errorf("Error executing command: unknown backend '%s'", backend)
	}

	// Validate the IP autodetection methods if specified.
	if err := validateIpAutodetectionMethod(ipv4ADMethod, 4); err != nil {
		return err
	}
	if err := validateIpAutodetectionMethod(ipv6ADMethod, 6); err != nil {
		return err
	}

	// Use the hostname if a name is not specified.  We should always
	// pass in a fixed value to the node container so that if the user
	// changes the hostname, the calico/node won't start using a different
	// name.
	if name == "" {
		name, err = names.Hostname()
		if err != nil || name == "" {
			return fmt.Errorf("Error executing command: unable to determine node name")
		}
	}

	// Load the etcd configuration.
	cfg, err := clientmgr.LoadClientConfig(config)
	if err != nil {
		return fmt.Errorf("Error executing command: invalid config file")
	}
	if cfg.Spec.DatastoreType != apiconfig.EtcdV3 {
		return fmt.Errorf("Error executing command: unsupported backend specified in config")
	}
	etcdcfg := cfg.Spec.EtcdConfig

	// Create a mapping of environment variables to values.
	envs := map[string]string{
		"NODENAME":                  name,
		"CALICO_NETWORKING_BACKEND": backend,
	}

	if nopools {
		envs["NO_DEFAULT_POOLS"] = "true"
	}
	if ipv4ADMethod != AUTODETECTION_METHOD_FIRST {
		envs["IP_AUTODETECTION_METHOD"] = ipv4ADMethod
	}
	if ipv6ADMethod != AUTODETECTION_METHOD_FIRST {
		envs["IP6_AUTODETECTION_METHOD"] = ipv6ADMethod
	}
	if asNumber != "" {
		envs["AS"] = asNumber
	}
	if ipv4 != "" {
		envs["IP"] = ipv4
	}
	if ipv6 != "" {
		envs["IP6"] = ipv6
	}

	// Create a struct for volumes to mount.
	type vol struct {
		hostPath      string
		containerPath string
	}

	// vols is a slice of volume bindings.
	vols := []vol{
		{hostPath: logDir, containerPath: "/var/log/calico"},
		{hostPath: "/var/run/calico", containerPath: "/var/run/calico"},
		{hostPath: "/var/lib/calico", containerPath: "/var/lib/calico"},
		{hostPath: "/lib/modules", containerPath: "/lib/modules"},
		{hostPath: "/run", containerPath: "/run"},
	}

	// Attach Felix config if file path given
	if felixConfig != "" {
		vols = append(vols, vol{hostPath: felixConfig, containerPath: FELIX_CONFIG_NODE_FILE})
	}

	envs["ETCD_ENDPOINTS"] = etcdcfg.EtcdEndpoints
	envs["ETCD_DISCOVERY_SRV"] = etcdcfg.EtcdDiscoverySrv
	if etcdcfg.EtcdCACertFile != "" {
		envs["ETCD_CA_CERT_FILE"] = ETCD_CA_CERT_NODE_FILE
		vols = append(vols, vol{hostPath: etcdcfg.EtcdCACertFile, containerPath: ETCD_CA_CERT_NODE_FILE})

	}
	if etcdcfg.EtcdKeyFile != "" && etcdcfg.EtcdCertFile != "" {
		envs["ETCD_KEY_FILE"] = ETCD_KEY_NODE_FILE
		vols = append(vols, vol{hostPath: etcdcfg.EtcdKeyFile, containerPath: ETCD_KEY_NODE_FILE})
		envs["ETCD_CERT_FILE"] = ETCD_CERT_NODE_FILE
		vols = append(vols, vol{hostPath: etcdcfg.EtcdCertFile, containerPath: ETCD_CERT_NODE_FILE})
	}

	// Create the Docker command to execute (or display).  Start with the
	// fixed parts.  If this is not for an init system, we'll include the
	// detach flag (to prevent the command blocking), and use Dockers built
	// in restart mechanism.  If this is for an init-system we want the
	// command to remain attached and for Docker to remove the dead
	// container so that it can be restarted by the init system.
	cmd := []string{"docker", "run", "--net=host", "--privileged",
		"--name=calico-node"}
	if initSystem {
		cmd = append(cmd, "--rm")
	} else {
		cmd = append(cmd, "-d", "--restart=always")
	}

	// Add the environment variable pass-through.
	for k, v := range envs {
		cmd = append(cmd, "-e", fmt.Sprintf("%s=%s", k, v))
	}

	// Add the volume mounts.
	for _, v := range vols {
		cmd = append(cmd, "-v", fmt.Sprintf("%s:%s", v.hostPath, v.containerPath))
	}

	// Add the container image name
	cmd = append(cmd, img)

	if dryrun {
		fmt.Println("Use the following command to start the calico/node container:")
		fmt.Printf("\n%s\n\n", strings.Join(cmd, " "))

		if !initSystem {
			fmt.Println("If you are running calico/node in an init system, use the --init-system flag")
			fmt.Println("to display the appropriate start and stop commands.")
		} else {
			fmt.Println("Use the following command to stop the calico/node container:")
			fmt.Printf("\ndocker stop calico-node\n\n")
		}
		return nil
	}

	// This is not a dry run.  Check that we are running as root.
	enforceRoot()

	// Normally, Felix will load the modules it needs, but when running inside a
	// container it might not be able to do so. Ensure the required modules are
	// loaded each time the node starts.
	// We only make a best effort attempt because the command may fail if the
	// modules are built in.
	if !runningInContainer() {
		log.Info("Running in container")
		loadModules()
		if err := setupIPForwarding(); err != nil {
			return err
		}
		setNFConntrackMax()
	}

	// Make sure the calico-node is not already running before we attempt
	// to start the node.
	fmt.Println("Removing old calico-node container (if running).")
	err = exec.Command("docker", "rm", "-f", "calico-node").Run()
	if err != nil {
		log.WithError(err).Debug("Unable to remove calico-node container (ok if container was not running)")
	}

	// Run the docker command.
	fmt.Println("Running the following command to start calico-node:")
	fmt.Printf("\n%s\n\n", strings.Join(cmd, " "))
	fmt.Println("Image may take a short time to download if it is not available locally.")

	// Now execute the actual Docker run command and check for the
	// unable to find image message.
	runCmd := exec.Command(cmd[0], cmd[1:]...)
	if output, err := runCmd.CombinedOutput(); err != nil {
		errStr := fmt.Sprintf("Error executing command: %v\n", err)
		for _, line := range strings.Split(string(output), "/n") {
			errStr += fmt.Sprintf(" | %s/n", line)
		}
		return fmt.Errorf(errStr)
	}

	// Create the command to follow the docker logs for the calico/node
	fmt.Print("Container started, checking progress logs.\n\n")
	logCmd := exec.Command("docker", "logs", "--follow", "calico-node")

	// Get the stdout pipe
	outPipe, err := logCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("Error executing command:  unable to check calico/node logs: %v", err)
	}
	outScanner := bufio.NewScanner(outPipe)

	// Start following the logs.
	err = logCmd.Start()
	if err != nil {
		return fmt.Errorf("Error executing command:  unable to check calico/node logs: %v", err)
	}

	// Protect against calico processes taking too long to start, or docker
	// logs hanging without output.
	time.AfterFunc(checkLogTimeout, func() {
		err = logCmd.Process.Kill()
		if err != nil {
			fmt.Printf("Error attempting to kill process: check logs for details")
		}
	})

	// Read stdout until the node fails, or until we see the output
	// indicating success.
	started := false
	for outScanner.Scan() {
		line := outScanner.Text()
		fmt.Println(line)
		if line == "Calico node started successfully" {
			started = true
			break
		}
	}

	// Kill the process if it is still running.
	err = logCmd.Process.Kill()
	if err != nil {
		return fmt.Errorf("Error attempting to kill process: check logs for details")
	}
	// Wait for the logging process to terminate.  We expect an error here, because we
	// just killed it.
	err = logCmd.Wait()
	log.WithError(err).Info("Expected error after killing docker logs command")

	// If we didn't successfully start then notify the user.
	if outScanner.Err() != nil {
		return fmt.Errorf("Error executing command: error reading calico/node logs, check logs for details")
	} else if !started {
		return fmt.Errorf("Error executing command: calico/node has terminated, check logs for details")
	}

	return nil
}

// runningInContainer returns whether we are running calicoctl within a container.
func runningInContainer() bool {
	v := os.Getenv("CALICO_CTL_CONTAINER")
	return v != ""
}

func loadModules() {
	cmd := []string{"modprobe", "-a", "xt_set", "ip6_tables"}
	fmt.Printf("Running command to load modules: %s\n", strings.Join(cmd, " "))
	err := exec.Command(cmd[0], cmd[1:]...).Run()
	if err != nil {
		log.Warning(err)
	}
}

func setupIPForwarding() error {
	fmt.Println("Enabling IPv4 forwarding")
	err := os.WriteFile("/proc/sys/net/ipv4/ip_forward",
		[]byte("1"), 0)
	if err != nil {
		return fmt.Errorf("ERROR: Could not enable ipv4 forwarding")
	}

	if _, err := os.Stat("/proc/sys/net/ipv6"); err == nil {
		fmt.Println("Enabling IPv6 forwarding")
		err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding",
			[]byte("1"), 0)
		if err != nil {
			return fmt.Errorf("ERROR: Could not enable ipv6 forwarding")
		}
	}

	return nil
}

func setNFConntrackMax() {
	// A common problem on Linux systems is running out of space in the conntrack
	// table, which can cause poor iptables performance. This can happen if you
	// run a lot of workloads on a given host, or if your workloads create a lot
	// of TCP connections or bidirectional UDP streams.
	//
	// To avoid this becoming a problem, we recommend increasing the conntrack
	// table size. To do so, run the following commands:
	fmt.Println("Increasing conntrack limit")
	err := os.WriteFile("/proc/sys/net/netfilter/nf_conntrack_max",
		[]byte("1000000"), 0)
	if err != nil {
		fmt.Println("WARNING: Could not set nf_contrack_max. This may have an impact at scale.")
	}
}

// Validate the IP autodection method string.
func validateIpAutodetectionMethod(method string, version int) error {
	if method == AUTODETECTION_METHOD_FIRST {
		// Auto-detection method is "first-found", no additional validation
		// required.
		return nil
	} else if strings.HasPrefix(method, AUTODETECTION_METHOD_CAN_REACH) {
		// Auto-detection method is "can-reach", validate that the address
		// resolves to at least one IP address of the required version.
		addrStr := strings.TrimPrefix(method, AUTODETECTION_METHOD_CAN_REACH)
		ips, err := gonet.LookupIP(addrStr)
		if err != nil {
			return fmt.Errorf("Error executing command: cannot resolve address specified for IP autodetection: %s", addrStr)
		}

		for _, ip := range ips {
			cip := net.IP{IP: ip}
			if cip.Version() == version {
				return nil
			}
		}
		return fmt.Errorf("Error executing command: address for IP autodetection does not resolve to an IPv%d address: %s", version, addrStr)
	} else if strings.HasPrefix(method, AUTODETECTION_METHOD_INTERFACE) {
		// Auto-detection method is "interface", validate that the interface
		// regex is a valid golang regex.
		ifStr := strings.TrimPrefix(method, AUTODETECTION_METHOD_INTERFACE)

		// Regexes are provided in a string separated by ","
		ifRegexes := strings.Split(ifStr, ",")
		for _, ifRegex := range ifRegexes {
			if _, err := regexp.Compile(ifStr); err != nil {
				return fmt.Errorf("Error executing command: invalid interface regex specified for IP autodetection: %s", ifRegex)
			}
		}
		return nil
	} else if strings.HasPrefix(method, AUTODETECTION_METHOD_SKIP_INTERFACE) {
		// Auto-detection method is "skip-interface", validate that the
		// interface regexes used are valid golang regexes.
		ifStr := strings.TrimPrefix(method, AUTODETECTION_METHOD_SKIP_INTERFACE)

		// Regexes are provided in a string separated by ","
		ifRegexes := strings.Split(ifStr, ",")
		for _, ifRegex := range ifRegexes {
			if _, err := regexp.Compile(ifRegex); err != nil {
				return fmt.Errorf("Error executing command: invalid interface regex specified for IP autodetection: %s", ifRegex)
			}
		}
		return nil
	}

	return fmt.Errorf("Error executing command: invalid IP autodetection method: %s", method)
}
