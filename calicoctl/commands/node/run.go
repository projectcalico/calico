// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	"fmt"
	"os"
	"os/exec"
	"strings"

	"regexp"

	"io/ioutil"

	log "github.com/Sirupsen/logrus"
	"github.com/docopt/docopt-go"
	"github.com/projectcalico/calico-containers/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico-containers/calicoctl/commands/argutils"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/etcd"
)

const (
	ETCD_KEY_NODE_FILE     = "/etc/calico/certs/key.pem"
	ETCD_CERT_NODE_FILE    = "/etc/calico/certs/cert.crt"
	ETCD_CA_CERT_NODE_FILE = "/etc/calico/certs/ca_cert.crt"
)

// Run function collects diagnostic information and logs
func Run(args []string) {
	var err error
	doc := `Usage:
  calicoctl node run [--ip=<IP>] [--ip6=<IP6>] [--as=<AS_NUM>]
                     [--name=<NAME>]
                     [--log-dir=<LOG_DIR>]
                     [--node-image=<DOCKER_IMAGE_NAME>]
                     [--backend=(bird|gobgp|none)]
                     [--config=<CONFIG>]
                     [--no-default-ippools]
                     [--dryrun]

Options:
  -h --help                Show this screen.
     --as=<AS_NUM>         The default AS number for this node.  If this is not
                           specified, the node will use the global AS number
                           (see 'calicoctl config' for details).
     --name=<NAME>         The name of the Calico node.  If this is not
                           supplied it defaults to the host name.
     --ip=<IP>             The local management address to use.  If this is not
                           specified, the node will attempt to auto-discover
                           the local IP address to use - however, it is
                           recommended to specify the required address to use.
     --ip6=<IP6>           The local IPv6 management address to use.  If this
                           is not specified, the node will not route IPv6.
     --log-dir=<LOG_DIR>   The directory containing Calico logs.
                           [default: /var/log/calico]
     --node-image=<DOCKER_IMAGE_NAME>
                           Docker image to use for Calico's
                           per-node container.
                           [default: calico/node:latest]
     --backend=(bird|gobgp|none)
                           Specify which networking backend to use.  When set
                           to "none", Calico node runs in policy only mode.
                           The option to run with gobgp is currently
                           experimental.
                           [default: bird]
     --dryrun              Output the appropriate Docker command, without
                           starting the container.
     --no-default-ippools  Do not create default pools upon startup.
                           Default IP pools will be created if this is not set
                           and there are no pre-existing Calico IP pools.
  -c --config=<CONFIG>     Filename containing connection configuration in
                           YAML or JSON format.
                           [default: /etc/calico/calicoctl.cfg]

Description:
  This command is used to start a Calico node container instance.  The
  Calico node is used to provide Calico networking on your compute host.

  This command is used to quickly start the Calico node container using Docker
  and by running with the --dryrun option can display the appropriate Docker
  command without actually running the command - this is useful if you intend
  to deploy Calico and therefore should include in your system startup
  configuraiton (e.g. systemd).

  For quickstart demonstration, this command may be run with no parameters.
`
	arguments, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		log.Info(err)
		fmt.Printf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.\n", strings.Join(args, " "))
		os.Exit(1)
	}
	if len(arguments) == 0 {
		return
	}

	// Extract all the parameters.
	ipv4 := argutils.ArgStringOrBlank(arguments, "--ip")
	ipv6 := argutils.ArgStringOrBlank(arguments, "--ip6")
	logDir := argutils.ArgStringOrBlank(arguments, "--log-dir")
	asNumber := argutils.ArgStringOrBlank(arguments, "--as")
	img := argutils.ArgStringOrBlank(arguments, "--node-image")
	backend := argutils.ArgStringOrBlank(arguments, "--backend")
	dryrun := argutils.ArgBoolOrFalse(arguments, "--dryrun")
	name := argutils.ArgStringOrBlank(arguments, "--name")
	nopools := argutils.ArgBoolOrFalse(arguments, "--no-default-ippools")
	config := argutils.ArgStringOrBlank(arguments, "--config")

	// Validate parameters.
	if ipv4 != "" {
		ip := argutils.ValidateIP(ipv4)
		if ip.Version() != 4 {
			fmt.Println("Error executing command: --ip is wrong IP version")
			os.Exit(1)
		}
	}
	if ipv6 != "" {
		ip := argutils.ValidateIP(ipv6)
		if ip.Version() != 6 {
			fmt.Println("Error executing command: --ip6 is wrong IP version")
			os.Exit(1)
		}
	}
	if asNumber != "" {
		argutils.ValidateASNumber(asNumber)
	}
	backendMatch := regexp.MustCompile("^(none|bird|gobgp)$")
	if !backendMatch.MatchString(backend) {
		fmt.Printf("Error executing command: unknown backend '%s'\n", backend)
		os.Exit(1)
	}

	// Use the hostname if a name is not specified.
	if name == "" {
		name, err = os.Hostname()
		if err != nil || name == "" {
			fmt.Println("Error executing command: unable to determine node name")
			os.Exit(1)
		}
	}

	// Load the etcd configuraiton.
	cfg, err := clientmgr.LoadClientConfig(config)
	if err != nil {
		fmt.Println("Error executing command: invalid config file")
		os.Exit(1)
	}
	if cfg.BackendType != api.EtcdV2 {
		fmt.Println("Error executing command: unsupported backend specified in config")
		os.Exit(1)
	}
	etcdcfg := cfg.BackendConfig.(*etcd.EtcdConfig)

	// Convert the nopools boolean to either an empty string or "true".
	noPoolsString := ""
	if nopools {
		noPoolsString = "true"
	}

	// Create a mapping of environment variables to values.
	envs := map[string]string{
		"HOSTNAME": name,
		"IP":       ipv4,
		"IP6":      ipv6,
		"CALICO_NETWORKING_BACKEND": backend,
		"AS":                        asNumber,
		"NO_DEFAULT_POOLS":          noPoolsString,
		"CALICO_LIBNETWORK_ENABLED": "true",
	}

	// Create a map of read only bindings.
	vols := map[string]string{
		logDir:                 "/var/log/calico",
		"/var/run/calico":      "/var/run/calico",
		"/lib/modules":         "/lib/modules",
		"/run/docker/plugins":  "/run/docker/plugins",
		"/var/run/docker.sock": "/var/run/docker.sock",
	}

	if etcdcfg.EtcdEndpoints == "" {
		envs["ETCD_AUTHORITY"] = etcdcfg.EtcdAuthority
		envs["ETCD_SCHEME"] = etcdcfg.EtcdScheme
		envs["ETCD_ENDPOINTS"] = ""
	} else {
		envs["ETCD_ENDPOINTS"] = etcdcfg.EtcdEndpoints
		envs["ETCD_AUTHORITY"] = ""
		envs["ETCD_SCHEME"] = ""
	}
	if etcdcfg.EtcdCACertFile != "" {
		envs["ETCD_CA_CERT_FILE"] = ETCD_CA_CERT_NODE_FILE
		vols[etcdcfg.EtcdCACertFile] = ETCD_CA_CERT_NODE_FILE
	}
	if etcdcfg.EtcdKeyFile != "" && etcdcfg.EtcdCertFile != "" {
		envs["ETCD_KEY_FILE"] = ETCD_KEY_NODE_FILE
		vols[etcdcfg.EtcdKeyFile] = ETCD_KEY_NODE_FILE
		envs["ETCD_CERT_FILE"] = ETCD_CERT_NODE_FILE
		vols[etcdcfg.EtcdCertFile] = ETCD_CERT_NODE_FILE
	}

	// Create the Docker command to execute (or display).  Start with the
	// fixed parts.
	cmd := []string{"docker", "run", "-d", "--net=host", "--privileged",
		"--name=calico-node"}

	// Add the environment variable pass-through.
	for k, v := range envs {
		cmd = append(cmd, "-e", fmt.Sprintf("%s=%s", k, v))
	}

	// Add the volume mounts.
	for k, v := range vols {
		cmd = append(cmd, "-v", fmt.Sprintf("%s:%s", k, v))
	}

	// Add the container image name
	cmd = append(cmd, img)

	if dryrun {
		fmt.Println("Use the following command to run Calico node:")
		fmt.Printf("\n%s\n\n", strings.Join(cmd, " "))
		fmt.Println("If you intend to run Calico node in an init system, such as systemd, remove")
		fmt.Println("the -d option so that the commands does not detach from the process.")
		return
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
		setupIPForwarding()
		setNFConntrackMax()
	}

	// Run the docker command.
	fmt.Println("Running the following command:")
	fmt.Printf("\n%s\n\n", strings.Join(cmd, " "))

	err = exec.Command(cmd[0], cmd[1:]...).Run()
	if err != nil {
		fmt.Println("Error executing command:")
		fmt.Println(err)
		os.Exit(1)
	}
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

func setupIPForwarding() {
	fmt.Println("Enabling IPv4 forwarding")
	err := ioutil.WriteFile("/proc/sys/net/ipv4/ip_forward",
		[]byte("1"), 0)
	if err != nil {
		fmt.Println("ERROR: Could not enable ipv4 forwarding")
		os.Exit(1)
	}

	if _, err := os.Stat("/proc/sys/net/ipv6"); err == nil {
		fmt.Println("Enabling IPv6 forwarding")
		err := ioutil.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding",
			[]byte("1"), 0)
		if err != nil {
			fmt.Println("ERROR: Could not enable ipv6 forwarding")
			os.Exit(1)
		}
	}
}

func setNFConntrackMax() {
	// A common problem on Linux systems is running out of space in the conntrack
	// table, which can cause poor iptables performance. This can happen if you
	// run a lot of workloads on a given host, or if your workloads create a lot
	// of TCP connections or bidirectional UDP streams.
	//
	// To avoid this becoming a problem, we recommend increasing the conntrack
	// table size. To do so, run the following commands:
	fmt.Println("Increasing contrack limit")
	err := ioutil.WriteFile("/proc/sys/net/netfilter/nf_conntrack_max",
		[]byte("1000000"), 0)
	if err != nil {
		fmt.Println("WARNING: Could not set nf_contrack_max. This may have an impact at scale.")
	}
}
