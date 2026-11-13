// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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

package externalnode

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/config"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

type Client struct {
	lock sync.Mutex

	extIP   string
	extKey  string
	extUser string
	intIPs  []string
	intIPv6 []string
}

// NewClient reads external node details from e2ecfg first. When configs are not available,
// it will parse information from a predefined list of environment variables.
func NewClient() *Client {
	if config.ExtNodeIP() == "" || config.ExtNodeSSHKey() == "" || config.ExtNodeUsername() == "" {
		logrus.Debug("External node details unavailable")
		return nil
	}
	client := &Client{
		extIP:   config.ExtNodeIP(),
		extKey:  config.ExtNodeSSHKey(),
		extUser: config.ExtNodeUsername(),
	}
	return client
}

// MustNewClient returns a client for the external node, failing the test if the
// cluster has none.
func MustNewClient() *Client {
	client := NewClient()
	if client == nil {
		framework.Failf("No external node is configured, so the lane should exclude the ExternalNode label")
	}
	return client
}

func NewClientManualConfig(ip, key, user string) *Client {
	return &Client{extIP: ip, extKey: key, extUser: user}
}

// IP returns the external node's first internal address. The ssh probe that
// discovers them can come back empty, which is a broken external node rather
// than a test failure, so say which node had none.
func (e *Client) IP() string {
	ips := e.IPs()
	Expect(ips).NotTo(BeEmpty(), fmt.Sprintf(
		"no internal IPs discovered on external node %s", e.extIP))
	return ips[0]
}

// SSHIP returns the address used to ssh to the external node.
func (e *Client) SSHIP() string { return e.extIP }

// SSHUser returns the ssh user.
func (e *Client) SSHUser() string { return e.extUser }

// SSHKeyPath returns the path to the private key used for ssh.
func (e *Client) SSHKeyPath() string { return e.extKey }

// IPs returns the external node's IPv4 addresses, or nil if the ssh probe fails.
func (e *Client) IPs() []string {
	ips, err := e.AddressesOf(utils.IPv4)
	if err != nil {
		logrus.WithError(err).Info("Setting external node intIPs failed")
		return nil
	}
	return ips
}

// AddressesOf returns the external node's addresses in one family. They can
// differ from the address used for ssh (e.g. AWS VMs), and they are what the
// cluster sees as the source. A failed probe isn't cached, so its error reaches
// the caller instead of looking like a node without the family.
func (e *Client) AddressesOf(f utils.IPFamily) ([]string, error) {
	e.lock.Lock()
	defer e.lock.Unlock()

	cache, probe, parse := &e.intIPs, ipv4Probe, parseInet4
	if f == utils.IPv6 {
		// Link-local addresses never leave the link, so policy can't see them as a source.
		cache, probe, parse = &e.intIPv6, []string{"ip", "-6", "-o", "addr", "show", "scope", "global"}, parseInet6
	}
	if *cache != nil {
		return *cache, nil
	}

	dest := fmt.Sprintf("%s@%s", e.extUser, e.extIP)
	args := append([]string{
		"-o", "ConnectTimeout=2",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-i", e.extKey,
		dest, "--",
	}, probe...)
	command := exec.Command("ssh", args...)
	logrus.Infof("Running '%s %s'", command.Path, strings.Join(command.Args[1:], " "))
	out, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return nil, fmt.Errorf("%w: %s", err, strings.Join(strings.Fields(string(exitErr.Stderr)), " "))
		}
		return nil, err
	}
	*cache = parse(string(out))
	logrus.Infof("External node %s addresses: %v", f, *cache)
	return *cache, nil
}

// ipv4Probe's last grep exits non-zero when nothing matches, so a node with no
// IPv4 address reports a probe error rather than an empty list.
var ipv4Probe = []string{
	"ip", "addr", "show",
	"|", "grep", "inet",
	"|", "grep", "-v", "inet6",
	"|", "grep", "-v", "127.0.0.1",
}

var inet4Re = regexp.MustCompile("inet ([0-9.]+)")

func parseInet4(out string) []string {
	ips := []string{}
	for _, m := range inet4Re.FindAllStringSubmatch(out, -1) {
		ips = append(ips, m[1])
	}
	return ips
}

var inet6Re = regexp.MustCompile(`inet6 ([0-9a-fA-F:]+)/`)

// parseInet6 never returns nil, so a node with no global IPv6 caches as empty
// instead of re-probing over ssh on every call.
func parseInet6(out string) []string {
	ips := []string{}
	for _, m := range inet6Re.FindAllStringSubmatch(out, -1) {
		ips = append(ips, m[1])
	}
	return ips
}

func (e *Client) MustExec(shell, opt, cmd string) string {
	out, err := e.Exec(shell, opt, cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), fmt.Sprintf(
		"failed to execute command %q %q %q on external node: %s", shell, opt, cmd, err))
	return out
}

func (e *Client) Exec(shell, opt, cmd string) (string, error) {
	return e.ExecTimeout(5, shell, opt, cmd)
}

func (e *Client) ExecTimeout(timeoutSecs int, shell, opt, cmd string) (string, error) {
	dest := fmt.Sprintf("%v@%v", e.extUser, e.extIP)
	command := exec.Command(
		"timeout", fmt.Sprint(timeoutSecs+10),
		"ssh",
		"-o", fmt.Sprintf("ConnectTimeout=%d", timeoutSecs),
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-i", e.extKey,
		dest,
		"--",
		shell, opt, fmt.Sprintf(`"%s"`, cmd))
	logrus.Infof("Running '%s %s'", command.Path, strings.Join(command.Args[1:], " "))
	out, err := command.Output()
	outstr := strings.TrimSpace(string(out))
	logrus.Infof("Output: %q", outstr)
	if err != nil {
		err := err.(*exec.ExitError)
		logrus.Infof("Stderr: %s", string(err.Stderr))
	}
	return outstr, err
}

func (e *Client) Get(target string, length int) string {
	// This is actually just trying to run something on the external node like:
	//   curl -m2 -w "\n%{time_total}" http://172.16.101.14:32517/length/20
	// So 2 special things needed here:
	// - The % character needs to be escaped so that fmt.Sprintf() doesn't try to interpret it as a format code.
	// - This whole string gets run in Exec() like this:
	//   `ssh .... -- /bin/sh -c "<this string>"`
	//   so we need to escape the double quotes here too.
	// -g stops curl reading the brackets of an IPv6 literal as a URL glob.
	return fmt.Sprintf(`curl -g -m2 -w \"\n%%{time_total}\" http://%v/length/%v`, target, length)
}

func (e *Client) Post(target string, postdata string) string {
	return fmt.Sprintf(`curl -g -m2 -w \"\n%%{time_total}\" -d "%v" -X POST http://%v/post`, postdata, target)
}

func (e *Client) UDP(target string, postdata string) string {
	// If target[0] != '[', this is an ipv4 address.
	if target[0] != '[' {
		target = strings.ReplaceAll(target, ":", " ")
		return fmt.Sprintf(`echo %v | nc -u -w1 %v`, postdata, target)
	}
	// IPv6 target is of the format [a:b:c:d]:port.
	// Replace the last ":" with " ".
	// Remove the "[" and "]"
	idx := strings.LastIndex(target, ":")
	target = target[:idx] + " " + target[idx+1:]
	target = strings.Replace(target, "[", "", 1)
	target = strings.Replace(target, "]", "", 1)
	return fmt.Sprintf(`echo %v | nc -6 -u -w1 %v`, postdata, target)
}

func (e *Client) SetupIperf() {
	shell := "/bin/sh"
	opt := "-c"
	cmd := fmt.Sprintf("sudo docker run --rm -d --network host --name iperf %s", images.Agnhost)
	_, err := e.Exec(shell, opt, cmd)
	Expect(err).NotTo(HaveOccurred())
}

func (e *Client) CleanupIperf() {
	shell := "/bin/sh"
	opt := "-c"
	cmd := "sudo docker stop iperf"
	_, err := e.Exec(shell, opt, cmd)
	Expect(err).NotTo(HaveOccurred())
}

func (e *Client) RunIperfCmd(iperfCmd string, timeoutSecs int) string {
	shell := "/bin/sh"
	opt := "-c"
	cmd := fmt.Sprintf("sudo docker exec -t iperf %s", iperfCmd)
	output, err := e.ExecTimeout(timeoutSecs, shell, opt, cmd)
	Expect(err).NotTo(HaveOccurred())

	return output
}

func joinArgs(parts ...string) string {
	return strings.Join(parts, " ")
}

// RunContainer launches a container by name on the external node. flags carry
// extra `docker run` options (e.g. -d, --privileged, --network host); args are
// appended after the image and become the container command. Returns the raw
// `docker run` stdout (typically the container ID for detached runs).
//
// For one-shot probes, prefer RunContainerOnce (which sets --rm).
func (e *Client) RunContainer(name, image string, flags []string, args ...string) (string, error) {
	cmd := "sudo docker run " + joinArgs(flags...) + " --name " + name + " " + image
	if len(args) > 0 {
		cmd = cmd + " " + joinArgs(args...)
	}
	return e.Exec("/bin/sh", "-c", cmd)
}

// RunContainerOnce runs an unnamed container with --rm semantics: exec,
// capture stdout, container is removed on exit. Useful for one-shot probes
// where the caller only cares about the captured output.
func (e *Client) RunContainerOnce(image string, flags []string, args ...string) (string, error) {
	cmd := "sudo docker run --rm " + joinArgs(flags...) + " " + image
	if len(args) > 0 {
		cmd = cmd + " " + joinArgs(args...)
	}
	return e.Exec("/bin/sh", "-c", cmd)
}

// RemoveContainer force-removes a container by name. Tolerates a missing
// container so cleanup paths never fail on a re-run.
func (e *Client) RemoveContainer(name string) error {
	_, err := e.Exec("/bin/sh", "-c", fmt.Sprintf("sudo docker rm -f %s 2>/dev/null", name))
	return err
}

// IsContainerRunning reports whether the named container exists and is in the
// Running state. Wrap in Eventually for readiness polling.
func (e *Client) IsContainerRunning(name string) (bool, error) {
	out, err := e.Exec("/bin/sh", "-c",
		fmt.Sprintf("sudo docker inspect -f '{{.State.Running}}' %s 2>&1", name))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "true", nil
}

// RunInContainer executes args inside an already-running named container via
// `docker exec`. Returns the command's stdout.
func (e *Client) RunInContainer(name string, args ...string) (string, error) {
	cmd := "sudo docker exec " + name + " " + joinArgs(args...)
	return e.Exec("/bin/sh", "-c", cmd)
}

// WriteFileInContainer writes contents to path inside the named container,
// using base64 to safely transport binary or multi-line data over docker exec
// stdin without shell-quoting hazards.
func (e *Client) WriteFileInContainer(name, path string, contents []byte) error {
	encoded := base64.StdEncoding.EncodeToString(contents)
	cmd := fmt.Sprintf("echo %s | base64 -d | sudo docker exec -i %s tee %s > /dev/null",
		encoded, name, path)
	_, err := e.Exec("/bin/sh", "-c", cmd)
	return err
}

// ContainerLogs returns the container runtime's captured stdout/stderr for
// the named container.
func (e *Client) ContainerLogs(name string) (string, error) {
	return e.Exec("/bin/sh", "-c", fmt.Sprintf("sudo docker logs %s 2>/dev/null", name))
}

func (e *Client) TestCalicoServiceReady(service string) error {
	// Wait for the service to be active.
	cmd := fmt.Sprintf("systemctl is-active %s.service", service)
	output, err := e.Exec("/bin/sh", "-c", cmd)
	if err != nil {
		return err
	}
	if output != "active" {
		return fmt.Errorf("service %s is not active, state=%s", service, output)
	}
	return nil
}
