/* Copyright (c) 2020-2021 Tigera, Inc. All rights reserved. */

package externalnode

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/e2e/pkg/config"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

type Client struct {
	lock sync.Mutex

	extIP   string
	extKey  string
	extUser string
	intIPs  []string
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

func NewClientManualConfig(ip, key, user string) *Client {
	return &Client{extIP: ip, extKey: key, extUser: user}
}

func (e *Client) IP() string {
	return e.IPs()[0]
}

func (e *Client) IPs() []string {
	e.lock.Lock()
	defer e.lock.Unlock()

	// Internal IP of external node may not be the same as the IP we use to ssh to it (e.g. AWS VMs)
	// This function returns the external node internal IP (and caches it) so that it can be used to check for NAT.
	if e.intIPs == nil {
		dest := fmt.Sprintf("%s@%s", e.extUser, e.extIP)
		command := exec.Command("ssh",
			"-o", "ConnectTimeout=2",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-i", e.extKey,
			dest, "--",
			"ip", "addr", "show",
			"|", "grep", "inet", // grab the lines with inet interfaces
			"|", "grep", "-v", "inet6", // throw out the ipv6 ones
			"|", "grep", "-v", "127.0.0.1", // throw out the loopback
		)
		logrus.Infof("Running '%s %s'", command.Path, strings.Join(command.Args[1:], " "))
		out, err := command.Output()
		if err != nil {
			logrus.WithError(err).Info("Setting external node intIPs failed")
			return nil
		}
		outstr := strings.TrimSpace(string(out))
		logrus.Infof("Output: %q", outstr)
		// outstr will look something like:
		// inet 172.16.101.163/24 brd 172.16.101.255 scope global dynamic eth0
		re := regexp.MustCompile("inet ([0-9.]+)")
		var ips []string
		for _, i := range re.FindAllStringSubmatch(outstr, -1) {
			ips = append(ips, i[1])
		}
		logrus.Infof("Setting external node intIPs=%v", ips)
		e.intIPs = ips
	}
	return e.intIPs
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
	return fmt.Sprintf(`curl -m2 -w \"\n%%{time_total}\" http://%v/length/%v`, target, length)
}

func (e *Client) Post(target string, postdata string) string {
	return fmt.Sprintf(`curl -m2 -w \"\n%%{time_total}\" -d "%v" -X POST http://%v/post`, postdata, target)
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

func (e *Client) TestCanConnect(target string) {
	command := fmt.Sprintf(`curl -s -m2 %v`, target)
	tryConnect := func() error {
		_, err := e.Exec("sh", "-c", command)
		return err
	}

	// Test connectivity. Use Eventually to handle potential race conditions in setting up the service.
	Eventually(tryConnect, 15*time.Second, 3*time.Second).ShouldNot(HaveOccurred())

	// Once we get a single success, it should consistently succeed afterwards.
	Consistently(tryConnect, 9*time.Second, 3*time.Second).ShouldNot(HaveOccurred())

	// It's reliably up. Check output.
	_, err := e.Exec("sh", "-c", command)
	Expect(err).NotTo(HaveOccurred())
}

func (e *Client) TestCannotConnect(target string) {
	command := fmt.Sprintf(`curl -s -m2 %v`, target)
	tryConnect := func() error {
		_, err := e.Exec("sh", "-c", command)
		return err
	}

	// Test connectivity. Use Eventually to handle potential race conditions in setting up the service.
	Eventually(tryConnect, 15*time.Second, 3*time.Second).Should(HaveOccurred())

	// Once we get a single failure, it should consistently fail afterwards.
	Consistently(tryConnect, 9*time.Second, 3*time.Second).Should(HaveOccurred())

	// It's reliably not working. Check output.
	_, err := e.Exec("sh", "-c", command)
	Expect(err).To(HaveOccurred())
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
