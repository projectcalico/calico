package docs

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/fixham/internal/command"
)

type SSHConfig struct {
	Host    string
	User    string
	KeyPath string
	Port    string
}

func sshCommand(args ...string) string {
	cmd := []string{"ssh"}
	cmd = append(cmd, args...)
	cmd = append(cmd, "-q", "-o StrictHostKeyChecking=no", "-o UserKnownHostsFile=/dev/null")
	return strings.Join(cmd, " ")
}

func PublishHashrelease(name, stream, dir string, sshConfig *SSHConfig) error {
	sshCmd := sshCommand("-i", sshConfig.KeyPath, "-p", sshConfig.Port)
	if _, err := command.Run("rsync", []string{"--stats", "-az", "--delete", "-e '" + sshCmd + "'", dir, fmt.Sprintf("%s@%s:/files/%s", sshConfig.User, sshConfig.Host, name)}); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease")
		return err
	}
	if _, err := command.Run("ssh", []string{strings.TrimPrefix(sshCmd, "ssh"), "cat \"https://" + name + ".docs.eng.tigera.net\\\" > /files/latest-os/" + stream + ".txt"}); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease")
		return err
	}
	return nil
}

func DeleteOldHashreleases(sshConfig *SSHConfig) error {
	// TODO
	return nil
}
