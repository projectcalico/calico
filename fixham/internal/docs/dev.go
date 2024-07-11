package docs

import (
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/fixham/internal/command"
)

func sshCommand(args ...string) string {
	cmd := []string{"ssh"}
	cmd = append(cmd, args...)
	cmd = append(cmd, "-q", "-o StrictHostKeyChecking=no", "-o UserKnownHostsFile=/dev/null", "-p 2222")
	return strings.Join(cmd, " ")
}

func PublishHashrelease(name, stream, dir, host string) error {
	sshCmd := sshCommand("")
	if _, err := command.Run("rsync", []string{"--stats", "-az", "--delete", "-e", sshCmd, dir, host + ":/files/" + name}); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease")
		return err
	}
	if _, err := command.Run("ssh", []string{strings.TrimPrefix(sshCmd, "ssh"), "cat \"https://" + name + ".docs.eng.tigera.net\\\" > /files/latest-os/" + stream + ".txt"}); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease")
		return err
	}
	return nil
}

func DeleteOldHashreleases(host string) error {
	// TODO
	return nil
}
