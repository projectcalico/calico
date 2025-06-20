package command

import (
	"strings"

	"github.com/sirupsen/logrus"
)

const gcloudBinaryName = "gcloud"

func GcloudStorageRsync(src, dest string, additionalFlags ...string) error {
	args := []string{
		"storage", "rsync",
		strings.TrimSuffix(src, "/"), dest,
	}
	if strings.HasSuffix(src, "/") {
		args = append(args, "--recursive")
	}
	if len(additionalFlags) > 0 {
		args = append(args, additionalFlags...)
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--verbosity=debug")
	}
	if _, err := runner().Run(gcloudBinaryName, args, nil); err != nil {
		return err
	}
	return nil
}
