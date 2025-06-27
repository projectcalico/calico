package command

import (
	"strings"

	"github.com/sirupsen/logrus"
)

const gcloudBinaryName = "gcloud"

func GcloudStorageRsync(src, dest string, additionalFlags ...string) error {
	recursive := strings.HasSuffix(src, "/")
	args := []string{
		"storage", "rsync",
		strings.TrimSuffix(src, "/"), dest,
	}
	if recursive {
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
