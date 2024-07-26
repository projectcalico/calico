package hashrelease

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/fixham/internal/command"
)

const (
	remoteReleasesPath = "/files"
)

// hashrelease represents a hashrelease folder in server
type hashrelease struct {
	// Name is the full path of the hashrelease folder
	Name string

	// Time is the modified time of the hashrelease folder
	Time time.Time
}

func remoteReleasesLibraryPath() string {
	return filepath.Join(remoteReleasesPath, "all-releases")
}

// hasHashrelease checks if a hashrelease exists in the server
func hasHashrelease(releaseHash string, sshConfig *command.SSHConfig) bool {
	if out, err := command.RunSSHCommand(sshConfig, fmt.Sprintf("cat %s | grep %s", remoteReleasesLibraryPath(), releaseHash)); err == nil {
		return strings.Contains(out, releaseHash)
	}
	return false
}

// PublishHashrelease publishes a hashrelease to the server
func PublishHashrelease(name, hash, note, stream, dir string, sshConfig *command.SSHConfig) error {
	if hasHashrelease(hash, sshConfig) {
		// TODO: determine if we should return an error here
		logrus.WithFields(logrus.Fields{
			"hash": hash,
			"note": note,
		}).Warn("Hashrelease already exists, skipping publish")
		return nil
	}
	if _, err := command.Run("rsync", []string{"--stats", "-az", "--delete", fmt.Sprintf(`-e 'ssh %s'`, sshConfig.Args()), dir, fmt.Sprintf("%s:/files/%s", sshConfig.HostString(), name)}); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease")
		return err
	}
	if _, err := command.RunSSHCommand(sshConfig, fmt.Sprintf("echo \"https://%s.docs.eng.tigera.net\" > /files/latest-os/%s.txt", name, stream)); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease")
		return err
	}
	if _, err := command.RunSSHCommand(sshConfig, fmt.Sprintf(`echo %s >> %s`, name, remoteReleasesLibraryPath())); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease")
		return err
	}
	return nil
}

// ListHashreleases lists all hashreleases in the server
func ListHashreleases(sshConfig *command.SSHConfig) ([]hashrelease, error) {
	cmd := fmt.Sprintf("ls -lt --time-style=+'%%Y-%%m-%%d %%H:%%M:%%S' %s", remoteReleasesPath)
	out, err := command.RunSSHCommand(sshConfig, cmd)
	if err != nil {
		logrus.WithError(err).Error("Failed to list hashreleases")
		return nil, err
	}
	lines := strings.Split(out, "\n")
	var folders []hashrelease
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		// Get the last field which is the folder name
		name := fields[len(fields)-1]
		time, err := time.Parse("2006-01-02 15:04:05", fmt.Sprintf("%s %s", fields[5], fields[6]))
		if err != nil {
			continue
		}
		folders = append(folders, hashrelease{
			Name: filepath.Join(remoteReleasesPath, name),
			Time: time,
		})
		sort.Slice(folders, func(i, j int) bool {
			return folders[i].Time.Before(folders[j].Time)
		})
	}
	return folders, nil
}

// DeleteOldHashreleases deletes old hashreleases from the server.
// The limit parameter specifies the number of hashreleases to keep
func DeleteOldHashreleases(sshConfig *command.SSHConfig, keepLimit int) error {
	if keepLimit < 1 {
		keepLimit = 400
	}
	folders, err := ListHashreleases(sshConfig)
	if err != nil {
		logrus.WithError(err).Error("Failed to list hashreleases")
		return err
	}
	if len(folders) > keepLimit {
		for i := 0; i < len(folders)-keepLimit; i++ {
			folderName := folders[i].Name
			if _, err := command.RunSSHCommand(sshConfig, fmt.Sprintf("rm -rf %s", folderName)); err != nil {
				logrus.WithField("folder", folderName).WithError(err).Error("Failed to delete old hashrelease")
				continue
			}
		}
	}
	return nil
}
