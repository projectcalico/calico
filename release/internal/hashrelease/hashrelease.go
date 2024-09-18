package hashrelease

import (
	"bufio"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

const (
	// maxHashreleasesToKeep is the number of hashreleases to keep in the server
	maxHashreleasesToKeep = 400

	// baseDomain is the base URL of the hashrelease
	baseDomain = "docs.eng.tigera.net"
)

// hashrelease represents a hashrelease folder in server
type hashrelease struct {
	// Name is the full path of the hashrelease folder
	Name string

	// Time is the modified time of the hashrelease folder
	Time time.Time
}

// URL returns the URL of the hashrelease
func URL(name string) string {
	return fmt.Sprintf("https://%s.%s", name, baseDomain)
}

func remoteDocsPath(user string) string {
	path := "files"
	if user != "root" {
		path = filepath.Join("home", "core", "disk", "docs-preview", path)
	}
	return "/" + path
}

func remoteReleasesLibraryPath(user string) string {
	return filepath.Join(remoteDocsPath(user), "all-releases")
}

// Exists checks if a hashrelease exists in the server
func Exists(releaseHash string, sshConfig *command.SSHConfig) bool {
	if out, err := command.RunSSHCommand(sshConfig, fmt.Sprintf("cat %s | grep %s", remoteReleasesLibraryPath(sshConfig.User), releaseHash)); err == nil {
		return strings.Contains(out, releaseHash)
	}
	return false
}

// Publish publishes a hashrelease to the server
func Publish(name, hash, note, stream, dir string, sshConfig *command.SSHConfig) error {
	dir = dir + "/"
	if _, err := command.Run("rsync", []string{"--stats", "-az", "--delete", fmt.Sprintf("--rsh=ssh %s", sshConfig.Args()), dir, fmt.Sprintf("%s:%s/%s", sshConfig.HostString(), remoteDocsPath(sshConfig.User), name)}); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease")
		return err
	}
	if _, err := command.RunSSHCommand(sshConfig, fmt.Sprintf(`echo "%s" > %s/latest-os/%s.txt && echo %s >> %s`, URL(name), remoteDocsPath(sshConfig.User), stream, name, remoteReleasesLibraryPath(sshConfig.User))); err != nil {
		logrus.WithError(err).Error("Failed to update latest hashrelease and hashrelease library")
		return err
	}
	return nil
}

// listHashreleases lists all hashreleases in the server
func listHashreleases(sshConfig *command.SSHConfig) ([]hashrelease, error) {
	cmd := fmt.Sprintf("ls -lt --time-style=+'%%Y-%%m-%%d %%H:%%M:%%S' %s", remoteDocsPath(sshConfig.User))
	out, err := command.RunSSHCommand(sshConfig, cmd)
	if err != nil {
		logrus.WithError(err).Error("Failed to get list of hashreleases")
		return nil, err
	}
	lines := strings.Split(out, "\n")
	var folders []hashrelease
	// Limit to folders name which have the format YYYY-MM-DD-vX.Y-<word>
	re := regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}-v[0-9]+\.[0-9]+-.*$`)
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
		if re.MatchString(name) {
			folders = append(folders, hashrelease{
				Name: filepath.Join(remoteDocsPath(sshConfig.User), name),
				Time: time,
			})
		}
		sort.Slice(folders, func(i, j int) bool {
			return folders[i].Time.Before(folders[j].Time)
		})
	}
	return folders, nil
}

func getHashreleaseLibrary(sshConfig *command.SSHConfig) (string, error) {
	out, err := command.RunSSHCommand(sshConfig, fmt.Sprintf("cat %s", remoteReleasesLibraryPath(sshConfig.User)))
	if err != nil {
		logrus.WithError(err).Error("Failed to get hashrelease library")
		return "", err
	}
	return out, nil
}

func cleanHashreleaseLibrary(sshConfig *command.SSHConfig, hashreleaseNames []string) error {
	library, err := getHashreleaseLibrary(sshConfig)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(strings.NewReader(library))
	var newLibrary []string
	for scanner.Scan() {
		line := scanner.Text()
		for _, name := range hashreleaseNames {
			if !strings.Contains(line, name) {
				newLibrary = append(newLibrary, line)
			}
		}
	}

	if _, err := command.RunSSHCommand(sshConfig, fmt.Sprintf("echo \"%s\" > %s", strings.Join(newLibrary, "\n"), remoteReleasesLibraryPath(sshConfig.User))); err != nil {
		logrus.WithError(err).Error("Failed to update hashrelease library")
		return err
	}
	return nil
}

// DeleteOld deletes old hashreleases from the server.
// The limit parameter specifies the number of hashreleases to keep
func DeleteOld(sshConfig *command.SSHConfig) error {
	folders, err := listHashreleases(sshConfig)
	if err != nil {
		logrus.WithError(err).Error("Failed to list hashreleases")
		return err
	}
	foldersToDelete := []string{}
	if len(folders) > maxHashreleasesToKeep {
		for i := 0; i < len(folders)-maxHashreleasesToKeep; i++ {
			foldersToDelete = append(foldersToDelete, folders[i].Name)
		}
	}
	if len(foldersToDelete) == 0 {
		logrus.Info("No hashreleases to delete")
		return nil
	}
	if _, err := command.RunSSHCommand(sshConfig, fmt.Sprintf("rm -rf %s", strings.Join(foldersToDelete, " "))); err != nil {
		logrus.WithField("folder", strings.Join(foldersToDelete, ", ")).WithError(err).Error("Failed to delete old hashrelease")
		return err
	}
	logrus.WithField("folders", strings.Join(foldersToDelete, ", ")).Info("Deleted old hashreleases")
	if err := cleanHashreleaseLibrary(sshConfig, foldersToDelete); err != nil {
		logrus.WithError(err).Warn("Failed to clean hashrelease library")
	}
	return nil
}
