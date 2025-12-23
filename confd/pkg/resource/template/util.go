package template

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

var NodeName = os.Getenv("NODENAME")

// fileInfo describes a configuration file and is returned by fileStat.
type fileInfo struct {
	Uid  uint32
	Gid  uint32
	Mode os.FileMode
	Md5  string
}

func expandKeys(prefix string, keys []string) []string {
	s := make([]string, len(keys))
	for i, k := range keys {
		// Prepend the prefix and replace "NODENAME" in the key by the actual node name.
		s[i] = path.Join(prefix, strings.Replace(k, "//NODENAME", "/"+NodeName, 1))
	}
	return s
}

// isFileExist reports whether path exits.
func isFileExist(fpath string) bool {
	if _, err := os.Stat(fpath); os.IsNotExist(err) {
		return false
	}
	return true
}

// sameConfig reports whether src and dest config files are equal.
// Two config files are equal when they have the same file contents and
// Unix permissions. The owner, group, and mode must match.
// It return false in other cases.
func sameConfig(src, dest string) (bool, error) {
	if !isFileExist(dest) {
		return false, nil
	}
	d, err := fileStat(dest)
	if err != nil {
		return false, err
	}
	s, err := fileStat(src)
	if err != nil {
		return false, err
	}
	if d.Uid != s.Uid {
		log.Debug(fmt.Sprintf("%s has UID %d should be %d", dest, d.Uid, s.Uid))
	}
	if d.Gid != s.Gid {
		log.Debug(fmt.Sprintf("%s has GID %d should be %d", dest, d.Gid, s.Gid))
	}
	if d.Mode != s.Mode {
		log.Debug(fmt.Sprintf("%s has mode %s should be %s", dest, os.FileMode(d.Mode), os.FileMode(s.Mode)))
	}
	if d.Md5 != s.Md5 {
		log.Debug(fmt.Sprintf("%s has md5sum %s should be %s", dest, d.Md5, s.Md5))
	}
	if d.Uid != s.Uid || d.Gid != s.Gid || d.Mode != s.Mode || d.Md5 != s.Md5 {
		return false, nil
	}
	return true, nil
}

// recursiveFindFiles find files with pattern in the root with depth.
func recursiveFindFiles(root string, pattern string) ([]string, error) {
	files := make([]string, 0)
	findfile := func(path string, f os.FileInfo, err error) (inner error) {
		if err != nil {
			return
		}
		if f.IsDir() {
			return
		} else if match, innerr := filepath.Match(pattern, f.Name()); innerr == nil && match {
			files = append(files, path)
		}
		return
	}
	return files, filepath.Walk(root, findfile)
}

// TruncateAndHashName truncates a name to maxLen characters, appending a hash suffix if truncation is needed.
// The maximum length of a k8s resource (253 bytes) is longer than the maximum length of BIRD symbols (64 chars).
// This function provides a way to map the k8s resource name to a BIRD symbol name that accounts
// for the length difference in a way that minimizes the chance of collisions.
func TruncateAndHashName(name string, maxLen int) (string, error) {
	if len(name) <= maxLen {
		return name, nil
	}
	// SHA256 outputs a hash 64 chars long but we'll use only the first 16
	hashCharsToUse := 16
	// Account for underscore we insert between truncated name and hash string
	hashStrSize := hashCharsToUse + 1
	if maxLen <= hashStrSize {
		return "", fmt.Errorf("max truncated string length must be greater than the minimum size of %d",
			hashStrSize)
	}
	hash := sha256.New()
	_, err := hash.Write([]byte(name))
	if err != nil {
		return "", err
	}
	truncationLen := maxLen - hashStrSize
	hashStr := fmt.Sprintf("%X", hash.Sum(nil))
	truncatedName := fmt.Sprintf("%s_%s", name[:truncationLen], hashStr[:hashCharsToUse])
	return truncatedName, nil
}

// HashToIPv4 hashes the given string and formats the resulting 4 bytes as an IPv4 address.
func HashToIPv4(nodeName string) (string, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(nodeName))
	if err != nil {
		return "", err
	}
	hashBytes := hash.Sum(nil)
	ip := hashBytes[:4]
	// BGP doesn't allow router IDs in special IP ranges (e.g., 224.x.x.x)
	ip0Value := int(ip[0])
	if ip0Value > 223 {
		ip0Value = ip0Value - 32
	}
	routerId := strconv.Itoa(ip0Value) + "." +
		strconv.Itoa(int(ip[1])) + "." +
		strconv.Itoa(int(ip[2])) + "." +
		strconv.Itoa(int(ip[3]))
	return routerId, nil
}
