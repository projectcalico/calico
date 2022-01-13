//go:build !windows

package template

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// fileStat return a fileInfo describing the named file.
func fileStat(name string) (fi fileInfo, err error) {
	if isFileExist(name) {
		f, err := os.Open(name)
		if err != nil {
			return fi, err
		}
		defer func() {
			if e := f.Close(); e != nil {
				log.WithError(e).WithField("filename", name).Error("error closing file")
			}
		}()
		stats, err := f.Stat()
		if err != nil {
			return fi, err
		}
		fi.Uid = stats.Sys().(*syscall.Stat_t).Uid
		fi.Gid = stats.Sys().(*syscall.Stat_t).Gid
		fi.Mode = stats.Mode()
		h := md5.New()
		if _, err := io.Copy(h, f); err != nil {
			return fileInfo{}, err
		}
		fi.Md5 = fmt.Sprintf("%x", h.Sum(nil))
		return fi, nil
	}
	return fi, errors.New("File not found")
}
