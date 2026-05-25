//go:build linux

// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package log

import (
	"os"
	"sync"
	"syscall"
)

// rotatingFile is an io.WriteCloser that follows external log rotation: when
// the file at its path is renamed or deleted (e.g. by logrotate), the next
// Write reopens at the original path so subsequent log lines land in the new
// file rather than the now-detached inode.
//
// Detection is by inode comparison via stat() on each Write. That's one
// extra syscall per log line — fine for the volumes log files see, and
// avoids depending on inotify or external libraries.
type rotatingFile struct {
	path string
	perm os.FileMode

	mu  sync.Mutex
	f   *os.File
	ino uint64
}

func newRotatingFile(path string, perm os.FileMode) (*rotatingFile, error) {
	r := &rotatingFile{path: path, perm: perm}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

// open opens (or creates) the file at r.path and records its inode.
// Caller must hold r.mu, or be in a constructor before the writer is shared.
func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, r.perm)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.f = f
	r.ino = inodeOf(info)
	return nil
}

// Write writes p to the underlying file, reopening first if the path now
// points to a different inode (rotation happened) or no longer exists.
func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if info, err := os.Stat(r.path); err == nil {
		if inodeOf(info) != r.ino {
			_ = r.f.Close()
			if err := r.open(); err != nil {
				return 0, err
			}
		}
	} else if os.IsNotExist(err) {
		_ = r.f.Close()
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	// Other stat errors (permission, transient IO): write through the
	// current handle and let the write itself surface the failure.

	return r.f.Write(p)
}

// Close closes the underlying file handle.
func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// inodeOf extracts the inode number from a stat result. Linux always
// returns *syscall.Stat_t from FileInfo.Sys(), so the type assertion is
// safe; the fallback exists only for the impossible case of a stale info
// object.
func inodeOf(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
