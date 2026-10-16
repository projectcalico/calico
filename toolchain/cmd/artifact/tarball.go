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

package main

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Cache objects are plain uncompressed tar streams, so entries written by
// the gsutil script (`tar -cf - -- paths`) restore here, and entries written
// here restore with `tar -xf -`.

// writeTar archives paths as GNU tar does: members keep the names given,
// directories recurse, symlinks are stored rather than followed, and a file
// reached twice through hard links is stored once.
func writeTar(w io.Writer, paths []string, warn io.Writer) error {
	t := &tarWriter{tw: tar.NewWriter(w), warn: warn, links: map[fileID]string{}}
	for _, p := range paths {
		if err := t.addTree(filepath.Clean(p)); err != nil {
			return err
		}
	}
	return t.tw.Close()
}

type fileID struct{ dev, ino uint64 }

type tarWriter struct {
	tw    *tar.Writer
	warn  io.Writer
	links map[fileID]string
}

func (t *tarWriter) addTree(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if err := t.add(p, fi); err != nil {
		return err
	}
	if !fi.IsDir() {
		return nil
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := t.addTree(filepath.Join(p, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func (t *tarWriter) add(p string, fi fs.FileInfo) error {
	if fi.Mode()&fs.ModeSocket != 0 {
		fmt.Fprintf(t.warn, "tar: %s: socket ignored\n", p)
		return nil
	}
	var link string
	if fi.Mode()&fs.ModeSymlink != 0 {
		var err error
		if link, err = os.Readlink(p); err != nil {
			return err
		}
	}
	hdr, err := tar.FileInfoHeader(fi, link)
	if err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	hdr.Name = filepath.ToSlash(p)
	if fi.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
		hdr.Name += "/"
	}
	// GNU tar truncates to whole seconds where archive/tar would round.
	hdr.ModTime = hdr.ModTime.Truncate(time.Second)
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && fi.Mode().IsRegular() && st.Nlink > 1 {
		id := fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)}
		if first, seen := t.links[id]; seen {
			hdr.Typeflag = tar.TypeLink
			hdr.Linkname = first
			hdr.Size = 0
		} else {
			t.links[id] = hdr.Name
		}
	}
	if err := t.tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	if hdr.Typeflag != tar.TypeReg {
		return nil
	}
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.CopyN(t.tw, f, hdr.Size); err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	return nil
}

// extractTar unpacks into dir the way `tar -xf -` does by default: existing
// files are replaced, existing directories are kept, and ownership and the
// full mode are restored only when running as root.
//
// Opening dir as an os.Root keeps every write inside it, even through a
// symlink the archive itself creates.
func extractTar(r io.Reader, dir string, warn io.Writer) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	x := &extractor{root: root, warn: warn, asRoot: os.Geteuid() == 0, umask: currentUmask()}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		// Names are checked below, whatever GODEBUG=tarinsecurepath says.
		if err != nil && !errors.Is(err, tar.ErrInsecurePath) {
			return err
		}
		if err := x.extract(hdr, tr); err != nil {
			return fmt.Errorf("%s: %w", hdr.Name, err)
		}
	}
	return x.finishDirs()
}

type extractor struct {
	root   *os.Root
	warn   io.Writer
	asRoot bool
	umask  fs.FileMode
	dirs   []*tar.Header
}

func (x *extractor) extract(hdr *tar.Header, r io.Reader) error {
	name, err := memberName(hdr.Name)
	if err != nil {
		return err
	}
	perm := hdr.FileInfo().Mode().Perm()
	switch hdr.Typeflag {
	case tar.TypeDir:
		if name != "." {
			if err := x.makeDir(name, perm); err != nil {
				return err
			}
		}
		// A directory's mode and mtime are set once its contents are in, so
		// a read-only directory such as Go's module cache can still be
		// filled, and filling it does not move its mtime.
		hdr.Name = name
		x.dirs = append(x.dirs, hdr)
		return nil
	case tar.TypeReg, tar.TypeGNUSparse:
		if err := x.replace(name); err != nil {
			return err
		}
		f, err := x.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, r)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	case tar.TypeSymlink:
		if err := x.replace(name); err != nil {
			return err
		}
		if err := x.root.Symlink(hdr.Linkname, name); err != nil {
			return err
		}
	case tar.TypeLink:
		target, err := memberName(hdr.Linkname)
		if err != nil {
			return err
		}
		if err := x.replace(name); err != nil {
			return err
		}
		// The target already carries the shared inode's attributes.
		return x.root.Link(target, name)
	default:
		fmt.Fprintf(x.warn, "tar: %s: unsupported member type '%c', skipped\n", hdr.Name, hdr.Typeflag)
		return nil
	}
	return x.setAttrs(name, hdr)
}

// memberName strips leading slashes and refuses '..', as GNU tar does, so a
// member can only land under the extraction directory.
func memberName(name string) (string, error) {
	n := strings.TrimLeft(name, "/")
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return "", errors.New("member name contains '..'")
		}
	}
	return path.Clean(n), nil
}

func (x *extractor) makeParent(name string) error {
	if dir := path.Dir(name); dir != "." {
		return x.root.MkdirAll(dir, 0o777)
	}
	return nil
}

func (x *extractor) makeDir(name string, perm fs.FileMode) error {
	if err := x.makeParent(name); err != nil {
		return err
	}
	// Writable by the owner until finishDirs applies the real mode.
	err := x.root.Mkdir(name, perm|0o700)
	if !errors.Is(err, fs.ErrExist) {
		return err
	}
	if fi, err := x.root.Stat(name); err == nil && fi.IsDir() {
		return nil
	}
	if err := x.root.Remove(name); err != nil {
		return err
	}
	return x.root.Mkdir(name, perm|0o700)
}

// replace clears the way for a non-directory member. Unlinking rather than
// truncating means a symlink in the way is replaced, not written through.
func (x *extractor) replace(name string) error {
	if err := x.makeParent(name); err != nil {
		return err
	}
	if err := x.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (x *extractor) setAttrs(name string, hdr *tar.Header) error {
	if x.asRoot {
		if err := x.root.Lchown(name, hdr.Uid, hdr.Gid); err != nil {
			return err
		}
	}
	if hdr.Typeflag == tar.TypeSymlink {
		return nil
	}
	mode := hdr.FileInfo().Mode()
	switch {
	case x.asRoot:
		// After the chown, which clears the setuid and setgid bits.
		if err := x.root.Chmod(name, mode&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky)); err != nil {
			return err
		}
	case hdr.Typeflag == tar.TypeDir:
		if err := x.root.Chmod(name, mode.Perm()&^x.umask); err != nil {
			return err
		}
	}
	return x.root.Chtimes(name, time.Time{}, hdr.ModTime)
}

func (x *extractor) finishDirs() error {
	// Archives list a directory before its contents, so going backwards
	// reaches children first: a parent that loses search permission cannot
	// lock them out.
	for i := len(x.dirs) - 1; i >= 0; i-- {
		hdr := x.dirs[i]
		if err := x.setAttrs(hdr.Name, hdr); err != nil {
			return fmt.Errorf("%s: %w", hdr.Name, err)
		}
	}
	return nil
}

func currentUmask() fs.FileMode {
	m := syscall.Umask(0)
	syscall.Umask(m)
	return fs.FileMode(m)
}
