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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"mime"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

// mtimeKey is the custom metadata gsutil writes on every upload and reads
// back on download, so artifacts keep their modification times across tools.
const mtimeKey = "goog-reserved-file-mtime"

const parallelTransfers = 16

// level runs push, pull, yank and list against one job or workflow location.
type level struct {
	*app
	cmd    string
	loc    location
	force  bool
	labels map[string]string

	b bucket
}

// bkt opens storage on first use, so that argument errors never wait on
// credential discovery.
func (l *level) bkt(ctx context.Context) (bucket, error) {
	if l.b == nil {
		b, err := l.open(ctx, l.loc.bucket)
		if err != nil {
			return nil, err
		}
		l.b = b
	}
	return l.b, nil
}

func (l *level) push(ctx context.Context, srcs []string, destination string) error {
	if len(srcs) == 0 {
		return errors.New("push: need a file or directory to upload")
	}
	if len(srcs) == 1 {
		rel := destination
		if rel == "" {
			rel = basename(strings.TrimSuffix(srcs[0], "/"))
		}
		return l.pushOne(ctx, srcs[0], rel)
	}
	prefix := ""
	if destination != "" {
		prefix = strings.TrimSuffix(destination, "/") + "/"
	}
	for _, src := range srcs {
		if err := l.pushOne(ctx, src, prefix+basename(strings.TrimSuffix(src, "/"))); err != nil {
			return err
		}
	}
	return nil
}

func (l *level) pushOne(ctx context.Context, src, rel string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("push: '%s' does not exist", src)
	}
	b, err := l.bkt(ctx)
	if err != nil {
		return err
	}
	name := l.loc.object(rel)
	// Only an object with exactly this name counts, so pushing a directory
	// again merges into what is there, as gsutil rsync did.
	exists, err := objectExists(ctx, b, name)
	if err != nil {
		return err
	}
	if exists && !l.force {
		return fmt.Errorf("push: '%s' already exists at this level (use --force to overwrite)", rel)
	}
	if fi.IsDir() {
		if exists {
			return fmt.Errorf("push: '%s' is an object at this level, so a directory cannot be synced into it", rel)
		}
		return l.pushDir(ctx, b, src, strings.TrimSuffix(name, "/"))
	}
	if strings.HasSuffix(name, "/") {
		name += basename(src)
	} else if !exists {
		// gsutil cp copies into an existing remote folder rather than beside it.
		_, prefixes, err := b.List(ctx, name, "/")
		if err != nil {
			return err
		}
		if slices.Contains(prefixes, name+"/") {
			name += "/" + basename(src)
		}
	}
	return l.upload(ctx, b, src, fi, name)
}

func (l *level) pushDir(ctx context.Context, b bucket, dir, dst string) error {
	var files []string
	if err := l.walkUploads(dir, "", &files); err != nil {
		return err
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(parallelTransfers)
	for _, rel := range files {
		g.Go(func() error {
			src := filepath.Join(dir, filepath.FromSlash(rel))
			fi, err := os.Stat(src)
			if err != nil {
				return err
			}
			return l.upload(gctx, b, src, fi, dst+"/"+rel)
		})
	}
	return g.Wait()
}

// walkUploads lists the files gsutil rsync -r would upload: symlinks to files
// are followed, symlinks to directories are skipped, and a broken symlink is
// an error rather than a silently missing artifact.
func (l *level) walkUploads(dir, rel string, files *[]string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		r := path.Join(rel, e.Name())
		t := e.Type()
		if t&fs.ModeSymlink != 0 {
			fi, err := os.Stat(p)
			if err != nil {
				return fmt.Errorf("push: '%s': %w", p, err)
			}
			t = fi.Mode().Type()
			if t.IsDir() {
				fmt.Fprintf(l.stderr, "Skipping symlink to directory %s\n", p)
				continue
			}
		} else if t.IsDir() {
			if err := l.walkUploads(p, r, files); err != nil {
				return err
			}
			continue
		}
		if !t.IsRegular() {
			fmt.Fprintf(l.stderr, "Skipping special file %s\n", p)
			continue
		}
		*files = append(*files, r)
	}
	return nil
}

func (l *level) upload(ctx context.Context, b bucket, src string, fi os.FileInfo, name string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	md := maps.Clone(l.labels)
	if md == nil {
		md = map[string]string{}
	}
	md[mtimeKey] = strconv.FormatInt(fi.ModTime().Unix(), 10)
	fmt.Fprintf(l.stderr, "Copying file://%s to %s\n", src, l.loc.url(name))
	if err := b.Write(ctx, name, f, contentType(src), md); err != nil {
		return fmt.Errorf("%s: uploading '%s': %w", l.cmd, src, err)
	}
	return nil
}

func contentType(file string) string {
	if t := mime.TypeByExtension(filepath.Ext(file)); t != "" {
		return t
	}
	return "application/octet-stream"
}

func (l *level) pull(ctx context.Context, positional []string, destination string) error {
	if len(positional) == 0 {
		if l.cmd == "yank" {
			return errors.New("yank: need a remote path to download and delete")
		}
		return errors.New("pull: need a remote path to download")
	}
	rel := positional[0]
	dest := destination
	if dest == "" {
		dest = basename(strings.TrimSuffix(rel, "/"))
	}
	if !l.force {
		if _, err := os.Stat(dest); err == nil {
			return fmt.Errorf("%s: '%s' already exists locally (use --force to overwrite)", l.cmd, dest)
		}
	}
	b, err := l.bkt(ctx)
	if err != nil {
		return err
	}
	name := l.loc.object(rel)
	attrs, err := b.Stat(ctx, name)
	isObject := err == nil
	switch {
	case isObject:
		if err := os.MkdirAll(filepath.Dir(dest), 0o777); err != nil {
			return err
		}
		if fi, err := os.Stat(dest); err == nil && fi.IsDir() {
			dest = filepath.Join(dest, basename(name))
		}
		if err := l.download(ctx, b, attrs, dest, false); err != nil {
			return err
		}
	case errors.Is(err, errNotExist):
		if err := l.pullDir(ctx, b, rel, name, dest); err != nil {
			return err
		}
	default:
		return err
	}
	if l.cmd == "yank" {
		return l.remove(ctx, b, name, isObject)
	}
	return nil
}

func (l *level) pullDir(ctx context.Context, b bucket, rel, name, dest string) error {
	prefix := strings.TrimSuffix(name, "/") + "/"
	objs, _, err := b.List(ctx, prefix, "")
	if err != nil {
		return err
	}
	// A trailing slash names a directory even when it is empty, as it did
	// for gsutil rsync.
	if len(objs) == 0 && !strings.HasSuffix(name, "/") {
		return fmt.Errorf("%s: '%s' does not exist at this level", l.cmd, rel)
	}
	if err := os.MkdirAll(dest, 0o777); err != nil {
		return err
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(parallelTransfers)
	for _, o := range objs {
		// Folder placeholders made by the console would collide with the
		// directories that hold their contents.
		if strings.HasSuffix(o.Name, "/") || strings.HasSuffix(o.Name, "_$folder$") {
			continue
		}
		r := strings.TrimPrefix(o.Name, prefix)
		if !filepath.IsLocal(filepath.FromSlash(r)) {
			return fmt.Errorf("%s: refusing to write '%s' outside '%s'", l.cmd, o.Name, dest)
		}
		local := filepath.Join(dest, filepath.FromSlash(r))
		g.Go(func() error {
			if err := os.MkdirAll(filepath.Dir(local), 0o777); err != nil {
				return err
			}
			return l.download(gctx, b, &o, local, true)
		})
	}
	return g.Wait()
}

// download writes to a temporary name and renames it into place, so an
// interrupted transfer never leaves a truncated file under the real name.
// The file gets the default 0666-minus-umask mode, as gsutil gave it.
func (l *level) download(ctx context.Context, b bucket, o *objectAttrs, dest string, rsync bool) error {
	fmt.Fprintf(l.stderr, "Copying %s to file://%s\n", l.loc.url(o.Name), dest)
	r, err := b.Read(ctx, o.Name)
	if err != nil {
		return fmt.Errorf("%s: downloading '%s': %w", l.cmd, o.Name, err)
	}
	defer r.Close()
	tmp := dest + "_.gstmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return err
	}
	_, err = f.ReadFrom(r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, dest)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: downloading '%s': %w", l.cmd, o.Name, err)
	}
	if mtime, ok := objectMtime(o, rsync); ok {
		return os.Chtimes(dest, time.Time{}, mtime)
	}
	return nil
}

// objectMtime follows gsutil: cp restores only a recorded mtime, while rsync
// falls back to the object's creation time.
func objectMtime(o *objectAttrs, rsync bool) (time.Time, bool) {
	if s, ok := o.Metadata[mtimeKey]; ok {
		secs, err := strconv.ParseInt(s, 10, 64)
		return time.Unix(secs, 0), err == nil
	}
	return o.Created, rsync && !o.Created.IsZero()
}

// remove deletes what yank downloaded: the object itself, or else everything
// under it, matching gsutil rm -r.
func (l *level) remove(ctx context.Context, b bucket, name string, isObject bool) error {
	names := []string{name}
	if !isObject {
		objs, _, err := b.List(ctx, strings.TrimSuffix(name, "/")+"/", "")
		if err != nil {
			return err
		}
		names = names[:0]
		for _, o := range objs {
			names = append(names, o.Name)
		}
		if len(names) == 0 {
			return fmt.Errorf("yank: no objects matched %s", l.loc.url(name))
		}
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(parallelTransfers)
	for _, n := range names {
		g.Go(func() error {
			fmt.Fprintf(l.stderr, "Removing %s\n", l.loc.url(n))
			// A retried delete can find that its first attempt succeeded.
			if err := b.Delete(gctx, n); err != nil && !errors.Is(err, errNotExist) {
				return fmt.Errorf("yank: deleting %s: %w", l.loc.url(n), err)
			}
			return nil
		})
	}
	return g.Wait()
}

func objectExists(ctx context.Context, b bucket, name string) (bool, error) {
	_, err := b.Stat(ctx, name)
	if errors.Is(err, errNotExist) {
		return false, nil
	}
	return err == nil, err
}
