// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package distribution

import (
	"context"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/steps"
)

type object struct {
	size    int64
	modTime time.Time
	// crc32c is the Castagnoli checksum; only GCS reports one.
	crc32c uint32
}

// objectStore is one bucket. Keys are full object names.
type objectStore interface {
	list(ctx context.Context, prefix string) (map[string]object, error)
	put(ctx context.Context, key, src string) error
	get(ctx context.Context, key, dest string) error
	remove(ctx context.Context, key string) error
}

// transfer copies between a local path and a bucket with the aws and gcloud
// CLI semantics that published objects and existing filters rely on.
type transfer struct {
	store objectStore

	// sync copies only what differs; mirror also deletes what the source lacks.
	sync   bool
	mirror bool
	dryRun bool

	rules []filterRule

	// differs reports whether src must be copied over an existing dst.
	differs func(src, dst object, srcPath string) (bool, error)
}

// bucketURI splits s3://bucket/key or gs://bucket/key.
func bucketURI(uri, scheme string) (bucket, key string, err error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", "", fmt.Errorf("parsing %s: %w", uri, err)
	}
	if parsed.Scheme != scheme || parsed.Host == "" {
		return "", "", fmt.Errorf("%s is not a %s:// URI", uri, scheme)
	}
	return parsed.Host, strings.TrimPrefix(parsed.Path, "/"), nil
}

// upload copies src, a file or a tree, to key. A file sent to a key ending
// in a slash keeps its name under it.
func (t transfer) upload(ctx context.Context, src, key string) error {
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}
	if !info.IsDir() {
		if !t.included(filepath.Base(src)) {
			return nil
		}
		if key == "" || strings.HasSuffix(key, "/") {
			key += filepath.Base(src)
		}
		return t.copy(ctx, "upload", key, func() error { return t.store.put(ctx, key, src) })
	}

	prefix := dirKey(key)
	local, err := localTree(src)
	if err != nil {
		return err
	}
	local = t.filtered(local)
	todo := slices.Sorted(maps.Keys(local))
	var remote map[string]object
	if t.sync || t.mirror {
		if remote, err = t.remoteTree(ctx, prefix); err != nil {
			return err
		}
		if todo, err = changed(todo, local, remote, func(rel string) string { return filepath.Join(src, filepath.FromSlash(rel)) }, t.differs); err != nil {
			return err
		}
	}
	_, err = steps.GoLimit(todo, steps.MaxConcurrency, func(rel string) (struct{}, error) {
		return struct{}{}, t.copy(ctx, "upload", prefix+rel, func() error {
			return t.store.put(ctx, prefix+rel, filepath.Join(src, filepath.FromSlash(rel)))
		})
	})
	if err != nil || !t.mirror {
		return err
	}
	var stale []string
	for rel := range remote {
		if _, ok := local[rel]; !ok {
			stale = append(stale, rel)
		}
	}
	slices.Sort(stale)
	_, err = steps.GoLimit(stale, steps.MaxConcurrency, func(rel string) (struct{}, error) {
		return struct{}{}, t.copy(ctx, "delete", prefix+rel, func() error { return t.store.remove(ctx, prefix+rel) })
	})
	return err
}

// fetch copies the tree under a key ending in a slash, or else the one object.
func (t transfer) fetch(ctx context.Context, key, dest string) error {
	if key == "" || strings.HasSuffix(key, "/") {
		return t.download(ctx, key, dest)
	}
	return t.copy(ctx, "download", key, func() error { return t.store.get(ctx, key, dest) })
}

// download copies the tree under key into dest. A synced file takes the
// object's time, so the next sync sees it as current.
func (t transfer) download(ctx context.Context, key, dest string) error {
	prefix := dirKey(key)
	remote, err := t.remoteTree(ctx, prefix)
	if err != nil {
		return err
	}
	todo := slices.Sorted(maps.Keys(remote))
	for _, rel := range todo {
		if !filepath.IsLocal(filepath.FromSlash(rel)) {
			return fmt.Errorf("object %s%s would land outside %s", prefix, rel, dest)
		}
	}
	if t.sync {
		local, err := localTree(dest)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if todo, err = changed(todo, remote, local, nil, newerOrResized); err != nil {
			return err
		}
	}
	_, err = steps.GoLimit(todo, steps.MaxConcurrency, func(rel string) (struct{}, error) {
		target := filepath.Join(dest, filepath.FromSlash(rel))
		return struct{}{}, t.copy(ctx, "download", prefix+rel, func() error {
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := t.store.get(ctx, prefix+rel, target); err != nil {
				return err
			}
			return os.Chtimes(target, remote[rel].modTime, remote[rel].modTime)
		})
	})
	return err
}

func (t transfer) copy(ctx context.Context, verb, key string, run func() error) error {
	log := logrus.WithField("key", key)
	if t.dryRun {
		log.Infof("Dry run, would %s", verb)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	log.Debugf("Starting %s", verb)
	if err := run(); err != nil {
		return fmt.Errorf("%s %s: %w", verb, key, err)
	}
	return nil
}

// remoteTree lists the objects under prefix, keyed relative to it. Keys that
// end in a slash are folder markers, not files.
func (t transfer) remoteTree(ctx context.Context, prefix string) (map[string]object, error) {
	listed, err := t.store.list(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", prefix, err)
	}
	tree := map[string]object{}
	for key, obj := range listed {
		rel := strings.TrimPrefix(key, prefix)
		if rel == "" || strings.HasSuffix(rel, "/") {
			continue
		}
		tree[rel] = obj
	}
	return t.filtered(tree), nil
}

func changed(rels []string, src, dst map[string]object, srcPath func(string) string, differs func(src, dst object, srcPath string) (bool, error)) ([]string, error) {
	var out []string
	for _, rel := range rels {
		have, ok := dst[rel]
		if !ok {
			out = append(out, rel)
			continue
		}
		var srcFile string
		if srcPath != nil {
			srcFile = srcPath(rel)
		}
		copyIt, err := differs(src[rel], have, srcFile)
		if err != nil {
			return nil, err
		}
		if copyIt {
			out = append(out, rel)
		}
	}
	return out, nil
}

func (t transfer) filtered(tree map[string]object) map[string]object {
	maps.DeleteFunc(tree, func(rel string, _ object) bool { return !t.included(rel) })
	return tree
}

func localTree(dir string) (map[string]object, error) {
	tree := map[string]object{}
	err := filepath.WalkDir(dir, func(file string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		// Stat rather than entry.Info so a symlink counts as the file it names.
		info, err := os.Stat(file)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, file)
		if err != nil {
			return err
		}
		tree[filepath.ToSlash(rel)] = object{size: info.Size(), modTime: info.ModTime()}
		return nil
	})
	return tree, err
}

func dirKey(key string) string {
	if key == "" {
		return ""
	}
	return addTrailingSlash(key)
}

// newerOrResized is aws sync's test: a size change or a newer source.
func newerOrResized(src, dst object, _ string) (bool, error) {
	return src.size != dst.size || src.modTime.After(dst.modTime), nil
}

// contentDiffers is a size and CRC32C check, which GCS reports on every object.
func contentDiffers(src, dst object, srcPath string) (bool, error) {
	if src.size != dst.size {
		return true, nil
	}
	sum, err := crc32cFile(srcPath)
	if err != nil {
		return false, err
	}
	return sum != dst.crc32c, nil
}

func crc32cFile(name string) (uint32, error) {
	file, err := os.Open(name)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()
	hasher := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	if _, err := io.Copy(hasher, file); err != nil {
		return 0, err
	}
	return hasher.Sum32(), nil
}

type filterRule struct {
	pattern *regexp.Regexp
	include bool
}

// filterRules keeps aws's order: every exclude, then every include.
func filterRules(exclude, include []string) ([]filterRule, error) {
	var rules []filterRule
	for _, group := range []struct {
		patterns []string
		include  bool
	}{{exclude, false}, {include, true}} {
		for _, pattern := range group.patterns {
			re, err := fnmatch(pattern)
			if err != nil {
				return nil, fmt.Errorf("filter %q: %w", pattern, err)
			}
			rules = append(rules, filterRule{pattern: re, include: group.include})
		}
	}
	return rules, nil
}

// included applies the rules left to right, and the last match decides.
func (t transfer) included(rel string) bool {
	in := true
	for _, rule := range t.rules {
		if rule.pattern.MatchString(rel) {
			in = rule.include
		}
	}
	return in
}

// fnmatch compiles a Python fnmatch pattern, the syntax aws filters use. Unlike
// path.Match, * and ? also match a slash.
func fnmatch(pattern string) (*regexp.Regexp, error) {
	var re strings.Builder
	re.WriteString(`^(?s:`)
	for idx := 0; idx < len(pattern); idx++ {
		switch char := pattern[idx]; char {
		case '*':
			re.WriteString(`.*`)
		case '?':
			re.WriteString(`.`)
		case '[':
			// As in Python, a ] straight after [ or [! is part of the set.
			start := idx + 1
			if start < len(pattern) && pattern[start] == '!' {
				start++
			}
			if start < len(pattern) && pattern[start] == ']' {
				start++
			}
			end := strings.IndexByte(pattern[start:], ']')
			if end < 0 {
				re.WriteString(`\[`)
				continue
			}
			class := pattern[idx+1 : start+end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			re.WriteString("[" + strings.NewReplacer(`\`, `\\`, `[`, `\[`, `]`, `\]`).Replace(class) + "]")
			idx = start + end
		default:
			re.WriteString(regexp.QuoteMeta(string(char)))
		}
	}
	re.WriteString(`)$`)
	return regexp.Compile(re.String())
}

// contentType follows Python's mimetypes, which typed every object already
// served. A compression suffix is skipped, so a.yaml.gz is YAML.
func contentType(name string) string {
	ext := path.Ext(name)
	if full, ok := suffixAliases[ext]; ok {
		name, ext = strings.TrimSuffix(name, ext)+full, path.Ext(full)
	}
	if encodingSuffixes[ext] {
		ext = path.Ext(strings.TrimSuffix(name, ext))
	}
	if ct, ok := contentTypes[ext]; ok {
		return ct
	}
	return contentTypes[strings.ToLower(ext)]
}

var suffixAliases = map[string]string{
	".svgz": ".svg.gz",
	".tgz":  ".tar.gz",
	".taz":  ".tar.gz",
	".tz":   ".tar.gz",
	".tbz2": ".tar.bz2",
	".txz":  ".tar.xz",
}

var encodingSuffixes = map[string]bool{".gz": true, ".Z": true, ".bz2": true, ".xz": true, ".br": true}

var contentTypes = map[string]string{
	".asc":    "application/pgp-keys",
	".crt":    "application/x-x509-ca-cert",
	".css":    "text/css",
	".csv":    "text/csv",
	".deb":    "application/vnd.debian.binary-package",
	".exe":    "application/x-msdos-program",
	".gif":    "image/gif",
	".htm":    "text/html",
	".html":   "text/html",
	".ico":    "image/vnd.microsoft.icon",
	".jpeg":   "image/jpeg",
	".jpg":    "image/jpeg",
	".js":     "text/javascript",
	".json":   "application/json",
	".md":     "text/markdown",
	".msi":    "application/x-msi",
	".pdf":    "application/pdf",
	".pem":    "application/pem-certificate-chain",
	".png":    "image/png",
	".rpm":    "application/x-redhat-package-manager",
	".sh":     "application/x-sh",
	".sig":    "application/pgp-signature",
	".sqlite": "application/vnd.sqlite3",
	".svg":    "image/svg+xml",
	".tar":    "application/x-tar",
	".txt":    "text/plain",
	".wasm":   "application/wasm",
	".woff":   "font/woff",
	".woff2":  "font/woff2",
	".xml":    "application/xml",
	".yaml":   "application/yaml",
	".yml":    "application/yaml",
	".zip":    "application/zip",
	".zst":    "application/zstd",
}
