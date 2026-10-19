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
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"

	"github.com/projectcalico/calico/release/internal/steps"
)

// GCS publishes to a Cloud Storage location: a file to the object the URI
// names, a directory to the objects under it.
type GCS struct {
	URI string

	// Sync deletes objects under the URI that the source no longer has.
	Sync bool

	DryRun bool

	store objectStore
}

func (d GCS) Name() string { return d.URI }

func (d GCS) Validate(u Upload) error {
	return validSource(u)
}

func (d GCS) Publish(ctx context.Context, src string) error {
	if err := d.publish(ctx, src); err != nil {
		return fmt.Errorf("copying to %s: %w", d.URI, err)
	}
	return nil
}

func (d GCS) publish(ctx context.Context, src string) error {
	bucket, prefix, err := parseGCSURI(d.URI)
	if err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	local, err := localObjects(src, info.IsDir(), prefix)
	if err != nil {
		return err
	}
	store := d.store
	if store == nil {
		client, err := storage.NewClient(ctx)
		if err != nil {
			return fmt.Errorf("storage client: %w", err)
		}
		defer func() { _ = client.Close() }()
		store = gcsStore{client: client}
	}

	// A directory owns everything under the prefix, and the separator keeps
	// hash/ from also matching hash-old/. A file owns only its own object, so a
	// sync never deletes a neighbour that merely shares its name as a prefix.
	listPrefix := dirPrefix(prefix)
	if !info.IsDir() {
		listPrefix = sortedKeys(local)[0]
	}
	remote, err := store.List(ctx, bucket, listPrefix)
	if err != nil {
		return fmt.Errorf("listing gs://%s/%s: %w", bucket, listPrefix, err)
	}
	if !info.IsDir() {
		for name := range remote {
			if name != listPrefix {
				delete(remote, name)
			}
		}
	}

	var uploads []localObject
	for _, name := range sortedKeys(local) {
		obj := local[name]
		if r, ok := remote[name]; ok && r.size == obj.size && bytes.Equal(r.md5, obj.md5) {
			continue
		}
		uploads = append(uploads, obj)
	}
	var deletes []string
	if d.Sync {
		for _, name := range sortedKeys(remote) {
			if _, ok := local[name]; !ok {
				deletes = append(deletes, name)
			}
		}
	}

	log := logrus.WithFields(logrus.Fields{"destination": d.URI, "upload": len(uploads), "delete": len(deletes), "unchanged": len(local) - len(uploads)})
	if d.DryRun {
		for _, o := range uploads {
			logrus.WithField("object", "gs://"+bucket+"/"+o.name).Info("Dry run, would upload")
		}
		for _, name := range deletes {
			logrus.WithField("object", "gs://"+bucket+"/"+name).Info("Dry run, would delete")
		}
		log.Info("Dry run, not copying")
		return nil
	}

	if _, err := steps.GoLimit(uploads, steps.MaxConcurrency, func(o localObject) (struct{}, error) {
		return struct{}{}, store.Upload(ctx, bucket, o)
	}); err != nil {
		return err
	}
	// Deleting last means a failed upload never leaves the destination with
	// less than it had.
	if _, err := steps.GoLimit(deletes, steps.MaxConcurrency, func(name string) (struct{}, error) {
		return struct{}{}, store.Delete(ctx, bucket, name)
	}); err != nil {
		return err
	}
	log.Info("Published")
	return nil
}

func parseGCSURI(uri string) (bucket, prefix string, err error) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "gs" || u.Host == "" {
		return "", "", fmt.Errorf("%q is not a gs://bucket/path URI", uri)
	}
	return u.Host, strings.TrimPrefix(u.Path, "/"), nil
}

type localObject struct {
	name string // object name in the bucket
	path string // file on disk
	size int64
	md5  []byte
}

// localObjects maps the object names src publishes to. A directory's files
// land under prefix by their path relative to it; a file becomes the object
// prefix names, or prefix/<file> when prefix ends in a slash.
func localObjects(src string, dir bool, prefix string) (map[string]localObject, error) {
	out := map[string]localObject{}
	add := func(name, p string) error {
		o, err := hashFile(p)
		if err != nil {
			return err
		}
		o.name = name
		out[name] = o
		return nil
	}
	if !dir {
		name := prefix
		if name == "" || strings.HasSuffix(name, "/") {
			name += filepath.Base(src)
		}
		return out, add(name, src)
	}
	base := dirPrefix(prefix)
	err := filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		return add(base+filepath.ToSlash(rel), p)
	})
	return out, err
}

// dirPrefix is prefix as a directory: empty for the bucket root, otherwise
// ending in exactly one slash.
func dirPrefix(prefix string) string {
	if prefix == "" {
		return ""
	}
	return strings.TrimSuffix(prefix, "/") + "/"
}

func hashFile(p string) (localObject, error) {
	f, err := os.Open(p)
	if err != nil {
		return localObject{}, err
	}
	defer func() { _ = f.Close() }()
	h := md5.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return localObject{}, fmt.Errorf("reading %s: %w", p, err)
	}
	return localObject{path: p, size: n, md5: h.Sum(nil)}, nil
}

// contentType follows the extension, as gcloud does. The hashrelease bucket is
// served as a website, and a browser refuses a stylesheet or script whose type
// was sniffed as text/plain.
func contentType(name string, head []byte) string {
	if t := mime.TypeByExtension(path.Ext(name)); t != "" {
		return t
	}
	return http.DetectContentType(head)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

type remoteObject struct {
	size int64
	md5  []byte
}

// objectStore is the part of Cloud Storage a publish needs.
type objectStore interface {
	List(ctx context.Context, bucket, prefix string) (map[string]remoteObject, error)
	Upload(ctx context.Context, bucket string, o localObject) error
	Delete(ctx context.Context, bucket, name string) error
}

type gcsStore struct {
	client *storage.Client
}

func (s gcsStore) List(ctx context.Context, bucket, prefix string) (map[string]remoteObject, error) {
	out := map[string]remoteObject{}
	q := &storage.Query{Prefix: prefix}
	if err := q.SetAttrSelection([]string{"Name", "Size", "MD5"}); err != nil {
		return nil, err
	}
	it := s.client.Bucket(bucket).Objects(ctx, q)
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out[attrs.Name] = remoteObject{size: attrs.Size, md5: attrs.MD5}
	}
}

func (s gcsStore) Upload(ctx context.Context, bucket string, o localObject) error {
	f, err := os.Open(o.path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// Closing a writer commits whatever it holds, even nothing, so a failed
	// copy cancels the context instead to leave the object as it was.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := s.client.Bucket(bucket).Object(o.name).NewWriter(ctx)
	w.ContentType = contentType(o.name, head[:n])
	// The server rejects the upload if what arrived does not match.
	w.MD5 = o.md5
	if _, err := io.Copy(w, f); err != nil {
		cancel()
		return fmt.Errorf("uploading %s: %w", o.name, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("uploading %s: %w", o.name, err)
	}
	return nil
}

func (s gcsStore) Delete(ctx context.Context, bucket, name string) error {
	err := s.client.Bucket(bucket).Object(name).Delete(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil
	}
	return err
}
