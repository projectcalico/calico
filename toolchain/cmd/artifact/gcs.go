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
	"io"
	"os"
	"slices"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/storage"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func openGCS(ctx context.Context, name string) (bucket, error) {
	opts, err := credentialOptions(ctx, os.Getenv)
	if err != nil {
		return nil, err
	}
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	// The default policy retries only requests with preconditions. Every
	// write here replaces an object with the same content and every delete
	// is wanted gone, so repeating either after a transient failure is safe.
	client.SetRetry(storage.WithPolicy(storage.RetryAlways))
	return &gcsBucket{h: client.Bucket(name)}, nil
}

// credentialOptions picks the identity gsutil used. ArgoCI pods have no
// ambient storage credentials, so the handler wraps every call with a
// BOTO_CONFIG naming a dedicated service-account key, and that key comes
// first. Without one, GCE and GKE use the metadata server even when
// GOOGLE_APPLICATION_CREDENTIALS is set, because steps point that variable at
// other accounts for their own tools (gsutil ignored it there through
// pass_credentials_to_gsutil=false). Anywhere else, Application Default
// Credentials apply.
func credentialOptions(ctx context.Context, getenv func(string) string) ([]option.ClientOption, error) {
	keyFile, err := botoServiceKeyFile(getenv("BOTO_CONFIG"))
	if err != nil {
		return nil, err
	}
	if keyFile != "" {
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("BOTO_CONFIG gs_service_key_file: %w", err)
		}
		return []option.ClientOption{option.WithAuthCredentialsJSON(option.ServiceAccount, key)}, nil
	}
	if metadata.OnGCEWithContext(ctx) {
		return []option.ClientOption{option.WithTokenSource(google.ComputeTokenSource(""))}, nil
	}
	return nil, nil
}

type gcsBucket struct {
	h *storage.BucketHandle
}

func (b *gcsBucket) Stat(ctx context.Context, name string) (*objectAttrs, error) {
	a, err := b.h.Object(name).Attrs(ctx)
	if err != nil {
		return nil, mapNotExist(err)
	}
	return &objectAttrs{Name: a.Name, Size: a.Size, Created: a.Created, Metadata: a.Metadata}, nil
}

func (b *gcsBucket) List(ctx context.Context, prefix, delimiter string) ([]objectAttrs, []string, error) {
	q := &storage.Query{Prefix: prefix, Delimiter: delimiter}
	if err := q.SetAttrSelection([]string{"Name", "Size", "Created", "Metadata"}); err != nil {
		return nil, nil, err
	}
	var objs []objectAttrs
	var prefixes []string
	it := b.h.Objects(ctx, q)
	for {
		a, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if a.Prefix != "" {
			prefixes = append(prefixes, a.Prefix)
			continue
		}
		objs = append(objs, objectAttrs{Name: a.Name, Size: a.Size, Created: a.Created, Metadata: a.Metadata})
	}
	slices.SortFunc(objs, func(x, y objectAttrs) int { return strings.Compare(x.Name, y.Name) })
	slices.Sort(prefixes)
	return objs, prefixes, nil
}

func (b *gcsBucket) Read(ctx context.Context, name string) (io.ReadCloser, error) {
	r, err := b.h.Object(name).NewReader(ctx)
	if err != nil {
		return nil, mapNotExist(err)
	}
	return r, nil
}

func (b *gcsBucket) Write(ctx context.Context, name string, r io.Reader, contentType string, md map[string]string) error {
	// Cancelling the context before Close is what abandons the upload, so a
	// failed read never becomes a truncated object.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := b.h.Object(name).NewWriter(ctx)
	w.ContentType = contentType
	w.Metadata = md
	if _, err := io.Copy(w, r); err != nil {
		return err
	}
	return w.Close()
}

func (b *gcsBucket) Delete(ctx context.Context, name string) error {
	return mapNotExist(b.h.Object(name).Delete(ctx))
}

func mapNotExist(err error) error {
	if errors.Is(err, storage.ErrObjectNotExist) {
		return errNotExist
	}
	return err
}
