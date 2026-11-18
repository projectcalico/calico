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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	tmtypes "github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"google.golang.org/api/iterator"
)

// The types each service gives an object uploaded with no type, which the SDKs
// would otherwise replace.
const (
	s3DefaultType  = "binary/octet-stream"
	gcsDefaultType = "application/octet-stream"
)

type s3Store struct {
	client *s3.Client
	bucket string

	// acl is empty for a private object.
	acl          types.ObjectCannedACL
	cacheControl string
}

func newS3Store(ctx context.Context, bucket string, d S3) (s3Store, error) {
	cfg := aws.Config{Credentials: d.Credentials}
	var err error
	if d.Credentials == nil {
		var opts []func(*config.LoadOptions) error
		if d.Profile != "" {
			opts = append(opts, config.WithSharedConfigProfile(d.Profile))
		}
		if cfg, err = config.LoadDefaultConfig(ctx, opts...); err != nil {
			return s3Store{}, fmt.Errorf("loading AWS config: %w", err)
		}
	}
	// The SDK does not follow a wrong-region redirect.
	if cfg.Region, err = bucketRegion(ctx, s3RegionEndpoint, bucket); err != nil {
		return s3Store{}, err
	}
	store := s3Store{client: s3.NewFromConfig(cfg), bucket: bucket, cacheControl: d.CachePolicy}
	if !d.Private {
		store.acl = types.ObjectCannedACLPublicRead
	}
	return store, nil
}

var s3RegionEndpoint = "https://s3.amazonaws.com"

// bucketRegion reads the region S3 names on any answer about a bucket, even a
// refusal, so it needs no permission on the bucket.
func bucketRegion(ctx context.Context, endpoint, bucket string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint+"/"+bucket, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("finding the region of %s: %w", bucket, err)
	}
	_ = resp.Body.Close()
	region := resp.Header.Get("X-Amz-Bucket-Region")
	if region == "" {
		return "", fmt.Errorf("finding the region of %s: %s with no region", bucket, resp.Status)
	}
	return region, nil
}

func (s s3Store) list(ctx context.Context, prefix string) (map[string]object, error) {
	out := map[string]object{}
	pages := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &prefix})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			out[aws.ToString(obj.Key)] = object{size: aws.ToInt64(obj.Size), modTime: aws.ToTime(obj.LastModified)}
		}
	}
	return out, nil
}

func (s s3Store) put(ctx context.Context, key, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	input := &transfermanager.UploadObjectInput{
		Bucket:      &s.bucket,
		Key:         &key,
		Body:        in,
		ACL:         tmtypes.ObjectCannedACL(s.acl),
		ContentType: aws.String(s3DefaultType),
	}
	if ct := contentType(key); ct != "" {
		input.ContentType = &ct
	}
	if s.cacheControl != "" {
		input.CacheControl = &s.cacheControl
	}
	_, err = transfermanager.New(s.client).UploadObject(ctx, input)
	return err
}

func (s s3Store) get(ctx context.Context, key, dest string) error {
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return writeFile(dest, resp.Body)
}

func (s s3Store) remove(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &key})
	return err
}

type gcsStore struct {
	bucket *storage.BucketHandle
}

func (s gcsStore) list(ctx context.Context, prefix string) (map[string]object, error) {
	out := map[string]object{}
	objects := s.bucket.Objects(ctx, &storage.Query{Prefix: prefix})
	for {
		attrs, err := objects.Next()
		if errors.Is(err, iterator.Done) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out[attrs.Name] = object{size: attrs.Size, modTime: attrs.Updated, crc32c: attrs.CRC32C}
	}
}

func (s gcsStore) put(ctx context.Context, key, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out := s.bucket.Object(key).NewWriter(ctx)
	// An empty type makes the writer sniff the content.
	out.ContentType = gcsDefaultType
	if ct := contentType(key); ct != "" {
		out.ContentType = ct
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func (s gcsStore) get(ctx context.Context, key, dest string) error {
	in, err := s.bucket.Object(key).NewReader(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	return writeFile(dest, in)
}

func (s gcsStore) remove(ctx context.Context, key string) error {
	return s.bucket.Object(key).Delete(ctx)
}

func writeFile(dest string, in io.Reader) error {
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
