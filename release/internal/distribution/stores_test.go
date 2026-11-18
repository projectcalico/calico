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
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/api/option"
)

// recorder keeps the headers of each request a fake endpoint received.
type recorder struct {
	mu       sync.Mutex
	requests []*http.Request
}

func (r *recorder) record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
}

func TestS3StorePut(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store s3Store
		file  string
		want  map[string]string
	}{
		{
			name:  "public, typed, with a cache policy",
			store: s3Store{acl: types.ObjectCannedACLPublicRead, cacheControl: MutableCachePolicy},
			file:  "tigera-operator.yaml",
			want:  map[string]string{"X-Amz-Acl": "public-read", "Cache-Control": MutableCachePolicy, "Content-Type": "application/yaml"},
		},
		{
			name:  "private, untyped, no cache policy",
			store: s3Store{},
			file:  "calicoctl-darwin-amd64",
			want:  map[string]string{"X-Amz-Acl": "", "Cache-Control": "", "Content-Type": "binary/octet-stream"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				_, _ = io.Copy(io.Discard, req.Body)
				rec.record(req)
			}))
			defer srv.Close()

			store := tc.store
			store.bucket = "bucket"
			store.client = s3.New(s3.Options{
				Region:       "us-east-1",
				BaseEndpoint: aws.String(srv.URL),
				UsePathStyle: true,
				Credentials:  credentials.NewStaticCredentialsProvider("id", "secret", ""),
			})
			src := filepath.Join(writeTree(t, time.Now(), tc.file), tc.file)
			if err := store.put(context.Background(), "charts/"+tc.file, src); err != nil {
				t.Fatal(err)
			}
			if len(rec.requests) != 1 {
				t.Fatalf("got %d requests, want 1", len(rec.requests))
			}
			req := rec.requests[0]
			if req.Method != http.MethodPut || req.URL.Path != "/bucket/charts/"+tc.file {
				t.Errorf("request = %s %s", req.Method, req.URL.Path)
			}
			got := map[string]string{}
			for header := range tc.want {
				got[header] = req.Header.Get(header)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("headers (-want +got):\n%s", diff)
			}
		})
	}
	t.Run("a large file goes up in parts, typed and public", func(t *testing.T) {
		rec := &recorder{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.Copy(io.Discard, req.Body)
			rec.record(req)
			query := req.URL.Query()
			switch {
			case req.Method == http.MethodPost && query.Has("uploads"):
				_, _ = io.WriteString(w, `<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>charts/big.tgz</Key><UploadId>upload</UploadId></InitiateMultipartUploadResult>`)
			case req.Method == http.MethodPut && query.Has("partNumber"):
				w.Header().Set("ETag", `"part-`+query.Get("partNumber")+`"`)
			case req.Method == http.MethodPost && query.Has("uploadId"):
				_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><Bucket>bucket</Bucket><Key>charts/big.tgz</Key><ETag>"done"</ETag></CompleteMultipartUploadResult>`)
			default:
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
		defer srv.Close()

		store := s3Store{acl: types.ObjectCannedACLPublicRead, bucket: "bucket", client: s3.New(s3.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(srv.URL),
			UsePathStyle: true,
			Credentials:  credentials.NewStaticCredentialsProvider("id", "secret", ""),
		})}
		src := filepath.Join(t.TempDir(), "big.tgz")
		if err := os.WriteFile(src, bytes.Repeat([]byte("x"), 20<<20), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := store.put(context.Background(), "charts/big.tgz", src); err != nil {
			t.Fatal(err)
		}
		var parts int
		var create *http.Request
		for _, req := range rec.requests {
			switch {
			case req.URL.Query().Has("partNumber"):
				parts++
			case req.URL.Query().Has("uploads"):
				create = req
			}
		}
		if parts < 2 {
			t.Errorf("sent %d parts, want a multipart upload", parts)
		}
		if create == nil {
			t.Fatal("no multipart upload was started")
		}
		got := map[string]string{"X-Amz-Acl": create.Header.Get("X-Amz-Acl"), "Content-Type": create.Header.Get("Content-Type")}
		if diff := cmp.Diff(map[string]string{"X-Amz-Acl": "public-read", "Content-Type": "application/x-tar"}, got); diff != "" {
			t.Errorf("upload headers (-want +got):\n%s", diff)
		}
	})
}

func TestGCSStorePut(t *testing.T) {
	var meta struct {
		Name        string `json:"name"`
		ContentType string `json:"contentType"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		part, err := multipart.NewReader(req.Body, params["boundary"]).NextPart()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := json.NewDecoder(part).Decode(&meta); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"bucket": "bucket", "name": meta.Name})
	}))
	defer srv.Close()

	client, err := storage.NewClient(context.Background(), option.WithEndpoint(srv.URL+"/storage/v1/"), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	for file, want := range map[string]string{
		"index.html": "text/html",
		// SHA256SUMS is text, and an unset type would be sniffed as text/plain.
		"SHA256SUMS": "application/octet-stream",
	} {
		t.Run(file, func(t *testing.T) {
			src := filepath.Join(writeTree(t, time.Now(), file), file)
			if err := (gcsStore{bucket: client.Bucket("bucket")}).put(context.Background(), "hash/"+file, src); err != nil {
				t.Fatal(err)
			}
			if meta.Name != "hash/"+file || meta.ContentType != want {
				t.Errorf("uploaded %q as %q, want hash/%s as %s", meta.Name, meta.ContentType, file, want)
			}
		})
	}
}

func TestBucketRegion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		region  string
		wantErr bool
	}{
		{name: "read from a refusal", status: http.StatusForbidden, region: "us-east-1"},
		{name: "read from a success", status: http.StatusOK, region: "eu-west-2"},
		{name: "missing bucket", status: http.StatusNotFound, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path != "/bucket" {
					http.NotFound(w, req)
					return
				}
				if tc.region != "" {
					w.Header().Set("X-Amz-Bucket-Region", tc.region)
				}
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			got, err := bucketRegion(context.Background(), srv.URL, "bucket")
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			if got != tc.region {
				t.Errorf("region = %q, want %q", got, tc.region)
			}
		})
	}
}

func TestNewS3Store(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Amz-Bucket-Region", "eu-west-2")
	}))
	defer srv.Close()
	prev := s3RegionEndpoint
	s3RegionEndpoint = srv.URL
	t.Cleanup(func() { s3RegionEndpoint = prev })
	t.Setenv("AWS_PROFILE", "no-such-profile")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "config"))

	t.Run("credentials read no env or shared config", func(t *testing.T) {
		creds := credentials.NewStaticCredentialsProvider("id", "secret", "")
		store, err := newS3Store(context.Background(), "bucket", S3{Credentials: creds})
		if err != nil {
			t.Fatal(err)
		}
		if got := store.client.Options().Region; got != "eu-west-2" {
			t.Errorf("region = %q, want eu-west-2", got)
		}
	})

	t.Run("without credentials the env profile is read", func(t *testing.T) {
		if _, err := newS3Store(context.Background(), "bucket", S3{}); err == nil {
			t.Error("a missing env profile was not read")
		}
	})
}
