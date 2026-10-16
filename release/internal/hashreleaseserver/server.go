// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package hashreleaseserver

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/googleapi"

	"github.com/projectcalico/calico/release/internal/registry"
)

const (

	// BaseDomain is the base URL of the hashrelease
	BaseDomain = "hashrelease.tools.tigera.net"

	releaseLibFileName = "all-releases"
)

type Hashrelease struct {
	// Name is the name of the hashrelease.
	// When publishing a hashrelease, this is the name of the folder in the server.
	// When getting a hashrelease, this is the full path of the hashrelease folder.
	Name string `yaml:"name"`

	// Hash is the hash of the hashrelease
	Hash string `yaml:"hash"`

	// Note is the info about the hashrelease
	Note string `yaml:"note,omitempty"`

	// Stream is the version the hashrelease is for (e.g master, v3.19)
	Stream string `yaml:"stream"`

	// ProductVersion is the product version in the hashrelease
	ProductVersion string `yaml:"version"`

	// ChartVersion qualifies the chart version when the charts rev with the product version.
	ChartVersion string `yaml:"chartVersion,omitempty"`

	// Operator is the operator for the hashrelease
	Operator registry.Component `yaml:"operator"`

	// Components are the pinned components in the hashrelease.
	Components map[string]registry.Component `yaml:"components,omitempty"`

	// Source is the source of hashrelease content on the local filesystem
	Source string `yaml:"source,omitempty"`

	// Latest is if the hashrelease is the latest for the stream
	Latest bool `yaml:"latest,omitempty"`

	// ImageScanResultURL is the URL to the image scan result for this hashrelease
	ImageScanResultURL string `yaml:"iss_url,omitempty"`
}

// BucketURI is where the hashrelease's content is served from.
func (h *Hashrelease) BucketURI(cfg *Config) string {
	return fmt.Sprintf("gs://%s/%s", cfg.BucketName, h.Name)
}

func (h *Hashrelease) URL() string {
	return HashreleaseURL(h.Name)
}

func HashreleaseURL(hashreleaseName string) string {
	return fmt.Sprintf("https://%s.%s", hashreleaseName, BaseDomain)
}

// Uploading the content is the caller's, not this.
func Record(productCode string, h *Hashrelease, cfg *Config) error {
	logrus.WithFields(logrus.Fields{
		"hashrelease": h.Name,
		"latest":      h.Latest,
	}).Info("Recording hashrelease")

	if err := addToHashreleaseLibrary(*h, cfg); err != nil {
		logrus.WithError(err).Error("failed to add hashrelease to library")
		return err
	}

	if h.Latest {
		if err := setHashreleaseAsLatest(*h, productCode, cfg); err != nil {
			// Being unreachable as "latest" is not worth failing a publish over.
			logrus.WithError(err).Error("failed to set hashrelease as latest")
		}
	}

	return nil
}

func HasHashrelease(hash string, cfg *Config) (bool, error) {
	logrus.WithField("hash", hash).Debug("Checking if hashrelease exists")
	objs, err := cfg.objects()
	if err != nil {
		return false, fmt.Errorf("failed to get bucket handler for hashrelease server: %w", err)
	}
	library, _, err := objs.Read(context.Background(), releaseLibFileName)
	if err != nil {
		return false, fmt.Errorf("failed to read hashrelease library from bucket: %w", err)
	}
	// Each entry is "<hash> - <note>". A hash is a dash-joined list of versions,
	// so a substring test would also match a longer hash, or a note.
	scanner := bufio.NewScanner(bytes.NewReader(library))
	for scanner.Scan() {
		if fields := strings.Fields(scanner.Text()); len(fields) > 0 && fields[0] == hash {
			logrus.WithField("hash", hash).Debug("Found hashrelease in library")
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("failed to scan hashrelease library: %w", err)
	}
	return false, nil
}

// setHashreleaseAsLatest sets the hashrelease as the latest for the stream
func setHashreleaseAsLatest(rel Hashrelease, productCode string, cfg *Config) error {
	logrus.WithFields(logrus.Fields{
		"hashrelease": rel.Name,
		"stream":      rel.Stream,
		"productCode": productCode,
	}).Info("Setting hashrelease as latest for stream")
	objs, err := cfg.objects()
	if err != nil {
		return fmt.Errorf("failed to get bucket handler for hashrelease publishing: %w", err)
	}
	name := path.Join("latest-"+productCode, rel.Stream+".txt")
	if err := objs.Write(context.Background(), name, []byte(rel.URL()+"/"), anyGeneration); err != nil {
		return fmt.Errorf("failed to update latest hashrelease file in bucket: %w", err)
	}
	return nil
}

func addToHashreleaseLibrary(rel Hashrelease, cfg *Config) error {
	logrus.WithField("hashrelease", rel.Name).WithField("hash", rel.Hash).Info("Adding hashrelease to library")
	objs, err := cfg.objects()
	if err != nil {
		return fmt.Errorf("failed to get bucket for hashrelease publishing: %w", err)
	}
	if err := appendLine(context.Background(), objs, releaseLibFileName, fmt.Sprintf("%s - %s ", rel.Hash, rel.Note)); err != nil {
		return fmt.Errorf("failed to update hashrelease library in bucket: %w", err)
	}
	return nil
}

// Publishes can run at once, so an append writes only over the generation it
// read and starts again when another writer got there first.
const maxAppendAttempts = 5

func appendLine(ctx context.Context, objs textObjects, name, line string) error {
	for attempt := 1; ; attempt++ {
		existing, generation, err := objs.Read(ctx, name)
		if err != nil {
			return err
		}
		updated := line + "\n"
		if trimmed := strings.TrimRight(string(existing), "\n"); trimmed != "" {
			updated = trimmed + "\n" + updated
		}
		err = objs.Write(ctx, name, []byte(updated), generation)
		if !errors.Is(err, errChanged) {
			return err
		}
		if attempt == maxAppendAttempts {
			return fmt.Errorf("%s changed under %d attempts to append to it: %w", name, attempt, err)
		}
		logrus.WithField("object", name).Debug("Object changed since it was read, retrying")
	}
}

var errChanged = errors.New("object changed since it was read")

// anyGeneration makes a Write unconditional.
const anyGeneration int64 = -1

// textObjects is the part of the bucket the library and the latest pointers use.
type textObjects interface {
	// Read returns an object and its generation. A missing object reads as
	// empty at generation 0.
	Read(ctx context.Context, name string) ([]byte, int64, error)
	// Write replaces an object only while it is at generation, where 0 means it
	// must not exist yet, and returns errChanged otherwise.
	Write(ctx context.Context, name string, data []byte, generation int64) error
}

type bucketObjects struct {
	bucket *storage.BucketHandle
}

func (b bucketObjects) Read(ctx context.Context, name string) ([]byte, int64, error) {
	r, err := b.bucket.Object(name).NewReader(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = r.Close() }()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, err
	}
	return data, r.Attrs.Generation, nil
}

func (b bucketObjects) Write(ctx context.Context, name string, data []byte, generation int64) error {
	obj := b.bucket.Object(name)
	switch {
	case generation == 0:
		obj = obj.If(storage.Conditions{DoesNotExist: true})
	case generation > 0:
		obj = obj.If(storage.Conditions{GenerationMatch: generation})
	}
	// Closing a writer commits whatever it holds, so a failed write cancels
	// the context instead to leave the object as it was.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := obj.NewWriter(ctx)
	w.ContentType = "text/plain"
	w.Metadata = map[string]string{
		"updated-by": "hashreleaseserver",
		"updated-at": time.Now().Format(time.RFC3339),
	}
	if _, err := w.Write(data); err != nil {
		cancel()
		return err
	}
	err := w.Close()
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) && apiErr.Code == http.StatusPreconditionFailed {
		return errChanged
	}
	return err
}
