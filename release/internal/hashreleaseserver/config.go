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
	"context"
	"fmt"

	"cloud.google.com/go/storage"
)

// Config holds the configuration for hashrelease publishing.
type Config struct {

	// cloud storage bucket name
	BucketName string

	gcsClient *storage.Client
}

func (s *Config) Valid() bool {
	return s.BucketName != ""
}

func (s *Config) Bucket() (*storage.BucketHandle, error) {
	if s.gcsClient == nil {
		cli, err := storage.NewClient(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to create storage client: %w", err)
		}
		s.gcsClient = cli
	}
	return s.gcsClient.Bucket(s.BucketName), nil
}
