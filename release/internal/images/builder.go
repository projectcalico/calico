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

package images

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

type Builder struct {
	cfg Config
}

// NewBuilder rejects publish-only fields rather than ignoring them: a caller
// setting one meant to publish.
func NewBuilder(cfg Config, opts ...Option) (*Builder, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.From != "" || cfg.FromTag != "" {
		return nil, fmt.Errorf("From is a publish setting and cannot be used to build")
	}
	if cfg.Scan != nil {
		return nil, fmt.Errorf("Scan is a publish setting and cannot be used to build")
	}
	return &Builder{cfg: cfg.apply(opts)}, nil
}

func (b *Builder) Build() error {
	units := b.cfg.units(b.cfg.env())
	logrus.WithField("images", len(units)).Info("Building container images")
	if err := b.cfg.runUnits(units, "build"); err != nil {
		return err
	}
	logrus.Info("Finished building container images")
	return nil
}
