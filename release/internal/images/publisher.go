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
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
)

type Publisher struct {
	cfg Config
}

func NewPublisher(cfg Config, opts ...Option) (*Publisher, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if len(cfg.Registries) == 0 {
		return nil, fmt.Errorf("no registries to publish to")
	}
	if (cfg.From == "") != (cfg.FromTag == "") {
		return nil, fmt.Errorf("from and fromTag must be set together")
	}
	if !cfg.Publish {
		// A dry run reaches no registry, so anything it recorded would claim
		// images exist when they do not.
		cfg.Refs = nil
	}
	return &Publisher{cfg: cfg.apply(opts)}, nil
}

func (p *Publisher) Publish() error {
	units := p.cfg.units(p.publishEnv())
	logrus.WithField("images", len(units)).Info("Publishing container images")
	publishErr := p.cfg.runUnits(units, publishStep)

	// Record before reporting a failure: a partial publish is exactly the run
	// whose record decides what a resume still has to do.
	if err := p.record(units); err != nil {
		return errors.Join(publishErr, err)
	}
	if publishErr != nil {
		return publishErr
	}
	logrus.Info("Finished publishing container images")

	if p.cfg.Scan != nil {
		p.scan(*p.cfg.Scan)
	}
	return nil
}

// publishEnv adds the release latch and, when retagging, the source to pull from.
func (p *Publisher) publishEnv() []string {
	env := append(p.cfg.env(), utils.EnvTrue(utils.EnvRelease))
	if p.cfg.Publish {
		env = append(env, utils.EnvTrue(utils.EnvConfirm))
	} else {
		env = append(env, utils.EnvTrue(utils.EnvDryRun))
	}
	if p.cfg.From != "" {
		// Retagging inverts DEV_REGISTRIES: it becomes the source, so the
		// destination has to be named separately.
		env = append(env,
			utils.EnvTrue(utils.EnvImageOnly),
			utils.Env(utils.EnvDevTag, p.cfg.FromTag),
			utils.Env(utils.EnvDevRegistries, p.cfg.From),
			utils.Env(utils.EnvReleaseRegistries, strings.Join(p.cfg.Registries, " ")),
			utils.Env(utils.EnvReleaseTag, p.cfg.Version),
		)
		if p.cfg.SkipDevImageRetag {
			env = append(env, utils.EnvTrue(utils.EnvSkipDevImageRetag))
		}
	}
	return env
}

// record writes the digest refs the publish produced. A dry run leaves Refs
// nil and records nothing.
func (p *Publisher) record(units []unit) error {
	if p.cfg.Refs == nil {
		return nil
	}
	resolve := p.cfg.ResolveDigest
	if resolve == nil {
		resolve = registry.ResolveDigest
	}
	for _, u := range units {
		refs, err := p.cfg.publishedRefs(u, resolve)
		if err != nil {
			return fmt.Errorf("recording published images for %s: %w", u.dir, err)
		}
		if err := p.cfg.Refs.Add(refs...); err != nil {
			return fmt.Errorf("recording published images for %s: %w", u.dir, err)
		}
	}
	return nil
}

func (p *Publisher) scan(req ScanRequest) {
	logrus.Info("Sending images to ISS")
	scanner := imagescanner.New(req.Config)
	if err := scanner.Scan(req.ProductCode, req.Images, req.Stream, req.Release, req.OutputDir); err != nil {
		// scanning should not fail a release, so log the error and continue.
		logrus.WithError(err).Error("Failed to scan images")
	}
}
