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

// Package plan runs a release as an ordered list of named nodes.
package plan

import (
	"errors"
	"fmt"
	"slices"

	"github.com/sirupsen/logrus"
)

type Node struct {
	Name string

	// When reports whether the node runs; nil means it always does. An off node
	// stays in the list, so Replace and Remove still find it.
	When func() bool

	// Requires names nodes that must be on and earlier in the list.
	Requires []string

	// Validate runs for every node that is on, before any node's Do.
	Validate func() error

	// Do may be nil for a node that only checks.
	Do func() error

	// Verify checks this node's own output, straight after its Do.
	Verify func() error

	// Rollback undoes Do when this node's Verify or any later node fails.
	Rollback func() error
}

type Options struct {
	// Preview runs every Validate, but no Do, and logs what would run.
	Preview bool
	Skip    map[string]bool
}

type Plan struct {
	nodes []Node
	on    map[string]bool
	opts  Options
}

// New rejects a plan that cannot run as written, before any node runs.
func New(opts Options, nodes ...Node) (*Plan, error) {
	var errs []error
	in := map[string]bool{}
	on := map[string]bool{}
	for i, n := range nodes {
		switch {
		case n.Name == "":
			errs = append(errs, fmt.Errorf("node %d has no name", i))
		case in[n.Name]:
			errs = append(errs, fmt.Errorf("node %q appears more than once", n.Name))
		case n.Do == nil && n.Validate == nil:
			errs = append(errs, fmt.Errorf("node %q has nothing to do", n.Name))
		}
		in[n.Name] = true
		on[n.Name] = (n.When == nil || n.When()) && !opts.Skip[n.Name]
	}
	before := map[string]bool{}
	for _, n := range nodes {
		for _, req := range n.Requires {
			switch {
			case !on[n.Name]:
			case !in[req]:
				errs = append(errs, fmt.Errorf("node %q requires %q, which does not exist", n.Name, req))
			case !on[req]:
				errs = append(errs, fmt.Errorf("node %q requires %q, which is off in this run", n.Name, req))
			case !before[req]:
				errs = append(errs, fmt.Errorf("node %q requires %q, which runs after it", n.Name, req))
			}
		}
		before[n.Name] = true
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("cannot assemble plan: %w", err)
	}
	return &Plan{nodes: nodes, on: on, opts: opts}, nil
}

// Replace and Remove fail when the name is absent, so a renamed node fails
// loudly instead of being silently added or left in place.
func Replace(nodes []Node, n Node) ([]Node, error) {
	i := slices.IndexFunc(nodes, func(m Node) bool { return m.Name == n.Name })
	if i < 0 {
		return nil, fmt.Errorf("cannot replace %q: no such node", n.Name)
	}
	out := slices.Clone(nodes)
	out[i] = n
	return out, nil
}

func Remove(nodes []Node, name string) ([]Node, error) {
	i := slices.IndexFunc(nodes, func(m Node) bool { return m.Name == name })
	if i < 0 {
		return nil, fmt.Errorf("cannot remove %q: no such node", name)
	}
	return slices.Delete(slices.Clone(nodes), i, i+1), nil
}

// Run reports every Validate failure together, so one run names all of them.
func (p *Plan) Run() (err error) {
	var errs []error
	for _, n := range p.nodes {
		if !p.on[n.Name] || n.Validate == nil {
			continue
		}
		if err := n.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n.Name, err))
		}
	}
	err = errors.Join(errs...)
	if p.opts.Preview {
		if err != nil {
			logrus.WithError(err).Warn("A real run would fail validation")
		}
		for _, n := range p.nodes {
			if p.on[n.Name] {
				logrus.WithField("step", n.Name).Info("Will run")
			} else {
				logrus.WithField("step", n.Name).Info("Will skip")
			}
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("validating plan: %w", err)
	}

	var done []Node
	defer func() {
		if p := recover(); p != nil {
			if err := rollback(done); err != nil {
				logrus.WithError(err).Error("Rollback failed")
			}
			panic(p)
		}
		if err != nil {
			err = errors.Join(err, rollback(done))
		}
	}()
	for _, n := range p.nodes {
		if !p.on[n.Name] {
			continue
		}
		if n.Do == nil {
			continue
		}
		logrus.WithField("step", n.Name).Info("Running")
		if err = n.Do(); err != nil {
			return fmt.Errorf("%s: %w", n.Name, err)
		}
		done = append(done, n)
		if n.Verify == nil {
			continue
		}
		if err = n.Verify(); err != nil {
			return fmt.Errorf("%s: verify: %w", n.Name, err)
		}
	}
	return nil
}

func rollback(done []Node) error {
	var errs []error
	for _, n := range slices.Backward(done) {
		if n.Rollback == nil {
			continue
		}
		logrus.WithField("step", n.Name).Warn("Rolling back")
		if err := n.Rollback(); err != nil {
			errs = append(errs, fmt.Errorf("rolling back %s: %w", n.Name, err))
		}
	}
	return errors.Join(errs...)
}
