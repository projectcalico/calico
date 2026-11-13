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

package testconfig

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/onsi/ginkgo/v2/types"
)

// Reason prefixes. A drop reason names its category up front so that a list of
// them can be grepped, counted and compared line by line.
const (
	upstreamReasonPrefix   = "upstream: "
	QuarantineReasonPrefix = "quarantine: "
	labelReasonPrefix      = "label "
	patternReasonPrefix    = "excluded: "
	notProvidedSuffix      = " not provided"
)

// Spec is what selection can see of a spec: the text Ginkgo matches name
// patterns against, and the labels it matches label filters against.
type Spec struct {
	// Suite is the description the suite passed to RunSpecs. Ginkgo prefixes it
	// to the spec text before matching --ginkgo.skip.
	Suite string

	// Text is the container texts and the leaf text joined by spaces.
	Text string

	// Labels is every label the spec carries, its containers' included.
	Labels []string
}

// IncludeOnly returns a config that keeps this one's include section and
// nothing else: what the suites select before any lane drops a spec.
func (c *Config) IncludeOnly() *Config {
	return &Config{Include: c.Include}
}

// Dropper explains why a config drops a spec. It is built once per config and
// reused for every spec.
type Dropper struct {
	requires types.LabelFilter
	provided map[string]bool
	rules    []dropRule
}

// dropRule is one reason a config can drop a spec.
type dropRule struct {
	reason  string
	matches func(Spec) bool
}

// NewDropper compiles the rules of cfg that drop specs, in the order Reason
// reports them: a missing capability, an upstream gap, a label exclusion, a
// name-pattern exclusion, and last a quarantine. Quarantine comes last so that
// lifting one never changes why another rule drops a spec, which keeps the
// count of specs a lane would run before quarantine independent of quarantines.
func NewDropper(cfg *Config) (*Dropper, error) {
	dropper := &Dropper{}

	// Capabilities: a spec requiring one the lane does not provide is dropped.
	if cfg.Provides != nil {
		filter, err := types.ParseLabelFilter(requiresClause(cfg))
		if err != nil {
			return nil, fmt.Errorf("requires filter: %w", err)
		}
		dropper.requires = filter
		dropper.provided = map[string]bool{}
		for _, p := range cfg.Provides {
			dropper.provided[strings.ToLower(p)] = true
		}
	}

	// Upstream gaps.
	for _, e := range cfg.Upstream {
		rule, err := patternRule(upstreamReasonPrefix+reasonOf(e), e)
		if err != nil {
			return nil, fmt.Errorf("upstream: %w", err)
		}
		dropper.rules = append(dropper.rules, rule)
	}

	// Label exclusions.
	for _, e := range cfg.Exclude.Labels {
		filter, err := types.ParseLabelFilter(e.Label)
		if err != nil {
			return nil, fmt.Errorf("exclude label %q: %w", e.Label, err)
		}
		dropper.rules = append(dropper.rules, dropRule{
			reason:  labelReasonPrefix + e.Label + ": " + oneLine(e.Reason),
			matches: func(s Spec) bool { return filter(s.Labels) },
		})
	}

	// Name patterns, plain exclusions first and quarantines after them.
	for _, quarantined := range []bool{false, true} {
		for _, e := range cfg.Exclude.NamePatterns {
			if (e.Ticket != "") != quarantined {
				continue
			}
			reason := patternReasonPrefix + reasonOf(e)
			if quarantined {
				reason = QuarantineReasonPrefix + ticketKey(e.Ticket)
			}
			rule, err := patternRule(reason, e)
			if err != nil {
				return nil, fmt.Errorf("exclude.namePatterns: %w", err)
			}
			dropper.rules = append(dropper.rules, rule)
		}
	}
	return dropper, nil
}

// Reason returns why the config drops spec and true, or false when the config
// keeps it. When several rules drop a spec, only the first is reported.
func (d *Dropper) Reason(spec Spec) (string, bool) {
	if d.requires != nil && !d.requires(spec.Labels) {
		return d.missingCapabilities(spec), true
	}
	for _, r := range d.rules {
		if r.matches(spec) {
			return r.reason, true
		}
	}
	return "", false
}

// missingCapabilities names the Requires: labels of spec that the lane does
// not provide, as the spec spells them.
func (d *Dropper) missingCapabilities(spec Spec) string {
	var missing []string
	for _, l := range spec.Labels {
		key, value, ok := strings.Cut(l, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), requiresKey) {
			continue
		}
		if !d.provided[strings.ToLower(strings.TrimSpace(value))] {
			missing = append(missing, strings.TrimSpace(l))
		}
	}
	sort.Strings(missing)
	if len(missing) == 0 {
		return requiresKey + notProvidedSuffix
	}
	return strings.Join(missing, ", ") + notProvidedSuffix
}

// patternRule builds a rule dropping every spec whose text matches one of the
// entry's patterns, the way --ginkgo.skip would.
func patternRule(reason string, e NamePatternEntry) (dropRule, error) {
	var res []*regexp.Regexp
	for _, p := range e.AllPatterns() {
		re, err := regexp.Compile(p)
		if err != nil {
			return dropRule{}, fmt.Errorf("pattern %q: %w", p, err)
		}
		res = append(res, re)
	}
	return dropRule{
		reason: reason,
		matches: func(s Spec) bool {
			text := s.Suite + " " + s.Text
			for _, re := range res {
				if re.MatchString(text) {
					return true
				}
			}
			return false
		},
	}, nil
}

// reasonOf returns the entry's group name, or its reason for a single pattern,
// collapsed onto one line.
func reasonOf(e NamePatternEntry) string {
	if e.Group != "" {
		return oneLine(e.Group)
	}
	return oneLine(e.Reason)
}

// oneLine collapses all whitespace runs to single spaces, so a multi-line YAML
// reason stays on one line of a drop list.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// ticketKey returns the issue key a quarantine ticket names: the last path
// segment of a URL such as https://tigera.atlassian.net/browse/CORE-13670, or
// the value itself when it is not a URL.
func ticketKey(ticket string) string {
	if u, err := url.Parse(ticket); err == nil && u.Path != "" {
		ticket = u.Path
	}
	return path.Base(strings.TrimRight(ticket, "/"))
}
