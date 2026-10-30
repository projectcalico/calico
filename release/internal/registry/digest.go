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

package registry

import (
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// DigestResolver reports the manifest digest of a tag. exists is false with a
// nil error when the tag is absent; auth and network failures return an error.
type DigestResolver func(ref string) (digest string, exists bool, err error)

// A repo publishes several tags at different digests, so it maps to a set.
type RecordedDigests struct {
	byRepo map[string]map[string]struct{}
	byTag  map[string]string
}

func PublishedRef(taggedRef, digest string) string {
	return taggedRef + "@" + digest
}

func DigestsByRepo(refs []string) RecordedDigests {
	out := RecordedDigests{
		byRepo: make(map[string]map[string]struct{}, len(refs)),
		byTag:  make(map[string]string, len(refs)),
	}
	for _, ref := range refs {
		repo, tag, digest, ok := parseRef(ref)
		if !ok || digest == "" {
			continue
		}
		if out.byRepo[repo] == nil {
			out.byRepo[repo] = map[string]struct{}{}
		}
		out.byRepo[repo][digest] = struct{}{}
		if tag != "" {
			out.byTag[repo+":"+tag] = digest
		}
	}
	return out
}

type DigestSource struct {
	records []RecordedDigests
}

func NewDigestSource(records ...RecordedDigests) DigestSource {
	return DigestSource{records: records}
}

func (s DigestSource) Digest(ref string) (string, bool) {
	for _, r := range s.records {
		if digest, ok := r.Digest(ref); ok {
			return digest, true
		}
	}
	return "", false
}

func (r RecordedDigests) Digests(repo string) map[string]struct{} {
	parsed, err := name.NewRepository(repo)
	if err != nil {
		return nil
	}
	return r.byRepo[parsed.Name()]
}

func (r RecordedDigests) Empty() bool {
	return len(r.byRepo) == 0
}

// Digest reports the digest recorded for a tagged reference. A record cannot
// fail, only miss, so a miss means the caller resolves instead.
func (r RecordedDigests) Digest(ref string) (string, bool) {
	repo, tag, _, ok := parseRef(ref)
	if !ok || tag == "" {
		return "", false
	}
	digest, found := r.byTag[repo+":"+tag]
	return digest, found
}

// The repo comes from the reference parser so a tagged and an untagged ref key
// alike; splitting on ":" by hand would break a registry carrying a port.
func parseRef(s string) (repo, tag, digest string, ok bool) {
	rest, digest, _ := strings.Cut(s, "@")
	parsed, err := name.ParseReference(rest, name.WithDefaultTag(""))
	if err != nil {
		return "", "", "", false
	}
	if t, isTag := parsed.(name.Tag); isTag {
		tag = t.TagStr()
	}
	return parsed.Context().Name(), tag, digest, true
}
