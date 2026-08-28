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

package utils

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"

	operatorv1 "github.com/tigera/operator/api/v1"
)

// DefaultsScope names which parts of status.Defaults a caller may rewrite, so two controllers
// defaulting the same Installation can't clobber each other's recorded defaults.
type DefaultsScope struct {
	// Owned lists dotted JSON paths this caller defaults, e.g. "calicoNetwork.ipPools".
	Owned []string

	// Foreign lists dotted JSON paths another controller owns, for a caller that defaults
	// everything else.
	Foreign []string
}

// MergeRecordedDefaults returns what to store in status.Defaults: whatever defaulted adds on top
// of declared, with the paths outside the caller's scope carried through from recorded.
//
//	recorded - the defaults already in status.Defaults, or nil if there are none yet.
//	declared - the spec as the user wrote it.
//	defaulted - that same spec with this caller's defaults applied.
func MergeRecordedDefaults(recorded *operatorv1.InstallationSpec, declared, defaulted operatorv1.InstallationSpec, scope DefaultsScope) (*operatorv1.InstallationSpec, error) {
	declaredContent, err := specToMap(declared)
	if err != nil {
		return nil, err
	}

	defaultedContent, err := specToMap(defaulted)
	if err != nil {
		return nil, err
	}
	added := addedKeys(declaredContent, defaultedContent, "")

	recordedContent := map[string]any{}
	if recorded != nil {
		if recordedContent, err = specToMap(*recorded); err != nil {
			return nil, err
		}
	}

	content := added
	if len(scope.Owned) > 0 {
		// Rewrite only the paths this caller owns; everything else carries through.
		content = recordedContent
		for _, path := range scope.Owned {
			deletePath(content, path)
			if value, present := lookupPath(added, path); present {
				setPath(content, path, value)
			}
		}
	}
	for _, path := range scope.Foreign {
		// Leave the paths another controller owns exactly as recorded.
		deletePath(content, path)
		if value, present := lookupPath(recordedContent, path); present {
			setPath(content, path, value)
		}
	}
	pruneEmptyObjects(content)

	if len(content) == 0 {
		return nil, nil
	}

	raw, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("marshal supplied defaults: %w", err)
	}

	defaults := &operatorv1.InstallationSpec{}
	if err := json.Unmarshal(raw, defaults); err != nil {
		return nil, fmt.Errorf("unmarshal supplied defaults: %w", err)
	}
	return defaults, nil
}

func lookupPath(content map[string]any, path string) (any, bool) {
	keys := strings.Split(path, ".")
	for _, key := range keys[:len(keys)-1] {
		nested, isObject := content[key].(map[string]any)
		if !isObject {
			return nil, false
		}
		content = nested
	}
	value, present := content[keys[len(keys)-1]]
	return value, present
}

func setPath(content map[string]any, path string, value any) {
	keys := strings.Split(path, ".")
	for _, key := range keys[:len(keys)-1] {
		nested, isObject := content[key].(map[string]any)
		if !isObject {
			nested = map[string]any{}
			content[key] = nested
		}
		content = nested
	}
	content[keys[len(keys)-1]] = value
}

func deletePath(content map[string]any, path string) {
	keys := strings.Split(path, ".")
	for _, key := range keys[:len(keys)-1] {
		nested, isObject := content[key].(map[string]any)
		if !isObject {
			return
		}
		content = nested
	}
	delete(content, keys[len(keys)-1])
}

// pruneEmptyObjects drops objects left empty by a deleted path, so they don't record as defaults.
func pruneEmptyObjects(content map[string]any) {
	for key, value := range content {
		object, isObject := value.(map[string]any)
		if !isObject {
			continue
		}
		pruneEmptyObjects(object)
		if len(object) == 0 {
			delete(content, key)
		}
	}
}

// NormalizeCIDR returns the canonical string form of the given CIDR, as produced by net.IPNet.String().
// This allows semantically-equal CIDRs that differ only in textual representation (for example IPv6
// addresses with leading zeros or differing "::" compression, such as "fd20:5213:94f6:01e9:001f::/96"
// versus "fd20:5213:94f6:1e9:1f::/96") to compare as equal. The Calico API server normalizes CIDRs when
// it stores IP pools, so without this the operator can mistake an existing pool for a missing one and
// enter an infinite delete/recreate loop. If the CIDR cannot be parsed, the original string is returned
// unchanged so callers fall back to an exact string comparison.
func NormalizeCIDR(cidr string) string {
	_, nw, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	return nw.String()
}

// LayerPoolDefaults fills fields left unset on a declared IP pool from the recorded
// default with the same CIDR.
func LayerPoolDefaults(spec, defaults *operatorv1.InstallationSpec) error {
	if spec == nil || defaults == nil || spec.CalicoNetwork == nil || defaults.CalicoNetwork == nil {
		return nil
	}

	// Key on the normalized CIDR, since the Installation can hold a non-canonical spelling.
	recorded := map[string]operatorv1.IPPool{}
	for _, pool := range defaults.CalicoNetwork.IPPools {
		recorded[NormalizeCIDR(pool.CIDR)] = pool
	}

	for i := range spec.CalicoNetwork.IPPools {
		declared := spec.CalicoNetwork.IPPools[i]
		base, ok := recorded[NormalizeCIDR(declared.CIDR)]
		if !ok {
			continue
		}
		merged, err := layerPool(base, declared)
		if err != nil {
			return err
		}
		spec.CalicoNetwork.IPPools[i] = merged
	}
	return nil
}

// layerPool decodes the declared pool over the default, so only fields the user set win.
func layerPool(base, declared operatorv1.IPPool) (operatorv1.IPPool, error) {
	raw, err := json.Marshal(declared)
	if err != nil {
		return base, fmt.Errorf("marshal declared IP pool: %w", err)
	}
	if err := json.Unmarshal(raw, &base); err != nil {
		return base, fmt.Errorf("unmarshal declared IP pool: %w", err)
	}
	return base, nil
}

// PoolDefaultsPath is the part of the Installation spec the IP pool controller defaults. It is
// also the one list we diff per element, since IP pools carry an identity in their CIDR;
// recording the list whole would claim the user's own pools as operator defaults.
const PoolDefaultsPath = "calicoNetwork.ipPools"

// poolCIDRKey is the merge key for PoolDefaultsPath.
const poolCIDRKey = "cidr"

// addedKeys walks two decoded specs and keeps only what defaulted added on top of declared.
// path is the dotted JSON path of the object being walked, empty at the top level.
func addedKeys(declared, defaulted map[string]any, path string) map[string]any {
	added := map[string]any{}
	for key, defaultedValue := range defaulted {
		childPath := key
		if path != "" {
			childPath = path + "." + key
		}

		declaredValue, present := declared[key]
		if !present {
			if isVacuous(defaultedValue) {
				continue
			}
			added[key] = defaultedValue
			continue
		}

		// Recurse so one user-set field doesn't hide the siblings defaulted alongside it.
		declaredObject, declaredIsObject := declaredValue.(map[string]any)
		defaultedObject, defaultedIsObject := defaultedValue.(map[string]any)
		if declaredIsObject && defaultedIsObject {
			if nested := addedKeys(declaredObject, defaultedObject, childPath); len(nested) > 0 {
				added[key] = nested
			}
			continue
		}

		declaredList, declaredIsList := declaredValue.([]any)
		defaultedList, defaultedIsList := defaultedValue.([]any)
		if declaredIsList && defaultedIsList && childPath == PoolDefaultsPath {
			if pools := addedPoolKeys(declaredList, defaultedList); len(pools) > 0 {
				added[key] = pools
			}
			continue
		}

		// Every other list is all-or-nothing; per-element merging needs a merge key.
		if !reflect.DeepEqual(declaredValue, defaultedValue) {
			added[key] = defaultedValue
		}
	}
	return added
}

// addedPoolKeys diffs two IP pool lists pool by pool, keyed on the normalized CIDR, so a pool
// the user declared records only the fields defaulting filled in.
func addedPoolKeys(declared, defaulted []any) []any {
	declaredPools := map[string]map[string]any{}
	for _, entry := range declared {
		pool, isObject := entry.(map[string]any)
		if !isObject {
			continue
		}
		if cidr, isString := pool[poolCIDRKey].(string); isString {
			declaredPools[NormalizeCIDR(cidr)] = pool
		}
	}

	added := []any{}
	for _, entry := range defaulted {
		pool, isObject := entry.(map[string]any)
		if !isObject {
			continue
		}
		cidr, isString := pool[poolCIDRKey].(string)
		if !isString {
			continue
		}

		declaredPool, wasDeclared := declaredPools[NormalizeCIDR(cidr)]
		if !wasDeclared {
			// A pool the user never named is ours whole.
			added = append(added, pool)
			continue
		}

		fields := addedKeys(declaredPool, pool, "")
		if len(fields) == 0 {
			continue
		}
		// Carry the declared CIDR so the recorded fields layer back onto the right pool.
		fields[poolCIDRKey] = declaredPool[poolCIDRKey]
		added = append(added, fields)
	}
	return added
}

// isVacuous reports whether a value the user never declared is empty all the way down.
func isVacuous(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for _, nested := range typed {
			if !isVacuous(nested) {
				return false
			}
		}
		return true
	case []any:
		// An empty list survives serialization only where a field drops omitempty on purpose,
		// as spec.calicoNetwork.ipPools does to mean "pools are managed out-of-band".
		return false
	default:
		return false
	}
}

func specToMap(spec operatorv1.InstallationSpec) (map[string]any, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("marshal installation spec: %w", err)
	}

	content := map[string]any{}
	if err := json.Unmarshal(raw, &content); err != nil {
		return nil, fmt.Errorf("unmarshal installation spec: %w", err)
	}
	pruneNulls(content)
	return content, nil
}

// pruneNulls drops null fields, so an unset pointer can't read as a default. status.Defaults
// preserves unknown fields, so nothing on the API server side prunes them for us.
func pruneNulls(content map[string]any) {
	for key, value := range content {
		if value == nil {
			delete(content, key)
			continue
		}
		pruneNullsIn(value)
	}
}

func pruneNullsIn(value any) {
	switch typed := value.(type) {
	case map[string]any:
		pruneNulls(typed)
	case []any:
		for _, entry := range typed {
			pruneNullsIn(entry)
		}
	}
}
