// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package model

import (
	"fmt"
	"regexp"

	"reflect"

	"sort"

	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/errors"
)

var (
	matchProfile = regexp.MustCompile("^/?calico/v1/policy/profile/([^/]+)/(tags|rules|labels)$")
	typeProfile  = reflect.TypeOf(Profile{})
)

// The profile key actually returns the common parent of the three separate entries.
// It is useful to define this to re-use some of the common machinery, and can be used
// for delete processing since delete needs to remove the common parent.
type ProfileKey struct {
	Name string `json:"-" validate:"required,name"`
}

func (key ProfileKey) DefaultPath() (string, error) {
	if key.Name == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	e := fmt.Sprintf("/calico/v1/policy/profile/%s", key.Name)
	return e, nil
}

func (key ProfileKey) DefaultDeletePath() (string, error) {
	return key.DefaultPath()
}

func (key ProfileKey) valueType() reflect.Type {
	return typeProfile // FIXME is this required?
}

func (key ProfileKey) String() string {
	return fmt.Sprintf("Profile(name=%s)", key.Name)
}

// ProfileRulesKey implements the KeyInterface for the profile rules
type ProfileRulesKey struct {
	ProfileKey
}

func (key ProfileRulesKey) DefaultPath() (string, error) {
	e, err := key.ProfileKey.DefaultPath()
	return e + "/rules", err
}

func (key ProfileRulesKey) valueType() reflect.Type {
	return reflect.TypeOf(ProfileRules{})
}

// ProfileTagsKey implements the KeyInterface for the profile tags
type ProfileTagsKey struct {
	ProfileKey
}

func (key ProfileTagsKey) DefaultPath() (string, error) {
	e, err := key.ProfileKey.DefaultPath()
	return e + "/tags", err
}

func (key ProfileTagsKey) valueType() reflect.Type {
	return reflect.TypeOf([]string{})
}

// ProfileLabelsKey implements the KeyInterface for the profile labels
type ProfileLabelsKey struct {
	ProfileKey
}

func (key ProfileLabelsKey) DefaultPath() (string, error) {
	e, err := key.ProfileKey.DefaultPath()
	return e + "/labels", err
}

func (key ProfileLabelsKey) valueType() reflect.Type {
	return reflect.TypeOf(map[string]string{})
}

type ProfileListOptions struct {
	Name string
}

func (options ProfileListOptions) DefaultPathRoot() string {
	k := "/calico/v1/policy/profile"
	if options.Name == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s", options.Name)
	return k
}

func (options ProfileListOptions) ParseDefaultKey(ekey string) Key {
	glog.V(2).Infof("Get Profile key from %s", ekey)
	r := matchProfile.FindAllStringSubmatch(ekey, -1)
	if len(r) != 1 {
		glog.V(2).Infof("Didn't match regex")
		return nil
	}
	name := r[0][1]
	kind := r[0][2]
	if options.Name != "" && name != options.Name {
		glog.V(2).Infof("Didn't match name %s != %s", options.Name, name)
		return nil
	}
	pk := ProfileKey{Name: name}
	switch kind {
	case "tags":
		return ProfileTagsKey{ProfileKey: pk}
	case "labels":
		return ProfileLabelsKey{ProfileKey: pk}
	case "rules":
		return ProfileRulesKey{ProfileKey: pk}
	}
	return pk
}

// The profile structure is defined to allow the client to define a conversion interface
// to map between the API and backend profiles.  However, in the actual underlying
// implementation the profile is written as three separate entries - rules, tags and labels.
type Profile struct {
	Rules  ProfileRules
	Tags   []string
	Labels map[string]string
}

type ProfileRules struct {
	InboundRules  []Rule `json:"inbound_rules,omitempty" validate:"omitempty,dive"`
	OutboundRules []Rule `json:"outbound_rules,omitempty" validate:"omitempty,dive"`
}

type client interface {
	Create(object *KVPair) (*KVPair, error)
	Update(object *KVPair) (*KVPair, error)
	Apply(object *KVPair) (*KVPair, error)
	Get(key Key) (*KVPair, error)
}

func (_ *ProfileListOptions) ListConvert(ds []*KVPair) []*KVPair {

	profiles := make(map[string]*KVPair)
	var name string
	for _, d := range ds {
		switch t := d.Key.(type) {
		case ProfileTagsKey:
			name = t.Name
		case ProfileLabelsKey:
			name = t.Name
		case ProfileRulesKey:
			name = t.Name
		default:
			panic(fmt.Errorf("Unexpected key type: %v", t))
		}

		// Get the KVPair for the profile, initialising if just created.
		pd, ok := profiles[name]
		if !ok {
			glog.V(2).Infof("Initialise profile %v", name)
			pd = &KVPair{
				Value: Profile{},
				Key:   ProfileKey{Name: name},
			}
			profiles[name] = pd
		}

		p := pd.Value.(Profile)
		switch t := d.Value.(type) {
		case []string: // must be tags #TODO should type these
			glog.V(2).Infof("Store tags %v", t)
			p.Tags = t
			pd.Revision = d.Revision
		case map[string]string: // must be labels
			glog.V(2).Infof("Store labels %v", t)
			p.Labels = t
		case ProfileRules: // must be rules
			glog.V(2).Infof("Store rules %v", t)
			p.Rules = t
		default:
			panic(fmt.Errorf("Unexpected type: %v", t))
		}
		pd.Value = p
	}

	glog.V(2).Infof("Map of profiles: %v", profiles)

	// To store the keys in slice in sorted order
	var keys []string
	for k := range profiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]*KVPair, len(keys))
	for i, k := range keys {
		out[i] = profiles[k]
	}

	glog.V(2).Infof("Sorted groups of profiles: %v", out)

	return out
}
