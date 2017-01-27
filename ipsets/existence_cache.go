// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package ipsets

import (
	"bytes"
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/set"
	"strings"
)

type ExistenceCache struct {
	existingIPSetNames set.Set
	newCmd             cmdFactory
}

func NewExistenceCache(cmdFactory cmdFactory) *ExistenceCache {
	cache := &ExistenceCache{
		existingIPSetNames: set.New(),
		newCmd:             cmdFactory,
	}
	cache.Reload()
	return cache
}

// Reload reloads the cache from the dataplane.
func (c *ExistenceCache) Reload() error {
	log.Info("Reloading IP set existence cache.")
	cmd := c.newCmd("ipset", "list", "-n")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	setNames := set.New()
	buf := bytes.NewBuffer(output)
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			break
		}
		setName := strings.Trim(line, "\n")
		log.WithField("setName", setName).Debug("Found IP set")
		setNames.Add(setName)
	}
	c.existingIPSetNames = setNames
	return nil
}

// SetIPSetExists is used to incrementally update the ExistenceCache after we create/delete an IP
// set.
func (c *ExistenceCache) SetIPSetExists(setName string, exists bool) {
	if exists {
		c.existingIPSetNames.Add(setName)
	} else {
		c.existingIPSetNames.Discard(setName)
	}
}

// IPSetExists returns true if the cache believes the IP set exists.
func (c *ExistenceCache) IPSetExists(setName string) bool {
	return c.existingIPSetNames.Contains(setName)
}

// Iter calls the given function once for each IP set name that exists.
func (c *ExistenceCache) Iter(f func(setName string)) {
	c.existingIPSetNames.Iter(func(item interface{}) error {
		f(item.(string))
		return nil
	})
}
