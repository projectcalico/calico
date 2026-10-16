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

package main

import (
	"context"
	"fmt"
	"strings"
)

// list prints what gsutil ls -r printed, since people and scripts read it:
// an exact object as a single URL, otherwise a "<url>:" header per folder
// followed by its objects, with a blank line between folders.
func (l *level) list(ctx context.Context, sub string) error {
	b, err := l.bkt(ctx)
	if err != nil {
		return err
	}
	name := l.loc.object(sub)
	if name == "" {
		n, err := l.listTree(ctx, b, "", false)
		if err == nil && n == 0 {
			err = fmt.Errorf("list: '%s' matched no objects", l.loc.url(name))
		}
		return err
	}
	exists, err := objectExists(ctx, b, name)
	if err != nil {
		return err
	}
	if exists {
		fmt.Fprintln(l.stdout, l.loc.url(name))
		return nil
	}

	// A trailing slash still matches the folder, and also an object named
	// without it.
	stripped := strings.TrimSuffix(name, "/")
	objs, prefixes, err := b.List(ctx, stripped, "/")
	if err != nil {
		return err
	}
	matched := false
	for _, o := range objs {
		if o.Name == stripped {
			fmt.Fprintln(l.stdout, l.loc.url(o.Name))
			matched = true
		}
	}
	for _, p := range prefixes {
		if p != stripped+"/" {
			continue
		}
		fmt.Fprintf(l.stdout, "%s:\n", l.loc.url(p))
		if _, err := l.listTree(ctx, b, p, true); err != nil {
			return err
		}
		matched = true
	}
	if !matched {
		return fmt.Errorf("list: '%s' matched no objects", l.loc.url(name))
	}
	return nil
}

func (l *level) listTree(ctx context.Context, b bucket, prefix string, newline bool) (int, error) {
	objs, prefixes, err := b.List(ctx, prefix, "/")
	if err != nil {
		return 0, err
	}
	n := len(objs)
	for _, o := range objs {
		fmt.Fprintln(l.stdout, l.loc.url(o.Name))
	}
	for _, p := range prefixes {
		if newline {
			fmt.Fprintln(l.stdout)
		}
		newline = true
		fmt.Fprintf(l.stdout, "%s:\n", l.loc.url(p))
		m, err := l.listTree(ctx, b, p, true)
		if err != nil {
			return 0, err
		}
		n += m + 1
	}
	return n, nil
}
