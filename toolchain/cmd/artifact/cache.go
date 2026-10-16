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
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// The cache level outlives the run that wrote it, so every operation is safe
// to repeat: a key is one object, and a second store overwrites it.
type cacheLevel struct {
	*app
	loc location
	b   bucket
}

func (a *app) cache(ctx context.Context, args []string) error {
	base := a.getenv("CI_CACHE_STORAGE")
	if base == "" {
		return errors.New("cache: CI_CACHE_STORAGE is not set")
	}
	// The injected prefix is shared by every repo, so scoping it per repo
	// stops one restoring what another stored under the same key.
	repo := a.getenv("CI_GIT_REPO_NAME")
	if repo == "" {
		return errors.New("cache: CI_GIT_REPO_NAME is not set")
	}
	loc, err := parseLocation(strings.TrimSuffix(base, "/") + "/" + repo)
	if err != nil {
		return fmt.Errorf("cache: CI_CACHE_STORAGE: %w", err)
	}
	c := &cacheLevel{app: a, loc: loc}

	op, args := shift(args)
	switch op {
	case "store":
		return c.store(ctx, args)
	case "restore":
		return c.restore(ctx, args)
	case "has_key":
		return c.hasKey(ctx, args)
	case "delete":
		return c.delete(ctx, args)
	case "list":
		return c.list(ctx)
	case "":
		return errors.New("cache: missing operation (expected store, restore, has_key, delete or list)")
	default:
		return fmt.Errorf("cache: unknown operation '%s' (expected store, restore, has_key, delete or list)", op)
	}
}

func (c *cacheLevel) bkt(ctx context.Context) (bucket, error) {
	if c.b == nil {
		b, err := c.open(ctx, c.loc.bucket)
		if err != nil {
			return nil, err
		}
		c.b = b
	}
	return c.b, nil
}

// checkKey refuses anything that could resolve outside the injected prefix,
// because that prefix is what a bucket lifecycle rule expires.
func checkKey(key string) error {
	switch {
	case key == "":
		return errors.New("cache: missing key")
	case strings.HasPrefix(key, "gs://"):
		return fmt.Errorf("cache: '%s' is a location, not a key", key)
	case strings.HasPrefix(key, "/"):
		return fmt.Errorf("cache: key '%s' must not start with '/'", key)
	case strings.Contains(key, ".."):
		return fmt.Errorf("cache: key '%s' must not contain '..'", key)
	case strings.HasPrefix(key, "-"):
		return fmt.Errorf("cache: unexpected option '%s'", key)
	}
	return nil
}

func (c *cacheLevel) store(ctx context.Context, args []string) error {
	key, paths := shift(args)
	if err := checkKey(key); err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("cache store: need a file or directory to cache")
	}
	for _, p := range paths {
		// Shape before existence, so the message does not depend on whether a
		// path that could never be restored happens to be there today.
		switch {
		case strings.HasPrefix(p, "/"):
			return fmt.Errorf("cache store: '%s' must be relative to the working directory", p)
		case strings.Contains(p, ".."):
			return fmt.Errorf("cache store: '%s' must not contain '..'", p)
		}
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("cache store: '%s' does not exist", p)
		}
	}
	b, err := c.bkt(ctx)
	if err != nil {
		return err
	}
	// Streamed rather than staged through a temp file, which would need as
	// much free disk as the cache is large.
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pw.CloseWithError(writeTar(pw, paths, c.stderr))
	}()
	err = b.Write(ctx, c.loc.object(key), pr, "application/octet-stream", nil)
	// Unblocks the archiver if the upload gave up first.
	pr.CloseWithError(errors.New("upload ended"))
	<-done
	if err != nil {
		return fmt.Errorf("cache store: %w", err)
	}
	fmt.Fprintf(c.stdout, "stored %s\n", key)
	return nil
}

func (c *cacheLevel) restore(ctx context.Context, args []string) error {
	arg, _ := shift(args)
	if arg == "" {
		return errors.New("cache restore: missing key")
	}
	for _, key := range strings.Split(arg, ",") {
		if key == "" {
			continue
		}
		if err := checkKey(key); err != nil {
			return err
		}
		b, err := c.bkt(ctx)
		if err != nil {
			return err
		}
		r, err := b.Read(ctx, c.loc.object(key))
		if errors.Is(err, errNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("cache restore: %w", err)
		}
		err = extractTar(r, ".", c.stderr)
		r.Close()
		if err != nil {
			return fmt.Errorf("cache restore: %s: %w", key, err)
		}
		fmt.Fprintf(c.stdout, "restored %s\n", key)
		return nil
	}
	// A cold cache is not a failed build, so this exits 0 and callers test
	// for what they wanted restored.
	fmt.Fprintf(c.stdout, "MISS %s\n", arg)
	return nil
}

func (c *cacheLevel) hasKey(ctx context.Context, args []string) error {
	key, _ := shift(args)
	if err := checkKey(key); err != nil {
		return err
	}
	b, err := c.bkt(ctx)
	if err != nil {
		return err
	}
	exists, err := objectExists(ctx, b, c.loc.object(key))
	if err != nil {
		return fmt.Errorf("cache has_key: %w", err)
	}
	if !exists {
		fmt.Fprintf(c.stdout, "MISS %s\n", key)
		return exitCode(1)
	}
	fmt.Fprintf(c.stdout, "HIT %s\n", key)
	return nil
}

func (c *cacheLevel) delete(ctx context.Context, args []string) error {
	key, _ := shift(args)
	if err := checkKey(key); err != nil {
		return err
	}
	b, err := c.bkt(ctx)
	if err != nil {
		return err
	}
	// Deleting a key that is already gone leaves the caller where they asked
	// to be, so it is not an error.
	err = b.Delete(ctx, c.loc.object(key))
	switch {
	case errors.Is(err, errNotExist):
		fmt.Fprintf(c.stdout, "MISS %s\n", key)
	case err != nil:
		return fmt.Errorf("cache delete: %w", err)
	default:
		fmt.Fprintf(c.stdout, "deleted %s\n", key)
	}
	return nil
}

// list prints keys the way gsutil ls did: objects first, then any folder a
// key with a slash created.
func (c *cacheLevel) list(ctx context.Context) error {
	b, err := c.bkt(ctx)
	if err == nil {
		var objs []objectAttrs
		var prefixes []string
		objs, prefixes, err = b.List(ctx, c.loc.prefix+"/", "/")
		for _, o := range objs {
			fmt.Fprintln(c.stdout, c.loc.url(o.Name))
		}
		for _, p := range prefixes {
			fmt.Fprintln(c.stdout, c.loc.url(p))
		}
	}
	// The script ignored the exit status of this listing, so a real failure
	// is reported but still exits 0.
	if err != nil {
		fmt.Fprintf(c.stderr, "[ERROR] artifact: cache list: %v\n", err)
	}
	return nil
}
