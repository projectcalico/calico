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

// Entrypoint for the calico/cni-plugins init image. Copies upstream CNI
// plugin binaries from a source directory into a staging directory shared
// with the install-cni init container, which mounts the staging dir at
// /opt/cni/bin and copies the binaries onto the host.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

const fileMode = 0o755

func main() {
	src := flag.String("src", "/plugins", "directory containing the plugin binaries")
	dst := flag.String("dst", envOrDefault("STAGE_DIR", "/stage"), "directory to stage the plugin binaries into")
	flag.Parse()

	if err := stage(*src, *dst); err != nil {
		log.Fatalf("staging plugins: %v", err)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func stage(src, dst string) error {
	// Refuse to stage in place — copyFile opens dst with O_TRUNC before
	// reading src, so src==dst silently zeroes every plugin binary.
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return fmt.Errorf("resolve src %s: %w", src, err)
	}
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return fmt.Errorf("resolve dst %s: %w", dst, err)
	}
	if filepath.Clean(srcAbs) == filepath.Clean(dstAbs) {
		return fmt.Errorf("src and dst resolve to the same path (%s)", srcAbs)
	}

	if err := os.MkdirAll(dst, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := copyFile(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			return err
		}
		log.Printf("staged %s -> %s", e.Name(), dst)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	if err := out.Chmod(fileMode); err != nil {
		return fmt.Errorf("chmod %s: %w", dst, err)
	}
	return nil
}
