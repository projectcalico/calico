// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package imagepuller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
)

// pullImageToArchive fetches the given image reference from its registry
// and writes a docker-compatible tarball to archivePath. The fetch is
// pure-Go — no docker daemon is involved on the host. The resulting
// archive is what kind nodes consume via `ctr images import` (called
// internally by nodeutils.LoadImageArchive).
//
// Auth: crane uses the default keychain, which picks up ~/.docker/config.json
// (including credential helpers), so private registries Just Work as long
// as the user has run `docker login` once.
func pullImageToArchive(ctx context.Context, imageRef, archivePath string) error {
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(archivePath), err)
	}

	img, err := crane.Pull(imageRef, crane.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("pull %s: %w", imageRef, err)
	}
	if err := crane.Save(img, imageRef, archivePath); err != nil {
		return fmt.Errorf("save %s to %s: %w", imageRef, archivePath, err)
	}
	return nil
}

// archivePathForImage maps a colon-and-slash-bearing image reference to a
// safe filename in cacheDir. Inverse of imageRefFromArchiveName.
func archivePathForImage(cacheDir, imageRef string) string {
	return filepath.Join(cacheDir, strings.ReplaceAll(imageRef, "/", "__")+".tar")
}

// imageRefFromArchiveName recovers the original image reference from a
// filename produced by archivePathForImage. Used at puller start-up so
// existing archives in cacheDir don't get re-pulled.
func imageRefFromArchiveName(name string) string {
	return strings.TrimSuffix(strings.ReplaceAll(name, "__", "/"), ".tar")
}
