// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package file

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/argutils"
)

// Iter extracts the filename from the parsed args and
//   - invokes the callback for each manifest files in the directory if the filename in the parsed arguments is a
//     directory (updating the arguments to include the specific file)
//   - otherwise just invoke the callback with the unmodified arguments.
func Iter(parsedArgs map[string]interface{}, cb func(map[string]interface{}) error) error {
	// File name is specified.
	f, ok := parsedArgs["--filename"].(string)
	if !ok {
		// Handle invalid or missing filename by invoking standard processing.
		return cb(parsedArgs)
	}

	if f == "-" {
		// Handle stdin filename by invoking standard processing.
		return cb(parsedArgs)
	}

	if !isDir(f) {
		// Handle non-directory by invoking standard processing.
		return cb(parsedArgs)
	}

	// Determine if we are following directories recursively.
	recursive := argutils.ArgBoolOrFalse(parsedArgs, "--recursive")

	// Handle directory by walking the directory contents and performing the action on each manifest file.
	return filepath.Walk(f,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				// Return nil or SkipDir dpending on whether or not we are recursively following directories (note that
				// we need to explicitly handle the root directory to ensure we do at least one layer of directory
				// walking by default).
				if recursive || path == f {
					return nil
				} else {
					return filepath.SkipDir
				}
			}

			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" || ext == ".json" {
				return cb(newParsedArgs(parsedArgs, path))
			}

			return nil
		})
}

// isDir returns true if the specified file path exists, is readable, and is a directory, otherwise returns false.
func isDir(f string) bool {
	if info, err := os.Stat(f); err != nil {
		return false
	} else {
		return info.IsDir()
	}
}

// newParsedArgs returns an updated set of arguments which include the specified filename.
func newParsedArgs(original map[string]interface{}, newFilename string) map[string]interface{} {
	out := make(map[string]interface{})
	for k, v := range original {
		out[k] = v
	}
	out["--filename"] = newFilename
	return out
}
