// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var logLevel = flag.String("log-level", "fatal", "Log level, one of fatal, error, info, debug, etc.")
var inPlace = flag.Bool("w", false, "Write result to (source) file instead of stdout")

func main() {
	flag.Parse()
	configureLogging()

	if flag.CommandLine.NArg() == 0 {
		logrus.Info("No files specified")
		os.Exit(0)
	} else if flag.CommandLine.NArg() > 1 && *inPlace {
		logrus.Info("Processing multiple files...")
		var g errgroup.Group
		for _, fileName := range flag.CommandLine.Args() {
			g.Go(func() error {
				return processFile(fileName)
			})
		}
		err := g.Wait()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "coalesce-imports: Failed to process one or more files: %v.\n", err)
			os.Exit(1)
		}
	} else {
		fileName := flag.CommandLine.Arg(0)
		err := processFile(fileName)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "coalesce-imports: Failed to process file: %v.\n", err)
			os.Exit(1)
		}
	}
}

func processFile(fileName string) (err error) {
	defer func() {
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "coalesce-imports: Failed to process file %q: %v.\n", fileName, err)
		}
	}()
	fileSet := token.NewFileSet()
	fileAST, err := parser.ParseFile(fileSet, fileName, nil, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("failed to parse file %q: %w", fileName, err)
	}

	if !coalesceImports(fileSet, fileAST) && *inPlace {
		// No changes made so we don't need to write out the file.
		return nil
	}

	dest := os.Stdout
	if *inPlace {
		stat, err := os.Stat(fileName)
		if err != nil {
			return fmt.Errorf("failed to stat file %q: %w", fileName, err)
		}
		err = os.Rename(fileName, fileName+".bak")
		if err != nil {
			return fmt.Errorf("failed to create backup file %q: %w", fileName+".bak", err)
		}
		defer func() {
			if err == nil {
				// Success, remove the backup file.
				err = os.Remove(fileName + ".bak")
				if err != nil {
					logrus.WithError(err).Error("Failed to remove backup file.")
				}
			} else {
				// Failure, try to restore the backup file.
				err := os.Rename(fileName+".bak", fileName)
				if err != nil {
					logrus.WithError(err).Error("Failed to move backup file back to original location.")
				}
			}
		}()
		dest, err = os.OpenFile(fileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, stat.Mode())
		if err != nil {
			return fmt.Errorf("failed to open file for write %q: %w", fileName, err)
		}
		defer func() {
			cerr := dest.Close()
			if cerr != nil {
				if err == nil {
					err = fmt.Errorf("failed to close file %q: %w", fileName, cerr)
				} else {
					logrus.WithError(cerr).Error("Failed to close file")
				}
			}
		}()
	}

	err = format.Node(dest, fileSet, fileAST)
	if err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	return nil
}

func configureLogging() {
	logutils.ConfigureFormatter("coalesce-imports")
	logrus.SetLevel(logrus.FatalLevel)
	logLevel, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatalf("Failed to parse log level: %v", err)
	}
	logrus.SetLevel(logLevel)
}

// Largely cribbed from the go/ast package:
//
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// coalesceImports removes blank lines from imports.
func coalesceImports(fset *token.FileSet, f *ast.File) (changed bool) {
	for _, d := range f.Decls {
		d, ok := d.(*ast.GenDecl)
		if !ok || d.Tok != token.IMPORT {
			// Not an import declaration, so we're done.
			// Imports are always first.
			break
		}

		if !d.Lparen.IsValid() {
			// Not a block: sorted by default.
			continue
		}

		// Identify the blank lines and squash them.
		for j, s := range d.Specs {
			if j == 0 {
				continue
			}
			prevLine := lineAt(fset, d.Specs[j-1].End())
			thisLine := lineAt(fset, s.Pos())
			for line := thisLine - 1; line > prevLine; line-- {
				changed = true
				fset.File(s.Pos()).MergeLine(line)
			}
		}
	}
	return
}

func lineAt(fset *token.FileSet, pos token.Pos) int {
	return fset.PositionFor(pos, false).Line
}
