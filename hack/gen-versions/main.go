// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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
	"flag"
	"log"
	"os"
	"path/filepath"
)

const (
	eeVersionsTpl    = "enterprise.go.tpl"
	osVersionsTpl    = "calico.go.tpl"
	cloudVersionsTpl = "cloud.go.tpl"
)

var (
	templateDir       string
	debug             bool
	eeVersionsPath    string
	osVersionsPath    string
	cloudVersionsPath string
)

func main() {
	flag.StringVar(&templateDir, "template-dir", "hack/gen-versions/", "path to directory containing templates files named calico.go.tpl, enterprise.go.tpl and cloud.go.tpl")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.StringVar(&eeVersionsPath, "ee-versions", "", "path to enterprise versions file")
	flag.StringVar(&osVersionsPath, "os-versions", "", "path to calico versions file")
	flag.StringVar(&cloudVersionsPath, "cloud-versions", "", "path to cloud versions file")
	flag.Parse()

	if debug {
		log.SetOutput(os.Stderr)
		log.Println("debug logging enabled")
	}

	// Exactly one of the versions flags must be set.
	set := 0
	for _, p := range []string{osVersionsPath, eeVersionsPath, cloudVersionsPath} {
		if p != "" {
			set++
		}
	}
	if set != 1 {
		log.Println("must specify exactly one of -os-versions, -ee-versions or -cloud-versions")
		flag.PrintDefaults()
		os.Exit(1)
	}

	switch {
	case osVersionsPath != "":
		if err := run(osVersionsPath, filepath.Join(templateDir, osVersionsTpl)); err != nil {
			log.Fatalln(err)
		}
	case eeVersionsPath != "":
		if err := run(eeVersionsPath, filepath.Join(templateDir, eeVersionsTpl)); err != nil {
			log.Fatalln(err)
		}
	case cloudVersionsPath != "":
		if err := run(cloudVersionsPath, filepath.Join(templateDir, cloudVersionsTpl)); err != nil {
			log.Fatalln(err)
		}
	}
}

func run(versionsPath, tpl string) error {
	vz, err := GetComponents(versionsPath)
	if err != nil {
		return err
	}

	return render(tpl, vz)
}
