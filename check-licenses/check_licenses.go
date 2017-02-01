// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"os"

	log "github.com/Sirupsen/logrus"

	"bufio"
	"regexp"
	"strings"

	"github.com/projectcalico/felix/logutils"
	"github.com/projectcalico/felix/set"
)

var (
	whitelistedLicenses = set.From(
		"Apache License 2.0",
		"MIT License",
		"ISC License",
		"BSD 3-clause \"New\" or \"Revised\" License",
	)
	whitelistedPkgs = set.FromArray([]pkgInfo{
		// These packages are licensed under the LGPL, which is normally viral and hence
		// incompatible with our licensing! However, they include the linking exception,
		// allowing us to distribute a binary based on them as long as we don't modify them.
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/juju/ratelimit",
			license: "GNU Lesser General Public License v3.0 (94%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/gopkg.in/yaml.v2",
			license: "GNU Lesser General Public License v3.0 (95%)"},

		// Variants on MIT/BSD; files tend to include updated copyright statement.
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/PuerkitoBio/urlesc",
			license: "BSD 3-clause \"New\" or \"Revised\" License (96%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/beorn7/perks/quantile",
			license: "MIT License (98%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/gogo/protobuf",
			license: "BSD 3-clause \"New\" or \"Revised\" License (90%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/golang/protobuf/proto",
			license: "BSD 3-clause \"New\" or \"Revised\" License (92%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/howeyc/gopass",
			license: "ISC License (98%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/imdario/mergo",
			license: "BSD 3-clause \"New\" or \"Revised\" License (96%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/kardianos/osext",
			license: "BSD 3-clause \"New\" or \"Revised\" License (96%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/kelseyhightower/envconfig",
			license: "MIT License (98%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/mailru/easyjson",
			license: "MIT License (98%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/pborman/uuid",
			license: "BSD 3-clause \"New\" or \"Revised\" License (96%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/satori/go.uuid",
			license: "MIT License (98%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/spf13/pflag",
			license: "BSD 3-clause \"New\" or \"Revised\" License (96%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/gopkg.in/inf.v0",
			license: "BSD 3-clause \"New\" or \"Revised\" License (97%)"},

		// Mixed license, Apache and some files under BSD-like.
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/ghodss/yaml",
			license: "? (BSD 3-clause \"New\" or \"Revised\" License, 83%)"},

		// Apache license with copyright statement in file.
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/vishvananda/netlink/nl",
			license: "Apache License 2.0 (96%)"},
		{pkgName: "github.com/projectcalico/felix/vendor/github.com/vishvananda/netns",
			license: "Apache License 2.0 (96%)"},
	})
	whitelistedPrefixes = []string{
		// Standard golang BSD-like license.
		"github.com/projectcalico/felix/vendor/golang.org/x/",
	}
)

func main() {
	logutils.ConfigureEarlyLogging()

	wd, _ := os.Getwd()
	log.WithField("PWD", wd).Info("Current directory")
	file, err := os.Open("check-licenses/dependency-licenses.txt") // For read access.
	if err != nil {
		log.WithError(err).Panic("Failed to open licenses file")
	}
	scanner := bufio.NewScanner(file)
	lineRE := regexp.MustCompile(`^(\S+)\s+(\S.*)$`)
	badPackages := []pkgInfo{}
lineLoop:
	for scanner.Scan() {
		line := scanner.Text()
		logCxt := log.WithField("line", line)
		submatches := lineRE.FindStringSubmatch(line)
		if len(submatches) != 3 {
			logCxt.Panic("Expected line to match regex")
		}
		pkgName := submatches[1]
		license := submatches[2]
		logCxt = logCxt.WithFields(log.Fields{
			"pkgName": pkgName,
			"license": license,
		})
		logCxt.Debug("Found package")
		pkgInfo := pkgInfo{
			pkgName: pkgName,
			license: license,
		}
		if strings.HasPrefix(pkgName, "github.com/projectcalico/felix/vendor/github.com/projectcalico/") ||
			(strings.HasPrefix(pkgName, "github.com/projectcalico/") &&
				!strings.Contains(pkgName, "vendor")) {
			logCxt.Info("One of our packages")
			continue
		}
		if whitelistedLicenses.Contains(license) {
			logCxt.Info("License is whitelisted")
			continue
		}
		if whitelistedPkgs.Contains(pkgInfo) {
			logCxt.Info("Package is whitelisted")
			continue
		}
		for _, prefix := range whitelistedPrefixes {
			if strings.HasPrefix(pkgName, prefix) {
				logCxt.WithField("prefix", prefix).Info("Package prefix is whitelisted")
				continue lineLoop
			}
		}
		logCxt.Error("License not whitelisted")
		badPackages = append(badPackages, pkgInfo)
	}

	if len(badPackages) > 0 {
		log.Error("Found bad licenses")
		for _, pkg := range badPackages {
			log.Errorf("\n\nNon-white-listed license:\n  Package: %v\n  License: %v\n", pkg.pkgName, pkg.license)
		}
		log.Info("")
		os.Exit(1)
	}
}

type pkgInfo struct {
	pkgName string
	license string
}
