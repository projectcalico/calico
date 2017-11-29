// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package server

import (
	"bufio"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	spireauth "github.com/spiffe/spire/pkg/agent/auth"
	"golang.org/x/net/context"
)

func getCallerInfo(ctx context.Context) (pid int32, err error) {
	info, ok := spireauth.CallerFromContext(ctx)
	if ok == false {
		return 0, errors.New("not able to get caller pid")
	}
	log.Debugf("Caller context is %v", info)
	return info.PID, nil
}

// Given the gRPC context, return the corresponding workload labels for the client.
func getContainerFromContext(ctx context.Context) (string, error) {
	// Resolve the caller info
	pid, err := getCallerInfo(ctx)
	if err != nil {
		return "", err
	}
	return getContainerId("/host", pid)
}

func getContainerId(pathPrefix string, pid int32) (cid string, err error) {
	path := pathPrefix + "/proc/" + strconv.Itoa(int(pid)) + "/cgroup"
	re := regexp.MustCompile("^1:name")
	file, err := os.Open(path)
	if err != nil {
		errS := "Not able to open proc file " + path + " (" + err.Error() + ")"
		return "", errors.New(errS)
	}
	defer file.Close()

	var rstr string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rstr = scanner.Text()
		r := re.FindString(rstr)
		if r != "" {
			break
		}
	}
	if rstr == "" {
		return "", errors.New("Not able to find the container id")
	}

	vals := strings.Split(rstr, "/")
	if vals[0] == rstr {
		log.Errorf("%v", vals)
		return "", errors.New("The cgroups does not contain CID")
	}

	return vals[len(vals)-1], nil
}
