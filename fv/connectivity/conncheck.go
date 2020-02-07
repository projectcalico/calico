// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package connectivity

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/set"

	uuid "github.com/satori/go.uuid"
)

// ConnectivityChecker records a set of connectivity expectations and supports calculating the
// actual state of the connectivity between the given workloads.  It is expected to be used like so:
//
//     var cc = &conncheck.ConnectivityChecker{}
//     cc.ExpectNone(w[2], w[0], 1234)
//     cc.ExpectSome(w[1], w[0], 5678)
//     cc.CheckConnectivity()
//
type Checker struct {
	ReverseDirection bool
	Protocol         string // "tcp" or "udp"
	expectations     []Expectation
	CheckSNAT        bool
}

func (c *Checker) ExpectSome(from ConnectionSource, to ConnectionTarget, explicitPort ...uint16) {
	UnactivatedCheckers.Add(c)
	if c.ReverseDirection {
		from, to = to.(ConnectionSource), from.(ConnectionTarget)
	}
	c.expectations = append(c.expectations, Expectation{from, to.ToMatcher(explicitPort...), true, from.SourceIPs()})
}

func (c *Checker) ExpectSNAT(from ConnectionSource, srcIP string, to ConnectionTarget, explicitPort ...uint16) {
	UnactivatedCheckers.Add(c)
	c.CheckSNAT = true
	if c.ReverseDirection {
		from, to = to.(ConnectionSource), from.(ConnectionTarget)
	}
	c.expectations = append(c.expectations, Expectation{from, to.ToMatcher(explicitPort...), true, []string{srcIP}})
}

func (c *Checker) ExpectNone(from ConnectionSource, to ConnectionTarget, explicitPort ...uint16) {
	UnactivatedCheckers.Add(c)
	if c.ReverseDirection {
		from, to = to.(ConnectionSource), from.(ConnectionTarget)
	}
	c.expectations = append(c.expectations, Expectation{from, to.ToMatcher(explicitPort...), false, nil})
}

func (c *Checker) ResetExpectations() {
	c.expectations = nil
	c.CheckSNAT = false
}

// ActualConnectivity calculates the current connectivity for all the expected paths.  It returns a
// slice containing one response for each attempted check (or nil if the check failed) along with
// a same-length slice containing a pretty-printed description of the check and its result.
func (c *Checker) ActualConnectivity() ([]*Response, []string) {
	UnactivatedCheckers.Discard(c)
	var wg sync.WaitGroup
	responses := make([]*Response, len(c.expectations))
	pretty := make([]string, len(c.expectations))
	for i, exp := range c.expectations {
		wg.Add(1)
		go func(i int, exp Expectation) {
			defer ginkgo.GinkgoRecover()
			defer wg.Done()
			p := "tcp"
			if c.Protocol != "" {
				p = c.Protocol
			}
			responses[i] = exp.From.CanConnectTo(exp.To.IP, exp.To.Port, p)
			pretty[i] = fmt.Sprintf("%s -> %s = %v", exp.From.SourceName(), exp.To.TargetName, responses[i] != nil)
			if c.CheckSNAT && responses[i] != nil {
				srcIP := strings.Split(responses[i].SourceAddr, ":")[0]
				pretty[i] += " (from " + srcIP + ")"
			}
		}(i, exp)
	}
	wg.Wait()
	logrus.Debug("Connectivity", responses)
	return responses, pretty
}

// ExpectedConnectivityPretty returns one string per recorded expectation in order, encoding the expected
// connectivity in similar format used by ActualConnectivity().
func (c *Checker) ExpectedConnectivityPretty() []string {
	result := make([]string, len(c.expectations))
	for i, exp := range c.expectations {
		result[i] = fmt.Sprintf("%s -> %s = %v", exp.From.SourceName(), exp.To.TargetName, exp.Expected)
		if c.CheckSNAT && exp.Expected {
			result[i] += " (from " + strings.Join(exp.ExpSrcIPs, "|") + ")"
		}
	}
	return result
}

var defaultConnectivityTimeout = 10 * time.Second

func (c *Checker) CheckConnectivityOffset(offset int, optionalDescription ...interface{}) {
	c.CheckConnectivityWithTimeoutOffset(offset+2, defaultConnectivityTimeout, optionalDescription...)
}

func (c *Checker) CheckConnectivity(optionalDescription ...interface{}) {
	c.CheckConnectivityWithTimeoutOffset(2, defaultConnectivityTimeout, optionalDescription...)
}

func (c *Checker) CheckConnectivityWithTimeout(timeout time.Duration, optionalDescription ...interface{}) {
	gomega.Expect(timeout).To(gomega.BeNumerically(">", 100*time.Millisecond),
		"Very low timeout, did you mean to multiply by time.<Unit>?")
	if len(optionalDescription) > 0 {
		gomega.Expect(optionalDescription[0]).NotTo(gomega.BeAssignableToTypeOf(time.Second),
			"Unexpected time.Duration passed for description")
	}
	c.CheckConnectivityWithTimeoutOffset(2, timeout, optionalDescription...)
}

func (c *Checker) CheckConnectivityWithTimeoutOffset(callerSkip int, timeout time.Duration, optionalDescription ...interface{}) {
	var expConnectivity []string
	start := time.Now()

	// Track the number of attempts. If the first connectivity check fails, we want to
	// do at least one retry before we time out.  That covers the case where the first
	// connectivity check takes longer than the timeout.
	completedAttempts := 0
	var actualConn []*Response
	var actualConnPretty []string
	for time.Since(start) < timeout || completedAttempts < 2 {
		actualConn, actualConnPretty = c.ActualConnectivity()
		failed := false
		expConnectivity = c.ExpectedConnectivityPretty()
		for i := range c.expectations {
			exp := c.expectations[i]
			act := actualConn[i]
			if !exp.Matches(act, c.CheckSNAT) {
				failed = true
				actualConnPretty[i] += " <---- WRONG"
				expConnectivity[i] += " <---- EXPECTED"
			}
		}
		if !failed {
			// Success!
			return
		}
		completedAttempts++
	}

	message := fmt.Sprintf(
		"Connectivity was incorrect:\n\nExpected\n    %s\nto match\n    %s",
		strings.Join(actualConnPretty, "\n    "),
		strings.Join(expConnectivity, "\n    "),
	)
	ginkgo.Fail(message, callerSkip)
}

func NewRequest() Request {
	return Request{
		Timestamp: time.Now(),
		ID:        uuid.NewV4().String(),
	}
}

type Request struct {
	Timestamp time.Time
	ID        string
}

func (req Request) Equal(oth Request) bool {
	return req.ID == oth.ID && req.Timestamp.Equal(oth.Timestamp)
}

type Response struct {
	Timestamp time.Time

	SourceAddr string
	ServerAddr string

	Request Request
}

func (r Response) SourceIP() string {
	return strings.Split(r.SourceAddr, ":")[0]
}

type ConnectionTarget interface {
	ToMatcher(explicitPort ...uint16) *Matcher
}

type TargetIP string // Just so we can define methods on it...

func (s TargetIP) ToMatcher(explicitPort ...uint16) *Matcher {
	if len(explicitPort) != 1 {
		panic("Explicit port needed with IP as a connectivity target")
	}
	port := fmt.Sprintf("%d", explicitPort[0])
	return &Matcher{
		IP:         string(s),
		Port:       port,
		TargetName: string(s) + ":" + port,
		Protocol:   "tcp",
	}
}

func HaveConnectivityTo(target ConnectionTarget, explicitPort ...uint16) types.GomegaMatcher {
	return target.ToMatcher(explicitPort...)
}

type Matcher struct {
	IP, Port, TargetName, Protocol string
}

type ConnectionSource interface {
	CanConnectTo(ip, port, protocol string) *Response
	SourceName() string
	SourceIPs() []string
}

func (m *Matcher) Match(actual interface{}) (success bool, err error) {
	success = actual.(ConnectionSource).CanConnectTo(m.IP, m.Port, m.Protocol) != nil
	return
}

func (m *Matcher) FailureMessage(actual interface{}) (message string) {
	src := actual.(ConnectionSource)
	message = fmt.Sprintf("Expected %v\n\t%+v\nto have connectivity to %v\n\t%v:%v\nbut it does not", src.SourceName(), src, m.TargetName, m.IP, m.Port)
	return
}

func (m *Matcher) NegatedFailureMessage(actual interface{}) (message string) {
	src := actual.(ConnectionSource)
	message = fmt.Sprintf("Expected %v\n\t%+v\nnot to have connectivity to %v\n\t%v:%v\nbut it does", src.SourceName(), src, m.TargetName, m.IP, m.Port)
	return
}

type Expectation struct {
	From      ConnectionSource // Workload or Container
	To        *Matcher         // Workload or IP, + port
	Expected  bool
	ExpSrcIPs []string
}

func (e Expectation) Matches(response *Response, checkSNAT bool) bool {
	if e.Expected {
		if response == nil {
			return false
		}
		if checkSNAT {
			for _, src := range e.ExpSrcIPs {
				if src == response.SourceIP() {
					return true
				}
			}
			return false
		}
	} else {
		if response != nil {
			return false
		}
	}
	return true
}

var UnactivatedCheckers = set.New()
