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
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/set"

	uuid "github.com/satori/go.uuid"
)

// ConnectivityChecker records a set of connectivity expectations and supports calculating the
// actual state of the connectivity between the given workloads.  It is expected to be used like so:
//
//     var cc = &connectivity.Checker{}
//     cc.ExpectNone(w[2], w[0], 1234)
//     cc.ExpectSome(w[1], w[0], 5678)
//     cc.CheckConnectivity()
//
type Checker struct {
	ReverseDirection bool
	Protocol         string // "tcp" or "udp"
	expectations     []Expectation
	CheckSNAT        bool
	RetriesDisabled  bool

	// OnFail, if set, will be called instead of ginkgo.Fail().  (Useful for testing the checker itself.)
	OnFail func(msg string)
}

func (c *Checker) ExpectSome(from ConnectionSource, to ConnectionTarget, explicitPort ...uint16) {
	UnactivatedCheckers.Add(c)
	if c.ReverseDirection {
		from, to = to.(ConnectionSource), from.(ConnectionTarget)
	}
	c.expectations = append(c.expectations, Expectation{From: from, To: to.ToMatcher(explicitPort...), Expected: true, ExpSrcIPs: from.SourceIPs()})
}

func (c *Checker) ExpectSNAT(from ConnectionSource, srcIP string, to ConnectionTarget, explicitPort ...uint16) {
	UnactivatedCheckers.Add(c)
	c.CheckSNAT = true
	if c.ReverseDirection {
		from, to = to.(ConnectionSource), from.(ConnectionTarget)
	}
	c.expectations = append(c.expectations, Expectation{From: from, To: to.ToMatcher(explicitPort...), Expected: true, ExpSrcIPs: []string{srcIP}})
}

func (c *Checker) ExpectNone(from ConnectionSource, to ConnectionTarget, explicitPort ...uint16) {
	UnactivatedCheckers.Add(c)
	if c.ReverseDirection {
		from, to = to.(ConnectionSource), from.(ConnectionTarget)
	}
	c.expectations = append(c.expectations, Expectation{From: from, To: to.ToMatcher(explicitPort...), Expected: false, ExpSrcIPs: nil})
}

func (c *Checker) ExpectLoss(from ConnectionSource, to ConnectionTarget,
	duration time.Duration, maxPacketLossPercent float64, maxPacketLossNumber int, explicitPort ...uint16) {

	Expect(duration.Seconds()).NotTo(BeZero(), "Packet loss test must have a duration")
	Expect(maxPacketLossPercent).To(BeNumerically("<=", 100), "Loss percentage should be <=100")
	Expect(maxPacketLossPercent >= 0 || maxPacketLossNumber >= 0).To(BeTrue(), "Either loss count or percent must be specified")

	UnactivatedCheckers.Add(c)
	if c.ReverseDirection {
		from, to = to.(ConnectionSource), from.(ConnectionTarget)
	}
	c.expectations = append(c.expectations, Expectation{
		From:      from,
		To:        to.ToMatcher(explicitPort...),
		Expected:  true,
		ExpSrcIPs: nil,
		ExpectedPacketLoss: ExpPacketLoss{
			Duration:   duration,
			MaxPercent: maxPacketLossPercent,
			MaxNumber:  maxPacketLossNumber,
		},
	})

	// Packet loss measurements shouldn't be retried.
	c.RetriesDisabled = true
}

func (c *Checker) ResetExpectations() {
	c.expectations = nil
	c.CheckSNAT = false
	c.RetriesDisabled = false
}

// ActualConnectivity calculates the current connectivity for all the expected paths.  It returns a
// slice containing one response for each attempted check (or nil if the check failed) along with
// a same-length slice containing a pretty-printed description of the check and its result.
func (c *Checker) ActualConnectivity() ([]*Result, []string) {
	UnactivatedCheckers.Discard(c)
	var wg sync.WaitGroup
	responses := make([]*Result, len(c.expectations))
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
			responses[i] = exp.From.CanConnectTo(exp.To.IP, exp.To.Port, p, exp.ExpectedPacketLoss.Duration)
			pretty[i] = fmt.Sprintf("%s -> %s = %v", exp.From.SourceName(), exp.To.TargetName, responses[i] != nil)
			if c.CheckSNAT && responses[i] != nil {
				srcIP := strings.Split(responses[i].LastResponse.SourceAddr, ":")[0]
				pretty[i] += " (from " + srcIP + ")"
			}
			if exp.ExpectedPacketLoss.Duration > 0 && responses[i] != nil {
				sent := responses[i].Stats.RequestsSent
				lost := responses[i].Stats.Lost()
				pct := responses[i].Stats.LostPercent()
				pretty[i] += fmt.Sprintf(" (sent: %d, lost: %d / %.1f%%)", sent, lost, pct)
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
		if exp.ExpectedPacketLoss.MaxNumber >= 0 {
			result[i] += fmt.Sprintf(" (maxLoss: %d packets)", exp.ExpectedPacketLoss.MaxNumber)
		}
		if exp.ExpectedPacketLoss.MaxPercent >= 0 {
			result[i] += fmt.Sprintf(" (maxLoss: %.1f%%)", exp.ExpectedPacketLoss.MaxPercent)
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

func (c *Checker) CheckConnectivityPacketLoss(optionalDescription ...interface{}) {
	// Timeout is not used for packet loss test because there is no retry.
	c.CheckConnectivityWithTimeoutOffset(2, 0*time.Second, optionalDescription...)
}

func (c *Checker) CheckConnectivityWithTimeout(timeout time.Duration, optionalDescription ...interface{}) {
	Expect(timeout).To(BeNumerically(">", 100*time.Millisecond),
		"Very low timeout, did you mean to multiply by time.<Unit>?")
	if len(optionalDescription) > 0 {
		Expect(optionalDescription[0]).NotTo(BeAssignableToTypeOf(time.Second),
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
	var actualConn []*Result
	var actualConnPretty []string
	for !c.RetriesDisabled && time.Since(start) < timeout || completedAttempts < 2 {
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
	if c.OnFail != nil {
		c.OnFail(message)
	} else {
		ginkgo.Fail(message, callerSkip)
	}
}

func NewRequest(payload string) Request {
	return Request{
		Timestamp: time.Now(),
		ID:        uuid.NewV4().String(),
		Payload:   payload,
	}
}

type Request struct {
	Timestamp time.Time
	ID        string
	Payload   string
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
	CanConnectTo(ip, port, protocol string, duration time.Duration) *Result
	SourceName() string
	SourceIPs() []string
}

func (m *Matcher) Match(actual interface{}) (success bool, err error) {
	success = actual.(ConnectionSource).CanConnectTo(m.IP, m.Port, m.Protocol, time.Duration(0)) != nil
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
	From               ConnectionSource // Workload or Container
	To                 *Matcher         // Workload or IP, + port
	Expected           bool
	ExpSrcIPs          []string
	ExpectedPacketLoss ExpPacketLoss
}

type ExpPacketLoss struct {
	Duration   time.Duration // how long test will run
	MaxPercent float64       // 10 means 10%. -1 means field not valid.
	MaxNumber  int           // 10 means 10 packets. -1 means field not valid.
}

func (e Expectation) Matches(response *Result, checkSNAT bool) bool {
	if e.Expected {
		if response == nil {
			return false
		}
		if checkSNAT {
			for _, src := range e.ExpSrcIPs {
				if src == response.LastResponse.SourceIP() {
					return true
				}
			}
			return false
		}

		if e.ExpectedPacketLoss.Duration > 0 {
			// This is a packet loss test.
			lossCount := response.Stats.Lost()
			lossPercent := response.Stats.LostPercent()

			if e.ExpectedPacketLoss.MaxNumber >= 0 && lossCount > e.ExpectedPacketLoss.MaxNumber {
				return false
			}
			if e.ExpectedPacketLoss.MaxPercent >= 0 && lossPercent > e.ExpectedPacketLoss.MaxPercent {
				return false
			}
		}

	} else {
		if response != nil {
			return false
		}
	}

	return true
}

var UnactivatedCheckers = set.New()

type Result struct {
	LastResponse Response
	Stats        Stats
}

func (r Result) PrintToStdout() {
	encoded, err := json.Marshal(r)
	if err != nil {
		logrus.WithError(err).Panic("Failed to marshall result to stdout")
	}
	fmt.Printf("RESULT=%s\n", string(encoded))
}

type Stats struct {
	RequestsSent      int
	ResponsesReceived int
}

func (s Stats) Lost() int {
	return s.RequestsSent - s.ResponsesReceived
}

func (s Stats) LostPercent() float64 {
	return float64(s.Lost()) * 100.0 / float64(s.RequestsSent)
}
