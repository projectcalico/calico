// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// ConnectivityChecker records a set of connectivity expectations and supports calculating the
// actual state of the connectivity between the given workloads.  It is expected to be used like so:
//
//     var cc = &connectivity.Checker{}
//     cc.Expect(None, w[2], w[0], 1234)
//     cc.Expect(Some, w[1], w[0], 5678)
//     cc.Expect(Some, w[1], w[0], 4321, ExpectWithABC, ExpectWithXYZ)
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

	description string
	beforeRetry func()       // called when a test fails and before it is retried
	finalTest   func() error // called after connectivity test, if it is successful, may fail the test.
}

// CheckerOpt is an option to CheckConnectivity()
type CheckerOpt func(*Checker)

// CheckWithDescription sets a description of a failure.
func CheckWithDescription(desc string) CheckerOpt {
	return func(c *Checker) {
		c.description = desc
	}
}

// CheckWithBeforeRetry sets a function executed after an attempt failed and
// before we retry.
func CheckWithBeforeRetry(f func()) CheckerOpt {
	return func(c *Checker) {
		log.Debug("CheckWithBeforeRetry set")
		c.beforeRetry = f
	}
}

func CheckWithFinalTest(f func() error) CheckerOpt {
	return func(c *Checker) {
		log.Debug("CheckWithFinalTest set")
		c.finalTest = f
	}
}

// Expected defines what connectivity expectations we can have
type Expected bool

const (
	// None no connectivity is expected
	None Expected = false
	// Some some connectivity, possibly after retries is expected
	Some Expected = true
)

func (c *Checker) ExpectSome(from ConnectionSource, to ConnectionTarget, explicitPort ...uint16) {
	c.expect(Some, from, to, ExpectWithPorts(explicitPort...))
}

func (c *Checker) ExpectSNAT(from ConnectionSource, srcIP string, to ConnectionTarget, explicitPort ...uint16) {
	c.CheckSNAT = true
	c.expect(Some, from, to, ExpectWithPorts(explicitPort...), ExpectWithSrcIPs(srcIP))
}

func (c *Checker) ExpectNone(from ConnectionSource, to ConnectionTarget, explicitPort ...uint16) {
	c.expect(None, from, to, ExpectWithPorts(explicitPort...))
}

// Expect asserts existing connectivity between a ConnectionSource
// and ConnectionTarget with details configurable with ExpectationOption(s).
// This is a super set of ExpectSome()
func (c *Checker) Expect(expected Expected,
	from ConnectionSource, to ConnectionTarget, opts ...ExpectationOption) {

	c.expect(expected, from, to, opts...)
}

func (c *Checker) ExpectLoss(from ConnectionSource, to ConnectionTarget,
	duration time.Duration, maxPacketLossPercent float64, maxPacketLossNumber int, explicitPort ...uint16) {

	// Packet loss measurements shouldn't be retried.
	c.RetriesDisabled = true

	c.expect(Some, from, to,
		ExpectWithPorts(explicitPort...),
		ExpectWithLoss(duration, maxPacketLossPercent, maxPacketLossNumber),
	)
}

func (c *Checker) expect(expected Expected, from ConnectionSource, to ConnectionTarget,
	opts ...ExpectationOption) {

	UnactivatedCheckers.Add(c)
	if c.ReverseDirection {
		from, to = to.(ConnectionSource), from.(ConnectionTarget)
	}

	e := Expectation{
		From:     from,
		Expected: expected,
	}

	if expected {
		// we expect the from.SourceIPs() by default
		e.ExpSrcIPs = from.SourceIPs()
	}

	for _, option := range opts {
		option(&e)
	}

	e.To = to.ToMatcher(e.explicitPorts...)

	c.expectations = append(c.expectations, e)
}

func (c *Checker) ResetExpectations() {
	c.expectations = nil
	c.CheckSNAT = false
	c.RetriesDisabled = false

	c.description = ""
	c.beforeRetry = nil
	c.finalTest = nil
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

			var res *Result

			opts := []CheckOption{
				WithDuration(exp.ExpectedPacketLoss.Duration),
			}

			if exp.sendLen > 0 || exp.recvLen > 0 {
				opts = append(opts, WithSendLen(exp.sendLen), WithRecvLen(exp.recvLen))
			}

			if exp.srcPort != 0 {
				opts = append(opts, WithSourcePort(strconv.Itoa(int(exp.srcPort))))
			}

			res = exp.From.CanConnectTo(exp.To.IP, exp.To.Port, p, opts...)

			pretty[i] += fmt.Sprintf("%s -> %s = %v", exp.From.SourceName(), exp.To.TargetName, res.HasConnectivity())

			if res != nil {
				if c.CheckSNAT {
					srcIP := strings.Split(res.LastResponse.SourceAddr, ":")[0]
					pretty[i] += " (from " + srcIP + ")"
				}
				if res.ClientMTU.Start != 0 {
					pretty[i] += fmt.Sprintf(" (client MTU %d -> %d)", res.ClientMTU.Start, res.ClientMTU.End)
				}
				if exp.ExpectedPacketLoss.Duration > 0 {
					sent := res.Stats.RequestsSent
					lost := res.Stats.Lost()
					pct := res.Stats.LostPercent()
					pretty[i] += fmt.Sprintf(" (sent: %d, lost: %d / %.1f%%)", sent, lost, pct)
				}
			}

			responses[i] = res
		}(i, exp)
	}
	wg.Wait()
	return responses, pretty
}

// ExpectedConnectivityPretty returns one string per recorded expectation in order, encoding the expected
// connectivity in similar format used by ActualConnectivity().
func (c *Checker) ExpectedConnectivityPretty() []string {
	result := make([]string, len(c.expectations))
	for i, exp := range c.expectations {
		result[i] = fmt.Sprintf("%s -> %s = %v", exp.From.SourceName(), exp.To.TargetName, exp.Expected)
		if exp.Expected {
			if c.CheckSNAT {
				result[i] += " (from " + strings.Join(exp.ExpSrcIPs, "|") + ")"
			}
			if exp.clientMTUStart != 0 || exp.clientMTUEnd != 0 {
				result[i] += fmt.Sprintf(" (client MTU %d -> %d)", exp.clientMTUStart, exp.clientMTUEnd)
			}
		}
		if exp.ExpectedPacketLoss.Duration > 0 {
			if exp.ExpectedPacketLoss.MaxNumber >= 0 {
				result[i] += fmt.Sprintf(" (maxLoss: %d packets)", exp.ExpectedPacketLoss.MaxNumber)
			}
			if exp.ExpectedPacketLoss.MaxPercent >= 0 {
				result[i] += fmt.Sprintf(" (maxLoss: %.1f%%)", exp.ExpectedPacketLoss.MaxPercent)
			}
		}
		if exp.ErrorStr != "" {
			result[i] += " " + exp.ErrorStr
		}
	}
	return result
}

var defaultConnectivityTimeout = 10 * time.Second

func (c *Checker) CheckConnectivityOffset(offset int, opts ...interface{}) {
	c.CheckConnectivityWithTimeoutOffset(offset+2, defaultConnectivityTimeout, opts...)
}

func (c *Checker) CheckConnectivity(opts ...interface{}) {
	c.CheckConnectivityWithTimeoutOffset(2, defaultConnectivityTimeout, opts...)
}

func (c *Checker) CheckConnectivityPacketLoss(opts ...interface{}) {
	// Timeout is not used for packet loss test because there is no retry.
	c.CheckConnectivityWithTimeoutOffset(2, 0*time.Second, opts...)
}

func (c *Checker) CheckConnectivityWithTimeout(timeout time.Duration, opts ...interface{}) {
	Expect(timeout).To(BeNumerically(">", 100*time.Millisecond),
		"Very low timeout, did you mean to multiply by time.<Unit>?")
	c.CheckConnectivityWithTimeoutOffset(2, timeout, opts...)
}

func (c *Checker) CheckConnectivityWithTimeoutOffset(callerSkip int, timeout time.Duration, opts ...interface{}) {

	for _, o := range opts {
		switch v := o.(type) {
		case string:
			c.description = v
		case CheckerOpt:
			v(c)
		}
	}

	var expConnectivity []string
	start := time.Now()

	// Track the number of attempts. If the first connectivity check fails, we want to
	// do at least one retry before we time out.  That covers the case where the first
	// connectivity check takes longer than the timeout.
	completedAttempts := 0
	var actualConn []*Result
	var actualConnPretty []string
	var finalErr error

	for !c.RetriesDisabled && time.Since(start) < timeout || completedAttempts < 2 {
		actualConn, actualConnPretty = c.ActualConnectivity()
		failed := false
		finalErr = nil
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
			if c.finalTest != nil {
				finalErr = c.finalTest()
				if finalErr != nil {
					failed = true
				}
			}
			if !failed {
				// Success!
				return
			}
		}
		completedAttempts++
		if c.beforeRetry != nil {
			log.Debug("calling beforeRetry")
			c.beforeRetry()
		}
	}

	message := fmt.Sprintf(
		"Connectivity was incorrect:\n\nExpected\n    %s\nto match\n    %s",
		strings.Join(actualConnPretty, "\n    "),
		strings.Join(expConnectivity, "\n    "),
	)

	if finalErr != nil {
		message += "\n Final test failed: " + finalErr.Error() + "\n"
	}

	if c.description != "" {
		message += "\nDescription:\n" + c.description
	}

	if c.OnFail != nil {
		c.OnFail(message)
	} else {
		ginkgo.Fail(message, callerSkip)
	}
}

func NewRequest(payload string) Request {
	return Request{
		Timestamp: time.Now(),
		ID:        uuid.NewString(),
		Payload:   payload,
	}
}

type Request struct {
	Timestamp    time.Time
	ID           string
	Payload      string
	SendSize     int
	ResponseSize int
}

func (req Request) Equal(oth Request) bool {
	return req.ID == oth.ID && req.Timestamp.Equal(oth.Timestamp)
}

type Response struct {
	Timestamp time.Time

	SourceAddr string
	ServerAddr string

	Request  Request
	ErrorStr string
}

func (r *Response) SourceIP() string {
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
	CanConnectTo(ip, port, protocol string, opts ...CheckOption) *Result
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

type ExpectationOption func(e *Expectation)

func ExpectWithSrcIPs(ips ...string) ExpectationOption {
	return func(e *Expectation) {
		e.ExpSrcIPs = ips
	}
}

func ExpectWithSrcPort(port uint16) ExpectationOption {
	return func(e *Expectation) {
		e.srcPort = port
	}
}

func ExpectNoneWithError(ErrorStr string) ExpectationOption {
	return func(e *Expectation) {
		e.ErrorStr = ErrorStr
	}
}

// ExpectWithSendLen asserts how much additional data on top of the original
// requests should be sent with success
func ExpectWithSendLen(l int) ExpectationOption {
	return func(e *Expectation) {
		e.sendLen = l
	}
}

// ExpectWithRecvLen asserts how much additional data on top of the original
// response should be received with success
func ExpectWithRecvLen(l int) ExpectationOption {
	return func(e *Expectation) {
		e.recvLen = l
	}
}

// ExpectWithClientAdjustedMTU asserts that the connection MTU should change
// during the transfer
func ExpectWithClientAdjustedMTU(from, to int) ExpectationOption {
	return func(e *Expectation) {
		e.clientMTUStart = from
		e.clientMTUEnd = to
	}
}

// ExpectWithLoss asserts that the connection has a certain loss rate
func ExpectWithLoss(duration time.Duration, maxPacketLossPercent float64, maxPacketLossNumber int) ExpectationOption {
	Expect(duration.Seconds()).NotTo(BeZero(),
		"Packet loss test must have a duration")
	Expect(maxPacketLossPercent).To(BeNumerically("<=", 100),
		"Loss percentage should be <=100")
	Expect(maxPacketLossPercent >= 0 || maxPacketLossNumber >= 0).To(BeTrue(),
		"Either loss count or percent must be specified")

	return func(e *Expectation) {
		e.ExpectedPacketLoss = ExpPacketLoss{
			Duration:   duration,
			MaxPercent: maxPacketLossPercent,
			MaxNumber:  maxPacketLossNumber,
		}
	}
}

func ExpectWithPorts(ports ...uint16) ExpectationOption {
	return func(e *Expectation) {
		e.explicitPorts = ports
	}
}

type Expectation struct {
	From               ConnectionSource // Workload or Container
	To                 *Matcher         // Workload or IP, + port
	Expected           Expected
	ExpSrcIPs          []string
	ExpectedPacketLoss ExpPacketLoss

	explicitPorts []uint16

	sendLen int
	recvLen int

	clientMTUStart int
	clientMTUEnd   int

	srcPort uint16

	ErrorStr string
}

type ExpPacketLoss struct {
	Duration   time.Duration // how long test will run
	MaxPercent float64       // 10 means 10%. -1 means field not valid.
	MaxNumber  int           // 10 means 10 packets. -1 means field not valid.
}

func (e Expectation) Matches(response *Result, checkSNAT bool) bool {
	if e.Expected {
		if !response.HasConnectivity() {
			return false
		}

		if checkSNAT {
			match := false
			for _, src := range e.ExpSrcIPs {
				if src == response.LastResponse.SourceIP() {
					match = true
					break
				}
			}
			if !match {
				return false
			}
		}

		if e.clientMTUStart != 0 && e.clientMTUStart != response.ClientMTU.Start {
			return false
		}
		if e.clientMTUEnd != 0 && e.clientMTUEnd != response.ClientMTU.End {
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
		} else if response.LastResponse.ErrorStr != "" {
			return false
		}
	} else {
		if response != nil {
			if e.ErrorStr != "" {
				// Return a match if the error string expected is in the response
				if strings.Contains(response.LastResponse.ErrorStr, e.ErrorStr) {
					return true
				}
			} else if response.Stats.ResponsesReceived == 0 {
				// In cases, were we don't expect an error and a response, but still get one,
				// return true, if the ResponsesReceived in the stats is 0. This is for
				// ExpectNone to pass
				return true
			}
			return false
		} else {
			// Return false if we expect an error string and we don't get a response
			if e.ErrorStr != "" {
				return false
			}
		}

	}

	return true
}

var UnactivatedCheckers = set.New()

// MTUPair is a pair of MTU value recorded before and after data were transferred
type MTUPair struct {
	Start int
	End   int
}

type Result struct {
	LastResponse Response
	Stats        Stats
	ClientMTU    MTUPair
}

func (r Result) PrintToStdout() {
	encoded, err := json.Marshal(r)
	if err != nil {
		log.WithError(err).Panic("Failed to marshall result to stdout")
	}
	fmt.Printf("RESULT=%s\n", string(encoded))
}

func (r *Result) HasConnectivity() bool {
	if r == nil {
		return false
	}
	if r.Stats.ResponsesReceived == 0 {
		return false
	}
	return true
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

// CheckOption is the option format for Check()
type CheckOption func(cmd *CheckCmd)

// CheckCmd is exported solely for the sake of CheckOption and should not be use
// on its own
type CheckCmd struct {
	nsPath string

	ip       string
	port     string
	protocol string

	ipSource   string
	portSource string

	duration time.Duration

	sendLen int
	recvLen int
}

// BinaryName is the name of the binary that the connectivity Check() executes
const BinaryName = "test-connection"

// Run executes the check command
func (cmd *CheckCmd) run(cName string, logMsg string) *Result {
	// Ensure that the container has the 'test-connection' binary.
	logCxt := log.WithField("container", cName)
	logCxt.Debugf("Entering connectivity.Check(%v,%v,%v,%v,%v)",
		cmd.ip, cmd.port, cmd.protocol, cmd.sendLen, cmd.recvLen)

	args := []string{"exec", cName,
		"/test-connection", "--protocol=" + cmd.protocol,
		fmt.Sprintf("--duration=%d", int(cmd.duration.Seconds())),
		fmt.Sprintf("--sendlen=%d", cmd.sendLen),
		fmt.Sprintf("--recvlen=%d", cmd.recvLen),
		cmd.nsPath, cmd.ip, cmd.port,
	}

	if cmd.ipSource != "" {
		args = append(args, fmt.Sprintf("--source-ip=%s", cmd.ipSource))
	}

	if cmd.portSource != "" {
		args = append(args, fmt.Sprintf("--source-port=%s", cmd.portSource))
	}

	// Run 'test-connection' to the target.
	connectionCmd := utils.Command("docker", args...)

	outPipe, err := connectionCmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	errPipe, err := connectionCmd.StderrPipe()
	Expect(err).NotTo(HaveOccurred())
	err = connectionCmd.Start()
	Expect(err).NotTo(HaveOccurred())

	var wg sync.WaitGroup
	wg.Add(2)
	var wOut, wErr []byte
	var outErr, errErr error

	go func() {
		defer wg.Done()
		wOut, outErr = ioutil.ReadAll(outPipe)
	}()

	go func() {
		defer wg.Done()
		wErr, errErr = ioutil.ReadAll(errPipe)
	}()

	wg.Wait()
	Expect(outErr).NotTo(HaveOccurred())
	Expect(errErr).NotTo(HaveOccurred())

	err = connectionCmd.Wait()
	logCxt.WithFields(log.Fields{
		"stdout": string(wOut),
		"stderr": string(wErr)}).WithError(err).Info(logMsg)

	var resp Result
	r := regexp.MustCompile(`RESULT=(.*)\n`)
	m := r.FindSubmatch(wOut)
	if len(m) > 0 {
		err := json.Unmarshal(m[1], &resp)
		if err != nil {
			logCxt.WithError(err).WithField("output", string(wOut)).Panic("Failed to parse connection check response")
		}
		return &resp
	}

	return nil
}

// WithSourceIP tell the check what source IP to use
func WithSourceIP(ip string) CheckOption {
	return func(c *CheckCmd) {
		c.ipSource = ip
	}
}

// WithSourcePort tell the check what source port to use
func WithSourcePort(port string) CheckOption {
	return func(c *CheckCmd) {
		c.portSource = port
	}
}

func WithNamespacePath(nsPath string) CheckOption {
	return func(c *CheckCmd) {
		c.nsPath = nsPath
	}
}

func WithDuration(duration time.Duration) CheckOption {
	return func(c *CheckCmd) {
		c.duration = duration
	}
}

func WithSendLen(l int) CheckOption {
	return func(c *CheckCmd) {
		c.sendLen = l
	}
}

func WithRecvLen(l int) CheckOption {
	return func(c *CheckCmd) {
		c.recvLen = l
	}
}

// Check executes the connectivity check
func Check(cName, logMsg, ip, port, protocol string, opts ...CheckOption) *Result {

	cmd := CheckCmd{
		nsPath:   "-",
		ip:       ip,
		port:     port,
		protocol: protocol,
	}

	for _, opt := range opts {
		opt(&cmd)
	}

	return cmd.run(cName, logMsg)
}

const ConnectionTypeStream = "stream"
const ConnectionTypePing = "ping"

type ConnConfig struct {
	ConnType string
	ConnID   string
}

func (cc ConnConfig) getTestMessagePrefix() string {
	return cc.ConnType + ":" + cc.ConnID + "~"
}

// Assembly a test message.
func (cc ConnConfig) GetTestMessage(sequence int) Request {
	req := NewRequest(cc.getTestMessagePrefix() + fmt.Sprintf("%d", sequence))
	return req
}

// Extract sequence number from test message.
func (cc ConnConfig) GetTestMessageSequence(msg string) (int, error) {
	msg = strings.TrimSpace(msg)
	seqString := strings.TrimPrefix(msg, cc.getTestMessagePrefix())
	if seqString == msg {
		// TrimPrefix failed.
		return 0, errors.New("invalid message prefix format:" + msg)
	}

	seq, err := strconv.Atoi(seqString)
	if err != nil || seq < 0 {
		return 0, errors.New("invalid message sequence format:" + msg)
	}
	return seq, nil
}

func IsMessagePartOfStream(msg string) bool {
	return strings.HasPrefix(strings.TrimSpace(msg), ConnectionTypeStream)
}

// Runtime abstracts *containers.Container to avoid import loops
type Runtime interface {
	EnsureBinary(name string)
	ExecMayFail(cmd ...string) error
}

type PersistentConnection struct {
	sync.Mutex

	RuntimeName         string
	Runtime             Runtime
	Name                string
	Protocol            string
	IP                  string
	Port                int
	SourcePort          int
	MonitorConnectivity bool
	NamespacePath       string

	loopFile string
	runCmd   *exec.Cmd

	lastPongTime time.Time
	pongCount    int
}

func (pc *PersistentConnection) Stop() {
	Expect(pc.stop()).NotTo(HaveOccurred())
}

var permConnIdx = 0 // XXX perhaps should be atomic / locked

func (pc *PersistentConnection) stop() error {
	if err := pc.Runtime.ExecMayFail("sh", "-c", fmt.Sprintf("echo > %s", pc.loopFile)); err != nil {
		log.WithError(err).
			WithField("loopfile", pc.loopFile).
			Warn("Failed to create a loop file to stop the permanent connection")
		return err
	}
	if err := pc.runCmd.Wait(); err != nil {
		return err
	}
	return nil
}

func (pc *PersistentConnection) Start() error {
	namespacePath := pc.NamespacePath
	if namespacePath == "" {
		namespacePath = "-"
	}

	// Ensure that the host has the 'test-connection' binary.
	pc.Runtime.EnsureBinary("test-connection")
	permConnIdx++
	n := fmt.Sprintf("%s-pc%d", pc.RuntimeName, permConnIdx)
	loopFile := fmt.Sprintf("/tmp/%s-loop", n)

	err := pc.Runtime.ExecMayFail("sh", "-c", fmt.Sprintf("echo > %s", loopFile))
	if err != nil {
		return err
	}

	args := []string{
		"exec",
		pc.RuntimeName,
		"/test-connection",
		namespacePath,
		pc.IP,
		fmt.Sprintf("%d", pc.Port),
		fmt.Sprintf("--source-port=%d", pc.SourcePort),
		fmt.Sprintf("--protocol=%s", pc.Protocol),
		fmt.Sprintf("--loop-with-file=%s", loopFile),
	}
	if pc.MonitorConnectivity {
		args = append(args, "--log-pongs")
	}
	runCmd := utils.Command(
		"docker",
		args...,
	)
	logName := fmt.Sprintf("permanent connection %s", n)
	stdout, err := runCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to start output logging for %s", logName)
	}
	stdoutReader := bufio.NewReader(stdout)
	go func() {
		for {
			line, err := stdoutReader.ReadString('\n')
			if err != nil {
				log.WithError(err).Info("End of permanent connection stdout")
				return
			}
			line = strings.TrimSpace(string(line))
			log.Infof("%s stdout: %s", logName, line)
			if line == "PONG" {
				pc.Lock()
				pc.lastPongTime = time.Now()
				pc.pongCount++
				pc.Unlock()
			}
		}
	}()
	if err := runCmd.Start(); err != nil {
		return fmt.Errorf("failed to start a permanent connection: %v", err)
	}
	Eventually(func() error {
		return pc.Runtime.ExecMayFail("stat", loopFile)
	}, 5*time.Second, time.Second).Should(
		HaveOccurred(),
		"Failed to wait for test-connection to be ready, the loop file did not disappear",
	)

	pc.loopFile = loopFile
	pc.runCmd = runCmd
	pc.Name = n

	return nil
}

func (pc *PersistentConnection) SinceLastPong() time.Duration {
	return time.Since(pc.LastPongTime())
}

func (pc *PersistentConnection) LastPongTime() time.Time {
	pc.Lock()
	defer pc.Unlock()
	return pc.lastPongTime
}

func (pc *PersistentConnection) PongCount() int {
	pc.Lock()
	defer pc.Unlock()
	return pc.pongCount
}
