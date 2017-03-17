// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package logutils_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/felix/logutils"
)

var _ = Describe("Logutils", func() {
	ourHook := ContextHook{}
	var savedWriter io.Writer
	var buf *bytes.Buffer
	BeforeEach(func() {
		log.AddHook(ourHook)
		savedWriter = log.StandardLogger().Out
		buf = &bytes.Buffer{}
		log.StandardLogger().Out = buf
	})
	AfterEach(func() {
		log.StandardLogger().Out = savedWriter
		levelHooks := log.StandardLogger().Hooks
		for level, hooks := range levelHooks {
			j := 0
			for _, hook := range hooks {
				if hook == ourHook {
					continue
				}
				hooks[j] = hook
				j += 1
			}
			levelHooks[level] = hooks[:len(hooks)-1]
		}
	})

	It("Should add correct file when invoked via log.Info", func() {
		log.Info("Test log")
		Expect(buf.String()).To(ContainSubstring("logutils_test.go"))
	})
	It("Should add correct file when invoked via Logger.Info", func() {
		log.StandardLogger().Info("Test log")
		Expect(buf.String()).To(ContainSubstring("logutils_test.go"))
	})
	It("Should add correct file when invoked via log.WithField(...).Info", func() {
		log.WithField("foo", "bar").Info("Test log")
		Expect(buf.String()).To(ContainSubstring("logutils_test.go"))
	})
})

var _ = DescribeTable("Formatter",
	func(entry log.Entry, expectedLog, expectedSyslog string) {
		f := &Formatter{}
		out, err := f.Format(&entry)
		Expect(err).NotTo(HaveOccurred())
		expectedLog = strings.Replace(expectedLog, "<PID>", fmt.Sprintf("%v", os.Getpid()), 1)
		Expect(string(out)).To(Equal(expectedLog))
		Expect(FormatForSyslog(&entry)).To(Equal(expectedSyslog))
	},
	Entry("Empty", log.Entry{},
		"0001-01-01 00:00:00.000 [PANIC][<PID>] <nil> <nil>: \n",
		"PANIC <nil> <nil>: \n"),
	Entry("Basic",
		log.Entry{
			Level: log.InfoLevel,
			Time:  theTime(),
			Data: log.Fields{
				"__file__": "foo.go",
				"__line__": 123,
			},
			Message: "The answer is 42.",
		},
		"2017-03-15 11:22:33.123 [INFO][<PID>] foo.go 123: The answer is 42.\n",
		"INFO foo.go 123: The answer is 42.\n",
	),
	Entry("With fields",
		log.Entry{
			Level: log.WarnLevel,
			Time:  theTime(),
			Data: log.Fields{
				"__file__": "foo.go",
				"__line__": 123,
				"a":        10,
				"b":        "foobar",
				"c":        theTime(),
				"err":      errors.New("an error"),
			},
			Message: "The answer is 42.",
		},
		"2017-03-15 11:22:33.123 [WARNING][<PID>] foo.go 123: The answer is 42. a=10 b=\"foobar\" c=2017-03-15 11:22:33.123 +0000 UTC err=an error\n",
		"WARNING foo.go 123: The answer is 42. a=10 b=\"foobar\" c=2017-03-15 11:22:33.123 +0000 UTC err=an error\n"),
)

func theTime() time.Time {
	theTime, err := time.Parse("2006-01-02 15:04:05.000", "2017-03-15 11:22:33.123")
	if err != nil {
		panic(err)
	}
	return theTime
}

var _ = Describe("StreamDestination", func() {
	var s *StreamDestination
	var pr *io.PipeReader
	var pw *io.PipeWriter
	var c chan<- QueuedLog

	BeforeEach(func() {
		pr, pw = io.Pipe()
		s = NewStreamDestination(log.InfoLevel, pw)
		go s.LoopWritingLogs()
		c = s.Channel()
	})
	AfterEach(func() {
		close(c)
	})

	It("should write a log (no WaitGroup)", func() {
		c <- QueuedLog{
			Level:         log.InfoLevel,
			Message:       []byte("Message"),
			SyslogMessage: "syslog message",
		}
		b := make([]byte, 1024)
		n, err := pr.Read(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b[:n])).To(Equal("Message"))
	})

	It("should log number of dropped logs", func() {
		// Increment the dropped logs counter.
		s.OnLogDropped()
		// Next log should emit a drop warning.
		c <- QueuedLog{
			Level:         log.InfoLevel,
			Message:       []byte("Message"),
			SyslogMessage: "syslog message",
		}
		// But log after that shouldn't.
		c <- QueuedLog{
			Level:         log.InfoLevel,
			Message:       []byte("Message 2"),
			SyslogMessage: "syslog message",
		}
		b := make([]byte, 1024)
		n, err := pr.Read(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b[:n])).To(Equal("... dropped 1 logs ...\n"))
		n, err = pr.Read(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b[:n])).To(Equal("Message"))
		n, err = pr.Read(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b[:n])).To(Equal("Message 2"))
	})

	It("should trigger WaitGroup", func() {
		wg := &sync.WaitGroup{}
		wg.Add(1)
		c <- QueuedLog{
			Level:         log.InfoLevel,
			Message:       []byte("Message"),
			SyslogMessage: "syslog message",
			WaitGroup:     wg,
		}
		b := make([]byte, 1024)
		n, err := pr.Read(b)
		wg.Wait()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b[:n])).To(Equal("Message"))
	})
})

var _ = Describe("SyslogDestination", func() {
	var s *SyslogDestination
	var pr *io.PipeReader
	var pw *io.PipeWriter
	var c chan<- QueuedLog

	BeforeEach(func() {
		pr, pw = io.Pipe()
		s = NewSyslogDestination(log.InfoLevel, (*mockSyslogWriter)(pw))
		go s.LoopWritingLogs()
		c = s.Channel()
	})
	AfterEach(func() {
		close(c)
	})

	It("should write a log (no WaitGroup)", func() {
		c <- QueuedLog{
			Level:         log.InfoLevel,
			Message:       []byte("Message"),
			SyslogMessage: "syslog message",
		}
		b := make([]byte, 1024)
		n, err := pr.Read(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b[:n])).To(Equal("INFO syslog message"))
	})

	It("should log number of dropped logs", func() {
		s.OnLogDropped()
		// Log after that should emit a drop warning.
		c <- QueuedLog{
			Level:         log.InfoLevel,
			Message:       []byte("Message"),
			SyslogMessage: "syslog message",
		}
		// But log after that shouldn't.
		c <- QueuedLog{
			Level:         log.InfoLevel,
			Message:       []byte("Message"),
			SyslogMessage: "syslog message 2",
		}
		b := make([]byte, 1024)
		n, err := pr.Read(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b[:n])).To(Equal("WARNING ... dropped 1 logs ...\n"))
		n, err = pr.Read(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b[:n])).To(Equal("INFO syslog message"))
		n, err = pr.Read(b)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b[:n])).To(Equal("INFO syslog message 2"))
	})

	It("should trigger WaitGroup", func() {
		wg := &sync.WaitGroup{}
		wg.Add(1)
		c <- QueuedLog{
			Level:         log.InfoLevel,
			Message:       []byte("Message"),
			SyslogMessage: "syslog message",
			WaitGroup:     wg,
		}
		b := make([]byte, 1024)
		n, err := pr.Read(b)
		wg.Wait()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(b[:n])).To(Equal("INFO syslog message"))
	})
})

type mockSyslogWriter io.PipeWriter

func (s *mockSyslogWriter) Debug(m string) error {
	_, err := fmt.Fprintf((*io.PipeWriter)(s), "DEBUG %s", m)
	return err
}
func (s *mockSyslogWriter) Info(m string) error {
	_, err := fmt.Fprintf((*io.PipeWriter)(s), "INFO %s", m)
	return err
}
func (s *mockSyslogWriter) Warning(m string) error {
	_, err := fmt.Fprintf((*io.PipeWriter)(s), "WARNING %s", m)
	return err
}
func (s *mockSyslogWriter) Err(m string) error {
	_, err := fmt.Fprintf((*io.PipeWriter)(s), "ERROR %s", m)
	return err
}
func (s *mockSyslogWriter) Crit(m string) error {
	_, err := fmt.Fprintf((*io.PipeWriter)(s), "CRITICAL %s", m)
	return err
}
