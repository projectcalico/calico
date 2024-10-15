// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
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
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	. "github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var (
	testCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_counter",
		Help: "Number of logs dropped and errors encountered while logging.",
	})
)

func init() {
	prometheus.MustRegister(testCounter)
	format.TruncatedDiff = false
}

var _ = Describe("Logutils", func() {
	var savedWriter io.Writer
	var buf *bytes.Buffer
	BeforeEach(func() {
		savedWriter = log.StandardLogger().Out
		buf = &bytes.Buffer{}
		log.StandardLogger().Out = buf
	})
	AfterEach(func() {
		log.StandardLogger().Out = savedWriter
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
	It("requires logrus.AllLevels to be consistent/in order", func() {
		// Formatter.init() pre-computes various strings on this assumption.
		for idx, level := range log.AllLevels {
			Expect(int(level)).To(Equal(idx))
		}
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
			Caller: &runtime.Frame{
				File: "biff.com/bar/foo.go",
				Line: 123,
			},
			Data: log.Fields{
				"__flush__": true, // Internal value, should be ignored.
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
			Caller: &runtime.Frame{
				File: "biff.com/bar/foo.go",
				Line: 123,
			},
			Data: log.Fields{
				"a":   10,
				"b":   "foobar",
				"c":   theTime(),
				"err": errors.New("an error"),
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

var (
	message1 = QueuedLog{
		Level:         log.InfoLevel,
		Message:       []byte("Message"),
		SyslogMessage: "syslog message",
	}
	message2 = QueuedLog{
		Level:         log.InfoLevel,
		Message:       []byte("Message2"),
		SyslogMessage: "syslog message2",
	}
)

var _ = Describe("BackgroundHook log flushing tests", func() {
	var counter prometheus.Counter
	var bh *BackgroundHook
	var counterIdx int
	var c chan QueuedLog
	var logger *log.Logger
	var hookOpts []BackgroundHookOpt

	BeforeEach(func() {
		hookOpts = nil
	})

	JustBeforeEach(func() {
		// Set up a background hook that will queue its logs to our channel.
		counter = prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "logutilstests",
			Name:      fmt.Sprint(counterIdx),
		})
		counterIdx++
		c = make(chan QueuedLog, 10)
		testDest := &Destination{
			Level:   log.DebugLevel,
			Channel: c,
		}
		bh = NewBackgroundHook(log.AllLevels, log.DebugLevel, []*Destination{testDest}, counter, hookOpts...)

		logger = log.New()
		logger.SetReportCaller(true)
		logger.AddHook(bh)
		logger.SetLevel(log.DebugLevel)

		// Suppress the output of this logger.
		logger.Out = &NullWriter{}
	})

	It("should let debug logs through by default", func() {
		logger.Debug("Hello")
		var ql QueuedLog
		Eventually(c).Should(Receive(&ql))
		Expect(string(ql.Message)).To(ContainSubstring("level=debug msg=Hello"))
	})

	Describe("with a regex set", func() {
		BeforeEach(func() {
			hookOpts = append(hookOpts, WithDebugFileRegexp(regexp.MustCompile("another_file_for_test")))
		})

		It("should filter debug logs", func() {
			logger.Debug("Hello")
			Consistently(c).ShouldNot(Receive())
			debugFromAnotherFile(logger, "What?")
			var ql QueuedLog
			Eventually(c).Should(Receive(&ql))
			Expect(string(ql.Message)).To(ContainSubstring(`level=debug msg="What?"`))
		})

		It("should not filter info logs", func() {
			logger.Info("Hello")
			var ql QueuedLog
			Eventually(c).Should(Receive(&ql))
			Expect(string(ql.Message)).To(ContainSubstring(`level=info msg=Hello`))
		})
	})

	It("when calling Panic, should block waiting for the background thread", func() {
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			Expect(func() {
				logger.Panic("Should flush")
			}).To(Panic())
		}()

		timeout := time.After(1 * time.Second)

		select {
		case <-timeout:
			Fail("Didn't receive queued log")
		case ql := <-c:
			Expect(ql.WaitGroup).ToNot(BeNil())
			Consistently(done).ShouldNot(BeClosed())
			ql.WaitGroup.Done()
			Eventually(done).Should(BeClosed())
		}
	})

	It("with FieldForceFlush, should block waiting for the background thread", func() {
		done := make(chan struct{})
		go func() {
			defer close(done)
			logger.WithField(FieldForceFlush, true).Info("Should flush")
		}()

		timeout := time.After(1 * time.Second)

		select {
		case <-timeout:
			Fail("Didn't receive queued log")
		case ql := <-c:
			Expect(ql.WaitGroup).ToNot(BeNil())
			Consistently(done).ShouldNot(BeClosed())
			ql.WaitGroup.Done()
			Eventually(done).Should(BeClosed())
		}
	})

	It("without FieldForceFlush, should not block waiting for the background thread", func() {
		done := make(chan struct{})
		go func() {
			defer close(done)
			logger.Info("Should not flush")
		}()

		timeout := time.After(1 * time.Second)

		select {
		case <-timeout:
			Fail("Didn't receive queued log")
		case ql := <-c:
			Expect(ql.WaitGroup).To(BeNil())
			Eventually(done).Should(BeClosed())
		}
	})
})

var _ = Describe("Stream Destination", func() {
	var s *Destination
	var c chan QueuedLog
	var pr *io.PipeReader
	var pw *io.PipeWriter

	BeforeEach(func() {
		c = make(chan QueuedLog, 1)
		pr, pw = io.Pipe()
		s = NewStreamDestination(
			log.InfoLevel,
			pw,
			c,
			false,
			testCounter,
		)
	})

	It("should report dropped logs to background thread", func() {
		// First message should be queued on the channel.
		ok := s.Send(message1)
		Expect(ok).To(BeTrue())
		// Second message should be dropped.  Drop counter should now be 1.
		ok = s.Send(message1)
		Expect(ok).To(BeFalse())
		// Drain the queue.
		Expect(<-c).To(Equal(message1))
		// Third message should go through.
		ok = s.Send(message1)
		Expect(ok).To(BeTrue())
		Expect(<-c).To(Equal(QueuedLog{
			Level:          log.InfoLevel,
			Message:        []byte("Message"),
			SyslogMessage:  "syslog message",
			NumSkippedLogs: 1,
		}))
		// Subsequent messages should have the counter reset.
		ok = s.Send(message1)
		Expect(ok).To(BeTrue())
		Expect(<-c).To(Equal(message1))
	})

	Describe("with dropping disabled", func() {
		BeforeEach(func() {
			c = make(chan QueuedLog, 1)
			pr, pw = io.Pipe()
			s = NewStreamDestination(
				log.InfoLevel,
				pw,
				c,
				true,
				testCounter,
			)
		})

		It("should not drop logs", func() {
			// First message should be queued on the channel.
			ok := s.Send(message1)
			Expect(ok).To(BeTrue())
			done := make(chan bool)
			go func() {
				// Second message should block so we do it in a goroutine.
				ok = s.Send(message2)
				done <- ok
			}()
			// Sleep so that the background goroutine has a chance to try to write.
			time.Sleep(10 * time.Millisecond)
			// Drain the queue.
			Expect(<-c).To(Equal(message1))
			Expect(<-c).To(Equal(message2))
			Expect(<-done).To(BeTrue())
		})
	})

	Describe("With real background thread", func() {
		BeforeEach(func() {
			go s.LoopWritingLogs()
		})
		AfterEach(func() {
			s.Close()
		})

		readNextMsg := func() string {
			b := make([]byte, 1024)
			n, err := pr.Read(b)
			Expect(err).NotTo(HaveOccurred())
			return string(b[:n])
		}

		It("should write a log (no WaitGroup)", func() {
			ok := s.Send(message1)
			Expect(ok).To(BeTrue())
			msg := readNextMsg()
			Expect(msg).To(Equal("Message"))
		})

		It("should log number of dropped logs", func() {
			// Bypass Send() so we can force NumSkippedLogs to be non-zero.
			c <- QueuedLog{
				Level:          log.InfoLevel,
				Message:        []byte("Message"),
				SyslogMessage:  "syslog message",
				NumSkippedLogs: 1,
			}
			msg := readNextMsg()
			Expect(msg).To(Equal("... dropped 1 logs ...\n"))
			msg = readNextMsg()
			Expect(msg).To(Equal("Message"))
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
})

var _ = Describe("Syslog Destination", func() {
	var s *Destination
	var c chan QueuedLog
	var pr *io.PipeReader
	var pw *io.PipeWriter

	BeforeEach(func() {
		c = make(chan QueuedLog, 1)
		pr, pw = io.Pipe()
		s = NewSyslogDestination(
			log.InfoLevel,
			(*mockSyslogWriter)(pw),
			c,
			false,
			testCounter,
		)
	})

	Describe("with dropping disabled", func() {
		BeforeEach(func() {
			s = NewSyslogDestination(
				log.InfoLevel,
				(*mockSyslogWriter)(pw),
				c,
				true,
				testCounter,
			)
		})

		It("should not drop logs", func() {
			// First message should be queued on the channel.
			ok := s.Send(message1)
			Expect(ok).To(BeTrue())
			done := make(chan bool)
			go func() {
				// Second message should block so we do it in a goroutine.
				ok = s.Send(message2)
				done <- ok
			}()
			// Sleep so that the background goroutine has a chance to try to write.
			time.Sleep(10 * time.Millisecond)
			// Drain the queue.
			Expect(<-c).To(Equal(message1))
			Expect(<-c).To(Equal(message2))
			Expect(<-done).To(BeTrue())
		})
	})

	Describe("With real background thread", func() {
		BeforeEach(func() {
			go s.LoopWritingLogs()
		})
		AfterEach(func() {
			s.Close()
		})

		readNextMsg := func() string {
			b := make([]byte, 1024)
			n, err := pr.Read(b)
			Expect(err).NotTo(HaveOccurred())
			return string(b[:n])
		}

		defineLogLevelTest := func(level log.Level, levelName string) {
			It("should write a log (no WaitGroup) level "+levelName, func() {
				ql := message1
				ql.Level = level
				ok := s.Send(ql)
				Expect(ok).To(BeTrue())
				msg := readNextMsg()
				Expect(msg).To(Equal(levelName + " syslog message"))
			})
		}
		defineLogLevelTest(log.InfoLevel, "INFO")
		defineLogLevelTest(log.WarnLevel, "WARNING")
		defineLogLevelTest(log.DebugLevel, "DEBUG")
		defineLogLevelTest(log.ErrorLevel, "ERROR")
		defineLogLevelTest(log.FatalLevel, "CRITICAL")
		defineLogLevelTest(log.PanicLevel, "CRITICAL")

		It("should log number of dropped logs", func() {
			// Bypass Send() so we can force NumSkippedLogs to be non-zero.
			c <- QueuedLog{
				Level:          log.InfoLevel,
				Message:        []byte("Message"),
				SyslogMessage:  "syslog message",
				NumSkippedLogs: 1,
			}
			msg := readNextMsg()
			Expect(msg).To(Equal("WARNING ... dropped 1 logs ...\n"))
			msg = readNextMsg()
			Expect(msg).To(Equal("INFO syslog message"))
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

// Benchmark "result" variables, reading/writing global variable prevents the loop from being optimised away.
var BenchOut bool
var BenchIn bool

func BenchmarkRegexpEmpty(b *testing.B) {
	re := regexp.MustCompile("")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BenchOut = BenchOut != re.MatchString("endpoint_mgr.go")
	}
}

func BenchmarkRegexpNilcheck(b *testing.B) {
	re := regexp.MustCompile("")
	if b.N > 0 || BenchIn {
		re = nil
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if re != nil {
			BenchOut = BenchOut != re.MatchString("endpoint_mgr.go")
		}
	}
}

func BenchmarkRegexpStar(b *testing.B) {
	re := regexp.MustCompile(".*")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BenchOut = BenchOut != re.MatchString("endpoint_mgr.go")
	}
}

// FuzzAppendTime fuzzes AppendTime against the stdlib time.Time.AppendFormat
// to make sure they agree.
func FuzzAppendTime(f *testing.F) {
	pool := sync.Pool{
		New: func() any {
			return &bytes.Buffer{}
		},
	}

	tFormat := "2006-01-02 15:04:05.000"
	var zeroTime time.Time
	f.Add(int(zeroTime.Unix()), int(zeroTime.Nanosecond()))
	f.Add(0, 0)
	// time.Now() at time of writing with various nanos.
	f.Add(1257894000, 0)
	f.Add(1257894000, 1)
	f.Add(1257894000, 100)
	f.Add(1257894000, 1000)
	f.Add(1257894000, 10000)
	f.Add(1257894000, 100000)
	f.Add(1257894000, 112345)
	f.Fuzz(func(t *testing.T, secs, nanos int) {
		timeVal := time.Unix(int64(secs), int64(nanos))
		buf1 := pool.Get().(*bytes.Buffer)
		buf2 := pool.Get().(*bytes.Buffer)
		{
			buf1.Write(timeVal.AppendFormat(buf1.AvailableBuffer(), tFormat))
			AppendTime(buf2, timeVal)
			if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
				t.Fatalf("Expected %s, got %s", buf1.String(), buf2.String())
			}
			buf1.Reset()
			buf2.Reset()
		}
		{
			utc := timeVal.UTC()
			buf1.Write(utc.AppendFormat(buf1.AvailableBuffer(), tFormat))
			AppendTime(buf2, utc)
			if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
				t.Fatalf("UTC: Expected %s, got %s", buf1.String(), buf2.String())
			}
			buf1.Reset()
			buf2.Reset()
		}
		pool.Put(buf1)
		pool.Put(buf2)
	})
}
