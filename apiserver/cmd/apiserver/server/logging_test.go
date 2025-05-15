package server

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/lib/std/log"
	"k8s.io/component-base/logs"
)

func TestLogLevel(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Logging Suite")
}

var _ = Describe("", func() {
	It("test logrus log level calculated with different verbosity values", func() {
		_, err := logs.GlogSetter("0")
		Expect(logrusLevel()).To(Equal(log.ErrorLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("1")
		Expect(logrusLevel()).To(Equal(log.WarnLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("2")
		Expect(logrusLevel()).To(Equal(log.InfoLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("3")
		Expect(logrusLevel()).To(Equal(log.DebugLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("4")
		Expect(logrusLevel()).To(Equal(log.DebugLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("5")
		Expect(logrusLevel()).To(Equal(log.DebugLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("6")
		Expect(logrusLevel()).To(Equal(log.DebugLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("7")
		Expect(logrusLevel()).To(Equal(log.TraceLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("8")
		Expect(logrusLevel()).To(Equal(log.TraceLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("9")
		Expect(logrusLevel()).To(Equal(log.TraceLevel))
		Expect(err).To(BeNil())
	})

	It("test verbosity values calculated from various logrus log level", func() {
		log.SetLevel(log.TraceLevel)
		Expect(logLevelToVerbosityLevel()).To(Equal("20"))

		log.SetLevel(log.DebugLevel)
		Expect(logLevelToVerbosityLevel()).To(Equal("6"))

		log.SetLevel(log.InfoLevel)
		Expect(logLevelToVerbosityLevel()).To(Equal("2"))

		log.SetLevel(log.WarnLevel)
		Expect(logLevelToVerbosityLevel()).To(Equal("1"))

		log.SetLevel(log.ErrorLevel)
		Expect(logLevelToVerbosityLevel()).To(Equal("0"))

		log.SetLevel(log.FatalLevel)
		Expect(logLevelToVerbosityLevel()).To(Equal("0"))
	})
})
