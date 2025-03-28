package server

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"k8s.io/component-base/logs"
)

func TestLogLevel(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Logging Suite")
}

var _ = Describe("", func() {
	It("test logrus log level calculated with different verbosity values", func() {
		_, err := logs.GlogSetter("0")
		Expect(logrusLevel()).To(Equal(logrus.ErrorLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("1")
		Expect(logrusLevel()).To(Equal(logrus.WarnLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("2")
		Expect(logrusLevel()).To(Equal(logrus.InfoLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("3")
		Expect(logrusLevel()).To(Equal(logrus.DebugLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("4")
		Expect(logrusLevel()).To(Equal(logrus.DebugLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("5")
		Expect(logrusLevel()).To(Equal(logrus.DebugLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("6")
		Expect(logrusLevel()).To(Equal(logrus.DebugLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("7")
		Expect(logrusLevel()).To(Equal(logrus.TraceLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("8")
		Expect(logrusLevel()).To(Equal(logrus.TraceLevel))
		Expect(err).To(BeNil())

		_, err = logs.GlogSetter("9")
		Expect(logrusLevel()).To(Equal(logrus.TraceLevel))
		Expect(err).To(BeNil())
	})

	It("test verbosity values calculated from various logrus log level", func() {
		logrus.SetLevel(logrus.TraceLevel)
		Expect(logLevelToVerbosityLevel()).To(Equal("20"))

		logrus.SetLevel(logrus.DebugLevel)
		Expect(logLevelToVerbosityLevel()).To(Equal("6"))

		logrus.SetLevel(logrus.InfoLevel)
		Expect(logLevelToVerbosityLevel()).To(Equal("2"))

		logrus.SetLevel(logrus.WarnLevel)
		Expect(logLevelToVerbosityLevel()).To(Equal("1"))

		logrus.SetLevel(logrus.ErrorLevel)
		Expect(logLevelToVerbosityLevel()).To(Equal("0"))

		logrus.SetLevel(logrus.FatalLevel)
		Expect(logLevelToVerbosityLevel()).To(Equal("0"))
	})
})
