package fv_test

import (
	"os"
	"testing"

	. "github.com/onsi/gomega"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func setup(t *testing.T) {
	logutils.ConfigureFormatter("guardian")
	logutils.RedirectLogrusToTestingT(t)
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)

	RegisterTestingT(t)
}
