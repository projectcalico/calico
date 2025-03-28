package fv

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/cryptoutils"
	jsontestutil "github.com/projectcalico/calico/lib/std/testutils/json"
)

type ObjWithErr[T any] struct {
	Obj T
	Err error
}

func createKeyCertPair(dir string) (*os.File, *os.File) {
	certPEM, keyPEM, err := cryptoutils.GenerateSelfSignedCert(
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageAny))
	Expect(err).ShouldNot(HaveOccurred())

	certFile, err := os.CreateTemp(dir, "cert.pem")
	Expect(err).ShouldNot(HaveOccurred())
	defer certFile.Close()

	keyFile, err := os.CreateTemp(dir, "key.pem")
	Expect(err).ShouldNot(HaveOccurred())
	defer keyFile.Close()

	_, err = certFile.Write(certPEM)
	Expect(err).ShouldNot(HaveOccurred())
	_, err = keyFile.Write(keyPEM)
	Expect(err).ShouldNot(HaveOccurred())

	return certFile, keyFile
}

// newSSEScanner creates a new scanner for reading "Server Side Events".
func newSSEScanner[E any](t *testing.T, r io.Reader) <-chan ObjWithErr[*E] {
	scanner := bufio.NewScanner(r)
	responseChan := make(chan ObjWithErr[*E])
	go func() {
		defer close(responseChan)
		for scanner.Scan() {
			line := scanner.Text()

			if strings.HasPrefix(line, "data:") {
				data := strings.TrimPrefix(line, "data:")
				fmt.Println("Event Data: ", strings.TrimSpace(data))

				responseChan <- ObjWithErr[*E]{Obj: jsontestutil.MustUnmarshal[E](t, []byte(data))}
			} else if line == "" {
				continue
			} else {
				responseChan <- ObjWithErr[*E]{Err: fmt.Errorf("unexpected line: %s", line)}
			}
		}
	}()

	return responseChan
}

// waitForClockIntervalAlignment waits until the clock is at some multiple of the given interval after the minute. This
// helps ensure flows are pushed into the latest bucket for testing the goldmane integration.
func waitForClockIntervalAlignment(interval time.Duration) {
	startTime := time.Now().Unix()
	secondsDiff := startTime % int64(interval.Seconds())
	logrus.Info("Waiting for clock to align with interval...")
	<-time.After(time.Duration(secondsDiff) * time.Second)
	logrus.Info("Clock is aligned.")
}
