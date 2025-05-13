package conn_test

import (
	"net"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/conn"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func TestForwardConnections(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	logutils.RedirectLogrusToTestingT(t)
	logutils.ConfigureFormatter("test")
	RegisterTestingT(t)
	t.Run("Forward sends connection data back and forth between the connections", func(t *testing.T) {
		var dst1, dst2 net.Conn
		var err error

		t.Log("Creating two localhost listeners")
		lst1, err := net.Listen("tcp", "localhost:0")
		Expect(err).ShouldNot(HaveOccurred())
		defer lst1.Close()

		lst2, err := net.Listen("tcp", "localhost:0")
		Expect(err).ShouldNot(HaveOccurred())
		defer lst2.Close()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			dst1, err = lst1.Accept()
			Expect(err).ShouldNot(HaveOccurred())
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			dst2, err = lst2.Accept()
			Expect(err).ShouldNot(HaveOccurred())
		}()

		t.Log("Connecting to the localhost listeners")
		src1, err := net.Dial("tcp", lst1.Addr().String())
		Expect(err).ShouldNot(HaveOccurred())

		src2, err := net.Dial("tcp", lst2.Addr().String())
		Expect(err).ShouldNot(HaveOccurred())

		wg.Wait()

		wg.Add(1)
		go func() {
			defer wg.Done()
			conn.Forward(dst1, src2)
		}()

		request := "request"
		response := "response"

		t.Log("Listening for data on dst2")
		go func() {
			buff := make([]byte, len(request))
			_, err := dst2.Read(buff)

			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(buff)).Should(Equal(request))

			_, err = dst2.Write([]byte(response))
			Expect(err).ShouldNot(HaveOccurred())
		}()

		t.Log("Writing data on src1")
		_, err = src1.Write([]byte(request))
		Expect(err).ShouldNot(HaveOccurred())

		buff := make([]byte, len(response))

		_, err = src1.Read(buff)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(buff)).Should(Equal(response))
		Expect(src1.Close()).ShouldNot(HaveOccurred())
		wg.Wait()
	})
}
