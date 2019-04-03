package health

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/projectcalico/app-policy/proto"
)

type reporter struct {
	Ready bool
}

func (r *reporter) Readiness() bool {
	return r.Ready
}

func TestHealthService(t *testing.T) {
	g := NewWithT(t)
	// Test happy path case where ReadinessReporter reports true.
	reporter := &reporter{
		Ready: true,
	}
	s := NewHealthCheckService(reporter)

	req := &proto.HealthCheckRequest{}
	resp, err := s.CheckReadiness(context.Background(), req)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.Healthy).To(BeTrue())

	resp, err = s.CheckLiveness(context.Background(), req)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.Healthy).To(BeTrue())

	// Now with ReadinessReporter returning false.
	reporter.Ready = false
	resp, err = s.CheckReadiness(context.Background(), req)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.Healthy).To(BeFalse())

	resp, err = s.CheckLiveness(context.Background(), req)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(resp.Healthy).To(BeTrue())
}
