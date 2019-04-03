package health

import (
	"context"
	"testing"

	"github.com/projectcalico/app-policy/proto"
)

type reporter struct {
	Ready bool
}

func (r *reporter) Readiness() bool {
	return r.Ready
}

func TestHealthService(t *testing.T) {
	// Test happy path case where ReadinessReporter reports true.
	reporter := &reporter{
		Ready: true,
	}
	s := NewHealthCheckService(reporter)

	req := &proto.HealthCheckRequest{}
	resp, err := s.CheckReadiness(context.Background(), req)
	if err != nil {
		t.Errorf("expected no error checking readiness, got: %s", err)
	}
	if !resp.Healthy {
		t.Error("expected readiness response to be true")
	}

	resp, err = s.CheckLiveness(context.Background(), req)
	if err != nil {
		t.Errorf("expected no error checking liveness, got: %s", err)
	}
	if !resp.Healthy {
		t.Error("expected liveness response to be true")
	}

	// Now with ReadinessReporter returning false.
	reporter.Ready = false
	resp, err = s.CheckReadiness(context.Background(), req)
	if err != nil {
		t.Errorf("expected no error checking readiness, got: %s", err)
	}
	if resp.Healthy {
		t.Error("expected readiness response to be false")
	}

	resp, err = s.CheckLiveness(context.Background(), req)
	if err != nil {
		t.Errorf("expected no error checking liveness, got: %s", err)
	}
	if !resp.Healthy {
		t.Error("expected liveness response to be true")
	}
}
