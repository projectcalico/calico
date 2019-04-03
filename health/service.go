package health

import (
	"context"

	"github.com/projectcalico/app-policy/proto"

	log "github.com/sirupsen/logrus"
)

// An implementation of the HealthzServer health check service.
type healthCheckService struct {
	reporter ReadinessReporter
}

// ReadinessReporter is a type that knows how to report its readiness.
type ReadinessReporter interface {
	Readiness() bool
}

func NewHealthCheckService(h ReadinessReporter) *healthCheckService {
	return &healthCheckService{reporter: h}
}

func (h healthCheckService) CheckReadiness(_ context.Context, request *proto.HealthCheckRequest) (*proto.HealthCheckResponse, error) {
	r := h.reporter.Readiness()
	log.Debugf("health service: returning readiness %t", r)
	return &proto.HealthCheckResponse{Healthy: r}, nil
}

func (h healthCheckService) CheckLiveness(_ context.Context, request *proto.HealthCheckRequest) (*proto.HealthCheckResponse, error) {
	log.Debugf("health service: checking liveness")
	return &proto.HealthCheckResponse{Healthy: true}, nil
}
