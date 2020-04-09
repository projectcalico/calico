package mock

import (
	"time"

	timeshim "github.com/projectcalico/felix/time"
)

func NewMockTime() *MockTime {
	startTime, _ := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
	return &MockTime{
		currentTime: startTime,
	}
}

var _ timeshim.Time = NewMockTime()

type MockTime struct {
	currentTime   time.Time
	autoIncrement time.Duration
}

func (m *MockTime) Now() time.Time {
	t := m.currentTime
	m.IncrementTime(m.autoIncrement)
	return t
}

func (m *MockTime) Since(t time.Time) time.Duration {
	return m.Now().Sub(t)
}

func (m *MockTime) SetAutoIncrement(t time.Duration) {
	m.autoIncrement = t
}

func (m *MockTime) IncrementTime(t time.Duration) {
	m.currentTime = m.currentTime.Add(t)
}
