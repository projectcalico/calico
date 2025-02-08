package types

import "fmt"

type ErrNoStore struct{}

func (e ErrNoStore) Error() string {
	return "store unavailable"
}

type ErrUnprocessable struct {
	Reason string
}

func (e ErrUnprocessable) Error() string {
	return fmt.Sprintf("unprocessable entity: %s", e.Reason)
}
