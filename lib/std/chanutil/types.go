package chanutil

type Response[T any] struct {
	Value T
	Err   error
}

// Request is a generic request/response channel that allows go routines to respond to requests.
//
// The request channel is used to send requests to the server. The response channel is used to receive responses from
// accepting go routine.
//
// The response channel is closed when a response has been written using either WriteResponse or WriteError.
type Request[RequestType any, ResponseType any] struct {
	Content    *RequestType
	responseCh chan Response[ResponseType]
}

type NoContentRequest[ResponseType any] = Request[any, ResponseType]

func NewNoContentRequest[ResponseType any]() NoContentRequest[ResponseType] {
	return NoContentRequest[ResponseType]{
		responseCh: make(chan Response[ResponseType], 1),
	}
}

func NewRequestResponse[RequestType any, ResponseType any](content *RequestType) Request[RequestType, ResponseType] {
	return Request[RequestType, ResponseType]{
		Content: content,
		// This channel is closed after a single response has been written, so we need exactly a buffer of 1.
		responseCh: make(chan Response[ResponseType], 1),
	}
}

func (rr *Request[RequestType, ResponseType]) WriteResponse(r ResponseType) {
	defer close(rr.responseCh)
	rr.responseCh <- Response[ResponseType]{Value: r}
}

func (rr *Request[RequestType, ResponseType]) WriteError(err error) {
	defer close(rr.responseCh)
	rr.responseCh <- Response[ResponseType]{Err: err}
}

func (rr *Request[RequestType, ResponseType]) ResponseChan() <-chan Response[ResponseType] {
	return rr.responseCh
}
