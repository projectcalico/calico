package handler

import (
	"encoding/json"
	"fmt"
	_ctx "github.com/projectcalico/calico/lib/httpapimachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/header"
	"github.com/sirupsen/logrus"
	"net/http"

	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/encoding"
)

// EventStream represents a http stream. Users can write objects to the response one at a time and the objects
// will be flushed based on the configuration of the stream in the format configured in the stream.
type EventStream[E any] interface {
	Data(E) error
	Error(msg string) error
}

type Event struct {
	Type string `json:"type,omitempty"`
	Data any    `json:"data"`
}

// jsonStreamWriter implements a ResponseStream. The format written to the http stream is json.
type jsonEventStreamWriter[E any] struct {
	*flusherWriter
}

func (w *jsonEventStreamWriter[E]) Error(msg string) error {
	_, err := fmt.Fprintf(w, "error: %s\n\n", msg)
	if err != nil {
		return fmt.Errorf("failed to send event: %w", err)
	}

	w.Flush()
	return nil
}

// Data encodes the given object as json and flushes it down the http stream.
func (w *jsonEventStreamWriter[E]) Data(e E) error {
	data, err := json.Marshal(e)

	_, err = fmt.Fprintf(w, "data: %s\n\n", data)
	if err != nil {
		return fmt.Errorf("failed to send event: %w", err)
	}

	w.Flush()
	return nil
}

type flusherWriter struct {
	http.ResponseWriter
	asFlusher http.Flusher
}

func newFlusherWriter(w http.ResponseWriter) *flusherWriter {
	return &flusherWriter{
		ResponseWriter: w,
		asFlusher:      w.(http.Flusher),
	}
}

func (f *flusherWriter) Flush() {
	f.asFlusher.Flush()
}

func newJSONStreamWriter[E any](w http.ResponseWriter) EventStream[E] {
	return &jsonEventStreamWriter[E]{flusherWriter: newFlusherWriter(w)}
}

type jsonStreamHandler[RequestParams any, Response any] struct {
	f func(_ctx.Context, RequestParams, EventStream[Response])
}

func NewJSONEventStreamHandler[RequestParams any, Response any](f func(_ctx.Context, RequestParams, EventStream[Response])) jsonStreamHandler[RequestParams, Response] {
	return jsonStreamHandler[RequestParams, Response]{f: f}
}

func (hdlr jsonStreamHandler[RequestParams, Response]) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	params := parseRequestParams[RequestParams](w, req)
	if params == nil {
		return
	}

	w.Header().Set(header.ContentType, header.TextEventStream)
	w.Header().Set(header.CacheControl, header.NoCache)
	w.Header().Set(header.Connection, header.KeepAlive)
	w.Header().Set(header.AccessControlAllowOrigin, "*")

	ctx := _ctx.NewRequestContext(req)

	jStream := newJSONStreamWriter[Response](w)
	hdlr.f(ctx, *params, jStream)
}

func parseRequestParams[RequestParams any](w http.ResponseWriter, req *http.Request) *RequestParams {
	params, err := encoding.DecodeAndValidateReqParams[RequestParams](req)
	if err != nil {
		logrus.WithError(err).Debug("Failed to decode request params.")
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return nil
	}

	return params
}
