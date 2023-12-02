// Copyright (c) 2022 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package multireadbuf

import (
	"fmt"
	"io"
	"sync"
)

const defaultFlushThreshold = 8192

var ErrClosed = fmt.Errorf("MultiReaderBuffer already closed for writes")

// MultiReaderSingleWriterBuffer manages a byte buffer that can be appended to by
// one goroutine (via Write()) while many readers read from the same buffer via
// Reader(). Readers block in Read() until data is available.  The writer must
// call Close() to flush the final block of data to the readers.
//
// The buffer is never discarded; even after the writer calls Close, new readers
// can still begin reading the buffer.
type MultiReaderSingleWriterBuffer struct {
	// Writer's public fields, can be set before calling Write();
	FlushThresholdBytes int

	// Writer's private fields, not protected by lock.  We write pending changes here
	// and then copy them to the readerXXX fields while holding the lock.  Since we only
	// ever append to writerBuf, when we copy it to the read size we only need to copy
	// the slice, not the contents.
	writerBuf             []byte
	writerComplete        bool
	bytesCopiedToReadSide int

	// lock protects the readerXXX fields.  Note: tried a RWMutex but it was slower
	// even for many clients.
	lock sync.Mutex
	cond *sync.Cond

	// Fields shared by writer and readers. Protected by lock.
	readerBuf      []byte
	readerComplete bool
}

func New(initialBufSize int) *MultiReaderSingleWriterBuffer {
	mrb := &MultiReaderSingleWriterBuffer{
		FlushThresholdBytes: defaultFlushThreshold,
		writerBuf:           make([]byte, 0, initialBufSize),
	}
	mrb.cond = sync.NewCond(&mrb.lock)
	return mrb
}

func (m *MultiReaderSingleWriterBuffer) Write(p []byte) (n int, err error) {
	if m.writerComplete {
		return 0, ErrClosed
	}
	m.writerBuf = append(m.writerBuf, p...)
	if len(m.writerBuf) > m.bytesCopiedToReadSide+m.FlushThresholdBytes {
		m.publishChanges()
	}
	return len(p), nil
}

func (m *MultiReaderSingleWriterBuffer) Close() error {
	m.writerComplete = true
	m.publishChanges()
	return nil
}

func (m *MultiReaderSingleWriterBuffer) Len() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return len(m.readerBuf)
}

func (m *MultiReaderSingleWriterBuffer) Reader() *Reader {
	return &Reader{mrb: m}
}

func (m *MultiReaderSingleWriterBuffer) publishChanges() {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.readerBuf = m.writerBuf
	m.readerComplete = m.writerComplete
	m.bytesCopiedToReadSide = len(m.writerBuf)
	m.cond.Broadcast()
}

func (m *MultiReaderSingleWriterBuffer) waitForData(offset int) ([]byte, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	for !m.readerComplete && len(m.readerBuf) <= offset {
		m.cond.Wait()
	}
	return m.readerBuf[offset:], m.readerComplete
}

type Reader struct {
	mrb    *MultiReaderSingleWriterBuffer
	offset int
}

func (r *Reader) WriteTo(w io.Writer) (n int64, err error) {
	for {
		buf, complete := r.mrb.waitForData(r.offset)
		n2, err := w.Write(buf)
		r.offset += n2
		n += int64(n2)
		if err != nil || complete {
			return n, err
		}
	}
}

func (r *Reader) Read(p []byte) (n int, err error) {
	buf, complete := r.mrb.waitForData(r.offset)
	n = copy(p, buf)
	r.offset += n
	if n == 0 && complete {
		err = io.EOF
	}
	return
}

var _ io.Writer = (*MultiReaderSingleWriterBuffer)(nil)
var _ io.Reader = (*Reader)(nil)
var _ io.WriterTo = (*Reader)(nil)
