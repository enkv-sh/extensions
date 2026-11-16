package output

import (
	"io"
	"sync"
)

// CopyRequestBody copies borrowed bytes into an independent request body.
// Until handoff, the caller owns Close. After handoff, the transport owns Close,
// including asynchronous body use. Closing the body clears the private copy;
// it does not clear borrowed. A nil or empty input makes an empty body.
func CopyRequestBody(borrowed []byte) io.ReadCloser {
	owned := make([]byte, len(borrowed))
	copy(owned, borrowed)
	return TakeRequestBody(owned)
}

// TakeRequestBody transfers an exclusively owned complete allocation to a
// request body without copying it. The slice must start at the allocation's
// beginning and expose its full capacity. The caller must stop using its aliases.
// Close waits for an active Read, clears the full capacity and is idempotent.
// Until handoff, the caller owns Close. After handoff, the transport owns Close,
// including asynchronous body use. A nil or empty input makes an empty body.
// Read and Close are serialized; reads after Close return io.EOF.
func TakeRequestBody(owned []byte) io.ReadCloser {
	return &requestBody{wire: owned}
}

type requestBody struct {
	mu     sync.Mutex
	wire   []byte
	offset int
	closed bool
}

// Read serializes access with Close, so clearing cannot race an active read.
func (b *requestBody) Read(dst []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.offset == len(b.wire) {
		return 0, io.EOF
	}
	n := copy(dst, b.wire[b.offset:])
	b.offset += n
	return n, nil
}

// Close waits for any active read and clears the complete transferred capacity.
func (b *requestBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		clear(b.wire[:cap(b.wire)])
		b.wire = nil
		b.offset = 0
		b.closed = true
	}
	return nil
}
