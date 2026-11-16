package output

import (
	"bytes"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestRequestBodyCopyIsolatedAndCapacity(t *testing.T) {
	for _, size := range []int{0, 1, 65536} {
		source := bytes.Repeat([]byte{73}, size)
		body := CopyRequestBody(source)
		owner := body.(*requestBody)
		retained := owner.wire
		if cap(retained) != size || size > 0 && &retained[0] == &source[0] {
			t.Fatal("copy did not own exact independent backing")
		}
		clear(source)
		got, err := io.ReadAll(body)
		if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{73}, size)) {
			t.Fatal("borrowed storage changed owned bytes", err)
		}
		if err := body.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(retained, make([]byte, size)) || owner.wire != nil {
			t.Fatal("copied body retained storage")
		}
	}
}

// full_only: false
func TestRequestBodyTransferRetainsAllocationAndClearsCapacity(t *testing.T) {
	for _, size := range []int{0, 1, 65536, 96 << 10, 2 << 20} {
		allocation := bytes.Repeat([]byte{91}, size+17)
		body := TakeRequestBody(allocation[:size])
		owner := body.(*requestBody)
		if cap(owner.wire) != len(allocation) || &owner.wire[:cap(owner.wire)][0] != &allocation[0] {
			t.Fatal("transfer replaced owned allocation")
		}
		got, err := io.ReadAll(body)
		if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{91}, size)) {
			t.Fatal("transferred body bytes changed", err)
		}
		for range 2 {
			if err := body.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if owner.wire != nil || !bytes.Equal(allocation, make([]byte, len(allocation))) {
			t.Fatal("Close did not clear full allocation")
		}
		if n, err := body.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Fatal("Read after Close did not stop")
		}
	}
}

// full_only: false
func TestRequestBodyReadCloseOrdering(t *testing.T) {
	for _, method := range []string{"Read", "Close"} {
		t.Run(method, func(t *testing.T) {
			allocation := bytes.Repeat([]byte{77}, 31)
			owner := TakeRequestBody(allocation[:17]).(*requestBody)
			destination := bytes.Repeat([]byte{99}, 17)
			type result struct {
				n   int
				err error
			}
			done := make(chan result, 1)
			owner.mu.Lock()
			locked, joined := true, false
			defer func() {
				if locked {
					owner.mu.Unlock()
				}
				if !joined {
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Error("body method did not join during cleanup")
					}
				}
			}()
			go func() {
				if method == "Read" {
					n, err := owner.Read(destination)
					done <- result{n, err}
				} else {
					done <- result{err: owner.Close()}
				}
			}()

			// The pinned runtime reports a parked mutex acquisition with this state.
			// A start signal alone cannot establish that the method reached its lock.
			stack := make([]byte, 64<<10)
			waiting := func() bool {
				n := runtime.Stack(stack, true)
				if n == len(stack) {
					t.Fatal("mutex waiter snapshot incomplete")
				}
				for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
					header, _, _ := strings.Cut(goroutine, "\n")
					if strings.Contains(header, "[sync.Mutex.Lock") &&
						strings.Contains(goroutine, "enkv.sh/sdk/output.(*requestBody)."+method+"(") &&
						strings.Contains(goroutine, "enkv.sh/sdk/output.TestRequestBodyReadCloseOrdering.") {
						return true
					}
				}
				return false
			}
			deadline := time.NewTimer(time.Second)
			defer deadline.Stop()
			for !waiting() {
				select {
				case <-done:
					joined = true
					t.Fatal("body method completed before a blocked mutex acquisition was observed")
				case <-deadline.C:
					t.Fatal("body method did not reach a blocked mutex acquisition")
				default:
					runtime.Gosched()
				}
			}
			if owner.offset != 0 || owner.closed || !bytes.Equal(allocation, bytes.Repeat([]byte{77}, len(allocation))) || !bytes.Equal(destination, bytes.Repeat([]byte{99}, len(destination))) {
				t.Fatal("blocked method changed body or destination storage")
			}
			owner.mu.Unlock()
			locked = false
			var got result
			select {
			case got = <-done:
				joined = true
			case <-time.After(time.Second):
				t.Fatal("body method did not join after unlock")
			}
			if got.err != nil {
				t.Fatal("body method failed after unlock", got.err)
			}
			if method == "Read" && (got.n != len(destination) || owner.offset != len(destination) || !bytes.Equal(destination, bytes.Repeat([]byte{77}, len(destination))) || !bytes.Equal(allocation, bytes.Repeat([]byte{77}, len(allocation)))) {
				t.Fatal("Read did not copy the complete admitted bytes before disposal")
			}
			if method == "Close" && (owner.wire != nil || !owner.closed || !bytes.Equal(allocation, make([]byte, len(allocation)))) {
				t.Fatal("Close did not release and clear the full allocation")
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			if owner.wire != nil || !owner.closed || !bytes.Equal(allocation, make([]byte, len(allocation))) {
				t.Fatal("body disposal left backing")
			}
			if n, err := owner.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatal("Read after Close did not stop access")
			}
		})
	}
}
