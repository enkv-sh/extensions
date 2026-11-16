package conformance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/generator"
	protocol "enkv.sh/sdk/protocols/generator"
)

func checkCallerContextDiagnosis(t *testing.T) {
	for _, condition := range []string{"cancelled", "expired", "during-exchange", "violation-before-cancellation"} {
		t.Run("caller-context/"+condition, func(t *testing.T) {
			impl, fixture, err := synthetic()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := error(context.Canceled)
			if condition == "cancelled" {
				cancel()
			}
			if condition == "expired" {
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(t.Context(), time.Unix(0, 0))
				defer stop()
				want = context.DeadlineExceeded
			}
			calls := 0
			actual := impl.Create
			var returned []byte
			impl.Create = func(ctx context.Context, inv generator.Invocation) (protocol.SafeFacts, []byte, error) {
				calls++
				f, v, e := actual(ctx, inv)
				returned = v
				if condition == "during-exchange" || condition == "violation-before-cancellation" {
					cancel()
				}
				if condition == "violation-before-cancellation" {
					f.RequestDigest[0] ^= 1
				}
				return f, v, e
			}
			err = CheckImplementation(ctx, generator.Run, impl, fixture)
			if condition == "violation-before-cancellation" {
				if err == nil || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "callback.facts") {
					t.Fatal("cancellation hid a prior facts violation", err)
				}
			} else if !errors.Is(err, want) || !errors.Is(err, protocol.ErrProtocol) || !strings.Contains(err.Error(), "caller.context:") {
				t.Fatal("caller context diagnosis lost its reason or cause", err)
			}
			expectedCalls := 0
			if condition == "during-exchange" || condition == "violation-before-cancellation" {
				expectedCalls = 1
			}
			if calls != expectedCalls || !allZero(returned[:cap(returned)]) {
				t.Fatal("context path skipped callback/disposal observations", calls)
			}
		})
	}
}
