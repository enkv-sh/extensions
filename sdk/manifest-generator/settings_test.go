package manifest

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestCopySettingsResult(t *testing.T) {
	encoded, err := json.Marshal(struct {
		Name string `json:"name"`
	}{"sample"})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded[:cap(encoded)])
	for _, input := range [][]byte{encoded, append(make([]byte, 0, 64), encoded...), []byte(`"` + strings.Repeat("s", 16382) + `"`)} {
		before := bytes.Clone(input[:cap(input)])
		got := CopySettingsResult(t.Context(), input)
		if got.Failure != "" || len(got.Settings) != len(input) || cap(got.Settings) != len(input) || !bytes.Equal(got.Settings, input) {
			t.Fatal("exact settings copy", got.Failure, len(got.Settings), cap(got.Settings))
		}
		if !bytes.Equal(input[:cap(input)], before) {
			t.Fatal("source backing changed")
		}
		clear(input[:cap(input)])
		if !bytes.Equal(got.Settings, before[:len(got.Settings)]) {
			t.Fatal("settings alias source")
		}
		clear(got.Settings[:cap(got.Settings)])
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, expire := context.WithDeadline(t.Context(), time.Unix(1, 0))
	defer expire()
	for _, row := range []struct {
		name  string
		ctx   context.Context
		input []byte
		want  Failure
	}{
		{"nil-context", nil, []byte(`{}`), InvalidInput},
		{"typed-nil-context", (*cancelAfter)(nil), []byte(`{}`), InvalidInput},
		{"cancelled", cancelled, []byte(`{}`), Cancelled},
		{"expired", expired, []byte(`{}`), Expired},
		{"utf8", t.Context(), []byte{'"', 255, '"'}, InvalidUTF8},
		{"json", t.Context(), []byte(`{`), InvalidInput},
		{"empty", t.Context(), nil, InvalidInput},
		{"over-limit", t.Context(), []byte(`"` + strings.Repeat("s", 16383) + `"`), LimitExceeded},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := append(make([]byte, 0, len(row.input)+8), row.input...)
			clear(input[len(input):cap(input)])
			before := bytes.Clone(input[:cap(input)])
			got := CopySettingsResult(row.ctx, input)
			if got.Failure != row.want || got.Settings != nil {
				t.Fatal("invalid settings escaped", got.Failure, row.want)
			}
			if !bytes.Equal(input[:cap(input)], before) {
				t.Fatal("failure changed caller backing")
			}
		})
	}
}

// full_only: false
func TestSettingsCopyCancellationClearsProvisionalBacking(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	owned := bytes.Repeat([]byte{0xa5}, MaxSettingsBytes)
	got := finishSettingsCopy(ctx, owned[:2])
	if got.Failure != Cancelled || got.Settings != nil || !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("provisional settings backing escaped cancellation")
	}
	input := []byte(`{"name":"sample"}`)
	late := &cancelAfter{Context: t.Context(), at: 2}
	got = CopySettingsResult(late, input)
	if got.Failure != Cancelled || got.Settings != nil || late.calls != 2 || string(input) != `{"name":"sample"}` {
		t.Fatal("late cancellation escaped", got.Failure, late.calls)
	}
}
