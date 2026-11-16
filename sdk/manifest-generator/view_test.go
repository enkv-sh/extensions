package manifest

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

// full_only: false
func TestCopyPlainValue(t *testing.T) {
	for _, length := range []int{0, 1, 49151, 49152, 49153, 65536} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			plain := make([]byte, length)
			for i := range plain {
				plain[i] = byte(i)
			}
			p := &Projection{Entries: []Entry{{Kind: Plain, PlainValue: plain}}}
			e, _ := Borrow(p).Entry(0)
			dst := bytes.Repeat([]byte{0xa5}, length+7)
			if n, f := e.CopyPlainValue(dst); n != length || f != "" || !bytes.Equal(dst[:length], plain) || !bytes.Equal(dst[length:], bytes.Repeat([]byte{0xa5}, 7)) {
				t.Fatal("complete value or tail", n, f)
			}
			clear(dst)
			for i, b := range plain {
				if b != byte(i) {
					t.Fatal("projection alias", i)
				}
			}
			if length > 0 {
				short := bytes.Repeat([]byte{0xa5}, length-1)
				if n, f := e.CopyPlainValue(short); n != 0 || f != InvalidInput || !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) {
					t.Fatal("short destination changed", n, f)
				}
			}
		})
	}
	for _, row := range []struct {
		name string
		view EntryView
		want Failure
	}{
		{"zero", EntryView{}, InvalidInput},
		{"secret", EntryView{owner: &Projection{Entries: []Entry{{Kind: Secret}}}}, InvalidInput},
		{"over-limit", EntryView{owner: &Projection{Entries: []Entry{{Kind: Plain, PlainValue: make([]byte, MaxRawValue+1)}}}}, LimitExceeded},
	} {
		t.Run(row.name, func(t *testing.T) {
			dst := bytes.Repeat([]byte{0xa5}, MaxRawValue+1)
			if n, f := row.view.CopyPlainValue(dst); n != 0 || f != row.want || !bytes.Equal(dst, bytes.Repeat([]byte{0xa5}, len(dst))) {
				t.Fatal("invalid view changed destination", n, f)
			}
		})
	}
}

// full_only: false
func TestViewCopiesAndBounds(t *testing.T) {
	p := fixtureProjection()
	p.Entries = []Entry{{Name: "plain", EntryIncarnationID: ID{5}, Kind: Plain, PlainValue: []byte{0, 1, 255}}}
	p.ResolvedEntries = []EntryIdentity{{"plain", ID{5}}}
	v := Borrow(p)
	e, ok := v.Entry(0)
	if !ok {
		t.Fatal("entry absent")
	}
	buf := make([]byte, 3)
	if n, f := e.CopyPlain(0, buf); n != 3 || f != "" {
		t.Fatal(n, f)
	}
	buf[0] = 9
	if p.Entries[0].PlainValue[0] != 0 {
		t.Fatal("plain alias")
	}
	if n, f := e.CopyPlain(4, buf); n != 0 || f != InvalidInput {
		t.Fatal(n, f)
	}
	if _, f := e.CopyPlain(0, make([]byte, 49153)); f != LimitExceeded {
		t.Fatal(f)
	}
	if _, ok := v.Entry(-1); ok {
		t.Fatal("negative entry")
	}
	if _, ok := v.Excluded(0); ok {
		t.Fatal("excess exclusion")
	}
	if _, f := v.CopySettings(0, buf); f != "" {
		t.Fatal(f)
	}
	buf[0] = 'x'
	if string(p.Settings) != "{}" {
		t.Fatal("settings alias")
	}
}

// full_only: false
func TestViewPublicValuesHaveNoMutableBacking(t *testing.T) {
	for _, v := range []any{Header{}, EntryMetadata{}, DestinationMetadata{}, ExcludedEntry{}} {
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Map || field.Type.Kind() == reflect.Pointer {
				t.Fatal("mutable metadata", typ.Name(), field.Name)
			}
		}
	}
}

// full_only: false
func TestViewDestinationCopies(t *testing.T) {
	p := fixtureProjection()
	fixtureSecret(p)
	p.Entries[0].Destinations[0].PolicyPresent = true
	p.Entries[0].Destinations[0].PolicyContractID = "private/policy"
	p.Entries[0].Destinations[0].PolicyData = []byte{3, 4, 5}
	p.Entries[0].Destinations[0].PolicyDigest = ID{7}
	e, _ := Borrow(p).Entry(0)
	d, _ := e.Destination(0)
	var target, policy [3]byte
	if n, f := d.CopyTargetData(0, target[:]); n != 3 || f != "" {
		t.Fatal(n, f)
	}
	if n, f := d.CopyPolicy(0, policy[:]); n != 3 || f != "" {
		t.Fatal(n, f)
	}
	target[0], policy[0] = 9, 9
	if p.Entries[0].Destinations[0].TargetData[0] != 0 || p.Entries[0].Destinations[0].PolicyData[0] != 3 {
		t.Fatal("destination alias")
	}
	if d.TargetDataLength() != 3 || d.PolicyLength() != 3 {
		t.Fatal("length")
	}
	if _, ok := e.Destination(1); ok {
		t.Fatal("excess destination")
	}
}

// full_only: false
func TestViewAccessorsAllocateNoBacking(t *testing.T) {
	p := fixtureProjection()
	fixtureSecret(p)
	v := Borrow(p)
	var scratch [64]byte
	if n := testing.AllocsPerRun(100, func() {
		_ = v.Header()
		_, _ = v.CopySettings(0, scratch[:])
		e, _ := v.Entry(0)
		_ = e.Metadata()
		d, _ := e.Destination(0)
		_ = d.Metadata()
		_, _ = d.CopyTargetData(0, scratch[:])
		_, _ = d.CopyPolicy(0, scratch[:])
	}); n != 0 {
		t.Fatal("view allocations", n)
	}
}
