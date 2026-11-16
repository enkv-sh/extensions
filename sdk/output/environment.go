package output

import (
	"context"
	"errors"
	"os"

	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
)

type nativeImplementation struct{ Implementation }

// Prepare installs only admitted inputs, then ties environment removal to
// prepared disposal. A refused preparation must remove the environment too.
func (v nativeImplementation) Prepare(ctx context.Context, c Preparation, p protocol.Policy, inputs []credentialroute.Input) (Prepared, error) {
	names := make([]string, 0, len(inputs))
	remove := func() error {
		var err error
		for _, name := range names {
			err = errors.Join(err, os.Unsetenv(name))
		}
		return err
	}
	for _, input := range inputs {
		if !input.Present {
			continue
		}
		if err := os.Setenv(input.Name, string(input.Value)); err != nil {
			return nil, errors.Join(err, remove())
		}
		names = append(names, input.Name)
	}
	prepared, err := v.Implementation.Prepare(ctx, c, p, inputs)
	if prepared == nil {
		return nil, errors.Join(err, remove())
	}
	return &nativePrepared{Prepared: prepared, remove: remove}, err
}

type nativePrepared struct {
	Prepared
	remove func() error
}

// Close disposes implementation resources before removing their environment.
// Both failures remain available to the caller.
func (v *nativePrepared) Close() error { return errors.Join(v.Prepared.Close(), v.remove()) }
