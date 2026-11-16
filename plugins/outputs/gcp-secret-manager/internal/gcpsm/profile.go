package gcpsm

import (
	outputcredential "enkv.sh/plugins/outputs/gcp-secret-manager/credential"
	"enkv.sh/sdk/output"
	"strconv"
	"strings"
	"time"

	"enkv.sh/plugins/outputs/gcp-secret-manager/profile"
	protocol "enkv.sh/sdk/protocols/output"
)

// MaximumRawValueBytes bounds the prepared application bytes before the API
// transport encoding. It is not a bound on the JSON request length.
const (
	MaximumRawValueBytes = 65536
	maximumRequestBytes  = 1 << 20 // Derived transport guard, not a service policy quota.
	maximumReplyBytes    = 1 << 20
	endpoint             = "https://secretmanager.googleapis.com"
)

func validateConsumer(command output.Preparation, policy protocol.Policy) error {
	if command.ConditionalToken != "" || policy.Present() || len(policy.Data) != 0 || command.Action != protocol.ActionCreateEmpty && command.Action != protocol.ActionWriteValue && command.Action != protocol.ActionDeleteOwned && command.Action != protocol.ActionDeleteReservedSlot {
		return profile.ErrProfile
	}
	if _, _, err := profile.ParseTarget(command.Target); err != nil {
		return err
	}
	if command.Action != protocol.ActionCreateEmpty && command.Action != protocol.ActionDeleteReservedSlot && command.OwnedInstance != command.Target.CanonicalTarget {
		return profile.ErrProfile
	}
	return nil
}

func validateCredential(body []byte) error {
	_, err := outputcredential.Decode(body, time.Now())
	return err
}

func canonicalVersion(parent, name string) bool {
	if !strings.HasPrefix(name, parent+"/versions/") {
		return false
	}
	part := strings.TrimPrefix(name, parent+"/versions/")
	if part == "" || part[0] == '0' {
		return false
	}
	v, err := strconv.ParseInt(part, 10, 64)
	return err == nil && v > 0 && strconv.FormatInt(v, 10) == part
}
