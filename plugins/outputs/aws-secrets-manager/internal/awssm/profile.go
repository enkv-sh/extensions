package awssm

import (
	"enkv.sh/sdk/output"
	"time"

	outputcredential "enkv.sh/plugins/outputs/aws-secrets-manager/credential"

	"enkv.sh/plugins/outputs/aws-secrets-manager/profile"
	protocol "enkv.sh/sdk/protocols/output"
)

// MaximumRawValueBytes bounds the prepared application bytes before the API
// transport encoding. It is not a bound on the JSON request length.
const (
	MaximumRawValueBytes = 65536
	maximumBodyBytes     = 96 << 10
	maximumReplyBytes    = 4 << 10
)

func validateConsumer(command output.Preparation, policy protocol.Policy) (profile.Target, error) {
	if command.ConditionalToken != "" || policy.Present() || len(policy.Data) != 0 || command.Action != protocol.ActionCreateEmpty && command.Action != protocol.ActionWriteValue && command.Action != protocol.ActionDeleteOwned && command.Action != protocol.ActionDeleteReservedSlot {
		return profile.Target{}, profile.ErrProfile
	}
	target, err := profile.ParseTarget(command.Target)
	if err != nil {
		return profile.Target{}, err
	}
	if command.Action != protocol.ActionCreateEmpty && command.Action != protocol.ActionDeleteReservedSlot {
		owned, err := profile.ParseOwnedInstance(command.OwnedInstance)
		if err != nil || owned.Slot != target.Slot {
			return profile.Target{}, profile.ErrProfile
		}
		target.ARN = owned.ARN
	}
	return target, nil
}

type credential struct {
	access, secret, token []byte
	expiry                time.Time
}

func parseCredential(b []byte) (credential, error) {
	value, err := outputcredential.Decode(b, time.Now())
	if err != nil {
		return credential{}, err
	}
	return credential{access: value.AccessKeyID, secret: value.SecretAccessKey, token: value.SessionToken, expiry: value.Expiry}, nil
}
