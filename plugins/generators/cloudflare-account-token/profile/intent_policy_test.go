package profile_test

import (
	"reflect"
	"testing"

	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
)

// full_only: false
func TestIntentPolicyCopiesAllPublicFields(t *testing.T) {
	body, account := intentFixture(t)
	intent, err := profile.ParseIntent(body, account)
	if err != nil {
		t.Fatal(err)
	}
	tag := func(s string) (v [32]byte) { copy(v[:], s); return }
	want := profile.Policy{Effect: profile.EffectAllow,
		PermissionGroups: [][32]byte{tag("123456789abcdef0123456789abcdef0")},
		Resources:        []profile.Resource{{Kind: profile.ResourceAccount, ID: account}, {Kind: profile.ResourceZone, ID: tag("23456789abcdef0123456789abcdef01")}}}
	got, ok := intent.CopyPolicy(0)
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatal("complete policy differs")
	}
	got.PermissionGroups[0][0] = 'f'
	got.Resources[0].ID[0] = 'f'
	got.Resources[1].Kind = profile.ResourceAccountZones
	clear(body)
	again, ok := intent.CopyPolicy(0)
	if !ok || !reflect.DeepEqual(again, want) {
		t.Fatal("returned policy shares mutable intent storage")
	}
	for _, i := range []int{-1, 1} {
		if _, ok := intent.CopyPolicy(i); ok {
			t.Fatal("invalid policy index accepted")
		}
	}
}
