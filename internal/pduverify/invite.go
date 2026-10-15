package pduverify

import (
	"context"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/acl"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// The account data types of invite permission config (api/constants.py).
const (
	invitePermissionConfig        = "m.invite_permission_config"
	msc4155InvitePermissionConfig = "org.matrix.msc4155.invite_permission_config"
)

// inviteAllowed is get_invite_config_for_user(invitee).get_invite_rule(
// inviter) == InviteRule.ALLOW (storage/invite_rule.py): an MSC4380 config
// first (block, or allow), then with msc4155_enabled an MSC4155 one, else
// everything is allowed.
func (s *Verifier) inviteAllowed(ctx context.Context, invitee, inviter string) (bool, error) {
	data, ok, err := s.st.AccountData(ctx, invitee, invitePermissionConfig)
	if err != nil {
		return false, err
	}
	if ok {
		j := gjson.ParseBytes(data)
		if !j.IsObject() {
			// data.get raises on anything but a dict.
			return false, &pdu.RaiseError{Msg: "invite permission config is not an object"}
		}
		d := pdu.Get(j, "default_action")
		return !(d.Type == gjson.String && d.Str == "block"), nil
	}
	if s.push == nil || !s.push.MSC4155 {
		return true, nil
	}
	data, ok, err = s.st.AccountData(ctx, invitee, msc4155InvitePermissionConfig)
	if err != nil || !ok {
		return true, err
	}
	j := gjson.ParseBytes(data)
	if !j.IsObject() {
		// `if account_data:` on a non-dict, then .get: anything truthy
		// raises.
		if pyTruthy(j) {
			return false, &pdu.RaiseError{Msg: "msc4155 invite config is not an object"}
		}
		return true, nil
	}
	patterns := func(field string) []string {
		v := pdu.Get(j, field)
		if !v.IsArray() {
			return nil
		}
		var out []string
		for _, x := range v.Array() {
			if x.Type == gjson.String && x.Str != "" && len(x.Str) <= 255 {
				out = append(out, x.Str)
			}
		}
		return out
	}
	domain := inviter
	if i := strings.IndexByte(inviter, ':'); i >= 0 {
		domain = inviter[i+1:]
	}
	for _, rule := range []struct {
		field string
		allow bool
		of    string
	}{
		{"allowed_users", true, inviter}, {"ignored_users", false, inviter}, {"blocked_users", false, inviter},
		{"allowed_servers", true, domain}, {"ignored_servers", false, domain}, {"blocked_servers", false, domain},
	} {
		for _, p := range patterns(rule.field) {
			if acl.GlobMatch(p, rule.of) {
				return rule.allow, nil
			}
		}
	}
	return true, nil
}
