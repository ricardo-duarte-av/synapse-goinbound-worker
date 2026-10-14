package pdu

import (
	"errors"
	"fmt"

	"github.com/tidwall/gjson"
)

// AuthError is Synapse's AuthError (and its UnstableSpecAuthError subclass):
// the event fails the auth rules. In the receive path this rejects the event;
// in state resolution it keeps the event out of the resolved state.
type AuthError struct{ Msg string }

func (e *AuthError) Error() string { return "auth: " + e.Msg }

func deny(format string, args ...any) error { return &AuthError{Msg: fmt.Sprintf(format, args...)} }

// RaiseError is anything else Synapse would raise from inside the auth
// checks: a SynapseError (which is NOT an AuthError), a KeyError, a ValueError
// from int(). Synapse does not catch these where it catches AuthError, so the
// consequence differs by caller -- a receive fails instead of rejecting, a
// state resolution fails outright. Callers must not treat it as a rejection.
type RaiseError struct{ Msg string }

func (e *RaiseError) Error() string { return "raise: " + e.Msg }

func raise(msg string) error { return &RaiseError{Msg: msg} }

// IsAuthError reports whether err is a plain auth failure.
func IsAuthError(err error) bool {
	var ae *AuthError
	return errors.As(err, &ae)
}

// intOf is int(v) inside an auth check, where its exception is a RaiseError.
func intOf(v gjson.Result) (int64, error) {
	n, err := pyInt(v)
	if err != nil {
		return 0, raise(err.Error())
	}
	return n, nil
}
