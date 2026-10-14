package dbrole

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestPasswordIsDerivedNotStored(t *testing.T) {
	a := Password("admin-secret", "goinbound_ro")
	if a == "" || a != Password("admin-secret", "goinbound_ro") {
		t.Fatal("the derived password is not stable across starts")
	}
	if a == Password("other-secret", "goinbound_ro") || a == Password("admin-secret", "other_role") {
		t.Error("the derived password does not depend on both the admin password and the role")
	}
	if strings.Contains(a, "admin-secret") {
		t.Error("the derived password contains the admin password")
	}
	// No admin password: the database trusts the connection, so no password.
	if Password("", "goinbound_ro") != "" {
		t.Error("a password was invented for a passwordless database")
	}
}

// The verifier is what PostgreSQL itself stores, so a client authenticating
// with the password must be able to prove knowledge of it against StoredKey.
func TestSCRAMVerifier(t *testing.T) {
	v, err := scramVerifier("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`^SCRAM-SHA-256\$(\d+):([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$`).FindStringSubmatch(v)
	if m == nil {
		t.Fatalf("not in PostgreSQL's verifier format: %s", v)
	}
	iter, _ := strconv.Atoi(m[1])
	salt, _ := base64.StdEncoding.DecodeString(m[2])
	stored, _ := base64.StdEncoding.DecodeString(m[3])
	server, _ := base64.StdEncoding.DecodeString(m[4])

	// Recompute as an authenticating client would (RFC 5802 section 3).
	salted, err := pbkdf2.Key(sha256.New, "hunter2", salt, iter, sha256.Size)
	if err != nil {
		t.Fatal(err)
	}
	ck := hmac.New(sha256.New, salted)
	ck.Write([]byte("Client Key"))
	h := sha256.Sum256(ck.Sum(nil))
	if !hmac.Equal(h[:], stored) {
		t.Error("StoredKey does not match the password")
	}
	sk := hmac.New(sha256.New, salted)
	sk.Write([]byte("Server Key"))
	if !hmac.Equal(sk.Sum(nil), server) {
		t.Error("ServerKey does not match the password")
	}

	if v2, _ := scramVerifier("hunter2"); v2 == v {
		t.Error("two verifiers share a salt")
	}
}

func TestQuoteLiteral(t *testing.T) {
	if got := quoteLiteral(`a'b`); got != `'a''b'` {
		t.Errorf("quoteLiteral = %s", got)
	}
}
