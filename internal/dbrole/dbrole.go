// Package dbrole creates and repairs the read-only PostgreSQL role this worker
// serves with.
//
// It is the only code in this worker that changes the database, and what it
// changes is the role, never Synapse's data: CREATE/ALTER ROLE and GRANT
// SELECT. It runs at startup, and only when connecting as the role failed or
// the role lacked something, using homeserver.yaml's credentials -- on a
// homeserver with a PostgreSQL of its own that is the database's only user, and
// a superuser. The serving connection never uses those credentials.
//
// The role's password, when it needs one, is derived from the admin password
// (Password), so nothing has to be stored anywhere: every start derives the
// same one. It is sent to PostgreSQL only as a SCRAM-SHA-256 verifier, so even
// a server logging every DDL statement records no usable password.
package dbrole

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Password derives the managed role's password from the admin password. Empty
// when the admin has none, in which case the role gets none either: the
// database evidently trusts the connection rather than a password, and a
// password nobody can use is only a secret to leak.
func Password(adminPassword, role string) string {
	if adminPassword == "" {
		return ""
	}
	m := hmac.New(sha256.New, []byte(adminPassword))
	m.Write([]byte("goinbound-worker read-only role:" + role))
	return hex.EncodeToString(m.Sum(nil))
}

// Spec is the role to ensure.
type Spec struct {
	Role string
	// Password is set when non-empty. An empty Password leaves an existing
	// role's password alone.
	Password string
	// Tables are granted SELECT, all in schema public.
	Tables []string
}

// Ensure creates the role if it does not exist and brings it to Spec if it
// does. Every statement is idempotent, so running it on a correct role
// changes nothing.
//
// adminDSN must reach PostgreSQL as a role that may create roles and grant on
// Synapse's tables: the owner of the tables, or a superuser.
func Ensure(ctx context.Context, adminDSN string, spec Spec) error {
	if spec.Role == "" {
		return errors.New("dbrole: no role name")
	}
	cfg, err := pgx.ParseConfig(adminDSN)
	if err != nil {
		return fmt.Errorf("dbrole: parse admin dsn: %w", err)
	}
	if cfg.User == spec.Role {
		return fmt.Errorf("dbrole: the admin connection is already the role %q; refusing to alter the role it connects as", spec.Role)
	}
	// Utility statements take no parameters, and a transaction pooler may
	// put the two halves of an extended-protocol query on different
	// connections. The simple protocol avoids both.
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("dbrole: connect as %s: %w", cfg.User, err)
	}
	defer conn.Close(ctx)

	stmts, err := statements(ctx, conn, spec)
	if err != nil {
		return err
	}
	for _, st := range stmts {
		if _, err := conn.Exec(ctx, st.sql); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "42501" {
				return fmt.Errorf("dbrole: %s is not allowed to %s (%s); create the role by hand with deploy/readonly-role.sql",
					cfg.User, st.what, pgErr.Message)
			}
			return fmt.Errorf("dbrole: %s: %w", st.what, err)
		}
	}
	return nil
}

type statement struct{ what, sql string }

func statements(ctx context.Context, conn *pgx.Conn, spec Spec) ([]statement, error) {
	role := pgx.Identifier{spec.Role}.Sanitize()

	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, spec.Role).Scan(&exists); err != nil {
		return nil, fmt.Errorf("dbrole: look up role: %w", err)
	}
	var db string
	if err := conn.QueryRow(ctx, `SELECT current_database()`).Scan(&db); err != nil {
		return nil, fmt.Errorf("dbrole: current database: %w", err)
	}

	// Only LOGIN. A new role is already NOSUPERUSER NOCREATEDB NOCREATEROLE,
	// and naming those attributes in ALTER ROLE needs a superuser on
	// PostgreSQL 16+, which would lock out an admin that merely owns the
	// tables and holds CREATEROLE.
	login := "LOGIN"
	if spec.Password != "" {
		v, err := scramVerifier(spec.Password)
		if err != nil {
			return nil, err
		}
		login += " PASSWORD " + quoteLiteral(v)
	}

	var out []statement
	if exists {
		out = append(out, statement{"alter role " + spec.Role, "ALTER ROLE " + role + " " + login})
	} else {
		out = append(out, statement{"create role " + spec.Role, "CREATE ROLE " + role + " " + login})
	}

	tables := make([]string, len(spec.Tables))
	for i, t := range spec.Tables {
		tables[i] = pgx.Identifier{"public", t}.Sanitize()
	}
	out = append(out,
		statement{"grant connect", "GRANT CONNECT ON DATABASE " + pgx.Identifier{db}.Sanitize() + " TO " + role},
		statement{"grant schema usage", "GRANT USAGE ON SCHEMA public TO " + role},
		statement{"grant select", "GRANT SELECT ON " + strings.Join(tables, ", ") + " TO " + role},
		// Belt and braces: even a write that somehow reached the database
		// as this role could not commit.
		statement{"make the role read-only", "ALTER ROLE " + role + " SET default_transaction_read_only = on"},
		// Every query is a primary-key lookup; anything slow is wrong.
		statement{"set statement timeout", "ALTER ROLE " + role + " SET statement_timeout = '10s'"},
	)
	return out, nil
}

// scramVerifier builds the SCRAM-SHA-256 verifier PostgreSQL stores for a
// password (RFC 5802, RFC 7677), in the form it accepts pre-hashed in
// CREATE/ALTER ROLE ... PASSWORD:
//
//	SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>
func scramVerifier(password string) (string, error) {
	const iterations = 4096 // PostgreSQL's default scram_iterations
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("dbrole: salt: %w", err)
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("dbrole: pbkdf2: %w", err)
	}
	clientKey := hmacSHA256(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(salted, "Server Key")

	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, b64(salt), b64(storedKey[:]), b64(serverKey)), nil
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// quoteLiteral quotes a string as an SQL literal. Only ever applied to a SCRAM
// verifier, whose alphabet is base64 plus "$:-", but quoted properly anyway.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
