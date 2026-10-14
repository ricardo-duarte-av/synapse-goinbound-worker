package store

import (
	"context"
	"fmt"
)

// Tables is every table this package reads. The read-only role is granted
// SELECT on exactly these; TestQueriesReadOnlyListedTables keeps the list and
// the queries in step.
var Tables = []string{
	"server_keys_json",
	"current_state_events",
	"event_json",
	"redactions",
	"destinations",
	"received_transactions",
}

const qTablePrivilege = `SELECT has_table_privilege(current_user, $1, 'SELECT')`

// MissingPrivileges reports what the connected role lacks: one of tables it
// cannot SELECT from, or "default_transaction_read_only" when the role does
// not default to read-only transactions. Empty means the role is as it should
// be.
func (s *Store) MissingPrivileges(ctx context.Context, tables []string) ([]string, error) {
	var missing []string
	for _, t := range tables {
		var ok bool
		if err := s.queryRow(ctx, "table_privilege", qTablePrivilege, "public."+t).Scan(&ok); err != nil {
			return nil, fmt.Errorf("store: check privilege on %s: %w", t, err)
		}
		if !ok {
			missing = append(missing, t)
		}
	}
	ro, err := s.IsReadOnly(ctx)
	if err != nil {
		return nil, err
	}
	if !ro {
		missing = append(missing, "default_transaction_read_only")
	}
	return missing, nil
}

// User returns the role this store connected as.
func (s *Store) User() string { return s.pool.Config().ConnConfig.User }
