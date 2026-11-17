// Package sqlkeystore is an example hierarchical.KeyStore on an SQL database:
// PostgreSQL or SQLite, through database/sql.
//
// It keeps one row per key in a single table. The rows are the wrapped
// intermediate keys of a hierarchical.Backend: they are not secret, since only
// the KMS root key unwraps them, but every object encrypted with a key is lost
// with its row. Back the database up, and keep write access to the table
// narrow.
//
// The package imports no database driver. Import the one for your database
// and pass the *sql.DB:
//
//	db, err := sql.Open("pgx", dsn) // github.com/jackc/pgx/v5/stdlib
//	store, err := sqlkeystore.New(db, sqlkeystore.PostgreSQL)
//	err = store.CreateTable(ctx)
package sqlkeystore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/hierarchical"
)

// Dialect is the SQL dialect of the database.
type Dialect int

// Supported dialects.
const (
	// PostgreSQL uses $1 placeholders and a bytea column for the wrapped key.
	PostgreSQL Dialect = iota + 1
	// SQLite uses ? placeholders and a blob column. A SQLite file is enough
	// for a single server instance; several instances need a database they
	// can share.
	SQLite
)

// DefaultTable is the name of the table the store uses by default.
const DefaultTable = "transhim_keys"

// Store is a hierarchical.KeyStore on an SQL table. It is safe for concurrent
// use, also by several processes on the same database.
type Store struct {
	db      *sql.DB
	dialect Dialect
	table   string

	getSQL, putSQL, deleteSQL string
}

var _ hierarchical.KeyStore = (*Store)(nil)

// Option configures a Store.
type Option func(*Store)

// WithTable sets the table name. The default is DefaultTable.
func WithTable(name string) Option {
	return func(s *Store) { s.table = name }
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// New returns a Store on db. The table must exist: create it with CreateTable
// or with the statement Schema returns.
func New(db *sql.DB, dialect Dialect, opts ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("sqlkeystore: db must not be nil")
	}
	if dialect != PostgreSQL && dialect != SQLite {
		return nil, errors.New("sqlkeystore: unknown dialect")
	}
	s := &Store{db: db, dialect: dialect, table: DefaultTable}
	for _, opt := range opts {
		opt(s)
	}
	// The name goes into the statements as it is.
	if !identifier.MatchString(s.table) {
		return nil, fmt.Errorf("sqlkeystore: %q is not a plain table name", s.table)
	}
	s.getSQL = s.bind(`SELECT key_ref, version, wrapped, created_at FROM ` + s.table + ` WHERE mount_id = ? AND key_name = ?`)
	// The primary key makes this atomic: of several concurrent inserts of the
	// same key, one inserts a row and the others insert none.
	s.putSQL = s.bind(`INSERT INTO ` + s.table + ` (mount_id, key_name, key_ref, version, wrapped, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (mount_id, key_name) DO NOTHING`)
	s.deleteSQL = s.bind(`DELETE FROM ` + s.table + ` WHERE mount_id = ? AND key_name = ?`)
	return s, nil
}

// bind turns the ? placeholders of a statement into the dialect's.
func (s *Store) bind(query string) string {
	if s.dialect != PostgreSQL {
		return query
	}
	var b strings.Builder
	n := 0
	for _, c := range query {
		if c == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// Schema returns the statement that creates the table, if it does not exist.
//
// The key columns must compare byte by byte: key names that differ only in
// case, or in trailing spaces, are different keys. PostgreSQL's text and
// SQLite's TEXT do. created_at is in microseconds since the Unix epoch.
func (s *Store) Schema() string {
	binary := "BYTEA"
	if s.dialect == SQLite {
		binary = "BLOB"
	}
	return `CREATE TABLE IF NOT EXISTS ` + s.table + ` (
    mount_id   TEXT    NOT NULL,
    key_name   TEXT    NOT NULL,
    key_ref    TEXT    NOT NULL,
    version    INTEGER NOT NULL,
    wrapped    ` + binary + `   NOT NULL,
    created_at BIGINT  NOT NULL,
    PRIMARY KEY (mount_id, key_name)
)`
}

// CreateTable creates the table if it does not exist.
func (s *Store) CreateTable(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, s.Schema()); err != nil {
		return fmt.Errorf("sqlkeystore: create table: %w", err)
	}
	return nil
}

// Get implements hierarchical.KeyStore.
//
// Read from a database that has the latest writes: Ceph RGW asks for a data
// key right after it had the bucket's key created, so a replica that lags
// would answer that the key does not exist.
func (s *Store) Get(ctx context.Context, mountID, keyName string) (hierarchical.StoredKey, error) {
	var k hierarchical.StoredKey
	var createdAt int64
	err := s.db.QueryRowContext(ctx, s.getSQL, mountID, keyName).
		Scan(&k.Wrapped.KeyRef, &k.Wrapped.Version, &k.Wrapped.Blob, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return hierarchical.StoredKey{}, fmt.Errorf("%w: %s", transhim.ErrKeyNotFound, keyName)
	}
	if err != nil {
		return hierarchical.StoredKey{}, storeError("get", err)
	}
	k.CreatedAt = time.UnixMicro(createdAt).UTC()
	return k, nil
}

// PutIfAbsent implements hierarchical.KeyStore.
func (s *Store) PutIfAbsent(ctx context.Context, mountID, keyName string, k hierarchical.StoredKey) error {
	blob := k.Wrapped.Blob
	if blob == nil {
		blob = []byte{} // not NULL
	}
	res, err := s.db.ExecContext(ctx, s.putSQL,
		mountID, keyName, k.Wrapped.KeyRef, k.Wrapped.Version, blob, k.CreatedAt.UnixMicro())
	if err != nil {
		return storeError("put", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return storeError("put", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", hierarchical.ErrKeyExists, keyName)
	}
	return nil
}

// Delete implements hierarchical.KeyStore. The row is removed for good: this
// is what makes a deleted bucket's data unreadable. It stays in backups made
// before, for as long as they are kept.
func (s *Store) Delete(ctx context.Context, mountID, keyName string) error {
	if _, err := s.db.ExecContext(ctx, s.deleteSQL, mountID, keyName); err != nil {
		return storeError("delete", err)
	}
	return nil
}

// storeError marks a database failure as one of the key service, so that the
// server answers 503 and S3 clients retry, instead of 500.
func storeError(op string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("sqlkeystore: %s: %w", op, err)
	}
	return &transhim.UpstreamError{Err: fmt.Errorf("sqlkeystore: %s: %w", op, err), Retryable: true}
}
