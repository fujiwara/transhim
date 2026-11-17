package sqlkeystore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/examples/sqlkeystore"
	"github.com/fujiwara/transhim/hierarchical"
	"github.com/fujiwara/transhim/transhimtest"
)

// database is a way to open the same database again, as a restarted server
// or a second instance would.
type database struct {
	name    string
	dialect sqlkeystore.Dialect
	open    func(t *testing.T) *sql.DB
}

// databases returns the databases to test against: SQLite in a temporary
// file, always, and PostgreSQL if TRANSHIM_TEST_POSTGRES_DSN is set:
//
//	docker compose up -d --wait postgres
//	TRANSHIM_TEST_POSTGRES_DSN=postgres://transhim:transhim@127.0.0.1:15432/transhim go test ./...
func databases(t *testing.T) []database {
	t.Helper()
	file := filepath.Join(t.TempDir(), "keys.sqlite")
	dbs := []database{{
		name:    "sqlite",
		dialect: sqlkeystore.SQLite,
		open: func(t *testing.T) *sql.DB {
			// wait for a writer instead of failing with SQLITE_BUSY
			db, err := sql.Open("sqlite", "file:"+file+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.Close() })
			return db
		},
	}}
	if dsn := os.Getenv("TRANSHIM_TEST_POSTGRES_DSN"); dsn != "" {
		dbs = append(dbs, database{
			name:    "postgresql",
			dialect: sqlkeystore.PostgreSQL,
			open: func(t *testing.T) *sql.DB {
				db, err := sql.Open("pgx", dsn)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Close() })
				return db
			},
		})
	} else {
		t.Log("TRANSHIM_TEST_POSTGRES_DSN is not set: PostgreSQL is not tested")
	}
	return dbs
}

func newStore(t *testing.T, d database, opts ...sqlkeystore.Option) *sqlkeystore.Store {
	t.Helper()
	store, err := sqlkeystore.New(d.open(t), d.dialect, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateTable(t.Context()); err != nil {
		t.Fatal(err)
	}
	return store
}

func key(blob string) hierarchical.StoredKey {
	return hierarchical.StoredKey{
		Wrapped:   transhim.WrappedKey{KeyRef: "ref", Version: 1, Blob: []byte(blob)},
		CreatedAt: time.Date(2026, 11, 17, 1, 2, 3, 456789000, time.UTC),
	}
}

func TestConformance(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			transhimtest.RunKeyStoreConformance(t, newStore(t, d))
		})
	}
}

// TestSurvivesRestart: the point of this store. A key written through one
// connection pool is there for another, opened later.
func TestSurvivesRestart(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			ctx := t.Context()
			const mount = "restart-test"
			first := newStore(t, d)
			first.Delete(ctx, mount, "bucket")
			t.Cleanup(func() { first.Delete(context.Background(), mount, "bucket") })
			if err := first.PutIfAbsent(ctx, mount, "bucket", key("wrapped key")); err != nil {
				t.Fatal(err)
			}

			second := newStore(t, d) // CreateTable again must not disturb the data
			got, err := second.Get(ctx, mount, "bucket")
			if err != nil {
				t.Fatalf("Get through a second connection: %v", err)
			}
			want := key("wrapped key")
			if string(got.Wrapped.Blob) != "wrapped key" || got.Wrapped.KeyRef != "ref" || got.Wrapped.Version != 1 || !got.CreatedAt.Equal(want.CreatedAt) {
				t.Errorf("Get = %+v, want %+v", got, want)
			}
			// the second instance sees the first one's key as existing ...
			if err := second.PutIfAbsent(ctx, mount, "bucket", key("another")); !errors.Is(err, hierarchical.ErrKeyExists) {
				t.Errorf("PutIfAbsent through a second connection: err = %v, want ErrKeyExists", err)
			}
			// ... and a delete through it is seen by the first
			if err := second.Delete(ctx, mount, "bucket"); err != nil {
				t.Fatal(err)
			}
			if _, err := first.Get(ctx, mount, "bucket"); !errors.Is(err, transhim.ErrKeyNotFound) {
				t.Errorf("Get after a delete through the other connection: err = %v, want ErrKeyNotFound", err)
			}
		})
	}
}

func TestTableName(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			ctx := t.Context()
			db := d.open(t)
			t.Cleanup(func() { db.ExecContext(context.Background(), "DROP TABLE IF EXISTS custom_keys") })
			custom := newStore(t, d, sqlkeystore.WithTable("custom_keys"))
			standard := newStore(t, d)
			custom.Delete(ctx, "table-test", "k")
			if err := custom.PutIfAbsent(ctx, "table-test", "k", key("in the custom table")); err != nil {
				t.Fatal(err)
			}
			if _, err := standard.Get(ctx, "table-test", "k"); !errors.Is(err, transhim.ErrKeyNotFound) {
				t.Errorf("the key written to the custom table is in the default one: err = %v", err)
			}
			if got, err := custom.Get(ctx, "table-test", "k"); err != nil || string(got.Wrapped.Blob) != "in the custom table" {
				t.Errorf("Get from the custom table = %q, %v", got.Wrapped.Blob, err)
			}
		})
	}
}

func TestNewErrors(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := sqlkeystore.New(nil, sqlkeystore.SQLite); err == nil {
		t.Error("New accepted a nil db")
	}
	if _, err := sqlkeystore.New(db, 0); err == nil {
		t.Error("New accepted an unknown dialect")
	}
	// the table name is part of the statements: nothing but a plain name
	for _, name := range []string{"", "keys; DROP TABLE x", "a b", "a.b", `"quoted"`, "1keys", "keys--"} {
		if _, err := sqlkeystore.New(db, sqlkeystore.SQLite, sqlkeystore.WithTable(name)); err == nil {
			t.Errorf("New accepted the table name %q", name)
		}
	}
	if _, err := sqlkeystore.New(db, sqlkeystore.SQLite, sqlkeystore.WithTable("My_keys2")); err != nil {
		t.Errorf("New rejected a plain table name: %v", err)
	}
}

// TestDatabaseFailure: a database that is down must look like a failing key
// service (503, retried by S3 clients), never like a missing key.
func TestDatabaseFailure(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			ctx := t.Context()
			db := d.open(t)
			store, err := sqlkeystore.New(db, d.dialect)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.CreateTable(ctx); err != nil {
				t.Fatal(err)
			}
			db.Close()

			_, getErr := store.Get(ctx, "m", "k")
			putErr := store.PutIfAbsent(ctx, "m", "k", key("x"))
			delErr := store.Delete(ctx, "m", "k")
			for op, err := range map[string]error{"Get": getErr, "PutIfAbsent": putErr, "Delete": delErr} {
				ue, ok := errors.AsType[*transhim.UpstreamError](err)
				if !ok || !ue.Retryable {
					t.Errorf("%s on a closed database: err = %v, want a retryable UpstreamError", op, err)
				}
				if errors.Is(err, transhim.ErrKeyNotFound) || errors.Is(err, hierarchical.ErrKeyExists) {
					t.Errorf("%s on a closed database: err = %v, must not look like an answer", op, err)
				}
			}
			if err := store.CreateTable(ctx); err == nil {
				t.Error("CreateTable on a closed database succeeded")
			}
		})
	}
}

// TestCanceled: a request that went away is not a failure of the database.
func TestCanceled(t *testing.T) {
	for _, d := range databases(t) {
		t.Run(d.name, func(t *testing.T) {
			store := newStore(t, d)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			_, err := store.Get(ctx, "m", "k")
			if !errors.Is(err, context.Canceled) || errors.Is(err, transhim.ErrUpstream) || errors.Is(err, transhim.ErrKeyNotFound) {
				t.Errorf("Get with a canceled context: err = %v, want context.Canceled only", err)
			}
		})
	}
}

func TestSchema(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pg, _ := sqlkeystore.New(db, sqlkeystore.PostgreSQL)
	lite, _ := sqlkeystore.New(db, sqlkeystore.SQLite, sqlkeystore.WithTable("other"))
	for _, tt := range []struct{ schema, table, binary string }{
		{pg.Schema(), "transhim_keys", "BYTEA"},
		{lite.Schema(), "other", "BLOB"},
	} {
		for _, want := range []string{"CREATE TABLE IF NOT EXISTS " + tt.table + " ", tt.binary, "PRIMARY KEY (mount_id, key_name)"} {
			if !strings.Contains(tt.schema, want) {
				t.Errorf("schema lacks %q:\n%s", want, tt.schema)
			}
		}
	}
}
