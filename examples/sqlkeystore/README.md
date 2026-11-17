# SQL key store example

An example `hierarchical.KeyStore` on an SQL database (package `sqlkeystore`): PostgreSQL or SQLite, through `database/sql`. It is what replaces `keystore/memstore` when the per-bucket keys of Ceph RGW SSE-S3 have to survive a restart. It is a Go module of its own; copy and adapt it.

```go
import _ "github.com/jackc/pgx/v5/stdlib" // or another database/sql driver

db, err := sql.Open("pgx", "postgres://user:password@host/dbname")
store, err := sqlkeystore.New(db, sqlkeystore.PostgreSQL)
err = store.CreateTable(ctx) // CREATE TABLE IF NOT EXISTS; or apply store.Schema() yourself

sseS3, err := hierarchical.New(kmsBackend, rootKeyName, store)
```

The package imports no driver. For SQLite, open the database with a driver such as `modernc.org/sqlite` and pass `sqlkeystore.SQLite`.

## The table

One row per key:

```sql
CREATE TABLE IF NOT EXISTS transhim_keys (
    mount_id   TEXT    NOT NULL,
    key_name   TEXT    NOT NULL,
    key_ref    TEXT    NOT NULL,
    version    INTEGER NOT NULL,
    wrapped    BYTEA   NOT NULL,  -- BLOB on SQLite
    created_at BIGINT  NOT NULL,  -- microseconds since the Unix epoch
    PRIMARY KEY (mount_id, key_name)
)
```

- `wrapped` is the bucket's intermediate key, wrapped by the KMS root key. Nobody without access to the root key can use it, so the table does not have to be secret.
- The primary key is what makes key creation safe when several servers create the same bucket's key at once: `INSERT ... ON CONFLICT DO NOTHING` lets exactly one of them win.
- `WithTable` changes the table name.

## What to take care of

- **Back the database up.** A lost row loses every object of that bucket. The whole SSE-S3 data of the cluster depends on this table.
- **Deleting is for good, except for backups.** When RGW deletes a bucket, the row is deleted, and the bucket's data cannot be read anymore. A backup made before still has the row, for as long as it is kept.
- **Keep write access narrow.** Whoever can delete or overwrite rows can make data unreadable.
- **Read where you write.** RGW asks for a data key right after it had a bucket's key created. A read replica that lags answers that the key does not exist, and the write fails. Use the primary, or a synchronous replica.
- **Key columns must compare byte by byte.** Key names that differ only in case or in trailing spaces are different keys. PostgreSQL's `text` and SQLite's `TEXT` do. This is why MySQL and MariaDB are not supported as they are: their usual collations are case-insensitive, and `ON CONFLICT` is spelled differently.
- **SQLite is for a single server instance.** Open it with a busy timeout (`_pragma=busy_timeout(10000)` with `modernc.org/sqlite`), and keep the file on storage that survives the host.
- A failing database is reported as a failing key service: clients get `503`, which S3 SDKs retry, never "key not found".

## Tests

```console
$ go test ./...                               # SQLite, in a temporary file
$ docker compose up -d --wait postgres        # in the repository root
$ TRANSHIM_TEST_POSTGRES_DSN=postgres://transhim:transhim@127.0.0.1:15432/transhim go test ./...
```

The tests run `transhimtest.RunKeyStoreConformance`, which checks the contract of `hierarchical.KeyStore`. Run it against a store of your own, too:

```go
func TestMyStore(t *testing.T) {
	transhimtest.RunKeyStoreConformance(t, mystore.New(db))
}
```

It cannot check durability. `TestSurvivesRestart` here shows the kind of test that does.
