// Command transhim-sakurakms is an example of a Vault Transit compatible
// server for Ceph RGW, backed by SAKURA Cloud KMS. Copy it and adapt it:
// transhim itself is a library and ships no server.
//
// It serves two mounts, one for each of RGW's two uses of Transit:
//
//   - /v1/transit-kms (SSE-KMS): the key ID of the S3 request must be one of
//     the names given with -key, and is used with the KMS key of that name.
//   - /v1/transit-sse-s3 (SSE-S3): RGW creates one key per bucket. They are
//     intermediate keys wrapped by a single KMS root key (-root-key).
//
// See docs/rgw.md for the matching RGW configuration.
//
// The KMS client takes its credentials from the usual SAKURA Cloud settings
// (SAKURA_ACCESS_TOKEN and SAKURA_ACCESS_TOKEN_SECRET, or a profile), and
// SAKURA_ENDPOINTS_KMS points it at another endpoint, such as sakumock.
//
// The intermediate keys are kept in memory. That is only good for trying it
// out: after a restart every SSE-S3 object is unreadable. Replace memstore
// with a durable hierarchical.KeyStore before storing anything you need.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sacloud/sacloud-sdk-go/api/kms"
	"github.com/sacloud/sacloud-sdk-go/common/saclient"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/examples/sakurakms"
	"github.com/fujiwara/transhim/hierarchical"
	"github.com/fujiwara/transhim/keystore/memstore"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	keys := map[string]string{}
	var (
		listen      = flag.String("listen", "127.0.0.1:8200", "address to listen on")
		tokenFile   = flag.String("token-file", "", "file holding the token clients must send (the one RGW reads as rgw_crypt_vault_token_file); required")
		rootKey     = flag.String("root-key", "", "SSE-S3: resource ID of the KMS key that wraps the per-bucket keys; required")
		tlsCert     = flag.String("tls-cert", "", "TLS certificate file")
		tlsKey      = flag.String("tls-key", "", "TLS key file")
		insecure    = flag.Bool("insecure-http", false, "serve plain HTTP: data keys cross the network unprotected")
		cacheTTL    = flag.Duration("decrypt-cache-ttl", 5*time.Minute, "how long decrypted data keys are kept in memory; 0 disables the cache")
		keyCacheTTL = flag.Duration("key-cache-ttl", hierarchical.DefaultKeyCacheTTL, "SSE-S3: how long an unwrapped per-bucket key is kept in memory")
	)
	flag.Func("key", "SSE-KMS: `NAME=ID`, a key ID S3 clients may use and the resource ID of its KMS key; repeatable", func(v string) error {
		name, id, ok := strings.Cut(v, "=")
		if !ok || name == "" || id == "" {
			return errors.New("want NAME=ID")
		}
		keys[name] = id
		return nil
	})
	flag.Parse()
	if (*tlsCert == "" || *tlsKey == "") && !*insecure {
		return errors.New("-tls-cert and -tls-key are required (or -insecure-http)")
	}
	if *tokenFile == "" || *rootKey == "" {
		return errors.New("-token-file and -root-key are required")
	}
	raw, err := os.ReadFile(*tokenFile)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return fmt.Errorf("%s is empty", *tokenFile)
	}

	var sa saclient.Client
	apiClient, err := kms.NewClient(&sa)
	if err != nil {
		return err
	}
	keyOp := kms.NewKeyOp(apiClient)

	// SSE-KMS: S3 users choose the key by name, and RGW does not check that
	// choice. Only the names given with -key can be used.
	sseKMS := sakurakms.New(keyOp, sakurakms.WithKeys(keys))

	// SSE-S3: the root backend takes the root key's resource ID as it is.
	slog.Warn("per-bucket keys are kept in memory only: SSE-S3 objects become unreadable when this process ends. DO NOT USE IN PRODUCTION without a durable KeyStore")
	sseS3, err := hierarchical.New(sakurakms.New(keyOp), *rootKey, memstore.New(), hierarchical.WithKeyCacheTTL(*keyCacheTTL))
	if err != nil {
		return err
	}

	opts := []transhim.Option{
		// The mount IDs are bound into every ciphertext: never change them.
		transhim.Mount("/v1/transit-kms", "rgw-kms", sseKMS, transhim.WithMaxPlaintextSize(sakurakms.MaxPlaintextSize)),
		transhim.Mount("/v1/transit-sse-s3", "rgw-sse-s3", sseS3),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(token)),
		transhim.WithAuditHook(audit),
	}
	if *cacheTTL > 0 {
		opts = append(opts, transhim.WithDecryptCache(transhim.DecryptCacheConfig{
			MaxEntries: 10000,
			TTL:        *cacheTTL,
			// A KMS call takes seconds. RGW decrypts the data key of a
			// multipart upload right after it got it; this saves that call.
			WarmOnDatakey: true,
		}))
	}
	handler, err := transhim.NewServer(opts...)
	if err != nil {
		return err
	}

	srv := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", *listen, "tls", !*insecure, "sse_kms_keys", len(keys))
		if *insecure {
			errc <- srv.ListenAndServe()
		} else {
			errc <- srv.ListenAndServeTLS(*tlsCert, *tlsKey)
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	// a KMS call in flight can take a while
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// audit logs every request. It must not block: slog to stderr is fine here; a
// slow sink needs a queue.
func audit(ctx context.Context, ev transhim.AuditEvent) {
	attrs := []any{
		"op", string(ev.Op), "mount_id", ev.MountID, "key_name", ev.KeyName,
		"status", ev.Status, "cache_hit", ev.CacheHit, "duration", ev.Duration,
		"remote_addr", ev.RemoteAddr, "request_id", ev.RequestID,
	}
	if ev.Context != nil {
		// With Ceph RGW: a JSON object naming the S3 object the request is
		// for. With SSE-KMS the S3 user can change it, so it is a record of
		// what was claimed, not proof.
		attrs = append(attrs, "context", string(ev.Context))
	}
	if ev.Err != nil {
		attrs = append(attrs, "error", ev.Err.Error())
	}
	slog.InfoContext(ctx, "audit", attrs...)
}
