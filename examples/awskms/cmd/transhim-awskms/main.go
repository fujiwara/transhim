// Command transhim-awskms is an example of a Vault Transit compatible server
// for Ceph RGW, backed by AWS KMS. Copy it and adapt it: transhim itself is a
// library and ships no server.
//
// It serves two mounts, one for each of RGW's two uses of Transit:
//
//   - /v1/transit-kms (SSE-KMS): the key ID of the S3 request "name" is used
//     with the KMS key behind the alias <alias prefix><name>.
//   - /v1/transit-sse-s3 (SSE-S3): RGW creates one key per bucket. They are
//     intermediate keys wrapped by a single KMS root key.
//
// See docs/rgw.md for the matching RGW configuration.
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

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/examples/awskms"
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
	var (
		listen      = flag.String("listen", "127.0.0.1:8200", "address to listen on")
		tokenFile   = flag.String("token-file", "", "file holding the token clients must send (the one RGW reads as rgw_crypt_vault_token_file); required")
		aliasPrefix = flag.String("alias-prefix", "alias/rgw/", "SSE-KMS: prefix of the KMS alias for a key ID")
		rootKey     = flag.String("root-key", "alias/transhim-root", "SSE-S3: KMS key (ID, ARN, or alias) that wraps the per-bucket keys")
		tlsCert     = flag.String("tls-cert", "", "TLS certificate file")
		tlsKey      = flag.String("tls-key", "", "TLS key file")
		insecure    = flag.Bool("insecure-http", false, "serve plain HTTP: data keys cross the network unprotected")
		cacheTTL    = flag.Duration("decrypt-cache-ttl", 5*time.Minute, "how long decrypted data keys are kept in memory; 0 disables the cache")
		kmsEndpoint = flag.String("kms-endpoint", "", "KMS endpoint URL, for an emulator")
	)
	flag.Parse()
	if (*tlsCert == "" || *tlsKey == "") && !*insecure {
		return errors.New("-tls-cert and -tls-key are required (or -insecure-http)")
	}
	if *tokenFile == "" {
		return errors.New("-token-file is required")
	}
	raw, err := os.ReadFile(*tokenFile)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return fmt.Errorf("%s is empty", *tokenFile)
	}

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	client := kms.NewFromConfig(awsCfg, func(o *kms.Options) {
		if *kmsEndpoint != "" {
			o.BaseEndpoint = kmsEndpoint
		}
	})

	// SSE-KMS: S3 users choose the key by name, and RGW does not check that
	// choice. The alias prefix is what limits them to the keys meant for it.
	sseKMS := awskms.New(client, awskms.WithAliasPrefix(*aliasPrefix))

	// SSE-S3: the root backend takes the root key as it is given.
	slog.Warn("per-bucket keys are kept in memory only: SSE-S3 objects become unreadable when this process ends. DO NOT USE IN PRODUCTION without a durable KeyStore")
	sseS3, err := hierarchical.New(awskms.New(client), *rootKey, memstore.New())
	if err != nil {
		return err
	}

	opts := []transhim.Option{
		// The mount IDs are bound into every ciphertext: never change them.
		transhim.Mount("/v1/transit-kms", "rgw-kms", sseKMS),
		transhim.Mount("/v1/transit-sse-s3", "rgw-sse-s3", sseS3),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(token)),
		transhim.WithAuditHook(audit),
	}
	if *cacheTTL > 0 {
		opts = append(opts, transhim.WithDecryptCache(transhim.DecryptCacheConfig{MaxEntries: 10000, TTL: *cacheTTL}))
	}
	handler, err := transhim.NewServer(opts...)
	if err != nil {
		return err
	}

	srv := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", *listen, "tls", !*insecure)
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
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	if ev.Err != nil {
		attrs = append(attrs, "error", ev.Err.Error())
	}
	slog.InfoContext(ctx, "audit", attrs...)
}
