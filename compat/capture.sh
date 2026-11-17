#!/bin/bash
# Captures the Vault Transit requests Ceph RGW makes for SSE-KMS and SSE-S3,
# plus a set of direct probes of the reference implementation (OpenBao).
#
#   RGW --> vaultrec (127.0.0.1:8201, records) --> OpenBao (127.0.0.1:8200)
#
# Usage: compat/capture.sh            (Ceph image pinned in compose.yml)
#        CEPH_IMAGE=quay.io/ceph/ceph:v19.2.7 compat/capture.sh
#
# Output: testdata/capture/ceph-<version>.jsonl (replaced on every run), named
# after the Ceph version the container reports. Marker lines ("mark") say
# which S3 operation or probe caused the exchanges that follow, and carry its
# outcome.
#
# CEPH_EXTRA_ARGS is passed through to the Ceph daemons (see compose.yml).
#
# EMPTY_KEY_WRITES=1 makes the recorder answer successful key create/config
# calls with 204 and no body, as transhim will, instead of OpenBao's 200 with
# key metadata. The output file then gets the suffix "-empty-key-writes".
#
# Needs docker compose, go, curl, jq and the aws CLI. Everything it starts is
# torn down on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${VAULT_TOKEN:=transhim-dev-token}"
export VAULT_TOKEN
BAO=http://127.0.0.1:8200
REC=http://127.0.0.1:8201
RGW=http://127.0.0.1:7480

ceph_image=${CEPH_IMAGE:-$(sed -n 's/.*CEPH_IMAGE:-\(.*\)}$/\1/p' compose.yml)}
work=$(mktemp -d)
rec_out=$work/capture.jsonl
rec_pid=

compose() { docker compose --profile ceph --profile openbao "$@"; }

cleanup() {
  [ -z "$rec_pid" ] || kill "$rec_pid" 2>/dev/null || true
  compose down -v >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
trap 'echo "capture failed at line $LINENO" >&2' ERR

# The aws CLI must talk to the local RGW only: no profile, no config files.
unset AWS_PROFILE AWS_SESSION_TOKEN
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
export AWS_ACCESS_KEY_ID=backendkey AWS_SECRET_ACCESS_KEY=backendsecret
export AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true AWS_PAGER=

mark() { curl -fsS -o /dev/null -X POST -G --data-urlencode "label=$1" "$REC/__mark"; }

# s3 LABEL ARGS...: runs "aws s3api ARGS", bracketed by markers. The closing
# marker records how the S3 client saw the operation end. The status and error
# code are read from the wire (--debug), not from the CLI's own message: the
# CLI crashes on the empty <Message> older RGW releases put in some errors.
s3() {
  local label=$1 rc=0 status code msg
  shift
  mark "s3: $label"
  aws --endpoint-url "$RGW" s3api "$@" --debug >"$work/s3.out" 2>"$work/s3.err" || rc=$?
  if [ "$rc" -eq 0 ]; then
    mark "s3 result: ok"
    return
  fi
  status=$(sed -n 's/.*" \([0-9][0-9][0-9]\) [0-9]*$/\1/p' "$work/s3.err" | tail -1)
  code=$(grep -o '<Code>[^<]*</Code>' "$work/s3.err" | tail -1 | sed 's/<[^>]*>//g')
  msg=$(grep -o '<Message>[^<]*</Message>' "$work/s3.err" | tail -1 | sed 's/<[^>]*>//g')
  mark "s3 result: error status=${status:-?} code=${code:-?} message=\"$msg\""
}

# probe LABEL METHOD PATH [BODY]: one direct request through the recorder.
# Prints the response body.
probe() {
  local label=$1 method=$2 path=$3 body=${4-}
  mark "probe: $label"
  if [ -n "$body" ]; then
    curl -sS -X "$method" -H "X-Vault-Token: $VAULT_TOKEN" -d "$body" "$REC$path"
  else
    curl -sS -X "$method" -H "X-Vault-Token: $VAULT_TOKEN" "$REC$path"
  fi
}

bao() { curl -fsS -H "X-Vault-Token: $VAULT_TOKEN" "$@"; }

echo "== start OpenBao"
compose down -v >/dev/null 2>&1 || true
compose up -d --wait openbao
for m in transit-kms transit-sse-s3 transit; do
  bao -X POST -d '{"type":"transit"}' "$BAO/v1/sys/mounts/$m"
done
# SSE-KMS keys are provisioned by the operator, not by RGW
bao -X POST "$BAO/v1/transit-kms/keys/testkey-1" >/dev/null
bao -X POST "$BAO/v1/transit-kms/keys/testkey-2" >/dev/null

echo "== start recorder"
go build -o "$work/vaultrec" ./tools/vaultrec
rec_args=() suffix=
if [ -n "${EMPTY_KEY_WRITES:-}" ]; then
  rec_args=(-empty-key-writes) suffix=-empty-key-writes
fi
"$work/vaultrec" -listen 127.0.0.1:8201 -upstream "$BAO" -out "$rec_out" "${rec_args[@]}" &
rec_pid=$!
for _ in $(seq 1 50); do curl -fsS -o /dev/null -X POST "$REC/__mark?label=recorder+is+up" 2>/dev/null && break; sleep 0.1; done

echo "== start Ceph RGW ($ceph_image)"
CEPH_IMAGE=$ceph_image compose up -d --wait ceph
ceph_version=$(compose exec -T ceph ceph --version)
bao_version=$(bao "$BAO/v1/sys/seal-status" | jq -r .version)
mark "rgw is up: $ceph_version; image $ceph_image; reference OpenBao $bao_version${suffix:+; recorder$suffix}"
out=testdata/capture/ceph-v$(echo "$ceph_version" | awk '{print $3}')$suffix.jsonl

head -c 1024 /dev/urandom >"$work/small"
head -c $((5 * 1024 * 1024)) /dev/urandom >"$work/part"

# multipart LABEL BUCKET KEY ARGS...: two-part upload; ARGS go to CreateMultipartUpload
multipart() {
  local label=$1 bucket=$2 key=$3 id
  shift 3
  s3 "$label: CreateMultipartUpload" create-multipart-upload --bucket "$bucket" --key "$key" "$@"
  id=$(jq -r .UploadId "$work/s3.out")
  s3 "$label: UploadPart 1" upload-part --bucket "$bucket" --key "$key" --upload-id "$id" --part-number 1 --body "$work/part"
  local e1; e1=$(jq -r .ETag "$work/s3.out")
  s3 "$label: UploadPart 2" upload-part --bucket "$bucket" --key "$key" --upload-id "$id" --part-number 2 --body "$work/small"
  local e2; e2=$(jq -r .ETag "$work/s3.out")
  s3 "$label: CompleteMultipartUpload" complete-multipart-upload --bucket "$bucket" --key "$key" --upload-id "$id" \
    --multipart-upload "{\"Parts\":[{\"PartNumber\":1,\"ETag\":$e1},{\"PartNumber\":2,\"ETag\":$e2}]}"
  s3 "$label: GetObject" get-object --bucket "$bucket" --key "$key" "$work/got"
}

echo "== SSE-KMS"
s3 "kms: CreateBucket" create-bucket --bucket kms-bucket
s3 "kms: PutObject (aws:kms, testkey-1)" put-object --bucket kms-bucket --key obj1 --body "$work/small" \
  --server-side-encryption aws:kms --ssekms-key-id testkey-1
s3 "kms: HeadObject" head-object --bucket kms-bucket --key obj1
s3 "kms: GetObject" get-object --bucket kms-bucket --key obj1 "$work/got"
cmp "$work/small" "$work/got"
s3 "kms: GetObject again" get-object --bucket kms-bucket --key obj1 "$work/got"
s3 "kms: GetObject range" get-object --bucket kms-bucket --key obj1 --range bytes=0-9 "$work/got"
s3 "kms: PutObject second object, same key" put-object --bucket kms-bucket --key obj2 --body "$work/small" \
  --server-side-encryption aws:kms --ssekms-key-id testkey-1
s3 "kms: PutObject with encryption context" put-object --bucket kms-bucket --key obj-ctx --body "$work/small" \
  --server-side-encryption aws:kms --ssekms-key-id testkey-1 \
  --ssekms-encryption-context "$(printf '{"purpose":"test"}' | base64 -w0)"
s3 "kms: GetObject with encryption context" get-object --bucket kms-bucket --key obj-ctx "$work/got"
s3 "kms: CopyObject (testkey-1 -> testkey-2)" copy-object --bucket kms-bucket --key obj-copy --copy-source kms-bucket/obj1 \
  --server-side-encryption aws:kms --ssekms-key-id testkey-2
s3 "kms: GetObject copy" get-object --bucket kms-bucket --key obj-copy "$work/got"
multipart "kms multipart" kms-bucket obj-mp --server-side-encryption aws:kms --ssekms-key-id testkey-1
s3 "kms: PutObject with a key ID Vault does not have" put-object --bucket kms-bucket --key obj-nokey --body "$work/small" \
  --server-side-encryption aws:kms --ssekms-key-id no-such-key
s3 "kms: PutObject with a slash in the key ID" put-object --bucket kms-bucket --key obj-slash --body "$work/small" \
  --server-side-encryption aws:kms --ssekms-key-id some/key
s3 "kms: PutObject without a key ID" put-object --bucket kms-bucket --key obj-noid --body "$work/small" \
  --server-side-encryption aws:kms
s3 "kms: PutBucketEncryption (default aws:kms, testkey-2)" put-bucket-encryption --bucket kms-bucket \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"testkey-2"}}]}'
s3 "kms: PutObject without SSE headers (bucket default)" put-object --bucket kms-bucket --key obj-default --body "$work/small"
s3 "kms: GetObject (bucket default)" get-object --bucket kms-bucket --key obj-default "$work/got"
# the operator removes a key behind RGW's back
bao -X POST -d '{"deletion_allowed":true}' "$BAO/v1/transit-kms/keys/testkey-2/config" >/dev/null
bao -X DELETE "$BAO/v1/transit-kms/keys/testkey-2"
s3 "kms: GetObject after the key was deleted in Vault" get-object --bucket kms-bucket --key obj-copy "$work/got"
for k in obj1 obj2 obj-ctx obj-copy obj-mp obj-default; do
  s3 "kms: DeleteObject $k" delete-object --bucket kms-bucket --key "$k"
done
s3 "kms: DeleteBucket" delete-bucket --bucket kms-bucket

echo "== SSE-S3"
default_aes='{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# per-request SSE-S3 header first, bucket default later
s3 "sse-s3: CreateBucket" create-bucket --bucket s3-bucket
s3 "sse-s3: PutObject without SSE (no key expected)" put-object --bucket s3-bucket --key plain --body "$work/small"
s3 "sse-s3: PutObject (AES256), first in bucket" put-object --bucket s3-bucket --key obj1 --body "$work/small" \
  --server-side-encryption AES256
s3 "sse-s3: PutObject (AES256), second in bucket" put-object --bucket s3-bucket --key obj2 --body "$work/small" \
  --server-side-encryption AES256
s3 "sse-s3: HeadObject" head-object --bucket s3-bucket --key obj1
s3 "sse-s3: GetObject" get-object --bucket s3-bucket --key obj1 "$work/got"
cmp "$work/small" "$work/got"
s3 "sse-s3: CopyObject" copy-object --bucket s3-bucket --key obj-copy --copy-source s3-bucket/obj1 \
  --server-side-encryption AES256
multipart "sse-s3 multipart" s3-bucket obj-mp --server-side-encryption AES256
s3 "sse-s3: PutBucketEncryption (default AES256)" put-bucket-encryption --bucket s3-bucket \
  --server-side-encryption-configuration "$default_aes"
s3 "sse-s3: PutObject without SSE headers (bucket default)" put-object --bucket s3-bucket --key obj-default --body "$work/small"
s3 "sse-s3: GetObject (bucket default)" get-object --bucket s3-bucket --key obj-default "$work/got"
s3 "sse-s3: DeleteBucket while not empty" delete-bucket --bucket s3-bucket
for k in plain obj1 obj2 obj-copy obj-mp obj-default; do
  s3 "sse-s3: DeleteObject $k" delete-object --bucket s3-bucket --key "$k"
done
s3 "sse-s3: DeleteBucket" delete-bucket --bucket s3-bucket

# per-request header only, never a bucket default
s3 "sse-s3 header-only: CreateBucket" create-bucket --bucket s3-header
s3 "sse-s3 header-only: PutObject (AES256)" put-object --bucket s3-header --key obj1 --body "$work/small" \
  --server-side-encryption AES256
s3 "sse-s3 header-only: DeleteObject" delete-object --bucket s3-header --key obj1
s3 "sse-s3 header-only: DeleteBucket" delete-bucket --bucket s3-header

# bucket default set on an empty bucket
s3 "sse-s3 default-first: CreateBucket" create-bucket --bucket s3-default
s3 "sse-s3 default-first: PutBucketEncryption (default AES256) on an empty bucket" put-bucket-encryption --bucket s3-default \
  --server-side-encryption-configuration "$default_aes"
s3 "sse-s3 default-first: PutObject" put-object --bucket s3-default --key obj1 --body "$work/small"
s3 "sse-s3 default-first: DeleteObject" delete-object --bucket s3-default --key obj1
s3 "sse-s3 default-first: DeleteBucket" delete-bucket --bucket s3-default

# DeleteBucketEncryption in the middle of a bucket's life
s3 "sse-s3 unconfigure: CreateBucket" create-bucket --bucket s3-unconf
s3 "sse-s3 unconfigure: PutObject (AES256)" put-object --bucket s3-unconf --key obj1 --body "$work/small" \
  --server-side-encryption AES256
s3 "sse-s3 unconfigure: DeleteBucketEncryption" delete-bucket-encryption --bucket s3-unconf
s3 "sse-s3 unconfigure: GetObject written before" get-object --bucket s3-unconf --key obj1 "$work/got"
s3 "sse-s3 unconfigure: PutObject (AES256) after" put-object --bucket s3-unconf --key obj2 --body "$work/small" \
  --server-side-encryption AES256
s3 "sse-s3 unconfigure: GetObject written before, again" get-object --bucket s3-unconf --key obj1 "$work/got"
cmp "$work/small" "$work/got"
s3 "sse-s3 unconfigure: DeleteBucketEncryption again" delete-bucket-encryption --bucket s3-unconf
s3 "sse-s3 unconfigure: DeleteObject obj1" delete-object --bucket s3-unconf --key obj1
s3 "sse-s3 unconfigure: DeleteObject obj2" delete-object --bucket s3-unconf --key obj2
s3 "sse-s3 unconfigure: DeleteBucket" delete-bucket --bucket s3-unconf

# never encrypted
s3 "sse-s3 unused: CreateBucket" create-bucket --bucket s3-unused
s3 "sse-s3 unused: DeleteBucket (never encrypted)" delete-bucket --bucket s3-unused

echo "== direct probes of the reference implementation"
T=/v1/transit
b64() { printf '%s' "$1" | base64 -w0; }
ctx=$(b64 'some context')

probe "create key, empty body" POST $T/keys/probe >/dev/null
probe "create key again (idempotent?)" POST $T/keys/probe >/dev/null
probe "create key with PUT" PUT $T/keys/probe-put >/dev/null
probe "create key, the body RGW sends for SSE-S3" POST $T/keys/probe-derived '{"type":"chacha20-poly1305","derived":true}' >/dev/null
probe "create key, exportable" POST $T/keys/probe-exportable '{"exportable":true}' >/dev/null
probe "read key" GET $T/keys/probe >/dev/null
probe "read derived key" GET $T/keys/probe-derived >/dev/null
probe "read missing key" GET $T/keys/no-such-key >/dev/null

dk=$(probe "datakey, empty body" POST $T/datakey/plaintext/probe)
probe "datakey, {}" POST $T/datakey/plaintext/probe '{}' >/dev/null
probe "datakey, empty context string" POST $T/datakey/plaintext/probe '{"context":""}' >/dev/null
dkctx=$(probe "datakey, context on a non-derived key" POST $T/datakey/plaintext/probe "{\"context\":\"$ctx\"}")
probe "datakey, bits=128" POST $T/datakey/plaintext/probe '{"bits":128}' >/dev/null
probe "datakey, bits=512" POST $T/datakey/plaintext/probe '{"bits":512}' >/dev/null
probe "datakey, bits=123" POST $T/datakey/plaintext/probe '{"bits":123}' >/dev/null
probe "datakey, context is not base64" POST $T/datakey/plaintext/probe '{"context":"!!!"}' >/dev/null
probe "datakey, malformed JSON" POST $T/datakey/plaintext/probe '{"context":' >/dev/null
probe "datakey, missing key" POST $T/datakey/plaintext/no-such-key '{"context":""}' >/dev/null
probe "datakey, GET" GET $T/datakey/plaintext/probe >/dev/null
dkd=$(probe "datakey, derived key with context" POST $T/datakey/plaintext/probe-derived "{\"context\":\"$ctx\"}")
probe "datakey, derived key without context" POST $T/datakey/plaintext/probe-derived '{"context":""}' >/dev/null

ct=$(echo "$dk" | jq -r .data.ciphertext)
ctctx=$(echo "$dkctx" | jq -r .data.ciphertext)
ctd=$(echo "$dkd" | jq -r .data.ciphertext)
probe "decrypt" POST $T/decrypt/probe "{\"ciphertext\":\"$ct\"}" >/dev/null
probe "decrypt, empty context string" POST $T/decrypt/probe "{\"ciphertext\":\"$ct\",\"context\":\"\"}" >/dev/null
probe "decrypt, context added on a non-derived key" POST $T/decrypt/probe "{\"ciphertext\":\"$ct\",\"context\":\"$ctx\"}" >/dev/null
probe "decrypt, context dropped on a non-derived key" POST $T/decrypt/probe "{\"ciphertext\":\"$ctctx\"}" >/dev/null
probe "decrypt, derived key, right context" POST $T/decrypt/probe-derived "{\"ciphertext\":\"$ctd\",\"context\":\"$ctx\"}" >/dev/null
probe "decrypt, derived key, wrong context" POST $T/decrypt/probe-derived "{\"ciphertext\":\"$ctd\",\"context\":\"$(b64 other)\"}" >/dev/null
probe "decrypt, derived key, no context" POST $T/decrypt/probe-derived "{\"ciphertext\":\"$ctd\"}" >/dev/null
probe "decrypt, wrong key" POST $T/decrypt/probe-put "{\"ciphertext\":\"$ct\"}" >/dev/null
probe "decrypt, missing key" POST $T/decrypt/no-such-key "{\"ciphertext\":\"$ct\"}" >/dev/null
tampered="${ct%????}AAAA"
probe "decrypt, tampered ciphertext" POST $T/decrypt/probe "{\"ciphertext\":\"$tampered\"}" >/dev/null
probe "decrypt, version that does not exist" POST $T/decrypt/probe "{\"ciphertext\":\"vault:v9:${ct#vault:v1:}\"}" >/dev/null
probe "decrypt, no vault prefix" POST $T/decrypt/probe "{\"ciphertext\":\"${ct#vault:v1:}\"}" >/dev/null
probe "decrypt, payload is not base64" POST $T/decrypt/probe '{"ciphertext":"vault:v1:!!!"}' >/dev/null
probe "decrypt, no ciphertext" POST $T/decrypt/probe '{}' >/dev/null

enc=$(probe "encrypt" POST $T/encrypt/probe "{\"plaintext\":\"$(b64 hello)\"}")
probe "encrypt, with context" POST $T/encrypt/probe "{\"plaintext\":\"$(b64 hello)\",\"context\":\"$ctx\"}" >/dev/null
probe "encrypt, no plaintext" POST $T/encrypt/probe '{}' >/dev/null
probe "encrypt, plaintext is not base64" POST $T/encrypt/probe '{"plaintext":"!!!"}' >/dev/null
probe "encrypt, missing key (auto-create?)" POST $T/encrypt/auto-created "{\"plaintext\":\"$(b64 hello)\"}" >/dev/null
probe "decrypt what encrypt returned" POST $T/decrypt/probe "{\"ciphertext\":\"$(echo "$enc" | jq -r .data.ciphertext)\"}" >/dev/null

probe "delete key without deletion_allowed" DELETE $T/keys/probe >/dev/null
probe "config deletion_allowed" POST $T/keys/probe/config '{"deletion_allowed":true}' >/dev/null
probe "delete key" DELETE $T/keys/probe >/dev/null
probe "delete key again (missing)" DELETE $T/keys/probe >/dev/null
probe "config on a missing key" POST $T/keys/no-such-key/config '{"deletion_allowed":true}' >/dev/null
probe "decrypt after the key was deleted" POST $T/decrypt/probe "{\"ciphertext\":\"$ct\"}" >/dev/null

probe "unknown operation" POST $T/nope/probe-put '{}' >/dev/null
probe "unknown mount" POST /v1/no-such-mount/datakey/plaintext/probe-put '{}' >/dev/null
mark "probe: no token"
curl -sS -o /dev/null -X POST -d '{}' "$REC$T/datakey/plaintext/probe-put"
mark "probe: wrong token"
curl -sS -o /dev/null -X POST -H 'X-Vault-Token: wrong' -d '{}' "$REC$T/datakey/plaintext/probe-put"
mark "end"

mkdir -p "$(dirname "$out")"
cp "$rec_out" "$out"
echo "== done: $(grep -c '"request"' "$out") exchanges in $out"
