.PHONY: test integration capture

test:
	go test -race ./...

# The acceptance test: a real Ceph RGW doing SSE-KMS and SSE-S3 against
# transhim. Another release: CEPH_IMAGE=quay.io/ceph/ceph:v19.2.7 make integration
integration:
	docker compose up -d --wait ceph
	cd integration && TRANSHIM_TEST_RGW_ENDPOINT=http://127.0.0.1:7480 go test -race -count=1 ./...

# Re-captures Ceph RGW's Transit requests (docs/compat.md).
capture:
	compat/capture.sh
