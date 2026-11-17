.PHONY: test capture

test:
	go test -race ./...

# Re-captures Ceph RGW's Transit requests (docs/compat.md).
capture:
	compat/capture.sh
