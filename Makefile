.PHONY: clean test capture

transhim: go.* *.go
	go build -o $@ ./cmd/transhim

clean:
	rm -rf transhim dist/

test:
	go test -race ./...

# Re-captures Ceph RGW's Transit requests (docs/compat.md).
capture:
	compat/capture.sh

install:
	go install github.com/fujiwara/transhim/cmd/transhim

dist:
	goreleaser build --snapshot --clean
