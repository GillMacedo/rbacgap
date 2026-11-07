.PHONY: test lint demo demo-broken demo-fixed tool

test:
	test -z "$$(gofmt -l plugin tests examples)"
	go vet ./...
	cd examples/bakery && go vet ./...
	cd examples/bakery-fixed && go vet ./...
	go test -race -count=1 ./...

lint:
	claude plugin validate ./plugin --strict
	claude plugin validate . --strict

TOOL := bin/rbacgap

tool:
	@go build -o $(TOOL) ./plugin/scripts

demo: demo-broken demo-fixed

# examples/bakery has five RBAC mistakes on purpose, so exit 1 is the expected result.
demo-broken: tool
	@$(TOOL) --dir examples/bakery || test $$? -eq 1

# The same operator with the mistakes fixed. It must stay quiet and exit 0.
demo-fixed: tool
	@$(TOOL) --dir examples/bakery-fixed
