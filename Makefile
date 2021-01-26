ifdef GIT_VERSION
	VERSION = ${GIT_VERSION}
else
	VERSION = $(shell git describe --always --tags --dirty --abbrev)
endif

guard-%:
	@ if [ "${${*}}" = "" ]; then \
             echo "Environment variable $* not set"; \
             exit 1; \
      fi

GOLANGCI_LINT_VERSION := 1.33.0
LINT_TARGETS = $(shell go list -f '{{.Dir}}' ./... | sed -e"s|${CURDIR}/\(.*\)\$$|\1/...|g" | grep -v ^node_modules/ )
BUILD_TIME = $(shell date +%FT%T%z)
SYSTEM = $(shell uname -s | tr A-Z a-z)_$(shell uname -m | sed "s/x86_64/amd64/")
LDFLAGS = -ldflags="-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"
export CGO_ENABLED=0

.PHONY: build
build:
	env GOOS=linux go build $(LDFLAGS)  -o ./bin/secret-inject-linux-amd64
	env GOOS=darwin go build $(LDFLAGS) -o ./bin/secret-inject-darwin-amd64
	# ToDo add MacOS ARM when it becomes available

.PHONY: install
install:
	go install

# excluding integration tests
.PHONY: test
test:
	go test -cover ./...

.PHONY: start-local-integration-test-environment
start-local-integration-test-environment:
	docker-compose -f ./localstack-docker-compose.yml up -d

.PHONY: stop-local-integration-test-environment
stop-local-integration-test-environment:
	docker-compose -f ./localstack-docker-compose.yml down

# runs all tests including integration tests
.PHONY: integration-test
integration-test:
	go test -cover -tags=integration ./...

/tmp/$(GOLANGCI_LINT_VERSION)/golangci-lint:
	mkdir -p /tmp/$(GOLANGCI_LINT_VERSION)
	curl -sSLf \
		https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_LINT_VERSION)/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(shell echo $(SYSTEM) | tr '_' '-').tar.gz \
		| tar xzOf - golangci-lint-$(GOLANGCI_LINT_VERSION)-$(shell echo $(SYSTEM) | tr '_' '-')/golangci-lint > /tmp/$(GOLANGCI_LINT_VERSION)/golangci-lint && chmod +x /tmp/$(GOLANGCI_LINT_VERSION)/golangci-lint

.PHONY: lint
lint: /tmp/$(GOLANGCI_LINT_VERSION)/golangci-lint
	/tmp/$(GOLANGCI_LINT_VERSION)/golangci-lint run --config ./.golangci.yml $(LINT_TARGETS)
