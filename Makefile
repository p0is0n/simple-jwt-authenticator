.PHONY: \
	build \
	build-server \
	build-cli \
	test \
	test-race \
	test-integration \
	test-benchmark \
	test-benchmark-save \
	fmt \
	fmt-check \
	vet \
	lint \
	check \
	check-all \
	docker-build \
	docker-build-server \
	docker-build-cli \
	docker-run-server \
	docker-run-cli \
	token-generate \
	token-validate

CONTAINER_SERVER ?= simple-jwt-authenticator-server
CONTAINER_CLI ?= simple-jwt-authenticator-cli

IMAGE_SERVER ?= simple-jwt-authenticator-server
IMAGE_CLI ?= simple-jwt-authenticator-cli
IMAGE_TAG ?= latest

SERVER_PORT ?= 8080

SERVER_CONFIG ?= $(CURDIR)/config/server.yaml
SERVER_SECRETS ?= $(CURDIR)/secrets

CLI_CONFIG ?= $(CURDIR)/config/cli.yaml
CLI_SECRETS ?= $(CURDIR)/secrets
CLI_CONFIG_CONTAINER ?= /app/config.yaml

CLI_ARGS ?=

build: build-server build-cli

build-server:
	go build -o bin/server ./cmd/server

build-cli:
	go build -o bin/cli ./cmd/cli

test:
	go test -v ./...

test-race:
	go test -v -race ./...

test-integration:
	go test -v -tags=integration ./tests/integration/...

test-benchmark:
	go test \
		-run '^$$' \
		-bench . \
		-benchmem \
		./...

test-benchmark-save:
	go test \
		-run '^$$' \
		-bench . \
		-benchmem \
		-count=$(BENCH_COUNT) \
		./... \
		> $(BENCH_OUTPUT)

fmt:
	goimports -w .

fmt-check:
	@test -z "$$(goimports -l .)" || \
		(echo "Files require formatting:"; goimports -l .; exit 1)

vet:
	go vet ./...

lint:
	golangci-lint run

check: fmt-check vet lint test

check-all: fmt-check vet lint test-race test-integration

docker-build: docker-build-server docker-build-cli

docker-build-server:
	docker build \
		--target server \
		-t $(IMAGE_SERVER):$(IMAGE_TAG) \
		.

docker-build-cli:
	docker build \
		--target cli \
		-t $(IMAGE_CLI):$(IMAGE_TAG) \
		.

docker-run-server:
	@test -f "$(SERVER_CONFIG)" || \
		(echo "SERVER_CONFIG file does not exist: $(SERVER_CONFIG)"; \
		exit 1)
	@test -d "$(SERVER_SECRETS)" || \
		(echo "SERVER_SECRETS directory does not exist: $(SERVER_SECRETS)"; \
		exit 1)
	docker run --rm \
		--name $(CONTAINER_SERVER) \
		-p $(SERVER_PORT):8080 \
		-v "$(SERVER_CONFIG):/app/config.yaml:ro" \
		-v "$(SERVER_SECRETS):/run/secrets:ro" \
		$(IMAGE_SERVER):$(IMAGE_TAG) \
		/app/config.yaml

docker-run-cli:
	docker run --rm \
		--name $(CONTAINER_CLI) \
		$(IMAGE_CLI):$(IMAGE_TAG) \
		$(CLI_ARGS)

token-generate:
	@test -f "$(CLI_CONFIG)" || \
		(echo "CLI_CONFIG file does not exist: $(CLI_CONFIG)"; \
		exit 1)
	@test -d "$(CLI_SECRETS)" || \
		(echo "CLI_SECRETS directory does not exist: $(CLI_SECRETS)"; \
		exit 1)
	@test -n "$(TOKEN_SUBJECT)" || \
		(echo "TOKEN_SUBJECT is required"; \
		echo; \
		echo "Usage:"; \
		echo "  make token-generate TOKEN_SUBJECT=user-123"; \
		echo; \
		echo "Optional:"; \
		echo "  TOKEN_USERNAME=alex"; \
		echo "  TOKEN_EMAIL=user@example.com"; \
		echo "  TOKEN_AUDIENCE=internal-services"; \
		echo "  TOKEN_TTL=1h"; \
		echo; \
		echo "Example:"; \
		echo "  make token-generate TOKEN_SUBJECT=user-123 TOKEN_USERNAME=arkadiy TOKEN_TTL=1h"; \
		exit 1)
	docker run --rm \
		--name $(CONTAINER_CLI) \
		-v "$(CLI_CONFIG):$(CLI_CONFIG_CONTAINER):ro" \
		-v "$(CLI_SECRETS):/run/secrets:ro" \
		$(IMAGE_CLI):$(IMAGE_TAG) \
		token generate \
		--config "$(CLI_CONFIG_CONTAINER)" \
		--subject "$(TOKEN_SUBJECT)" \
		$(if $(TOKEN_USERNAME),--username "$(TOKEN_USERNAME)") \
		$(if $(TOKEN_EMAIL),--email "$(TOKEN_EMAIL)") \
		$(if $(TOKEN_AUDIENCE),--audience "$(TOKEN_AUDIENCE)") \
		$(if $(TOKEN_TTL),--ttl "$(TOKEN_TTL)")

token-validate:
	@test -f "$(CLI_CONFIG)" || \
		(echo "CLI_CONFIG file does not exist: $(CLI_CONFIG)"; \
		exit 1)

	@test -d "$(CLI_SECRETS)" || \
		(echo "CLI_SECRETS directory does not exist: $(CLI_SECRETS)"; \
		exit 1)

	@test -n "$(TOKEN)" || \
		(echo "TOKEN is required"; \
		echo; \
		echo "Usage:"; \
		echo '  make token-validate TOKEN="eyJ..."'; \
		echo '  make token-validate TOKEN="eyJ..." CLAIM_EXPRESSION='\''subject == "camera-front"'\'''; \
		echo; \
		echo "Example:"; \
		echo '  make token-validate TOKEN="$$TOKEN"'; \
		echo '  make token-validate TOKEN="$$TOKEN" CLAIM_EXPRESSION='\''subject == "camera-front" && audience == "frigate"'\'''; \
		exit 1)

	docker run --rm \
		--name $(CONTAINER_CLI) \
		-v "$(CLI_CONFIG):$(CLI_CONFIG_CONTAINER):ro" \
		-v "$(CLI_SECRETS):/run/secrets:ro" \
		$(IMAGE_CLI):$(IMAGE_TAG) \
		token validate \
		--config "$(CLI_CONFIG_CONTAINER)" \
		--token "$(TOKEN)" \
		$(if $(CLAIM_EXPRESSION),--claim-expression '$(CLAIM_EXPRESSION)')
