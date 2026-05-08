SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

NODE_VERSION_MIN := 22

MOCK_PORT ?= 7073
APP_PORT  ?= 7074
DEV_PORT  ?= 5173

LOG_DIR  := .dev-logs
TOKEN_F  := .dev-runtime-token
KEY_F    := .dev-auth-token-key

.PHONY: help install build test typecheck clean dev stop check-node deps

help:  ## list targets
	@awk 'BEGIN{FS=":.*##"} /^[a-zA-Z_-]+:.*##/{printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Bail out early if Node is too old. The npm engines field requires >=22.
check-node:
	@v=$$(node -v 2>/dev/null | sed 's/^v//;s/\..*//'); \
	if [ -z "$$v" ] || [ "$$v" -lt "$(NODE_VERSION_MIN)" ]; then \
	  echo "ERROR: Node $(NODE_VERSION_MIN)+ required (found $${v:-none})."; \
	  echo "Try:  nix shell nixpkgs#nodejs_22 -c make $(MAKECMDGOALS)"; \
	  exit 1; \
	fi

install: check-node  ## npm install
	npm install

build: check-node  ## build every workspace
	npm run build

test: check-node  ## run all tests
	npm test

typecheck: check-node  ## tsc --noEmit across the workspace
	npm run typecheck

clean:  ## remove dist + dev artefacts
	npm run clean
	rm -rf $(LOG_DIR) $(TOKEN_F) $(KEY_F)

# Persist the runtime token + auth key across `make dev` invocations so the
# server doesn't reject existing JWTs / WebAuthn nonces every restart.
$(TOKEN_F):
	openssl rand -hex 32 > $@
$(KEY_F):
	openssl rand -hex 32 > $@

# `tsx watch` resolves workspace deps via the package.json `main` fields, which
# point at dist/. Make sure those exist before starting the server.
deps: $(TOKEN_F) $(KEY_F) protocol/dist/index.js lib/dist/index.js

protocol/dist/index.js: $(wildcard protocol/src/*.ts)
	npm -w @e2ee-kv/protocol run build

lib/dist/index.js: $(wildcard lib/src/*.ts)
	npm -w @enclave-sdk/browser run build

dev: check-node deps  ## mock-runtime + server (tsx watch) + vite dev — Ctrl+C stops all
	@mkdir -p $(LOG_DIR)
	@# Reap stragglers from a previous run so the ports are free. Quiet — most
	@# of the time there's nothing to kill.
	@pkill -f 'test/mock-runtime.mjs' 2>/dev/null || true; \
	pkill -f 'tsx watch.*src/index.ts' 2>/dev/null || true; \
	pkill -f 'enclave-e2ee-kv/server/dist/index.js' 2>/dev/null || true; \
	pkill -f 'enclave-e2ee-kv/node_modules/.bin/vite' 2>/dev/null || true; \
	sleep 0.3
	@RUNTIME_TOKEN=$$(cat $(TOKEN_F)); AUTH_KEY=$$(cat $(KEY_F)); \
	printf "\n  mock-runtime   → http://localhost:%s\n" "$(MOCK_PORT)"; \
	printf "  e2ee-kv-server → http://localhost:%s  (tsx watch)\n" "$(APP_PORT)"; \
	printf "  vite dev       → http://localhost:%s\n\n" "$(DEV_PORT)"; \
	printf "Open http://localhost:%s in your browser. Ctrl+C stops everything.\n\n" "$(DEV_PORT)"; \
	trap 'kill 0' INT TERM EXIT; \
	ENCLAVE_RUNTIME_TOKEN=$$RUNTIME_TOKEN MOCK_PORT=$(MOCK_PORT) \
	  node test/mock-runtime.mjs 2>&1 | sed -u 's/^/[mock]   /' & \
	ENCLAVE_RUNTIME_TOKEN=$$RUNTIME_TOKEN AUTH_TOKEN_KEY=$$AUTH_KEY \
	  RP_ORIGIN=http://localhost:$(DEV_PORT) ENCLAVE_APP_PORT=$(APP_PORT) \
	  npm -w e2ee-kv-server run dev 2>&1 | sed -u 's/^/[server] /' & \
	npm -w e2ee-kv-client run dev 2>&1 | sed -u 's/^/[vite]   /' & \
	wait

stop:  ## kill any stray dev processes from a previous `make dev`
	-pkill -f 'test/mock-runtime.mjs' 2>/dev/null || true
	-pkill -f 'tsx watch.*src/index.ts' 2>/dev/null || true
	-pkill -f 'enclave-e2ee-kv/server/dist/index.js' 2>/dev/null || true
	-pkill -f 'node_modules/.bin/vite' 2>/dev/null || true
	@echo "stopped (or nothing to stop)"

regtest-deps: check-node  ## one-shot: download Playwright Chromium (~250MB)
	npx playwright install chromium

regtest: check-node  ## boot EIF in QEMU + smoke + headless browser flow (Ctrl+C tears down)
	@./test/run.sh

regtest-fast: check-node  ## same as regtest but reuses an existing EIF (skips build phase)
	@EIF=enclave/.enclave/artifacts/image.eif ./test/run.sh
