# Load variables from .env (if present) and export them to all recipes so both
# the Node ingest script and the Go parser binary can read FACEIT_API_KEY.
ifneq (,$(wildcard .env))
include .env
export
endif

NODE       ?= node
GO         ?= go
PARSER_BIN ?= parser.bin

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## Create .env from .env.example if it does not exist
	@if [ ! -f .env ]; then cp .env.example .env && echo "Created .env - add your FACEIT_API_KEY"; else echo ".env already exists"; fi

.PHONY: check-key
check-key:
	@if [ -z "$(FACEIT_API_KEY)" ]; then \
		echo "FACEIT_API_KEY is not set. Run 'make setup' and fill in .env."; \
		exit 1; \
	fi

.PHONY: ingest
ingest: check-key ## Fetch recent FACEIT matches -> data/matches.json, data/state.json
	$(NODE) scripts/ingest.mjs

.PHONY: build-parser
build-parser: ## Compile the Go demo parser -> parser.bin
	cd parser && $(GO) build -o ../$(PARSER_BIN) .

.PHONY: parse
parse: check-key build-parser ## Build + parse demos -> data/highlights.json, data/leaderboards.json
	./$(PARSER_BIN)

.PHONY: pipeline
pipeline: ingest parse ## Run the full pipeline locally (ingest, then parse)

.PHONY: tidy
tidy: ## Run go mod tidy for the parser module
	cd parser && $(GO) mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	rm -f $(PARSER_BIN)
