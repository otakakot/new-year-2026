SHELL := /bin/bash

export APP_NAME := $(basename $(notdir $(shell pwd)))

.PHONY: help
help: ## display this help screen
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: local
local: ## start the application
	@docker compose --project-name ${APP_NAME} --file ./.docker/compose.yaml up --detach

.PHONY: down
down: ## stop the application
	@docker compose --project-name $(APP_NAME) down --volumes

.PHONY: gen
gen: ## generate code.
	@go generate ./...
	@go mod tidy
