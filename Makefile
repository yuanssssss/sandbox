SHELL := /bin/bash

PROJECT_NAME ?= sandbox
DOCKER ?= docker
REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
DOCKER_DIR := $(REPO_ROOT)/docker
DOCKER_PLATFORM ?=
SANDBOX_PORT ?= 3000

DEV_IMAGE ?= $(PROJECT_NAME)-dev
PROD_IMAGE ?= $(PROJECT_NAME)-prod
DEV_CONTAINER ?= $(PROJECT_NAME)-dev
PROD_CONTAINER ?= $(PROJECT_NAME)-prod

DEV_DOCKERFILE := $(DOCKER_DIR)/dev.Dockerfile
PROD_DOCKERFILE := $(DOCKER_DIR)/prod.Dockerfile
DOCKER_PLATFORM_ARG := $(if $(DOCKER_PLATFORM),--platform $(DOCKER_PLATFORM),)
COMMON_CONTAINER_FLAGS := --privileged --cgroupns=host --mount type=bind,src=/sys/fs/cgroup,dst=/sys/fs/cgroup
DEV_CONTAINER_FLAGS := $(COMMON_CONTAINER_FLAGS) --mount type=bind,src=$(REPO_ROOT),dst=/workspace --workdir /workspace
PROD_CONTAINER_FLAGS := $(COMMON_CONTAINER_FLAGS) -p $(SANDBOX_PORT):3000

.PHONY: help docker-build docker-build-dev docker-build-prod docker-run-dev docker-run-prod \
	docker-shell-dev docker-shell-prod docker-stop-dev docker-stop-prod docker-rm-dev \
	docker-rm-prod docker-logs-prod

help:
	@echo "make docker-build-dev      # 构建开发环境镜像"
	@echo "make docker-build-prod     # 构建发布环境镜像"
	@echo "make docker-build          # 同时构建开发/发布镜像"
	@echo "make docker-run-dev        # 启动开发容器并挂载当前仓库"
	@echo "make docker-shell-dev      # 进入开发容器"
	@echo "make docker-stop-dev       # 停止开发容器"
	@echo "make docker-rm-dev         # 删除开发容器"
	@echo "make docker-run-prod       # 启动发布容器，默认监听 0.0.0.0:3000"
	@echo "make docker-shell-prod     # 进入发布容器"
	@echo "make docker-logs-prod      # 查看发布容器日志"
	@echo "make docker-stop-prod      # 停止发布容器"
	@echo "make docker-rm-prod        # 删除发布容器"

docker-build: docker-build-dev docker-build-prod

docker-build-dev:
	$(DOCKER) build $(DOCKER_PLATFORM_ARG) -f $(DEV_DOCKERFILE) -t $(DEV_IMAGE) $(REPO_ROOT)

docker-build-prod:
	$(DOCKER) build $(DOCKER_PLATFORM_ARG) -f $(PROD_DOCKERFILE) -t $(PROD_IMAGE) $(REPO_ROOT)

docker-run-dev: docker-build-dev
	-$(DOCKER) rm -f $(DEV_CONTAINER)
	$(DOCKER) run -d \
		--name $(DEV_CONTAINER) \
		$(DEV_CONTAINER_FLAGS) \
		$(DEV_IMAGE) \
		sleep infinity

docker-run-prod: docker-build-prod
	-$(DOCKER) rm -f $(PROD_CONTAINER)
	$(DOCKER) run -d \
		--name $(PROD_CONTAINER) \
		$(PROD_CONTAINER_FLAGS) \
		$(PROD_IMAGE)

docker-shell-dev:
	@if ! $(DOCKER) ps --format '{{.Names}}' | grep -qx '$(DEV_CONTAINER)'; then \
		if $(DOCKER) ps -a --format '{{.Names}}' | grep -qx '$(DEV_CONTAINER)'; then \
			$(DOCKER) start $(DEV_CONTAINER) >/dev/null; \
		else \
			$(MAKE) docker-run-dev; \
		fi; \
	fi
	$(DOCKER) exec -it $(DEV_CONTAINER) bash

docker-shell-prod:
	@if ! $(DOCKER) ps --format '{{.Names}}' | grep -qx '$(PROD_CONTAINER)'; then \
		if $(DOCKER) ps -a --format '{{.Names}}' | grep -qx '$(PROD_CONTAINER)'; then \
			$(DOCKER) start $(PROD_CONTAINER) >/dev/null; \
		else \
			$(MAKE) docker-run-prod; \
		fi; \
	fi
	$(DOCKER) exec -it $(PROD_CONTAINER) bash

docker-logs-prod:
	$(DOCKER) logs -f $(PROD_CONTAINER)

docker-stop-dev:
	-$(DOCKER) stop $(DEV_CONTAINER)

docker-stop-prod:
	-$(DOCKER) stop $(PROD_CONTAINER)

docker-rm-dev:
	-$(DOCKER) rm -f $(DEV_CONTAINER)

docker-rm-prod:
	-$(DOCKER) rm -f $(PROD_CONTAINER)
