CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -pedantic

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
EXAMPLE_DIR := $(dir $(abspath $(THIS_MAKEFILE)))
REPO_ROOT := $(abspath $(EXAMPLE_DIR)/../..)
EXAMPLE_REL_DIR := examples/01
BUILD_DIR ?= $(EXAMPLE_DIR)/build
CONFIG_DIR ?= $(EXAMPLE_REL_DIR)/configs
JUDGE_JOB_DIR ?= $(EXAMPLE_REL_DIR)/judge-jobs
SANDBOX ?= cd $(REPO_ROOT) && cargo run --manifest-path $(REPO_ROOT)/Cargo.toml -p sandbox-cli --
API_BASE ?= http://127.0.0.1:3000

BINARIES := \
	$(BUILD_DIR)/hello \
	$(BUILD_DIR)/memory_limit \
	$(BUILD_DIR)/timeout \
	$(BUILD_DIR)/danger_ptrace \
	$(BUILD_DIR)/danger_socket

.PHONY: all clean help sandbox-validate sandbox-compile sandbox-run-hello sandbox-run-timeout \
	sandbox-run-memory-limit sandbox-run-danger-ptrace sandbox-run-danger-socket \
	sandbox-judge-cpp sandbox-judge-java sandbox-judge-python \
	sandbox-judge-cpp-portable sandbox-judge-python-portable

all: $(BINARIES)

help:
	@echo "current example dir: $(EXAMPLE_DIR)"
	@echo "repo root: $(REPO_ROOT)"
	@echo "make -f examples/01/Makefile all"
	@echo "make -f examples/01/Makefile clean"
	@echo "make -f examples/01/Makefile sandbox-validate"
	@echo "make -f examples/01/Makefile sandbox-compile"
	@echo "make -f examples/01/Makefile sandbox-run-hello"
	@echo "make -f examples/01/Makefile sandbox-run-timeout"
	@echo "make -f examples/01/Makefile sandbox-run-memory-limit"
	@echo "make -f examples/01/Makefile sandbox-run-danger-ptrace"
	@echo "make -f examples/01/Makefile sandbox-run-danger-socket"
	@echo "make -f examples/01/Makefile sandbox-judge-cpp API_BASE=http://127.0.0.1:3000"
	@echo "make -f examples/01/Makefile sandbox-judge-java API_BASE=http://127.0.0.1:3000"
	@echo "make -f examples/01/Makefile sandbox-judge-python API_BASE=http://127.0.0.1:3000"
	@echo "make -f examples/01/Makefile sandbox-judge-cpp-portable API_BASE=http://127.0.0.1:3000"
	@echo "make -f examples/01/Makefile sandbox-judge-python-portable API_BASE=http://127.0.0.1:3000"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/hello: $(EXAMPLE_DIR)/main.c $(EXAMPLE_DIR)/extra.c $(EXAMPLE_DIR)/extra.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXAMPLE_DIR)/main.c $(EXAMPLE_DIR)/extra.c -o $@

$(BUILD_DIR)/memory_limit: $(EXAMPLE_DIR)/memory_limit.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXAMPLE_DIR)/memory_limit.c -o $@

$(BUILD_DIR)/timeout: $(EXAMPLE_DIR)/timeout.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXAMPLE_DIR)/timeout.c -o $@

$(BUILD_DIR)/danger_ptrace: $(EXAMPLE_DIR)/danger_ptrace.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXAMPLE_DIR)/danger_ptrace.c -o $@

$(BUILD_DIR)/danger_socket: $(EXAMPLE_DIR)/danger_socket.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(EXAMPLE_DIR)/danger_socket.c -o $@

clean:
	rm -rf $(BUILD_DIR)

sandbox-validate:
	$(SANDBOX) validate --config $(CONFIG_DIR)/compile.toml
	$(SANDBOX) validate --config $(CONFIG_DIR)/run-hello.toml
	$(SANDBOX) validate --config $(CONFIG_DIR)/run-timeout.toml
	$(SANDBOX) validate --config $(CONFIG_DIR)/run-memory-limit.toml
	$(SANDBOX) validate --config $(CONFIG_DIR)/run-danger-ptrace.toml
	$(SANDBOX) validate --config $(CONFIG_DIR)/run-danger-socket.toml

sandbox-compile:
	$(SANDBOX) compile --config $(CONFIG_DIR)/compile.toml --source-dir . --output-dir $(EXAMPLE_REL_DIR)/build

sandbox-run-hello: all
	$(SANDBOX) run --config $(CONFIG_DIR)/run-hello.toml

sandbox-run-timeout: all
	$(SANDBOX) run --config $(CONFIG_DIR)/run-timeout.toml

sandbox-run-memory-limit: all
	$(SANDBOX) run --config $(CONFIG_DIR)/run-memory-limit.toml

sandbox-run-danger-ptrace: all
	$(SANDBOX) run --config $(CONFIG_DIR)/run-danger-ptrace.toml

sandbox-run-danger-socket: all
	$(SANDBOX) run --config $(CONFIG_DIR)/run-danger-socket.toml

sandbox-judge-cpp:
	sed "s|__REPO_ROOT__|$(REPO_ROOT)|g" $(JUDGE_JOB_DIR)/cpp-isolated.json.in | \
		curl -sS $(API_BASE)/api/v1/judge-jobs -H 'content-type: application/json' --data-binary @-

sandbox-judge-java:
	sed "s|__REPO_ROOT__|$(REPO_ROOT)|g" $(JUDGE_JOB_DIR)/java-isolated.json.in | \
		curl -sS $(API_BASE)/api/v1/judge-jobs -H 'content-type: application/json' --data-binary @-

sandbox-judge-python:
	sed "s|__REPO_ROOT__|$(REPO_ROOT)|g" $(JUDGE_JOB_DIR)/python-isolated.json.in | \
		curl -sS $(API_BASE)/api/v1/judge-jobs -H 'content-type: application/json' --data-binary @-

sandbox-judge-cpp-portable:
	sed "s|__REPO_ROOT__|$(REPO_ROOT)|g" $(JUDGE_JOB_DIR)/cpp-portable.json.in | \
		curl -sS $(API_BASE)/api/v1/judge-jobs -H 'content-type: application/json' --data-binary @-

sandbox-judge-python-portable:
	sed "s|__REPO_ROOT__|$(REPO_ROOT)|g" $(JUDGE_JOB_DIR)/python-portable.json.in | \
		curl -sS $(API_BASE)/api/v1/judge-jobs -H 'content-type: application/json' --data-binary @-
