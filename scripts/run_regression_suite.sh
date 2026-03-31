#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cd "$ROOT_DIR"

echo "[regression] cargo fmt --all --check"
cargo fmt --all --check

echo "[regression] cargo check --workspace"
cargo check --workspace

echo "[regression] cargo test --workspace --exclude sandbox-seccomp --exclude sandbox-supervisor"
cargo test --workspace --exclude sandbox-seccomp --exclude sandbox-supervisor

echo "[regression] cargo test -p sandbox-supervisor -- --test-threads=1"
cargo test -p sandbox-supervisor -- --test-threads=1

echo "[regression] cargo test -p sandbox-seccomp -- --test-threads=1"
cargo test -p sandbox-seccomp -- --test-threads=1

echo "[regression] validate minimal config"
cargo run -p sandbox-cli -- --log-level warn validate --config configs/minimal.toml

echo "[regression] validate strict config"
cargo run -p sandbox-cli -- --log-level warn validate --config configs/strict.toml

echo "[regression] inspect minimal config"
cargo run -p sandbox-cli -- --log-level warn inspect --config configs/minimal.toml --result-format json >"$TMP_DIR/minimal-inspect.json"

echo "[regression] inspect strict config"
cargo run -p sandbox-cli -- --log-level warn inspect --config configs/strict.toml --result-format json >"$TMP_DIR/strict-inspect.json"

echo "[regression] completed successfully"
