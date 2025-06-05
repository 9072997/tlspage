#!/bin/sh
cd "$(dirname "$0")"
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" .
GOARCH=wasm GOOS=js go build -o tlspagelib.wasm
