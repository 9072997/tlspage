#!/bin/sh
cd "$(dirname "$0")"
CGO_LDFLAGS="-l:libdqlite.a -l:libraft.a -l:libxxhash.a -l:liblz4.a -l:libuv.a -Wl,-z,now" go build
