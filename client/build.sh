#!/bin/bash
prefix="tlspage"

cd "$(dirname "$0")"
if [ -d "builds" ]; then
	echo "Removing existing builds directory..."
	rm -rf builds
fi

# Get supported platforms/architectures from Go
platforms=$(go tool dist list)

export GOOS GOARCH
export CGO_ENABLED=0
for platform in $platforms
do
	IFS="/" read -r GOOS GOARCH <<< "$platform"
	echo "Building for $GOOS/$GOARCH..."
	mkdir -p "builds/$GOOS/$GOARCH"
	
	# Special case for WebAssembly
	if [ "$GOOS" = "js" ] && [ "$GOARCH" = "wasm" ]; then
		(
			out="builds/$GOOS/$GOARCH"
			mkdir -p "$out"
			cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$out/"
			build_output=`go build -o "$out/tlspagelib.wasm" ../js`
			if [ $? -ne 0 ]; then
				echo "	Failed to build for $GOOS/$GOARCH"
			fi
			if [ -n "$build_output" ]; then
				sed 's/^/	/' <<< "$build_output"
			fi
		)
		continue
	elif [ "$GOARCH" = "wasm" ]; then
		echo "Skipping WASM build for $GOOS/$GOARCH"
		continue
	elif [ "$GOOS" = "js" ]; then
		echo "Skipping JS build for $GOOS/$GOARCH"
		continue
	fi
	
	output_name="builds/${GOOS}/${GOARCH}/${prefix}"
	if [ "$GOOS" = "windows" ]; then
		output_name="${output_name}.exe"
	fi

	build_output=`go build -o "$output_name" 2>&1`
	if [ $? -ne 0 ]; then
		echo "	Failed to build for $GOOS/$GOARCH"
	fi
	if [ -n "$build_output" ]; then
		sed 's/^/	/' <<< "$build_output"
	fi
done

# remove any empty directories
find builds -type d -empty -delete

# get the help text from the binary
echo "Generating help text for the current build..."
export -n GOOS GOARCH
GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)
our_bin="builds/${GOOS}/${GOARCH}/${prefix}"
if [ -f "$our_bin" ]; then
	"$our_bin" --help 2>&1 | sed "s|$our_bin|tlspage|" > "builds/help.txt"
else
	echo "Help text not available for $GOOS/$GOARCH build."
fi

echo "Done."
