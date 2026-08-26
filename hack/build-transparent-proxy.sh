#!/usr/bin/env bash
# Build the (private) transparent-proxy binary into this repo's build context so
# the Dockerfile can bundle it. Local-dev only, until transparent-proxy publishes
# release artifacts fetched like the other sidecars.
#
# Usage: hack/build-transparent-proxy.sh [GOARCH]
#   GOARCH defaults to the host arch (arm64 on Apple Silicon). Set it to match
#   the architecture of the image you are building / your minikube node.
set -euo pipefail

ARCH="${1:-$(go env GOARCH)}"
SRC="${TRANSPARENT_PROXY_SRC:-../transparent-proxy}"
OUT="transparent-proxy.bin"

if [[ ! -d "$SRC" ]]; then
  echo "transparent-proxy source not found at '$SRC' (set TRANSPARENT_PROXY_SRC)" >&2
  exit 1
fi

OUT_ABS="$(pwd)/$OUT"
echo "Building transparent-proxy (linux/$ARCH) from $SRC -> $OUT"
( cd "$SRC" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -o "$OUT_ABS" . )
chmod a+x "$OUT_ABS"
echo "Done: $(ls -lh "$OUT_ABS" | awk '{print $5}')"
