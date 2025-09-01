#!/bin/bash
set -e

WRKDIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="bcl-umj-probe"
VERSION="1.0.0"
ARCH="all"
BUILD_DIR="$WRKDIR/bcl_umj_probe"
MAINTAINER="derekb@baughcl.com"
DESCRIPTION="umjiniti probe for network monitoring, mapping & troubleshooting."

# Create venv in staged prefix (per Python venv docs)
echo "⚙️ Creating Python venv inside build staging..."
sudo python3 -m venv "$BUILD_DIR/venv"
sudo "$BUILD_DIR/venv/bin/pip" install --upgrade pip
sudo "$BUILD_DIR/venv/bin/pip" install -r requirements.txt
sudo "$BUILD_DIR/venv/bin/pip" install .

echo "✅ Package built successfully."
