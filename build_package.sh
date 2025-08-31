#!/bin/bash
set -e

WRKDIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="bcl-umj-probe"
VERSION="1.0.0"
ARCH="all"
INSTALL_DIR="/opt/$APP_NAME"
FREEBSD_INSTALL_DIR="/usr/local/$APP_NAME"
BUILD_DIR="$WRKDIR/build"
MAINTAINER="derekb@baughcl.com"
DESCRIPTION="umjiniti probe for network monitoring, mapping & troubleshooting."
PRE_INSTALL="$BUILD_DIR/scripts/preinstall.sh"
POST_INSTALL="$BUILD_DIR/scripts/postinstall.sh"

# Clean & stage
make clean
mkdir -p "$BUILD_DIR$INSTALL_DIR"
mkdir -p "$BUILD_DIR$FREEBSD_INSTALL_DIR"

echo "📦 Copying probe files into build directory..."
cp requirements.txt setup.py "$BUILD_DIR$INSTALL_DIR/"
cp -r "$WRKDIR/bcl_umj_probe" "$BUILD_DIR$INSTALL_DIR/"

mkdir -p "$BUILD_DIR/scripts"
cp -r "$WRKDIR/scripts/"* "$BUILD_DIR/scripts/"

# Create venv in staged prefix (per Python venv docs)
echo "⚙️ Creating Python venv inside build staging..."
python3 -m venv "$BUILD_DIR$INSTALL_DIR/venv"
"$BUILD_DIR$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$BUILD_DIR$INSTALL_DIR/venv/bin/pip" install -r requirements.txt
"$BUILD_DIR$INSTALL_DIR/venv/bin/pip" install .

# Build package via fpm
echo "🚀 Building package..."
case "$1" in
  --deb)
    make build-deb ;;
  --rpm)
    make build-rpm ;;
  --pkg)
    make build-pkg ;;
  --txz)
    make build-txz ;;
  *)
    echo "Usage: $0 [--deb | --rpm | --pkg | --txz]"
    exit 1 ;;
esac

echo "✅ Package built successfully."
