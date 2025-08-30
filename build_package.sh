#!/bin/bash
set -e

WRKDIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="bcl-umj-probe"
VERSION="1.0.0"
ARCH="all"
INSTALL_DIR="/opt/$APP_NAME"
FREEBSD_INSTALL_DIR="/usr/local/$APP_NAME"
BUILD_DIR="$WRKDIR/build"
PKG_ROOT="$WRKDIR"
MAINTAINER="derekb@baughcl.com"
DESCRIPTION="umjiniti probe for network monitoring, mapping & troubleshooting."
PRE_INSTALL="$BUILD_DIR/scripts/preinstall.sh"
POST_INSTALL="$BUILD_DIR/scripts/postinstall.sh"

# Clean previous build & create build folder
make clean

mkdir -p $BUILD_DIR

echo "📦 Copying probe files to build directory..."

cp requirements.txt setup.py "$BUILD_DIR/"

# Bash scripts
cp -r $WRKDIR/scripts "$BUILD_DIR/"

# App files
cp -r $WRKDIR/bcl_umj_probe "$BUILD_DIR/"

# setup virtual env
make build-venv

# === PACKAGE CREATION ===
echo "🚀 Building .deb, .rpm, and FreeBSD packages..."

case "$1" in 
    --deb)
        make build-deb
        echo "✅ Package built successfully."   
        ;;
    --rpm)
        make build-rpm
        echo "✅ Package built successfully."
        ;;
    --pkg)
        make build-pkg
        echo "✅ Package built successfully."
        ;;
    --txz)
        make build-txz
        echo "🔒 pfSense/OPNsense compatible package created."
        ;;
    *)
        echo "Usage: $0 [--deb | --rpm | --pkg | --txz]"
        exit 1
        ;;

esac
