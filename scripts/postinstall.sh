#!/bin/sh

set -e

get_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /usr/share/man/man1/freebsd-update.1.gz ]; then
        echo "freebsd"
    else
        echo "unknown"
    fi
}

DISTRIBUTION=$(get_distro)

case "$DISTRIBUTION" in
    debian|ubuntu|rhel|centos|fedora|rocky|almalinux)
        echo "Detected Linux system with systemd."
        systemctl daemon-reexec || true
        systemctl enable bcl-umj-probe.service
        systemctl restart bcl-umj-probe.service
        ;;
    freebsd)
        echo "Detected FreeBSD system."
        chmod +x /usr/local/etc/rc.d/bcl-umj-probe
        sysrc bcl_umj_probe_enable="YES"
        service bcl-umj-probe start
        ;;
    *)
        echo "Unsupported distribution: $DISTRIBUTION"
        exit 1
        ;;
esac
