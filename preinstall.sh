#!/bin/sh

install_dependencies() {
    DISTRO=$1
    echo "Updating package repository..."

    case "$DISTRO" in
        debian|ubuntu)
            sudo apt update -y

            if ! command -v redis-server > /dev/null 2>&1; then
                echo "Installing Redis..."
                sudo apt-get install lsb-release curl gpg
                curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
                sudo chmod 644 /usr/share/keyrings/redis-archive-keyring.gpg
                echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
                sudo apt-get update
                sudo apt-get install redis
            
                echo "Enabling and starting Redis service..."
                sudo systemctl enable redis-server
                sudo systemctl start redis-server
            else
                echo "redis-server is already installed."
            fi

            PACKAGE_MANAGER="apt"
            PACKAGE_LIST="tshark tcpdump gpsd gpsd-clients iputils-ping iperf3 aircrack-ng libpcap-dev p0f traceroute"
            ;;
        rhel|centos|fedora|rocky|almalinux)
            sudo dnf update -y
            if ! command -v redis > /dev/null 2>&1; then
                echo "Installing redis..."
                sudo yum install -y redis || sudo dnf install -y redis

                sudo systemctl enable redis
                sudo systemctl start redis
            else
                echo "traceroute is already installed."
            fi
            PACKAGE_MANAGER="dnf"
            PACKAGE_LIST="tshark tcpdump gpsd gpsd-clients iputils-ping iperf3 aircrack-ng libpcap-dev p0f traceroute"
            ;;
        freebsd)
            sudo pkg update -y
            if ! command -v redis > /dev/null 2>&1; then
                echo "Redis is not installed. Installing Redis..."
                sudo pkg install -y redis

                sudo service redis enable
                sudo service redis start
            fi
            PACKAGE_MANAGER="pkg"
            PACKAGE_LIST="tshark tcpdump gpsd gpsd-clients iputils-ping iperf3 aircrack-ng libpcap-dev p0f traceroute"
            ;;
        *)
            echo "Unknown or unsupported distribution. Exiting."
            exit 1
            ;;
    esac

    # Install all necessary packages for probe
    echo "Installing packages: $PACKAGE_LIST"
    $PACKAGE_MANAGER install -y $PACKAGE_LIST

    # Python setup
    echo "Checking for Python installation..."
    if ! command -v python3 > /dev/null 2>&1; then
        echo "Installing Python3..."
        case "$DISTRO" in
            debian|ubuntu) sudo apt install -y python3 ;;
            rhel|centos|fedora|rocky|almalinux) sudo yum install -y python3 || sudo dnf install -y python3 ;;
            freebsd) sudo pkg install -y python3 ;;
        esac
    fi

    # pip3 setup
    if ! command -v pip3 > /dev/null 2>&1; then
        echo "Installing pip3..."
        case "$DISTRO" in
            debian|ubuntu) sudo apt install -y python3-pip ;;
            rhel|centos|fedora|rocky|almalinux) sudo yum install -y python3-pip || sudo dnf install -y python3-pip ;;
            freebsd) sudo pkg install -y py39-pip ;;
        esac
    fi

    # python3-venv setup
    echo "Checking for python3-venv installation..."
    if ! python3 -m venv --help > /dev/null 2>&1; then
        echo "Installing python3-venv..."
        case "$DISTRO" in
            debian|ubuntu) sudo apt install -y python3-venv ;;
            rhel|centos|fedora|rocky|almalinux) sudo yum install -y python3-venv || sudo dnf install -y python3-venv ;;
            freebsd) sudo pkg install -y py39-virtualenv ;;
        esac
    fi

    echo "Installation of dependencies completed."
}

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
install_dependencies "$DISTRIBUTION"