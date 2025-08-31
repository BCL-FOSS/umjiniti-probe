# umjiniti-probe
Open source network monitoring and analysis MCP server and API

```bash
# Update system and install Ruby and build tools
$ sudo apt-get install -y \
    ruby-full \
    rpm \
    squashfs-tools \
    build-essential 

# Install FPM (from official docs)
$ gem install fpm

$ sudo chmod +x build_package.sh

$ sudo ./build_package.sh  "Usage: $0 [--deb | --rpm | --pkg | --txz]"
```
