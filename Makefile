WRKDIR=$(cd $(dirname $0) && pwd)
APP_NAME=bcl-umj-probe
VERSION=1.0.0
ARCH=all
INSTALL_DIR=/opt/$(APP_NAME)
FREEBSD_INSTALL_DIR=/usr/local/$(APP_NAME)
BUILD_DIR=$(WRKDIR)/build
MAINTAINER=derekb@baughcl.com
DESCRIPTION=umjiniti probe for network monitoring, mapping & troubleshooting.
PRE_INSTALL=$(BUILD_DIR)/scripts/preinstall.sh
POST_INSTALL=$(BUILD_DIR)/scripts/postinstall.sh
SYSMD_VENV_DIR=$(INSTALL_DIR)/venv
RC_VENV_DIR=$(FREEBSD_INSTALL_DIR)/venv

clean:
	rm -rf $(BUILD_DIR) *.deb *.rpm *.pkg *.txz

build-venv:
	python3 -m venv $(BUILD_DIR)/venv
	$(BUILD_DIR)/venv/bin/pip install --upgrade pip
	$(BUILD_DIR)/venv/bin/pip install -r requirements.txt
	$(BUILD_DIR)/venv/bin/python python -m pip install .

build-deb:
	fpm -s dir -t deb -n $(APP_NAME) -v $(VERSION) -a $(ARCH) -p $(APP_NAME)-$(VERSION)-$(ARCH).deb --description $(DESCRIPTION) --maintainer $(MAINTAINER) --prefix /opt --chdir $(BUILD_DIR) --before-install $(PRE_INSTALL) --after-install $(POST_INSTALL) --deb-systemd $(BUILD_DIR)/scripts/$(APP_NAME).service --config-files /etc/systemd/system/bcl-umj-probe.service --directories $(INSTALL_DIR) --depends python3 --depends python3-pip --depends python3-venv --depends iperf3 --depends tshark --depends redis --depends traceroute --depends p0f $(BUILD_DIR)/scripts/bcl-umj-probe.service=etc/systemd/system/bcl-umj-probe.service $(BUILD_DIR)/=$(INSTALL_DIR)

build-rpm:
	fpm -s dir -t rpm -n $(APP_NAME) -v $(VERSION) -a $(ARCH) -p $(APP_NAME)-$(VERSION)-$(ARCH).rpm  --description $(DESCRIPTION) --maintainer $(MAINTAINER) --prefix /opt --chdir $(BUILD_DIR) --before-install $(PRE_INSTALL) --after-install $(POST_INSTALL) --rpm-systemd $(BUILD_DIR)/scripts/$(APP_NAME).service --config-files /etc/systemd/system/bcl-umj-probe.service --directories $(INSTALL_DIR) --chdir $(BUILD_DIR) --depends python3 --depends python3-pip --depends python3-venv --depends iperf3 --depends tshark --depends redis --depends traceroute --depends p0f $(BUILD_DIR)/scripts/bcl-umj-probe.service=etc/systemd/system/bcl-umj-probe.service $(BUILD_DIR)/=$(INSTALL_DIR)

build-pkg:
	fpm -s dir -t freebsd -n $(APP_NAME) -v $(VERSION) -a $(ARCH) -p $(APP_NAME)-$(VERSION)-$(ARCH).pkg --description $(DESCRIPTION) --maintainer $(MAINTAINER) --prefix /usr/local --chdir $(BUILD_DIR) --before-install $(PRE_INSTALL) --after-install $(POST_INSTALL) --config-files /etc/rc.d/bcl-umj-probe --chdir $(BUILD_DIR) $(BUILD_DIR)/scripts/bcl-umj-probe=/etc/rc.d/bcl-umj-probe $(BUILD_DIR)/=$(FREEBSD_INSTALL_DIR)

build-txz:
	fpm -s dir -t freebsd -n $(APP_NAME) -v $(VERSION) -a amd64 -p $(APP_NAME)-FIREWALL-$(VERSION)-amd64.txz --description $(DESCRIPTION) --maintainer $(MAINTAINER) --prefix /usr/local --chdir $(BUILD_DIR) --before-install $(PRE_INSTALL) --after-install $(POST_INSTALL) --config-files /etc/rc.d/bcl-umj-probe --chdir $(BUILD_DIR) $(BUILD_DIR)/scripts/bcl-umj-probe=/etc/rc.d/bcl-umj-probe $(BUILD_DIR)/=$(FREEBSD_INSTALL_DIR)

.PHONY: build-deb build-rpm build-pkg build-txz build-venv clean
