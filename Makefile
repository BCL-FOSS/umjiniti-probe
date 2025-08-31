WRKDIR=$(shell cd $(dir $(lastword $(MAKEFILE_LIST))) && pwd)
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
SYSMD_VENV_DIR=$(BUILD_DIR)$(INSTALL_DIR)/venv
RC_VENV_DIR=$(BUILD_DIR)$(FREEBSD_INSTALL_DIR)/venv

clean:
	rm -rf $(BUILD_DIR) *.deb *.rpm *.pkg *.txz

# Create venv in staged tree (per Python venv docs)
build-venv:
	mkdir -p $(BUILD_DIR)$(INSTALL_DIR)
	python3 -m venv $(SYSMD_VENV_DIR)
	$(SYSMD_VENV_DIR)/bin/pip install --upgrade pip
	$(SYSMD_VENV_DIR)/bin/pip install -r requirements.txt
	$(SYSMD_VENV_DIR)/bin/pip install .

# fpm packaging (per fpm docs: https://fpm.readthedocs.io/en/latest/)
build-deb:
	fpm -s dir -t deb -n $(APP_NAME) -v $(VERSION) -a $(ARCH) \
		-p $(APP_NAME)-$(VERSION)-$(ARCH).deb \
		--description "$(DESCRIPTION)" --maintainer $(MAINTAINER) \
		--prefix / --chdir $(BUILD_DIR) \
		--before-install scripts/preinstall.sh \
		--after-install scripts/postinstall.sh \
		--deb-systemd scripts/$(APP_NAME).service \
		--config-files /etc/systemd/system/bcl-umj-probe.service \
		--directories $(INSTALL_DIR) \
		--depends python3 --depends python3-pip --depends python3-venv \
		--depends iperf3 --depends tshark --depends redis --depends traceroute --depends p0f \
		scripts/bcl-umj-probe.service=etc/systemd/system/bcl-umj-probe.service \
		./=$(PREFIX)

build-rpm:
	fpm -s dir -t rpm -n $(APP_NAME) -v $(VERSION) -a $(ARCH) \
		-p $(APP_NAME)-$(VERSION)-$(ARCH).rpm \
		--description "$(DESCRIPTION)" --maintainer $(MAINTAINER) \
		--prefix / --chdir $(BUILD_DIR) \
		--before-install scripts/preinstall.sh \
		--after-install scripts/postinstall.sh \
		--rpm-systemd scripts/$(APP_NAME).service \
		--config-files /etc/systemd/system/bcl-umj-probe.service \
		--directories $(INSTALL_DIR) \
		--depends python3 --depends python3-pip --depends python3-venv \
		--depends iperf3 --depends tshark --depends redis --depends traceroute --depends p0f \
		scripts/bcl-umj-probe.service=etc/systemd/system/bcl-umj-probe.service \
		./=$(PREFIX)

build-pkg:
	fpm -s dir -t freebsd -n $(APP_NAME) -v $(VERSION) -a $(ARCH) \
		-p $(APP_NAME)-$(VERSION)-$(ARCH).pkg \
		--description "$(DESCRIPTION)" --maintainer $(MAINTAINER) \
		--prefix / --chdir $(BUILD_DIR) \
		--before-install scripts/preinstall.sh \
		--after-install scripts/postinstall.sh \
		--config-files /etc/rc.d/bcl-umj-probe \
		scripts/bcl-umj-probe=/etc/rc.d/bcl-umj-probe \
		./=$(PREFIX)

build-txz:
	fpm -s dir -t freebsd -n $(APP_NAME) -v $(VERSION) -a amd64 \
		-p $(APP_NAME)-FIREWALL-$(VERSION)-amd64.txz \
		--description "$(DESCRIPTION)" --maintainer $(MAINTAINER) \
		--prefix / --chdir $(BUILD_DIR) \
		--before-install scripts/preinstall.sh \
		--after-install scripts/postinstall.sh \
		--config-files /etc/rc.d/bcl-umj-probe \
		scripts/bcl-umj-probe=/etc/rc.d/bcl-umj-probe \
		./=$(PREFIX)


.PHONY: build-deb build-rpm build-pkg build-txz build-venv clean
