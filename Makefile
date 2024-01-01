VERSION := $(file <version)

SRC_FILE := grub-$(VERSION).tar.xz
SIGN_FILE := $(SRC_FILE).sig

URL := https://ftp.gnu.org/gnu/grub/

URL_FILE := $(URL)$(SRC_FILE)
URL_SIGN := $(URL)$(SIGN_FILE)

ifeq ($(FETCH_CMD),)
$(error "You can not run this Makefile without having FETCH_CMD defined")
endif

get-sources: $(SRC_FILE) $(SIGN_FILE)

$(SRC_FILE):
	@$(FETCH_CMD) $(SRC_FILE) $(URL_FILE) || { echo "Curl failed with code $$?"; exit 1; }

$(SIGN_FILE):
	@$(FETCH_CMD) $(SIGN_FILE) $(URL_SIGN) || { echo "Curl failed with code $$?"; exit 1; }

import-keys:
	@if [ -n "$$GNUPGHOME" ]; then rm -f "$$GNUPGHOME/linux-pvgrub2-trustedkeys.gpg"; fi
	@gpg --no-auto-check-trustdb --no-default-keyring --keyring linux-pvgrub2-trustedkeys.gpg -q --import *-key.asc

verify-sources: import-keys
	@gpgv --keyring linux-pvgrub2-trustedkeys.gpg $(SIGN_FILE) $(SRC_FILE) 2>/dev/null

.PHONY : clean
clean:
	rm -rf pkgs
