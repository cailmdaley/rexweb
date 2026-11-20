APP := build/RexWeb.app
PREFIX ?= $(HOME)/.local
APPDIR ?= $(HOME)/Applications
ARCH := $(shell uname -m)

.PHONY: build install uninstall clean
build: $(APP)

$(APP): Sources/RexWeb.swift Info.plist bin/rexweb-pane bin/rexweb bin/rexweb-remote AGENTS.md
	mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources
	swiftc -O -swift-version 5 -target $(ARCH)-apple-macos14 Sources/RexWeb.swift -o $(APP)/Contents/MacOS/RexWeb
	cp Info.plist $(APP)/Contents/Info.plist
	cp bin/rexweb-pane bin/rexweb bin/rexweb-remote AGENTS.md $(APP)/Contents/Resources/
	codesign --force --sign - $(APP)
	touch $(APP)

install: build
	-pkill -x RexWeb
	mkdir -p $(APPDIR) $(PREFIX)/bin
	rm -rf $(APPDIR)/RexWeb.app && cp -R $(APP) $(APPDIR)/
	ln -sf $(APPDIR)/RexWeb.app/Contents/Resources/rexweb $(PREFIX)/bin/rexweb
	@echo "installed $(APPDIR)/RexWeb.app and $(PREFIX)/bin/rexweb"

uninstall:
	-pkill -x RexWeb
	-/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -u $(APPDIR)/RexWeb.app 2>/dev/null
	rm -rf $(APPDIR)/RexWeb.app $(PREFIX)/bin/rexweb

clean:
	rm -rf build
